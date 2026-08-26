package claude

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core"
	"github.com/codingway-hub/a3/pkg/schema"
)

// hookCommandMarker a3 写入的 Hook 命令固定子命令片段（识别标记）。
const hookCommandMarker = "hook pretooluse"

// backupGlobPattern settings 备份文件匹配模式（保留最早一份，不覆盖）。
const backupGlobPattern = "settings.json.a3-bak-*"

// hookEntry settings.json hooks.PreToolUse 数组元素结构。
type hookEntry struct {
	Matcher string     `json:"matcher"`
	Hooks   []hookSpec `json:"hooks"`
}

// hookSpec 单个 hook 命令。
type hookSpec struct {
	Type    string `json:"type"`
	Command string `json:"command"`
}

// 编译期断言：ConfigureHook 就位后 Plugin 完整实现 core.Plugin。
var _ core.Plugin = (*Plugin)(nil)

// ConfigureHook 实现 core.Plugin：enable=true 安装本插件的 PreToolUse Hook，false 卸载。
func (claudePlugin *Plugin) ConfigureHook(homeDir string, enable bool) (bool, error) {
	claudeDirectory := filepath.Join(homeDir, ".claude")
	if enable {
		agentBinaryPath, execErr := os.Executable()
		if execErr != nil {
			agentBinaryPath = os.Args[0] // 兜底：go run 等场景
		}
		absoluteAgentPath, absErr := filepath.Abs(agentBinaryPath)
		if absErr != nil {
			absoluteAgentPath = agentBinaryPath
		}
		return InstallHook(claudeDirectory, absoluteAgentPath, claudePlugin.Name())
	}
	return UninstallPluginHook(claudeDirectory, claudePlugin.Name())
}

// InstallHook 将本插件的 a3 前置 Hook 合并进 <claudeDir>/settings.json：
// 首次安装先备份原文件（已有备份则保留最早一份不覆盖）；幂等——同插件已是规范形态时跳过；
// 升级场景先移除同插件旧写入形态条目再追加规范条目；其他插件与用户的 hooks 全部保留；
// 写回采用临时文件+原子改名。返回配置是否发生变更。
func InstallHook(claudeDirectory string, agentBinaryPath string, pluginName string) (bool, error) {
	settingsPath := filepath.Join(claudeDirectory, "settings.json")
	existingRawBytes, readErr := os.ReadFile(settingsPath)
	switch {
	case readErr == nil:
		if backupErr := backupSettingsOnce(claudeDirectory, settingsPath); backupErr != nil {
			return false, backupErr
		}
	case os.IsNotExist(readErr):
		existingRawBytes = []byte("{}")
	default:
		return false, fmt.Errorf("读取 settings.json 失败: %w", readErr)
	}
	var settingsMap map[string]json.RawMessage
	if len(strings.TrimSpace(string(existingRawBytes))) > 0 {
		if unmarshalErr := json.Unmarshal(existingRawBytes, &settingsMap); unmarshalErr != nil {
			return false, fmt.Errorf("settings.json 不是合法 JSON: %w", unmarshalErr)
		}
	} else {
		settingsMap = map[string]json.RawMessage{}
	}
	hookCommandText := quotedAgentCommand(agentBinaryPath, pluginName)
	changed, mergeErr := mergePreToolUseEntry(settingsMap, hookCommandText, pluginName, agentBinaryPath)
	if mergeErr != nil || !changed {
		return false, mergeErr
	}
	return true, writeSettingsAtomic(settingsPath, settingsMap)
}

// UninstallHook 移除全部插件的 a3 Hook 项（全量清理入口），
// 其余内容保留；无 a3 项或文件不存在时返回未变更。返回配置是否发生变更。
func UninstallHook(claudeDirectory string) (bool, error) {
	return removeHookEntries(claudeDirectory, "")
}

// UninstallPluginHook 仅移除指定插件的 a3 Hook 项（空插件名等价全量清理）。
func UninstallPluginHook(claudeDirectory string, targetPluginName string) (bool, error) {
	return removeHookEntries(claudeDirectory, targetPluginName)
}

// removeHookEntries 按「固定子命令标记 + 二进制归属」识别并移除 a3 Hook 项：
// 目标插件名非空时仅移除该插件的条目；识别兼容新旧两种写入形态（有无插件尾参）。
func removeHookEntries(claudeDirectory string, targetPluginName string) (bool, error) {
	currentBinaryPath, _ := os.Executable()
	settingsPath := filepath.Join(claudeDirectory, "settings.json")
	existingRawBytes, readErr := os.ReadFile(settingsPath)
	if os.IsNotExist(readErr) {
		return false, nil
	}
	if readErr != nil {
		return false, fmt.Errorf("读取 settings.json 失败: %w", readErr)
	}
	var settingsMap map[string]json.RawMessage
	if unmarshalErr := json.Unmarshal(existingRawBytes, &settingsMap); unmarshalErr != nil {
		return false, fmt.Errorf("settings.json 不是合法 JSON: %w", unmarshalErr)
	}
	var preToolUseRaw json.RawMessage
	var hasPreToolUse bool
	if hooksRaw, hooksExists := settingsMap["hooks"]; hooksExists {
		var hooksMap map[string]json.RawMessage
		if unmarshalErr := json.Unmarshal(hooksRaw, &hooksMap); unmarshalErr == nil {
			preToolUseRaw, hasPreToolUse = hooksMap["PreToolUse"]
		}
	}
	if !hasPreToolUse {
		return false, nil
	}
	var matcherEntries []hookEntry
	if unmarshalErr := json.Unmarshal(preToolUseRaw, &matcherEntries); unmarshalErr != nil {
		return false, nil // 形状非预期：不动用户配置
	}
	keptEntries := make([]hookEntry, 0, len(matcherEntries))
	entryChanged := false
	for _, matcherEntry := range matcherEntries {
		keptHooks := make([]hookSpec, 0, len(matcherEntry.Hooks))
		for _, hookItem := range matcherEntry.Hooks {
			hookOwnerName, recognized := parseA3HookCommand(hookItem.Command, currentBinaryPath)
			if recognized && (targetPluginName == "" || hookOwnerName == targetPluginName) {
				entryChanged = true
				continue
			}
			keptHooks = append(keptHooks, hookItem)
		}
		if len(keptHooks) > 0 || len(matcherEntry.Hooks) == 0 {
			matcherEntry.Hooks = keptHooks
			keptEntries = append(keptEntries, matcherEntry)
		}
	}
	if !entryChanged {
		return false, nil
	}
	if storeBackErr := storeBackHooks(settingsMap, keptEntries); storeBackErr != nil {
		return false, storeBackErr
	}
	return true, writeSettingsAtomic(settingsPath, settingsMap)
}

// mergePreToolUseEntry 向 settingsMap 的 hooks.PreToolUse 合入本插件规范 Hook 项：
// 先移除同插件全部旧条目（含一期无尾参的旧写入形态），再追加规范新条目，
// 保证升级后收敛到唯一规范形态；其他插件与用户的条目原样保留。
// 返回是否发生变更（同插件已是唯一规范形态时为 false，即幂等跳过）。
func mergePreToolUseEntry(settingsMap map[string]json.RawMessage,
	hookCommandText string, targetPluginName string, currentBinaryPath string) (bool, error) {
	hooksMap := map[string]json.RawMessage{}
	if hooksRaw, exists := settingsMap["hooks"]; exists {
		if unmarshalErr := json.Unmarshal(hooksRaw, &hooksMap); unmarshalErr != nil {
			return false, fmt.Errorf("hooks 字段形状不合法: %w", unmarshalErr)
		}
	}
	var matcherEntries []hookEntry
	if preToolUseRaw, exists := hooksMap["PreToolUse"]; exists && len(preToolUseRaw) > 0 {
		if unmarshalErr := json.Unmarshal(preToolUseRaw, &matcherEntries); unmarshalErr != nil {
			return false, fmt.Errorf("hooks.PreToolUse 形状不合法: %w", unmarshalErr)
		}
	}
	foundCanonical := false
	staleRemoved := false
	keptEntries := make([]hookEntry, 0, len(matcherEntries))
	for _, matcherEntry := range matcherEntries {
		keptHooks := make([]hookSpec, 0, len(matcherEntry.Hooks))
		for _, hookItem := range matcherEntry.Hooks {
			hookOwnerName, recognized := parseA3HookCommand(hookItem.Command, currentBinaryPath)
			if recognized && hookOwnerName == targetPluginName {
				if hookItem.Command == hookCommandText && !staleRemoved {
					foundCanonical = true
				}
				continue
			}
			keptHooks = append(keptHooks, hookItem)
		}
		if len(keptHooks) > 0 || len(matcherEntry.Hooks) == 0 {
			matcherEntry.Hooks = keptHooks
			keptEntries = append(keptEntries, matcherEntry)
		}
	}
	changedNeeded := staleRemoved || !foundCanonical
	if changedNeeded {
		keptEntries = append(keptEntries, hookEntry{
			Matcher: "*",
			Hooks:   []hookSpec{{Type: "command", Command: hookCommandText}},
		})
	}
	if !changedNeeded {
		return false, nil
	}
	if storeBackErr := storeBackHooks(settingsMap, keptEntries); storeBackErr != nil {
		return false, storeBackErr
	}
	return true, nil
}

// storeBackHooks 把裁剪后的 PreToolUse 条目写回 settingsMap（空列表时移除该键）。
func storeBackHooks(settingsMap map[string]json.RawMessage, keptEntries []hookEntry) error {
	hooksMap := map[string]json.RawMessage{}
	if hooksRaw, exists := settingsMap["hooks"]; exists {
		if unmarshalErr := json.Unmarshal(hooksRaw, &hooksMap); unmarshalErr != nil {
			return fmt.Errorf("hooks 字段形状不合法: %w", unmarshalErr)
		}
	}
	if len(keptEntries) == 0 {
		delete(hooksMap, "PreToolUse")
	} else {
		mergedRaw, marshalErr := json.Marshal(keptEntries)
		if marshalErr != nil {
			return marshalErr
		}
		hooksMap["PreToolUse"] = mergedRaw
	}
	if len(hooksMap) == 0 {
		delete(settingsMap, "hooks")
		return nil
	}
	hooksWhole, marshalErr := json.Marshal(hooksMap)
	if marshalErr != nil {
		return marshalErr
	}
	settingsMap["hooks"] = hooksWhole
	return nil
}

// quotedAgentCommand 组装 Hook 命令文本：二进制路径含空白/引号时用双引号包裹
// （macOS/Linux sh 与 Windows cmd 兼容；裸路径保持原样便于人工辨识）；
// pluginName 非空时追加插件尾参，形成 <bin> hook pretooluse <plugin> 规范形态。
func quotedAgentCommand(agentBinaryPath string, pluginName string) string {
	commandText := agentBinaryPath
	if strings.ContainsAny(agentBinaryPath, " \"") {
		commandText = "\"" + agentBinaryPath + "\""
	}
	commandText += " " + hookCommandMarker
	if pluginName != "" {
		commandText += " " + pluginName
	}
	return commandText
}

// parseA3HookCommand 识别 a3 写入的 Hook 命令并解析目标插件名（新旧形态兼容）：
//   - 旧形态：<bin> hook pretooluse            → 视为 claude-code（一期写入）
//   - 新形态：<bin> hook pretooluse <plugin>   → 尾参即插件名
//
// 归属判定要求命令含固定子命令标记，且与当前可执行文件的规范命令一致，
// 或首 token 二进制名含 a3（跨重装/换路径升级兼容）；带引号路径同样覆盖。
// 非归属命令返回 recognized=false。
func parseA3HookCommand(commandText string, currentBinaryPath string) (string, bool) {
	trimmedText := strings.TrimSpace(commandText)
	markerIndex := strings.Index(trimmedText, hookCommandMarker)
	if markerIndex < 0 {
		return "", false
	}
	if !isOwnedA3Binary(trimmedText, currentBinaryPath) {
		return "", false
	}
	trailingText := strings.TrimSpace(trimmedText[markerIndex+len(hookCommandMarker):])
	if trailingText == "" || strings.ContainsAny(trailingText, " \t\"'") {
		return schema.AgentTypeClaudeCode, true
	}
	return strings.ToLower(trailingText), true
}

// isOwnedA3Binary 二进制归属判定：与当前可执行文件规范命令前缀一致，或首 token 名含 a3。
func isOwnedA3Binary(trimmedText string, currentBinaryPath string) bool {
	if currentBinaryPath != "" {
		canonicalPrefix := quotedAgentCommand(currentBinaryPath, "")
		if trimmedText == canonicalPrefix || strings.HasPrefix(trimmedText, canonicalPrefix+" ") {
			return true
		}
	}
	binaryToken := strings.Trim(leadingCommandToken(trimmedText), `"`)
	binaryBaseName := strings.TrimSuffix(filepath.Base(binaryToken), ".exe")
	return strings.Contains(binaryBaseName, "a3")
}

// isA3HookCommand 兼容入口：判断命令是否为 a3 写入的 Hook（任意插件形态）。
func isA3HookCommand(commandText string, currentBinaryPath string) bool {
	_, recognized := parseA3HookCommand(commandText, currentBinaryPath)
	return recognized
}

// leadingCommandToken 提取命令首 token（兼容带引号的含空格路径）。
func leadingCommandToken(commandText string) string {
	if strings.HasPrefix(commandText, "\"") {
		if endQuoteIndex := strings.Index(commandText[1:], "\""); endQuoteIndex >= 0 {
			return commandText[1 : 1+endQuoteIndex]
		}
	}
	fields := strings.Fields(commandText)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// backupSettingsOnce 首次备份 settings.json；已存在任一备份时保留最早的、不再新增。
func backupSettingsOnce(claudeDirectory string, settingsPath string) error {
	existingBackups, globErr := filepath.Glob(filepath.Join(claudeDirectory, backupGlobPattern))
	if globErr == nil && len(existingBackups) > 0 {
		return nil
	}
	backupPath := filepath.Join(claudeDirectory,
		fmt.Sprintf("settings.json.a3-bak-%d", time.Now().Unix()))
	return os.WriteFile(backupPath, mustReadFileForBackup(settingsPath), 0o600)
}

// mustReadFileForBackup 备份用读取（失败返回空内容并让上层继续）。
func mustReadFileForBackup(settingsPath string) []byte {
	contentBytes, _ := os.ReadFile(settingsPath)
	return contentBytes
}

// writeSettingsAtomic 以临时文件+改名方式原子写回 settings.json（缩进两空格便于人工检查）。
func writeSettingsAtomic(settingsPath string, settingsMap map[string]json.RawMessage) error {
	prettyBytes, marshalErr := json.MarshalIndent(settingsMap, "", "  ")
	if marshalErr != nil {
		return marshalErr
	}
	prettyBytes = append(prettyBytes, '\n')
	settingsDirectory := filepath.Dir(settingsPath)
	if mkdirErr := os.MkdirAll(settingsDirectory, 0o755); mkdirErr != nil {
		return mkdirErr
	}
	tempFile, createErr := os.CreateTemp(settingsDirectory, ".settings-*.tmp")
	if createErr != nil {
		return createErr
	}
	tempName := tempFile.Name()
	if _, writeErr := tempFile.Write(prettyBytes); writeErr != nil {
		_ = tempFile.Close()
		_ = os.Remove(tempName)
		return writeErr
	}
	if closeErr := tempFile.Close(); closeErr != nil {
		_ = os.Remove(tempName)
		return closeErr
	}
	if renameErr := os.Rename(tempName, settingsPath); renameErr != nil {
		_ = os.Remove(tempName)
		return renameErr
	}
	return nil
}
