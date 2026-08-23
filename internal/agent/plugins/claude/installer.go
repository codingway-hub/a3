package claude

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core"
)

// hookCommandMarker a3 写入的 Hook 命令固定子命令片段（卸载识别标记）。
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

// ConfigureHook 实现 core.Plugin：enable=true 安装 PreToolUse Hook，false 卸载。
func (claudePlugin *Plugin) ConfigureHook(homeDir string, enable bool) (bool, error) {
	if enable {
		agentBinaryPath, execErr := os.Executable()
		if execErr != nil {
			agentBinaryPath = os.Args[0] // 兜底：go run 等场景
		}
		absoluteAgentPath, absErr := filepath.Abs(agentBinaryPath)
		if absErr != nil {
			absoluteAgentPath = agentBinaryPath
		}
		return InstallHook(filepath.Join(homeDir, ".claude"), absoluteAgentPath)
	}
	return UninstallHook(filepath.Join(homeDir, ".claude"))
}

// InstallHook 将 a3 前置 Hook 合并进 <claudeDir>/settings.json：
// 首次安装先备份原文件（已有备份则保留最早一份不覆盖）；幂等——已存在相同项时跳过；
// 原有其他配置与 hooks 全部保留；写回采用临时文件+原子改名。返回配置是否发生变更。
func InstallHook(claudeDirectory string, agentBinaryPath string) (bool, error) {
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

	hookCommandText := fmt.Sprintf("%s %s", agentBinaryPath, hookCommandMarker)
	changed, mergeErr := mergePreToolUseEntry(settingsMap, hookCommandText)
	if mergeErr != nil || !changed {
		return false, mergeErr
	}

	return true, writeSettingsAtomic(settingsPath, settingsMap)
}

// UninstallHook 从 settings.json 移除 a3 写入的 Hook 项，
// 其余内容保留；无 a3 项或文件不存在时返回未变更。返回配置是否发生变更。
// 识别依据：固定子命令标记 + 二进制名含 a3，或与当前可执行文件完全一致。
func UninstallHook(claudeDirectory string) (bool, error) {
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
			if isA3HookCommand(hookItem.Command, currentBinaryPath) {
				entryChanged = true
				continue // 移除 a3 项
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

	mergedHooksErr := storeBackHooks(settingsMap, keptEntries)
	if mergedHooksErr != nil {
		return false, mergedHooksErr
	}
	return true, writeSettingsAtomic(settingsPath, settingsMap)
}

// mergePreToolUseEntry 向 settingsMap 的 hooks.PreToolUse 追加 a3 项（幂等），返回是否发生变更。
func mergePreToolUseEntry(settingsMap map[string]json.RawMessage, hookCommandText string) (bool, error) {
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

	for _, matcherEntry := range matcherEntries {
		for _, hookItem := range matcherEntry.Hooks {
			if hookItem.Command == hookCommandText {
				return false, nil // 幂等：已存在相同项
			}
		}
	}
	matcherEntries = append(matcherEntries, hookEntry{
		Matcher: "*",
		Hooks:   []hookSpec{{Type: "command", Command: hookCommandText}},
	})

	mergedRaw, marshalErr := json.Marshal(matcherEntries)
	if marshalErr != nil {
		return false, marshalErr
	}
	hooksMap["PreToolUse"] = mergedRaw

	hooksWhole, marshalErr := json.Marshal(hooksMap)
	if marshalErr != nil {
		return false, marshalErr
	}
	settingsMap["hooks"] = hooksWhole
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

// isA3HookCommand 判断命令是否为 a3 写入的 Hook：
// 含固定子命令标记，且首 token 二进制名含 a3，或与当前可执行文件路径完全一致。
func isA3HookCommand(commandText string, currentBinaryPath string) bool {
	trimmedText := strings.TrimSpace(commandText)
	if !strings.HasSuffix(trimmedText, hookCommandMarker) {
		return false
	}
	if currentBinaryPath != "" && trimmedText == currentBinaryPath+" "+hookCommandMarker {
		return true
	}
	binaryToken := strings.Fields(trimmedText)[0]
	binaryBaseName := strings.TrimSuffix(filepath.Base(binaryToken), ".exe")
	return strings.Contains(binaryBaseName, "a3")
}

// backupSettingsOnce 首次备份 settings.json；已存在任一备份时保留最早的、不再新增。
func backupSettingsOnce(claudeDirectory string, settingsPath string) error {
	existingBackups, globErr := filepath.Glob(filepath.Join(claudeDirectory, backupGlobPattern))
	if globErr == nil && len(existingBackups) > 0 {
		return nil // 已有备份（最早的那份），不覆盖
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

// writeSettingsAtomically 以临时文件+改名方式原子写回 settings.json（缩进两空格便于人工检查）。
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
