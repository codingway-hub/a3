package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/codingway-hub/a3/internal/agent/core"
	"github.com/codingway-hub/a3/internal/agent/plugins/claude"
	"github.com/codingway-hub/a3/pkg/schema"
)

// builtinPluginConstructors 编译内置插件的构造函数表：
// 新增适配 = 新增插件包 + 在此登记一行，其余装配逻辑零改动。
var builtinPluginConstructors = map[string]func(homeDir string) (core.Plugin, error){
	schema.AgentTypeClaudeCode: func(homeDir string) (core.Plugin, error) { return claude.NewPlugin(homeDir) },
}

// legacyOffsetsFileName 一期按纯序号命名的偏移状态文件（仅存在 claude-code 的 spec 0）。
const legacyOffsetsFileName = "offsets-00.json"

// buildRegistry 按配置选择装配插件注册表。selected 为 [all] 时展开全部内置插件；
// 含未知名称时返回错误——启动即失败优于静默跳过（用户以为在采、实际没采）。
func buildRegistry(selected []string, homeDir string) (*core.Registry, error) {
	wantedNames := selected
	if len(selected) == 1 && selected[0] == core.PluginAll {
		wantedNames = sortedBuiltinPluginNames()
	}
	pluginRegistry := core.NewRegistry()
	for _, wantedName := range wantedNames {
		constructorFn, knownPlugin := builtinPluginConstructors[wantedName]
		if !knownPlugin {
			return nil, fmt.Errorf("未知插件 %q（可用: %s, %s）",
				wantedName, strings.Join(sortedBuiltinPluginNames(), ", "), core.PluginAll)
		}
		agentPlugin, constructorErr := constructorFn(homeDir)
		if constructorErr != nil {
			return nil, fmt.Errorf("加载插件 %s 失败: %w", wantedName, constructorErr)
		}
		pluginRegistry.Register(agentPlugin)
	}
	return pluginRegistry, nil
}

// enabledPluginNames 返回注册表内全部插件名的有序列表（信封 Plugins 能力上报用）。
func enabledPluginNames(pluginRegistry *core.Registry) []string {
	registeredPlugins := pluginRegistry.All()
	pluginNames := make([]string, 0, len(registeredPlugins))
	for _, agentPlugin := range registeredPlugins {
		pluginNames = append(pluginNames, agentPlugin.Name())
	}
	return pluginNames
}

// sortedBuiltinPluginNames 返回内置插件构造表的稳定有序名称列表。
func sortedBuiltinPluginNames() []string {
	pluginNames := make([]string, 0, len(builtinPluginConstructors))
	for pluginName := range builtinPluginConstructors {
		pluginNames = append(pluginNames, pluginName)
	}
	sort.Strings(pluginNames)
	return pluginNames
}

// migrateLegacyOffsetsFile 把一期旧命名偏移文件迁移到「插件名+序号」新命名，
// 保证升级后断点续传状态不丢（否则等价于 offset 清零：增量丢失+全量重扫）。
// 仅适用于 (claude-code, spec 0) 绑定；目标已存在或无旧文件时不动。
func migrateLegacyOffsetsFile(logger *slog.Logger, stateDirectory string,
	targetStateFile string, pluginName string, specIndex int) {
	if pluginName != schema.AgentTypeClaudeCode || specIndex != 0 {
		return
	}
	legacyPath := filepath.Join(stateDirectory, legacyOffsetsFileName)
	if _, statLegacyErr := os.Stat(legacyPath); statLegacyErr != nil {
		return // 无旧文件：新部署或已完成迁移
	}
	if _, statTargetErr := os.Stat(targetStateFile); statTargetErr == nil {
		return // 新命名文件已存在：以新文件为准，旧文件留置不删
	}
	if renameErr := os.Rename(legacyPath, targetStateFile); renameErr != nil {
		logger.Warn("旧偏移文件迁移失败(将重新全量扫描)", slog.String("error", renameErr.Error()))
	} else {
		logger.Info("已迁移一期偏移状态文件", slog.String("to", targetStateFile))
	}
}
