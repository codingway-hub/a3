package core

import (
	"fmt"
	"sort"
	"sync"
)

// Registry 插件注册表：进程内编译期注册，重复名称视为编程错误直接 panic 早暴露。
type Registry struct {
	mu           sync.RWMutex
	pluginByName map[string]Plugin
}

// NewRegistry 创建空注册表。
func NewRegistry() *Registry {
	return &Registry{pluginByName: make(map[string]Plugin)}
}

// Register 注册插件；名称为空或重复时 panic（装配期错误应当场崩溃而非静默降级）。
func (registry *Registry) Register(agentPlugin Plugin) {
	if agentPlugin == nil {
		panic(fmt.Sprintf("插件注册失败: 插件为 nil"))
	}
	if agentPlugin.Name() == "" {
		panic(fmt.Sprintf("插件注册失败: 插件名称不能为空"))
	}

	registry.mu.Lock()
	defer registry.mu.Unlock()
	if _, nameTaken := registry.pluginByName[agentPlugin.Name()]; nameTaken {
		panic(fmt.Sprintf("插件注册失败: 名称 %q 重复注册", agentPlugin.Name()))
	}
	registry.pluginByName[agentPlugin.Name()] = agentPlugin
}

// All 返回全部已注册插件，按名称稳定排序（保证遍历行为可复现）。
func (registry *Registry) All() []Plugin {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	allPlugins := make([]Plugin, 0, len(registry.pluginByName))
	for _, agentPlugin := range registry.pluginByName {
		allPlugins = append(allPlugins, agentPlugin)
	}
	sort.Slice(allPlugins, func(leftIndex, rightIndex int) bool {
		return allPlugins[leftIndex].Name() < allPlugins[rightIndex].Name()
	})
	return allPlugins
}

// Get 按名称查找插件。
func (registry *Registry) Get(pluginName string) (Plugin, bool) {
	registry.mu.RLock()
	defer registry.mu.RUnlock()
	foundPlugin, found := registry.pluginByName[pluginName]
	return foundPlugin, found
}
