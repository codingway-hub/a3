// a3-agent 终端采集器：监听 AI 编码工具会话日志、前置风险拦截、批量加密上报。
//
// 子命令：
//
//	run              常驻采集主循环（默认流水线装配）
//	hook pretooluse  ClaudeCode PreToolUse 前置 Hook（stdin JSON → 裁决）
//	install-hook     安装 PreToolUse Hook 到 ~/.claude/settings.json
//	uninstall-hook   卸载上述 Hook
//	register         显式注册设备并保存 Token（分布式部署模式）
//	version          打印版本
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core"
)

// agentVersion 当前终端采集器版本。
const agentVersion = "0.1.0"

func main() {
	os.Exit(runAgentCLI(os.Args[1:]))
}

// runAgentCLI 子命令分发；返回进程退出码。
func runAgentCLI(arguments []string) int {
	if len(arguments) == 0 {
		printUsage(os.Stderr)
		return 1
	}
	switch arguments[0] {
	case "run":
		return runCommand(arguments[1:])
	case "hook":
		if len(arguments) < 2 || arguments[1] != "pretooluse" {
			fmt.Fprintln(os.Stderr, "用法: a3-agent hook pretooluse")
			return 1
		}
		return hookCommand(arguments[2:])
	case "install-hook":
		return installHookCommand()
	case "uninstall-hook":
		return uninstallHookCommand()
	case "register":
		return registerCommand(arguments[1:])
	case "version":
		fmt.Printf("a3-agent %s\n", agentVersion)
		return 0
	case "help", "-h", "--help":
		printUsage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", arguments[0])
		printUsage(os.Stderr)
		return 1
	}
}

// loadAgentConfig 构建并绑定 CLI flag（优先级高于环境变量），返回校验后的配置。
func loadAgentConfig(flagArguments []string) (core.Config, error) {
	homeDir, homeErr := core.ResolveHomeDir()
	if homeErr != nil {
		return core.Config{}, homeErr
	}

	agentConfig := core.Default(homeDir)
	agentConfig.ApplyEnv(os.Getenv)

	flagSet := flag.NewFlagSet("a3-agent", flag.ContinueOnError)
	flagSet.StringVar(&agentConfig.ServerURL, "server", agentConfig.ServerURL, "服务端地址，如 http://127.0.0.1:8080")
	flagSet.StringVar(&agentConfig.DeviceToken, "token", agentConfig.DeviceToken, "设备 Token（a3d_ 开头）")
	flagSet.StringVar(&agentConfig.SpoolDir, "spool-dir", agentConfig.SpoolDir, "断网缓存目录")
	flagSet.StringVar(&agentConfig.StateDir, "state-dir", agentConfig.StateDir, "状态目录")
	flagSet.IntVar(&agentConfig.BatchSize, "batch-size", agentConfig.BatchSize, "单批上报条数上限")
	flushSeconds := flagSet.Int("flush-interval-seconds", int(agentConfig.FlushInterval/time.Second), "批量化冲刷间隔（秒）")
	flagSet.BoolVar(&agentConfig.MaskEnabled, "mask", agentConfig.MaskEnabled, "终端侧脱敏开关")
	flagSet.BoolVar(&agentConfig.InsecureTLS, "insecure-skip-tls-verify", agentConfig.InsecureTLS, "跳过 TLS 证书校验（仅自签名单机部署）")
	flagSet.StringVar(&agentConfig.LogLevel, "log-level", agentConfig.LogLevel, "日志级别 debug|info|warn|error")
	var pluginsFlagText string
	flagSet.StringVar(&pluginsFlagText, "plugins", "", "启用的插件，逗号分隔（默认 all；env A3_PLUGINS）")
	if flagErr := flagSet.Parse(flagArguments); flagErr != nil {
		return core.Config{}, flagErr
	}
	agentConfig.FlushInterval = time.Duration(*flushSeconds) * time.Second
	if pluginsFlagText != "" {
		// 只做词法归一：非法名称由 Validate 统一报错（与 env 路径同一收口）
		agentConfig.Plugins = core.ParsePluginSelection(pluginsFlagText)
	}

	if validateErr := agentConfig.Validate(); validateErr != nil {
		return core.Config{}, validateErr
	}
	return agentConfig, nil
}

func printUsage(output *os.File) {
	usageText := `a3-agent %s — AI 编码行为审计终端采集器

用法:
  a3-agent run [flags]              常驻采集
  a3-agent hook pretooluse          PreToolUse 前置 Hook（由 ClaudeCode 调用）
  a3-agent install-hook             安装 Hook 到 ~/.claude/settings.json
  a3-agent uninstall-hook           卸载 Hook
  a3-agent register --server URL    注册设备并保存 Token
  a3-agent version                  版本

run 常用 flags:
  --server                          服务端地址（env A3_SERVER_URL）
  --token                           设备 Token（env A3_DEVICE_TOKEN）
  --insecure-skip-tls-verify        自签名场景跳过证书校验
  --log-level                       debug|info|warn|error
  --plugins                         启用的插件，逗号分隔（默认 all；env A3_PLUGINS）
`
	fmt.Fprintf(output, usageText, agentVersion)
}
