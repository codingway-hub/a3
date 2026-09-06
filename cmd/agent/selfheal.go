package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core/transport"
)

// 自愈看门狗：以「路由不可达」作为唯一动作信号。
// 这是操作系统在路由/网络层直接拒绝拨号（EHOSTUNREACH/ENETUNREACH，典型如 macOS 15
// 本地网络权限未授权），退避重试永不自愈。普通拒绝/超时/断网（ECONNREFUSED、timeout、
// 5xx）都不触发——那属正常离线，采集以断网缓存兜底，绝不自杀。

// 探针周期与单次超时。包级变量以便测试缩短周期；同一进程内仅一条看门狗循环，
// 值只在循环启动时读取一次，测试改动不产生数据竞争。
var (
	selfHealProbeEvery   = 10 * time.Second
	selfHealProbeTimeout = 3 * time.Second
)

// probeFunc 单次连通性探测：返回目标是否为「路由不可达」。注入式便于单测
// 确定性覆盖触发/复位逻辑；生产一律用 probeRoutedUnreachable。
type probeFunc func(address string, timeout time.Duration) bool

// selfHealReport 看门狗对外输出：当前是否「路由不可达」、连续时长、是否已提示授权、是否已触发自愈退出。
type selfHealReport struct {
	unreachable       bool
	unreachableSince  time.Time
	consecutiveFails  int
	authGuidanceGiven bool
	selfExitTriggered bool
}

// selfHealLoop 自愈看门狗主循环。周期性对服务端地址做一次 TCP 拨号（仅连通性，不上报不写库），
// 统计「路由不可达」连续时长：
//
//   - 首次判定位不可达时，打印一次中文授权指引（不重复刷屏）；
//   - 连续不可达超过 unreachableWindow 时，向 triggerExit 写入一次信号——调用方据此进入
//     优雅关闭并退出，让常驻守护（launchd StartInterval / systemd Restart=on-failure）以新的
//     拉起上下文重启采集进程，可能绕过系统对该上下文的局域网拦截。
//
// 探针一旦成功立即清零计数。ctx 取消即退出。
// 设计边界：看门狗只做代理自己能做的三件事——检测、提示、换上下文自重；需要 GUI 的授权动作
// （点「允许」）是用户决定，由指引引导。
func selfHealLoop(runCtx context.Context, serverHost string, serverPort string,
	unreachableWindow time.Duration, logger *slog.Logger, triggerExit chan<- struct{},
	report *selfHealReport, appBundlePath string, probe probeFunc) {
	if unreachableWindow <= 0 || serverHost == "" {
		return
	}

	deadline := unreachableWindow
	if deadline < selfHealProbeEvery*3 {
		deadline = selfHealProbeEvery * 3
	}
	probeAddress := net.JoinHostPort(serverHost, serverPort)
	logger.Debug("自愈看门狗启动",
		slog.String("probe", probeAddress), slog.Duration("window", deadline))

	probeTicker := time.NewTicker(selfHealProbeEvery)
	defer probeTicker.Stop()

	for {
		select {
		case <-runCtx.Done():
			return
		case <-probeTicker.C:
			if !probe(probeAddress, selfHealProbeTimeout) {
				if report.unreachable {
					logger.Warn("自愈看门狗：服务端路由恢复可达，重置计数",
						slog.Duration("was_unreachable_for", time.Since(report.unreachableSince).Truncate(time.Second)))
					report.unreachable = false
					report.unreachableSince = time.Time{}
					report.consecutiveFails = 0
				}
				continue
			}

			report.consecutiveFails++
			if !report.unreachable {
				report.unreachable = true
				report.unreachableSince = time.Now()
				if !report.authGuidanceGiven {
					report.authGuidanceGiven = true
					// 尽力触发系统授权记录：非 macOS 15 / 无应用包装时静默跳过，不报错。
					// 这只是「把应用递到系统授权入口」的宽松尝试，真正的「允许」由用户在面板点。
					if appBundlePath != "" {
						surfaceLocalNetworkApp(appBundlePath, logger)
					}
					logger.Error(
						"服务端被判定为「路由不可达」：系统在路由层拦截了对服务端的连接。\n"+
							"  常见于 macOS 15（Sequoia）的本地网络权限未授权。\n"+
							"  处理：打开 系统设置 → 隐私与安全性 → 本地网络，允许 A3Agent；\n"+
							"  若已授权仍离线，说明常驻进程被护栏拦死——本看门狗将在到达阈值后主动退出，"+
							"由守护自动以新上下文重启采集进程（数据已安全落地断网缓存，不丢失）。",
						slog.String("probe", probeAddress))
				}
				continue
			}

			// 已在不可达状态：达到阈值则触发一次自愈退出
			continuity := time.Since(report.unreachableSince)
			if continuity >= deadline && !report.selfExitTriggered {
				report.selfExitTriggered = true
				logger.Error("自愈看门狗触发：服务端持续「路由不可达」已达阈值，主动退出以让常驻守护"+
					"用新上下文重启采集（数据已在断网缓存中，续传不丢失）",
					slog.Duration("unreachable_for", continuity.Truncate(time.Second)))
				select {
				case triggerExit <- struct{}{}:
				default:
				}
			} else if report.consecutiveFails%4 == 0 {
				logger.Debug("服务端仍不可达（继续计数）",
					slog.Int("consecutive_fails", report.consecutiveFails),
					slog.Duration("unreachable_for", continuity.Truncate(time.Second)))
			}
		}
	}
}

// probeRoutedUnreachable 对目标地址做一次 TCP 拨号，返回是否「路由不可达」。
// 仅 EHOSTUNREACH/ENETUNREACH 返回 true；拒绝/超时/其他一律 false（正常离线，与自愈无关）。
func probeRoutedUnreachable(address string, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	connection, dialErr := dialer.Dial("tcp", address)
	if dialErr == nil {
		_ = connection.Close()
		return false
	}
	return transport.IsRoutedUnreachable(dialErr)
}

// parseServerHostPort 从服务端 URL 解析 host 与 port（无端口时按 scheme 取默认 80/443）。
// 解析失败返回空，调用方据此不再启动看门狗。
func parseServerHostPort(serverURL string) (host string, port string) {
	rest := serverURL
	scheme := "http"
	if schemeCut, afterCut, hasScheme := strings.Cut(serverURL, "://"); hasScheme {
		scheme = schemeCut
		rest = afterCut
	}
	if slashIndex := strings.Index(rest, "/"); slashIndex >= 0 {
		rest = rest[:slashIndex]
	}
	host = rest
	if host == "" {
		return "", ""
	}
	port = "80"
	if scheme == "https" {
		port = "443"
	}
	if colonIndex := strings.LastIndex(rest, ":"); colonIndex >= 0 {
		host = rest[:colonIndex]
		port = rest[colonIndex+1:]
	}
	return host, port
}

// surfaceLocalNetworkApp 尽力把应用包装递到系统「本地网络」授权入口，触发一次权限询问。
// 这是宽松的最佳努力：非 macOS 直返；应用包装不存在或 open 失败仅记日志，不阻塞主流程。
// 它不做任何需用户授权的动作——真正的「允许」由用户在面板点；意义在于让应用有机会出现在
// 系统本地网络授权记录里（macOS 15 首次会弹权限询问）。
func surfaceLocalNetworkApp(appBundlePath string, logger *slog.Logger) {
	if runtime.GOOS != "darwin" || appBundlePath == "" {
		return
	}
	if _, statErr := os.Stat(appBundlePath); statErr != nil {
		logger.Debug("未找到应用包装，跳过本地网络授权强调（非 macOS 15 或仅前台运行）",
			slog.String("path", appBundlePath))
		return
	}
	launchErr := exec.Command("open", "-g", appBundlePath).Run()
	if launchErr != nil {
		logger.Debug("尝试打开应用包装以触发本地网络授权失败", slog.String("error", launchErr.Error()))
		return
	}
	logger.Warn("已尝试将 A3Agent 应用递到系统本地网络授权入口——请在系统弹窗/设置中允许")
}
