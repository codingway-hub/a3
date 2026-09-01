package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core"
	"github.com/codingway-hub/a3/internal/agent/core/masking"
	"github.com/codingway-hub/a3/internal/agent/core/spool"
	"github.com/codingway-hub/a3/internal/agent/core/transport"
	"github.com/codingway-hub/a3/internal/agent/core/watcher"
	"github.com/codingway-hub/a3/pkg/schema"
)

// 事件通道容量与 spool 重放周期。通道容量只用于平滑瞬时突发：
// 下游持续处理不过来时发送端阻塞背压，不丢事件（见 consumeLogLines）。
const (
	eventChannelCapacity  = 4096
	spoolReplayEvery      = 30 * time.Second
	batchUploadCtxTimeout = 60 * time.Second

	// 重放退避双档：瞬时可重试（网络/5xx/429）短退避；鉴权失效等（401/403/其余 4xx）
	// 放回后长退避，绝不以烧库换取速度。
	replayBackoffFastInitial = 1 * time.Second
	replayBackoffFastCap     = 60 * time.Second
	replayBackoffSlowInitial = 1 * time.Minute
	replayBackoffSlowCap     = 30 * time.Minute
)

// runCommand 常驻采集主循环：watcher → ParseLine → 脱敏 → 批量化 → 上报；失败入 spool 后台重放。
func runCommand(flagArguments []string) int {
	agentConfig, loadErr := loadAgentConfig(flagArguments)
	if loadErr != nil {
		fmt.Fprintf(os.Stderr, "配置错误: %v\n", loadErr)
		return 1
	}
	logger := core.NewLogger(agentConfig)

	runExitCode := 1
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Error("主循环异常退出", slog.Any("panic", recovered))
			}
		}()
		runExitCode = runPipeline(agentConfig, logger)
	}()
	return runExitCode
}

// runPipeline 流水线装配与生命周期管理。返回退出码（0 正常）。
func runPipeline(agentConfig core.Config, logger *slog.Logger) int {
	ctx, stopOnSignal := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopOnSignal()

	homeDir, homeErr := core.ResolveHomeDir()
	if homeErr != nil {
		logger.Error("无法定位主目录", slog.String("error", homeErr.Error()))
		return 1
	}

	deviceToken, deviceID, tokenErr := resolveDeviceIdentity(ctx, agentConfig, logger)
	if tokenErr != nil {
		logger.Error("设备身份不可用", slog.String("error", tokenErr.Error()))
		return 1
	}
	logger.Info("设备身份就绪", slog.String("device_id", deviceID))

	uploaderClient, uploaderErr := transport.NewUploader(
		agentConfig.ServerURL, deviceToken, agentVersion, agentConfig.InsecureTLS, logger)
	if uploaderErr != nil {
		logger.Error("构建上报客户端失败", slog.String("error", uploaderErr.Error()))
		return 1
	}
	spoolQueue, spoolErr := spool.NewWithLimits(agentConfig.SpoolDir,
		agentConfig.SpoolMaxBytes, agentConfig.SpoolQuarantineMaxBytes)
	if spoolErr != nil {
		logger.Error("初始化断网缓存失败", slog.String("error", spoolErr.Error()))
		return 1
	}
	pluginRegistry, registryErr := buildRegistry(agentConfig.Plugins, homeDir)
	if registryErr != nil {
		logger.Error("装配插件失败", slog.String("error", registryErr.Error()))
		return 1
	}
	enabledPlugins := enabledPluginNames(pluginRegistry)
	uploaderClient.SetPlugins(enabledPlugins)

	eventChannel := make(chan schema.Event, eventChannelCapacity)
	var activeTailers []*watcher.Tailer
	for _, watchPlugin := range pluginRegistry.All() {
		for specIndex, watchSpecCopy := range watchPlugin.LogWatchSpecs(homeDir) {
			stateFile := filepath.Join(agentConfig.StateDir,
				fmt.Sprintf("offsets-%s-%02d.json", watchPlugin.Name(), specIndex))
			migrateLegacyOffsetsFile(logger, agentConfig.StateDir, stateFile, watchPlugin.Name(), specIndex)
			tailWorker, startErr := watcher.Start(watchSpecCopy.RootDirectory,
				watcher.Options{
					MatchGlob: watchSpecCopy.MatchGlob,
					// 状态文件按「插件名+序号」命名：不同插件的 spec 序号互不冲突，
					// 新增插件也不会使既有插件的状态文件名漂移
					StateFile: stateFile,
				},
				func(sourcePath string, lines [][]byte) {
					consumeLogLines(watchPlugin, sourcePath, lines, deviceID, agentConfig.MaskEnabled, eventChannel, logger)
				})
			if startErr != nil {
				logger.Warn("监听器启动失败(跳过)", slog.String("root", watchSpecCopy.RootDirectory),
					slog.String("error", startErr.Error()))
				continue
			}
			activeTailers = append(activeTailers, tailWorker)
			logger.Info("正在监听会话日志", slog.String("root", watchSpecCopy.RootDirectory),
				slog.String("glob", watchSpecCopy.MatchGlob))
		}
	}
	if len(activeTailers) == 0 {
		logger.Error("没有任何可用监听器，退出")
		return 1
	}

	batcherDone := make(chan struct{})
	go batchingLoop(ctx, eventChannel, uploaderClient, spoolQueue, agentConfig.BatchSize,
		agentConfig.FlushInterval, enabledPlugins, logger, batcherDone)

	replayerDone := make(chan struct{})
	go spoolReplayLoop(ctx, spoolQueue, uploaderClient, deviceID, logger, replayerDone)

	// 规则下发：常驻进程周期拉取服务端权威规则集并落本地快照；
	// hook 短命进程只读快照、绝不联网（工具调用热路径不容网络往返）
	rulesSyncDone := make(chan struct{})
	go ruleSyncLoop(ctx, uploaderClient, agentConfig.StateDir, logger, rulesSyncDone)

	// 常驻心跳：周期刷新设备在线态并上报 spool 待送达积压，供控制台
	// online/abnormal 判定。关闭心跳（interval≤0）时立即退出，仅靠事件上报维持在线态
	if agentConfig.HeartbeatInterval <= 0 {
		logger.Info("常驻心跳已关闭(仅靠事件上报维持在线态)", slog.String("env", "A3_HEARTBEAT_INTERVAL_SECONDS"))
	}
	heartbeatDone := make(chan struct{})
	go heartbeatLoop(ctx, uploaderClient, spoolQueue, agentConfig.HeartbeatInterval, logger, heartbeatDone)

	logger.Info("a3 终端采集器已启动",
		slog.String("server", agentConfig.ServerURL),
		slog.Int("batch_size", agentConfig.BatchSize),
		slog.Bool("mask_enabled", agentConfig.MaskEnabled))

	<-ctx.Done()
	logger.Info("收到退出信号，开始优雅关闭")
	stopOnSignal()

	for _, tailWorker := range activeTailers {
		tailWorker.Close()
	}
	close(eventChannel) // 批处理协程冲刷余量后退出
	<-batcherDone

	cancelReplayer, cancelFunc := context.WithCancel(context.Background())
	go func() {
		<-time.After(5 * time.Second)
		cancelFunc()
	}()
	select {
	case <-replayerDone:
	case <-cancelReplayer.Done():
	}
	select {
	case <-rulesSyncDone:
	case <-time.After(2 * time.Second):
	}
	select {
	case <-heartbeatDone:
	case <-time.After(2 * time.Second):
	}
	logger.Info("a3 终端采集器已退出")
	return 0
}

// consumeLogLines 单文件增量行回调：逐行解析 → 脱敏 → 填充设备身份 → 入事件通道。
func consumeLogLines(sourcePlugin core.Plugin, sourcePath string, lines [][]byte,
	deviceID string, maskEnabled bool, eventChannel chan<- schema.Event, logger *slog.Logger) {
	for _, lineBytes := range lines {
		parsedEvents, parseErr := sourcePlugin.ParseLine(sourcePath, lineBytes)
		if parseErr != nil {
			logger.Warn("日志行解析失败(跳过)", slog.String("path", sourcePath),
				slog.String("error", parseErr.Error()))
			continue
		}
		for _, parsedEvent := range parsedEvents {
			parsedEvent.DeviceID = deviceID
			if maskEnabled {
				maskEventContent(&parsedEvent)
			}
			// 阻塞式发送形成背压：下游批处理/上报积压时，tailer 暂停在当前
			// 文件的当前 offset 上，事件零丢失。offset 在本回调返回后才推进，
			// 阻塞期间崩溃也只会让该行重启后重新消费（至少一次，服务端幂等）。
			eventChannel <- parsedEvent
		}
	}
}

// maskEventContent 对对话内容、工具结果摘要与工具输入字符串值做终端侧二次脱敏。
func maskEventContent(producedEvent *schema.Event) {
	if producedEvent.Content != "" {
		producedEvent.Content = masking.RedactAll(producedEvent.Content)
	}
	if producedEvent.ToolOutput != nil && producedEvent.ToolOutput.Summary != "" {
		producedEvent.ToolOutput.Summary = masking.RedactAll(producedEvent.ToolOutput.Summary)
	}
	producedEvent.ToolInput = masking.RedactJSONLeaves(producedEvent.ToolInput)
}

// batchingLoop 批处理：攒批（条数或时间阈值）后上报；可重试类失败整批入 spool。
// 生命周期由 eventChannel 关闭驱动（runPipeline 在退出序列中负责关闭）；
// 上报超时派生自主运行 ctx：退出信号一到，在途重试立即失败转本地缓存，断网下也能秒级优雅退出。
func batchingLoop(runCtx context.Context, eventChannel <-chan schema.Event,
	uploaderClient *transport.Uploader, spoolQueue *spool.Spool,
	batchLimit int, flushEvery time.Duration, enabledPlugins []string,
	logger *slog.Logger, doneChan chan<- struct{}) {
	defer close(doneChan)

	flushTicker := time.NewTicker(flushEvery)
	defer flushTicker.Stop()

	pendingEvents := make([]schema.Event, 0, batchLimit)
	flushPending := func(finalFlush bool) {
		if len(pendingEvents) == 0 {
			return
		}
		envelopeBytes, marshalErr := json.Marshal(core.EventEnvelope{
			AgentVersion: agentVersion,
			Plugins:      enabledPlugins,
			Events:       pendingEvents,
		})
		if marshalErr != nil {
			logger.Error("批次序列化失败(丢弃)", slog.String("error", marshalErr.Error()))
			pendingEvents = pendingEvents[:0]
			return
		}
		uploadCtx, cancelUpload := context.WithTimeout(runCtx, batchUploadCtxTimeout)
		uploadResult, uploadErr := uploaderClient.PostBatch(uploadCtx, pendingEvents)
		cancelUpload()
		switch {
		case uploadErr == nil:
			logger.Debug("批次上报成功",
				slog.Int("accepted", uploadResult.Accepted), slog.Int("duplicates", uploadResult.Duplicates))
		default:
			// 可重试失败与明确拒绝（鉴权失效/批次非法）一概入 spool：重放循环按状态码
			// 分类处置（401/403 放回+长退避、400/422 归档），实时链路绝不再烧库——
			// 证据一律先落盘、后裁决
			failureKind := "上报失败"
			if isNonRetryable(uploadErr) {
				failureKind = "服务端明确拒绝"
			}
			if enqueueErr := spoolQueue.Enqueue(envelopeBytes); enqueueErr != nil {
				logger.Error("批次落盘缓存失败(丢弃)", slog.String("error", enqueueErr.Error()))
			} else if finalFlush {
				logger.Info("退出前未完成批次已入本地缓存，恢复后将自动续传",
					slog.Int("events", len(pendingEvents)))
			} else {
				logger.Warn(failureKind+"，批次已入本地缓存，由重放循环分类续传",
					slog.String("error", uploadErr.Error()),
					slog.Int("events", len(pendingEvents)))
			}
		}
		pendingEvents = pendingEvents[:0]
	}

	for {
		select {
		case producedEvent, channelOpen := <-eventChannel:
			if !channelOpen {
				flushPending(true)
				return
			}
			pendingEvents = append(pendingEvents, producedEvent)
			if len(pendingEvents) >= batchLimit {
				flushPending(false)
			}
		case <-flushTicker.C:
			flushPending(false)
		}
	}
}

// replayOutcome 是本地缓存单批次的分类处置建议；对应动作由重放循环执行。
type replayOutcome int

const (
	// replayCommit 上报成功：删除在途租约。
	replayCommit replayOutcome = iota
	// replayQuarantine 证据归档（解码损坏 / 400/422 明确拒绝）：移入隔离区留证。
	replayQuarantine
	// replayRetryFast 瞬时可重试（网络/5xx/429）：放回队列 + 短退避。
	replayRetryFast
	// replayRetrySlow 鉴权失效（401/403）及其余 4xx：放回队列 + 长退避，绝不烧库。
	replayRetrySlow
)

// replaySingleBatch 对单个在途批次做一次分类处置，返回建议动作。
// 解码失败与 400/422 在此处直接归档（原因随文件名留痕）；成功与可恢复失败只判定
// 不执行——Commit/Restore 及退避节奏由 spoolReplayLoop 统一驱动，便于回归测试
// 直接校验单批次的分流决策。返回 error 属硬故障（如归档失败），调用方应保留在途
// 租约让重启回收，不得误判为成功烧掉证据。
func replaySingleBatch(ctx context.Context, uploaderClient *transport.Uploader,
	deviceID string, inflightBatch *spool.Batch) (replayOutcome, error) {

	eventsToReplay, unmarshalErr := decodeEnvelopeFillDevice(inflightBatch.Payload, deviceID)
	if unmarshalErr != nil {
		// 解码失败属证据损坏：归档留证（不阻塞后续批次，也不再重复解码）
		if quarantineErr := inflightBatch.Quarantine("corrupt"); quarantineErr != nil {
			return replayQuarantine, quarantineErr
		}
		return replayQuarantine, nil
	}

	replayCtx, cancelReplay := context.WithTimeout(ctx, batchUploadCtxTimeout)
	_, replayErr := uploaderClient.PostBatchOnce(replayCtx, eventsToReplay)
	cancelReplay()
	if replayErr == nil {
		return replayCommit, nil
	}

	var nonRetryableErr *transport.NonRetryableError
	if !errors.As(replayErr, &nonRetryableErr) {
		return replayRetryFast, nil // 网络/5xx/429：瞬时状态，短退避后重试
	}
	switch nonRetryableErr.StatusCode {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		// 载荷永久非法（字段缺失/越界）：重试必然复败，归档留证继续
		if quarantineErr := inflightBatch.Quarantine("reject-" + strconv.Itoa(nonRetryableErr.StatusCode)); quarantineErr != nil {
			return replayQuarantine, quarantineErr
		}
		return replayQuarantine, nil
	case http.StatusUnauthorized, http.StatusForbidden:
		// 鉴权失效（设备吊销/令牌轮换中）：证据绝不能烧，放回长退避，恢复后由 run 续传
		return replayRetrySlow, nil
	default:
		// 其余 4xx 保守处理：放回 + 长退避，不因未预期状态码丢证据
		return replayRetrySlow, nil
	}
}

// spoolReplayLoop 断网缓存重放：周期性取最旧批次尝试续传，按 replaySingleBatch
// 的分类处置——
//
//   - replayCommit：删除在途租约（至少一次，服务端按 event_id 幂等兜底）；
//   - replayQuarantine：已在 replaySingleBatch 内归档，重置退避继续；
//   - replayRetryFast：Restore 放回原队 + 短退避（1s→60s）；
//   - replayRetrySlow：Restore 放回原队 + 长退避（1min→30min），鉴权失效绝不烧库。
//
// Restore 放回与重试之间若进程崩溃，在途文件留存，下次启动归位重新排队。
func spoolReplayLoop(ctx context.Context, spoolQueue *spool.Spool, uploaderClient *transport.Uploader,
	deviceID string, logger *slog.Logger, doneChan chan<- struct{}) {
	defer close(doneChan)

	fastBackoff := replayBackoffFastInitial
	slowBackoff := replayBackoffSlowInitial
	for {
		inflightBatch, dequeueErr := spoolQueue.Dequeue()
		if errors.Is(dequeueErr, spool.ErrEmpty) {
			// 队列空：慢速空转等待新缓存
			sleepTimer := time.NewTimer(spoolReplayEvery)
			select {
			case <-ctx.Done():
				sleepTimer.Stop()
				return
			case <-sleepTimer.C:
			}
			fastBackoff = replayBackoffFastInitial
			slowBackoff = replayBackoffSlowInitial
			continue
		} else if dequeueErr != nil {
			logger.Warn("读取本地缓存失败", slog.String("error", dequeueErr.Error()))
			time.Sleep(time.Second)
			continue
		}

		decision, classifyErr := replaySingleBatch(ctx, uploaderClient, deviceID, inflightBatch)
		if classifyErr != nil {
			// 归档等硬故障：保留在途租约，重启自动归位重试；不误判成功
			logger.Error("缓存批次分类处置失败(保留在途)", slog.String("error", classifyErr.Error()))
			time.Sleep(time.Second)
			continue
		}
		switch decision {
		case replayCommit:
			logger.Info("本地缓存续传成功")
			if commitErr := inflightBatch.Commit(); commitErr != nil {
				logger.Warn("缓存批次确认失败(重启后可能重复续传)", slog.String("error", commitErr.Error()))
			}
			fastBackoff = replayBackoffFastInitial
			slowBackoff = replayBackoffSlowInitial
		case replayQuarantine:
			logger.Warn("缓存批次已归档(证据保留)")
			fastBackoff = replayBackoffFastInitial
			slowBackoff = replayBackoffSlowInitial
		case replayRetryFast:
			logger.Warn("本地缓存续传暂不可用，批次放回待短退避重试")
			if restoreErr := inflightBatch.Restore(); restoreErr != nil {
				logger.Error("缓存批次放回失败(保留在途待重启回收重试)", slog.String("error", restoreErr.Error()))
				continue
			}
			if !sleepAndGrow(ctx, &fastBackoff, replayBackoffFastCap) {
				return
			}
		case replayRetrySlow:
			logger.Warn("服务端拒绝缓存批次(鉴权/其他 4xx)，放回绝不烧库，长退避后重试")
			if restoreErr := inflightBatch.Restore(); restoreErr != nil {
				logger.Error("缓存批次放回失败(保留在途待重启回收重试)", slog.String("error", restoreErr.Error()))
				continue
			}
			if !sleepAndGrow(ctx, &slowBackoff, replayBackoffSlowCap) {
				return
			}
		}
	}
}

// sleepAndGrow 等待退避后翻倍时长（封顶）。返回 false 表示上下文已取消，调用方应退出。
func sleepAndGrow(ctx context.Context, backoff *time.Duration, capDuration time.Duration) bool {
	wakeTimer := time.NewTimer(*backoff)
	defer wakeTimer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-wakeTimer.C:
	}
	*backoff *= 2
	if *backoff > capDuration {
		*backoff = capDuration
	}
	return true
}

// decodeEnvelopeFillDevice 解码缓存信封并把缺失 DeviceID 补为本机身份。
func decodeEnvelopeFillDevice(envelopeBytes []byte, deviceID string) ([]schema.Event, error) {
	var decodedEnvelope core.EventEnvelope
	if unmarshalErr := json.Unmarshal(envelopeBytes, &decodedEnvelope); unmarshalErr != nil {
		return nil, unmarshalErr
	}
	for eventIndex := range decodedEnvelope.Events {
		if decodedEnvelope.Events[eventIndex].DeviceID == "" {
			decodedEnvelope.Events[eventIndex].DeviceID = deviceID
		}
	}
	return decodedEnvelope.Events, nil
}

// isNonRetryable 判断是否服务端明确拒绝（重试无意义）。
func isNonRetryable(reportError error) bool {
	var nonRetryableErr *transport.NonRetryableError
	return errors.As(reportError, &nonRetryableErr)
}
