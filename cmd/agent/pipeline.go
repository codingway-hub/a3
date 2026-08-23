package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core"
	"github.com/codingway-hub/a3/internal/agent/core/masking"
	"github.com/codingway-hub/a3/internal/agent/core/spool"
	"github.com/codingway-hub/a3/internal/agent/core/transport"
	"github.com/codingway-hub/a3/internal/agent/core/watcher"
	"github.com/codingway-hub/a3/internal/agent/plugins/claude"
	"github.com/codingway-hub/a3/pkg/schema"
)

// 事件通道容量与 spool 重放周期。
const (
	eventChannelCapacity  = 4096
	spoolReplayEvery      = 30 * time.Second
	batchUploadCtxTimeout = 60 * time.Second
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
	spoolQueue, spoolErr := spool.New(agentConfig.SpoolDir, 0)
	if spoolErr != nil {
		logger.Error("初始化断网缓存失败", slog.String("error", spoolErr.Error()))
		return 1
	}
	claudePlugin, pluginErr := claude.NewPlugin(homeDir)
	if pluginErr != nil {
		logger.Error("加载 claude 插件失败", slog.String("error", pluginErr.Error()))
		return 1
	}

	eventChannel := make(chan schema.Event, eventChannelCapacity)
	var activeTailers []*watcher.Tailer
	for specIndex, watchSpec := range claudePlugin.LogWatchSpecs(homeDir) {
		watchSpecCopy := watchSpec
		tailWorker, startErr := watcher.Start(watchSpecCopy.RootDirectory,
			watcher.Options{
				MatchGlob: watchSpecCopy.MatchGlob,
				// 每个监听规格独立偏移文件，避免多规格时快照互相覆盖
				StateFile: filepath.Join(agentConfig.StateDir,
					fmt.Sprintf("offsets-%02d.json", specIndex)),
			},
			func(sourcePath string, lines [][]byte) {
				consumeLogLines(claudePlugin, sourcePath, lines, deviceID, agentConfig.MaskEnabled, eventChannel, logger)
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
	if len(activeTailers) == 0 {
		logger.Error("没有任何可用监听器，退出")
		return 1
	}

	batcherDone := make(chan struct{})
	go batchingLoop(ctx, eventChannel, uploaderClient, spoolQueue, agentConfig.BatchSize,
		agentConfig.FlushInterval, logger, batcherDone)

	replayerDone := make(chan struct{})
	go spoolReplayLoop(ctx, spoolQueue, uploaderClient, deviceID, logger, replayerDone)

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
	logger.Info("a3 终端采集器已退出")
	return 0
}

// consumeLogLines 单文件增量行回调：逐行解析 → 脱敏 → 填充设备身份 → 入事件通道。
func consumeLogLines(claudePlugin *claude.Plugin, sourcePath string, lines [][]byte,
	deviceID string, maskEnabled bool, eventChannel chan<- schema.Event, logger *slog.Logger) {
	for _, lineBytes := range lines {
		parsedEvents, parseErr := claudePlugin.ParseLine(sourcePath, lineBytes)
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
			select {
			case eventChannel <- parsedEvent:
			default:
				logger.Error("事件通道已满，丢弃事件", slog.String("event_id", parsedEvent.EventID))
			}
		}
	}
}

// maskEventContent 对对话内容与工具结果摘要做终端侧二次脱敏。
func maskEventContent(producedEvent *schema.Event) {
	if producedEvent.Content != "" {
		producedEvent.Content = masking.RedactAll(producedEvent.Content)
	}
	if producedEvent.ToolOutput != nil && producedEvent.ToolOutput.Summary != "" {
		producedEvent.ToolOutput.Summary = masking.RedactAll(producedEvent.ToolOutput.Summary)
	}
}

// batchingLoop 批处理：攒批（条数或时间阈值）后上报；可重试类失败整批入 spool。
// 生命周期由 eventChannel 关闭驱动（runPipeline 在退出序列中负责关闭）；
// 上报超时派生自主运行 ctx：退出信号一到，在途重试立即失败转本地缓存，断网下也能秒级优雅退出。
func batchingLoop(runCtx context.Context, eventChannel <-chan schema.Event,
	uploaderClient *transport.Uploader, spoolQueue *spool.Spool,
	batchLimit int, flushEvery time.Duration, logger *slog.Logger, doneChan chan<- struct{}) {
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
			Plugins:      []string{schema.AgentTypeClaudeCode},
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
		case isNonRetryable(uploadErr):
			logger.Error("服务端拒绝批次(丢弃)", slog.String("error", uploadErr.Error()))
		default:
			if enqueueErr := spoolQueue.Enqueue(envelopeBytes); enqueueErr != nil {
				logger.Error("批次落盘缓存失败(丢弃)", slog.String("error", enqueueErr.Error()))
			} else if finalFlush {
				logger.Info("退出前未完成批次已入本地缓存，恢复后将自动续传",
					slog.Int("events", len(pendingEvents)))
			} else {
				logger.Warn("上报暂不可用，批次已入本地缓存", slog.Int("events", len(pendingEvents)))
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

// spoolReplayLoop 断网缓存重放：周期性取最旧批次尝试续传，失败放回队尾并退避。
func spoolReplayLoop(ctx context.Context, spoolQueue *spool.Spool, uploaderClient *transport.Uploader,
	deviceID string, logger *slog.Logger, doneChan chan<- struct{}) {
	defer close(doneChan)

	backoffDuration := spoolReplayEvery
	for {
		batchPayload, dequeueErr := spoolQueue.Dequeue()
		if errors.Is(dequeueErr, spool.ErrEmpty) {
			// 队列空：慢速空转等待新缓存
			sleepTimer := time.NewTimer(spoolReplayEvery)
			select {
			case <-ctx.Done():
				sleepTimer.Stop()
				return
			case <-sleepTimer.C:
			}
			backoffDuration = spoolReplayEvery
			continue
		} else if dequeueErr != nil {
			logger.Warn("读取本地缓存失败", slog.String("error", dequeueErr.Error()))
			time.Sleep(time.Second)
			continue
		}

		eventsToReplay, unmarshalErr := decodeEnvelopeFillDevice(batchPayload, deviceID)
		if unmarshalErr != nil {
			logger.Warn("缓存批次损坏(丢弃)", slog.String("error", unmarshalErr.Error()))
			continue
		}

		replayCtx, cancelReplay := context.WithTimeout(ctx, batchUploadCtxTimeout)
		replayResult, replayErr := uploaderClient.PostBatch(replayCtx, eventsToReplay)
		cancelReplay()
		switch {
		case replayErr == nil:
			logger.Info("本地缓存续传成功", slog.Int("accepted", replayResult.Accepted))
			backoffDuration = spoolReplayEvery
		case isNonRetryable(replayErr):
			logger.Error("服务端拒绝缓存批次(丢弃)", slog.String("error", replayErr.Error()))
		default:
			if requeueErr := spoolQueue.Enqueue(batchPayload); requeueErr != nil {
				logger.Error("缓存批次放回失败(丢弃)", slog.String("error", requeueErr.Error()))
			}
			sleepTimer := time.NewTimer(backoffDuration)
			select {
			case <-ctx.Done():
				sleepTimer.Stop()
				return
			case <-sleepTimer.C:
			}
			backoffDuration *= 2
			if backoffDuration > 10*time.Minute {
				backoffDuration = 10 * time.Minute
			}
		}
	}
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
