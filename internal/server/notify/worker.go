// Package notify worker：轮询未通知告警，聚合外送，管理退避与重试。
package notify

import (
	"context"
	"log/slog"
	"time"

	"github.com/codingway-hub/a3/internal/server/store"
)

// Worker 配置默认值：批大小、重试上限、轮询周期、单次唤醒最大批数与退避封顶。
const (
	defaultBatchSize   = 50
	defaultMaxAttempts = 10
	defaultPollEvery   = time.Minute
	defaultMaxBurst    = 10
	maxBackoffWait     = 15 * time.Minute
)

// Worker 周期捞取未通知告警，聚合成 Digest 经 Channel 外送。
// 行级 notify_attempts 达上限的告警永久排除（坏 URL 自然老化）；
// worker 级连续失败指数退避 1min→15min，成功复位。
type Worker struct {
	eventStore    *store.Store
	channel       Channel
	severities    []string // 必须非空：config.NotifySeverities() 保证；空集会让 ANY() 匹配不到任何行
	batchSize     int
	maxAttempts   int
	pollEvery     time.Duration
	maxBatchBurst int
	logger        *slog.Logger
}

// NewWorker 构建 worker；severities 需非空（来自 config.NotifySeverities()）。
func NewWorker(eventStore *store.Store, channel Channel, severities []string, logger *slog.Logger) *Worker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Worker{
		eventStore:    eventStore,
		channel:       channel,
		severities:    severities,
		batchSize:     defaultBatchSize,
		maxAttempts:   defaultMaxAttempts,
		pollEvery:     defaultPollEvery,
		maxBatchBurst: defaultMaxBurst,
		logger:        logger,
	}
}

// Run 主循环直到 ctx 取消。启动即捞一次（照 alert.Run 先例）；
// 失败退避翻倍封顶 15min，成功复位到 pollEvery。失败即停本轮：
// created_at 升序下老告警先送，避免坏批反复占用发送预算。
func (worker *Worker) Run(ctx context.Context) {
	worker.deliverPending(ctx)
	wait := worker.pollEvery
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
			roundFailed := worker.deliverPending(ctx)
			if roundFailed {
				wait = min(wait*2, maxBackoffWait)
			} else {
				wait = worker.pollEvery
			}
		}
	}
}

// deliverPending 捞取并外送本轮全部待通知告警；返回本轮是否出现失败。
func (worker *Worker) deliverPending(ctx context.Context) bool {
	roundFailed := false
	for burst := 0; burst < worker.maxBatchBurst; burst++ {
		pendingAlerts, listErr := worker.eventStore.ListUnnotifiedAlerts(
			ctx, worker.severities, worker.maxAttempts, worker.batchSize)
		if listErr != nil {
			worker.logger.Warn("通知外送：捞取未通知告警失败", slog.Any("err", listErr))
			return true
		}
		if len(pendingAlerts) == 0 {
			return roundFailed
		}
		if sendErr := worker.deliverBatch(ctx, pendingAlerts); sendErr != nil {
			worker.logger.Warn("通知外送：本批发送失败，等待重试",
				slog.Int("count", len(pendingAlerts)), slog.Any("err", sendErr))
			roundFailed = true
			break // 失败即停本轮，老告警先送
		}
	}
	// burst 用尽仍有积压：不置失败，下轮 pollEvery 后继续
	return roundFailed
}

// deliverBatch 把一批告警聚合成摘要外送；成功标记已通知，失败累计次数。
// Mark 失败只记日志：下轮 ListUnnotifiedAlerts 会再次捞出（at-least-once 重发）。
func (worker *Worker) deliverBatch(ctx context.Context, batchAlerts []store.Alert) error {
	windowStart, windowEnd := batchAlerts[0].CreatedAt, batchAlerts[0].CreatedAt
	for _, alertRow := range batchAlerts {
		if alertRow.CreatedAt.Before(windowStart) {
			windowStart = alertRow.CreatedAt
		}
		if alertRow.CreatedAt.After(windowEnd) {
			windowEnd = alertRow.CreatedAt
		}
	}
	digest := Digest{Alerts: batchAlerts, WindowStart: windowStart, WindowEnd: windowEnd}

	sendErr := worker.channel.Send(ctx, digest)
	if sendErr != nil {
		if incrementErr := worker.eventStore.IncrementAlertNotifyAttempts(ctx, alertIDsOf(batchAlerts)); incrementErr != nil {
			worker.logger.Warn("通知外送：累计失败次数落库失败", slog.Any("err", incrementErr))
		}
		return sendErr
	}
	if markErr := worker.eventStore.MarkAlertsNotified(ctx, alertIDsOf(batchAlerts)); markErr != nil {
		worker.logger.Warn("通知外送：发送成功但标记落库失败，下轮将重发", slog.Any("err", markErr))
	}
	return nil
}

// alertIDsOf 提取告警 ID 列表。
func alertIDsOf(alertList []store.Alert) []string {
	ids := make([]string, 0, len(alertList))
	for _, alertRow := range alertList {
		ids = append(ids, alertRow.ID)
	}
	return ids
}
