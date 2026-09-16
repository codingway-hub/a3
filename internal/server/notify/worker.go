// Package notify worker：周期领取到期的通知 outbox，聚合外送，管理退避与投递状态。
package notify

import (
	"context"
	"log/slog"
	"time"

	"github.com/codingway-hub/a3/internal/server/store"
)

// Worker 配置默认值：批大小、重试上限、轮询周期、单次唤醒最大批数与退避底数/封顶。
const (
	defaultBatchSize   = 50
	defaultMaxAttempts = 10
	defaultPollEvery   = time.Minute
	defaultMaxBurst    = 10
	backoffBaseDelay   = time.Minute
	backoffMaxDelay    = 15 * time.Minute
)

// Worker 周期领取到期待投递的通知（outbox），聚合成 Digest 经 Channel 外送。
// 投递状态与退避全部按行落在 outbox 上：领取即置 sending（SKIP LOCKED，多副本安全），
// 成功置 sent；失败累计 attempts、按指数退避推后 next_attempt_at，达上限置 dropped。
type Worker struct {
	eventStore    *store.Store
	channel       Channel
	severities    []string // 必须非空：config.NotifySeverities() 保证；空集会让 ANY() 匹配不到任何行
	batchSize     int
	maxAttempts   int
	pollEvery     time.Duration
	maxBatchBurst int
	backoffBase   time.Duration
	backoffCap    time.Duration
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
		backoffBase:   backoffBaseDelay,
		backoffCap:    backoffMaxDelay,
		logger:        logger,
	}
}

// Run 主循环直到 ctx 取消，启动即捞一次（照 alert.Run 先例）。
// 重试节奏由各 outbox 行的 next_attempt_at 独立调度，进程无需维护全局退避。
func (worker *Worker) Run(ctx context.Context) {
	worker.deliverPending(ctx)
	ticker := time.NewTicker(worker.pollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			worker.deliverPending(ctx)
		}
	}
}

// deliverPending 领取并外送本轮全部到期通知。单批失败即停本轮：失败的批已各自
// 推后 next_attempt_at（≥1min），先把发送预算让给其余到期行，避免连环失败占满周期。
func (worker *Worker) deliverPending(ctx context.Context) {
	for burst := 0; burst < worker.maxBatchBurst; burst++ {
		due, claimErr := worker.eventStore.ClaimDueNotifications(
			ctx, worker.severities, worker.maxAttempts, worker.batchSize)
		if claimErr != nil {
			worker.logger.Warn("通知外送：领取到期通知失败", slog.Any("err", claimErr))
			return
		}
		if len(due) == 0 {
			return
		}
		if deliveryErr := worker.deliverBatch(ctx, due); deliveryErr != nil {
			worker.logger.Warn("通知外送：本批发送失败，等待退避重试",
				slog.Int("count", len(due)), slog.Any("err", deliveryErr))
			return
		}
	}
}

// deliverBatch 把一批领取到的通知聚合成摘要外送；成功标记 sent，失败累计次数并退避。
// Mark 失败只记日志：sending 行超过孤儿窗口后会被下轮领取查询回收重投（at-least-once）。
func (worker *Worker) deliverBatch(ctx context.Context, due []store.Notification) error {
	alerts := make([]store.Alert, len(due))
	notificationIDs := make([]string, len(due))
	windowStart, windowEnd := due[0].Alert.CreatedAt, due[0].Alert.CreatedAt
	for index, notification := range due {
		alerts[index] = notification.Alert
		notificationIDs[index] = notification.ID
		if notification.Alert.CreatedAt.Before(windowStart) {
			windowStart = notification.Alert.CreatedAt
		}
		if notification.Alert.CreatedAt.After(windowEnd) {
			windowEnd = notification.Alert.CreatedAt
		}
	}
	digest := Digest{Alerts: alerts, WindowStart: windowStart, WindowEnd: windowEnd}

	if sendErr := worker.channel.Send(ctx, digest); sendErr != nil {
		// 本条失败后下一次尝试号为 attempts+1；退避按其指数展开
		nextAttemptCount := 0
		for _, notification := range due {
			if notification.Attempts+1 > nextAttemptCount {
				nextAttemptCount = notification.Attempts + 1
			}
		}
		nextDelay := notifyBackoff(nextAttemptCount, worker.backoffBase, worker.backoffCap)
		if markErr := worker.eventStore.MarkNotificationsFailed(
			ctx, notificationIDs, sendErr.Error(), nextDelay, worker.maxAttempts); markErr != nil {
			worker.logger.Warn("通知外送：失败状态落库失败", slog.Any("err", markErr))
		}
		return sendErr
	}
	if markErr := worker.eventStore.MarkNotificationsSent(ctx, notificationIDs); markErr != nil {
		worker.logger.Warn("通知外送：发送成功但标记落库失败，sending 孤儿将由下轮回收重投", slog.Any("err", markErr))
	}
	return nil
}

// notifyBackoff 第 nextAttempt 次尝试的等待时长：底数倍增、封顶（首次失败即扣底数）。
func notifyBackoff(nextAttempt int, base time.Duration, backoffCap time.Duration) time.Duration {
	if nextAttempt <= 1 {
		return base
	}
	delay := base
	for attempt := 1; attempt < nextAttempt && delay < backoffCap; attempt++ {
		delay *= 2
	}
	if delay > backoffCap {
		return backoffCap
	}
	return delay
}