package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core/spool"
	"github.com/codingway-hub/a3/internal/agent/core/transport"
)

// heartbeatBackoffInitial / heartbeatBackoffCap 心跳退避：网络/服务端短暂不可达时，
// 心跳从基线退避翻倍（1s→60s 封顶），避免断网期间高频空转；恢复后下一拍转常。
const (
	heartbeatBackoffInitial = 1 * time.Second
	heartbeatBackoffCap     = 60 * time.Second
)

// heartbeatLoop 常驻心跳：按配置周期读取 spool 待送达积压并上报服务端，刷新设备
// 在线态并同步「数据滞留(abnormal)」信号。失败分类处置——
//
//   - 瞬时可重试（网络/5xx/429，普通错误）：指数退避后继续，恢复后按基线转常；
//   - 鉴权失效（401/403，NonRetryableError）：设备已吊销或 Token 轮换，心跳永无
//     治愈可能——停止空转，否则已吊销设备会持续把自己刷新成「在线」，掩盖吊销事实。
//
// 积压读取失败仅跳过本轮（本地状态异常不应影响在线态刷新）。生命周期与主 ctx 同步。
// heartbeatEvery ≤ 0 表示关闭心跳：仅靠事件上报刷新在线态，立即返回。
func heartbeatLoop(runCtx context.Context, uploaderClient *transport.Uploader,
	spoolQueue *spool.Spool, heartbeatEvery time.Duration, logger *slog.Logger, doneChan chan<- struct{}) {
	defer close(doneChan)

	if heartbeatEvery <= 0 {
		return
	}

	backoff := heartbeatBackoffInitial
	for {
		pendingBatches, pendingBytes, statusErr := spoolQueue.Status()
		if statusErr != nil {
			logger.Warn("读取断网缓存积压失败(跳过本轮心跳)", slog.String("error", statusErr.Error()))
		} else if heartbeatErr := uploaderClient.Heartbeat(runCtx, pendingBatches, pendingBytes); heartbeatErr != nil {
			var nonRetryableErr *transport.NonRetryableError
			if errors.As(heartbeatErr, &nonRetryableErr) {
				logger.Error("心跳鉴权失败，设备已吊销或 Token 轮换，停止心跳",
					slog.Int("status_code", nonRetryableErr.StatusCode))
				return
			}
			logger.Warn("心跳上报失败(待退避重试)", slog.String("error", heartbeatErr.Error()))
			if !sleepAndGrow(runCtx, &backoff, heartbeatBackoffCap) {
				return
			}
			continue
		} else {
			backoff = heartbeatBackoffInitial
			logger.Debug("心跳上报成功",
				slog.Int64("spool_batches", pendingBatches), slog.Int64("spool_bytes", pendingBytes))
		}

		sleepTimer := time.NewTimer(heartbeatEvery)
		select {
		case <-runCtx.Done():
			sleepTimer.Stop()
			return
		case <-sleepTimer.C:
		}
	}
}