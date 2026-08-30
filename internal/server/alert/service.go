// Package alert 实现告警中心：异步消费已入库事件，经规则引擎打标后
// 原子回写扫描结果（风险标签+扫描进度）、按处置策略落告警并累计会话风险计数。
package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codingway-hub/a3/internal/server/rules"
	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/pkg/schema"
)

// scanBackfillEvery 周期对账间隔；scanBackfillBatchSize 单轮对账批量上限。
const (
	scanBackfillEvery     = time.Minute
	scanBackfillBatchSize = 200
)

// eventChannelBuffer 事件扫描队列容量；写满即丢弃只影响实时性、不影响完整性——
// 事件落库在先，未扫描积压由 Run 的周期对账从库里捞回补扫（最终无损）。
const eventChannelBuffer = 1024

// Service 是告警中心服务：SubmitAsync 投递、Run 消费、ReloadRules 热更新规则集。
type Service struct {
	eventStore *store.Store

	engineMu sync.RWMutex
	engine   *rules.Engine

	eventCh      chan schema.Event
	droppedCount atomic.Int64 // 队列满被丢弃的未扫描事件数
	failedCount  atomic.Int64 // 单事件处理失败数（DB 异常等）
}

// NewService 构建服务；初始规则集经 reloadFromStore 从库中加载。
func NewService(eventStore *store.Store) *Service {
	return &Service{
		eventStore: eventStore,
		eventCh:    make(chan schema.Event, eventChannelBuffer),
	}
}

// SubmitAsync 把事件投入异步扫描队列。满时丢弃并累加计数（监控可见）：
// 丢弃只影响该事件的扫描实时性，事件本体已在库中，周期对账会补扫兜底。
func (service *Service) SubmitAsync(event schema.Event) {
	select {
	case service.eventCh <- event:
	default:
		service.droppedCount.Add(1)
	}
}

// Run 启动消费循环直到 ctx 取消。每个进程只需一个 worker（单机一期吞吐足够）。
// 除消费实时队列外，启动即对账、此后周期性对账仍未扫描的事件：SubmitAsync
// 满时丢弃、进程重启丢失内存队列、引擎未就绪失败等都不会漏扫——事件落库在先、
// 扫描进度（scanned_at）在后，积压总能被对账捞回，实现最终无损。
func (service *Service) Run(ctx context.Context) {
	service.backfillUnscannedEvents(ctx)
	backfillTicker := time.NewTicker(scanBackfillEvery)
	defer backfillTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case producedEvent := <-service.eventCh:
			if processErr := service.processEvent(ctx, producedEvent); processErr != nil {
				// 单事件失败不影响后续消费，计数留观测（M1-9 装配时接日志输出）
				service.failedCount.Add(1)
			}
		case <-backfillTicker.C:
			service.backfillUnscannedEvents(ctx)
		}
	}
}

// backfillUnscannedEvents 捞取一批仍未扫描的事件重新走扫描链路（启动即扫 +
// 周期对账共用）。payload 异常或单事件处理失败只计数不中断，下一轮继续。
func (service *Service) backfillUnscannedEvents(ctx context.Context) {
	unscannedRows, listErr := service.eventStore.ListUnscannedEvents(ctx, scanBackfillBatchSize)
	if listErr != nil {
		return // 对账查询失败：等下一轮，不影响实时链路
	}
	for _, unscannedRow := range unscannedRows {
		var unscannedEvent schema.Event
		if decodeErr := json.Unmarshal(unscannedRow.PayloadJSON, &unscannedEvent); decodeErr != nil {
			service.failedCount.Add(1)
			continue
		}
		if processErr := service.processEvent(ctx, unscannedEvent); processErr != nil {
			service.failedCount.Add(1)
		}
	}
}

// DroppedCount 返回因队列满被丢弃的未扫描事件数（仅损失实时性，完整性由对账兜底）。
func (service *Service) DroppedCount() int64 {
	return service.droppedCount.Load()
}

// FailedCount 返回处理失败的事件数。
func (service *Service) FailedCount() int64 {
	return service.failedCount.Load()
}

// ReloadRules 重新从 rules 表加载启用规则并原子替换引擎（控制台启停规则后调用）。
func (service *Service) ReloadRules(ctx context.Context) error {
	enabledRecords, listErr := service.eventStore.ListEnabledRules(ctx)
	if listErr != nil {
		return listErr
	}
	ruleList := make([]rules.Rule, 0, len(enabledRecords))
	for _, record := range enabledRecords {
		rule, convertErr := rules.FromStoreRecord(record)
		if convertErr != nil {
			return convertErr
		}
		ruleList = append(ruleList, rule)
	}
	engine, engineErr := rules.NewSystemEngine(ruleList)
	if engineErr != nil {
		return engineErr
	}

	service.engineMu.Lock()
	defer service.engineMu.Unlock()
	service.engine = engine
	return nil
}

// currentEngine 返回当前引擎快照。
func (service *Service) currentEngine() *rules.Engine {
	service.engineMu.RLock()
	defer service.engineMu.RUnlock()
	return service.engine
}

// Evaluate 用当前规则快照同步评估事件（供测试与 hook 告警链路复用）。
func (service *Service) Evaluate(event schema.Event) []schema.RiskTag {
	engine := service.currentEngine()
	if engine == nil {
		return nil
	}
	return engine.Evaluate(event)
}

// processEvent 对单条已入库事件执行：评估 → 原子应用扫描结果。
// 结果应用是条件更新：仅当事件尚未被扫描才生效，实时队列与补扫对账并发命中
// 同一事件时至多一方产生告警副作用（同一事件至多一次告警）。
func (service *Service) processEvent(ctx context.Context, event schema.Event) error {
	engine := service.currentEngine()
	if engine == nil {
		return fmt.Errorf("规则引擎未就绪") // 不标记扫描进度：事件保持未扫描，留待引擎就绪后由对账补扫
	}
	riskTags := engine.Evaluate(event)

	riskTagsJSON, marshalErr := json.Marshal(riskTags)
	if marshalErr != nil {
		return marshalErr
	}
	alertsToCreate := make([]*store.Alert, 0, len(riskTags))
	for _, riskTag := range riskTags {
		if !shouldAlert(riskTag) {
			continue
		}
		alertsToCreate = append(alertsToCreate, &store.Alert{
			DeviceID:   event.DeviceID,
			SessionKey: event.SessionID,
			EventID:    event.EventID,
			RuleID:     riskTag.MatchedRule,
			RuleName:   riskTag.Name,
			Severity:   string(riskTag.Severity),
			Action:     string(riskTag.Action),
			Snippet:    riskTag.Snippet,
			Summary:    buildAlertSummary(event, riskTag),
		})
	}

	applied, applyErr := service.eventStore.ApplyScanOutcome(ctx, store.ScanOutcome{
		DeviceID:     event.DeviceID,
		EventID:      event.EventID,
		RiskTagsJSON: riskTagsJSON,
		Alerts:       alertsToCreate,
		SessionUpdate: store.SessionUpdate{
			DeviceID:        event.DeviceID,
			SessionKey:      event.SessionID,
			AgentType:       event.AgentType,
			Title:           "",
			LastOccurredAt:  event.OccurredAt,
			EventCountDelta: 0,
			RiskCountDelta:  len(riskTags),
		},
	})
	if applyErr != nil {
		return fmt.Errorf("应用扫描结果失败: %w", applyErr)
	}
	_ = applied // false=已被补扫抢先处理过：跳过即可，无需报错
	return nil
}

// shouldAlert 判定是否落告警：block 动作一律落；alert 动作需 severity ≥ medium。
func shouldAlert(riskTag schema.RiskTag) bool {
	if riskTag.Action == schema.RiskActionBlock {
		return true
	}
	return riskTag.Severity == schema.SeverityMedium || riskTag.Severity == schema.SeverityHigh
}

// buildAlertSummary 组装中文一句话告警摘要。
func buildAlertSummary(event schema.Event, riskTag schema.RiskTag) string {
	actionText := "提醒关注"
	if riskTag.Action == schema.RiskActionBlock {
		actionText = "建议阻断"
	}
	return fmt.Sprintf("设备 %s 会话 %s 中命中风险规则「%s」（%s），%s",
		event.DeviceID, event.SessionID, riskTag.Name, riskTag.Severity, actionText)
}
