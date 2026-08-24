// Package alert 实现告警中心：异步消费已入库事件，经规则引擎打标后
// 回写风险标签、按处置策略落告警并累计会话风险计数。
package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/codingway-hub/a3/internal/server/rules"
	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/pkg/schema"
)

// eventChannelBuffer 事件扫描队列容量；写满即丢弃并计数，绝不阻塞上报主链路。
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

// SubmitAsync 把事件投入异步扫描队列；队列满时丢弃并累加计数（监控可见）。
func (service *Service) SubmitAsync(event schema.Event) {
	select {
	case service.eventCh <- event:
	default:
		service.droppedCount.Add(1)
	}
}

// Run 启动消费循环，直到 ctx 取消。每个进程只需一个 worker（单机一期吞吐足够）。
func (service *Service) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-service.eventCh:
			if processErr := service.processEvent(ctx, event); processErr != nil {
				// 单事件失败不影响后续消费，计数留观测（M1-9 装配时接日志输出）
				service.failedCount.Add(1)
			}
		}
	}
}

// DroppedCount 返回因队列满被丢弃的未扫描事件数。
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

// processEvent 对单条已入库事件执行：评估 → 回写 risk_tags → 落告警 → 会话风险计数。
func (service *Service) processEvent(ctx context.Context, event schema.Event) error {
	engine := service.currentEngine()
	if engine == nil {
		return nil // 规则尚未加载完成时不扫描
	}
	riskTags := engine.Evaluate(event)
	if len(riskTags) == 0 {
		return nil
	}

	riskTagsJSON, marshalErr := json.Marshal(riskTags)
	if marshalErr != nil {
		return marshalErr
	}
	if updateErr := service.eventStore.UpdateEventRiskTags(ctx, event.EventID, riskTagsJSON); updateErr != nil {
		return fmt.Errorf("回写风险标签失败: %w", updateErr)
	}

	for _, riskTag := range riskTags {
		if !shouldAlert(riskTag) {
			continue
		}
		newAlert := &store.Alert{
			DeviceID:   event.DeviceID,
			SessionKey: event.SessionID,
			EventID:    event.EventID,
			RuleID:     riskTag.MatchedRule,
			RuleName:   riskTag.Name,
			Severity:   string(riskTag.Severity),
			Action:     string(riskTag.Action),
			Snippet:    riskTag.Snippet,
			Summary:    buildAlertSummary(event, riskTag),
		}
		if createErr := service.eventStore.CreateAlert(ctx, newAlert); createErr != nil {
			return fmt.Errorf("落告警失败: %w", createErr)
		}
	}

	return service.eventStore.UpsertSession(ctx, store.SessionUpdate{
		DeviceID:        event.DeviceID,
		SessionKey:      event.SessionID,
		AgentType:       event.AgentType,
		Title:           "",
		LastOccurredAt:  event.OccurredAt,
		EventCountDelta: 0,
		RiskCountDelta:  len(riskTags),
	})
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
