// Package ingest 实现终端接入业务：设备注册（指纹幂等）与事件批量上报
// （校验→幂等落库→会话聚合→异步风险扫描）。HTTP 编解码在 handler 层。
package ingest

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/codingway-hub/a3/internal/server/alert"
	"github.com/codingway-hub/a3/internal/server/auth"
	"github.com/codingway-hub/a3/internal/server/rules"
	"github.com/codingway-hub/a3/internal/server/store"
	"github.com/codingway-hub/a3/pkg/schema"
)

// 业务约束与哨兵错误。
const (
	maxBatchEvents = 500 // 单批事件上限，超出整批拒绝
	titleMaxRunes  = 50  // 会话标题截取长度
	deviceIDPrefix = "dev-"
)

var (
	// ErrAutoRegisterDisabled 未开放自动注册（分布式模式下改控制台预生成）。
	ErrAutoRegisterDisabled = errors.New("自动注册未开放")
	// ErrBatchTooLarge 单批事件数超限。
	ErrBatchTooLarge = fmt.Errorf("单批事件数超过上限 %d", maxBatchEvents)
	// ErrEventInvalid 事件校验失败或设备归属不符。
	ErrEventInvalid = errors.New("事件不合法")
)

// RegisterInput 是设备注册请求的业务字段。
type RegisterInput struct {
	Hostname           string `json:"hostname"`
	OS                 string `json:"os"`
	Arch               string `json:"arch"`
	MachineFingerprint string `json:"machine_fingerprint"`
}

// RegisterResult 返回给终端的注册结果：明文 Token 仅此一次出现。
type RegisterResult struct {
	DeviceID string
	Token    string
}

// BatchEnvelope 是事件批量上报信封。
type BatchEnvelope struct {
	AgentVersion string         `json:"agent_version"`
	Plugins      []string       `json:"plugins"`
	Events       []schema.Event `json:"events"`
}

// BatchResult 是上报处理结果。
type BatchResult struct {
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
}

// Service 是终端接入服务。
type Service struct {
	eventStore   *store.Store
	alertService *alert.Service
	autoRegister bool // 对应 A3_ALLOW_AUTO_REGISTER
}

// NewService 构建接入服务。
func NewService(eventStore *store.Store, alertService *alert.Service, autoRegister bool) *Service {
	return &Service{eventStore: eventStore, alertService: alertService, autoRegister: autoRegister}
}

// RegisterDevice 注册设备：新指纹创建；同指纹则要求携带既有 Token 凭证证明身份后
// 轮换（claimedToken 为空或与库中不符 → ErrCredentialRequired / ErrCredentialMismatch）。
// 凭证语义：指纹不再足以换发他人 Token，杜绝无凭证顶替。
func (service *Service) RegisterDevice(ctx context.Context, registerInput RegisterInput, claimedToken string) (*RegisterResult, error) {
	if !service.autoRegister {
		return nil, ErrAutoRegisterDisabled
	}
	if strings.TrimSpace(registerInput.MachineFingerprint) == "" {
		return nil, fmt.Errorf("%w: machine_fingerprint 不能为空", ErrEventInvalid)
	}

	newToken, tokenErr := auth.GenerateDeviceToken()
	if tokenErr != nil {
		return nil, tokenErr
	}
	device := &store.Device{
		DeviceID:           generateDeviceID(),
		TokenHash:          auth.HashToken(newToken),
		MachineFingerprint: registerInput.MachineFingerprint,
		Hostname:           registerInput.Hostname,
		OS:                 registerInput.OS,
		Arch:               registerInput.Arch,
		Status:             "active",
	}
	claimedTokenHash := ""
	if claimedToken != "" {
		claimedTokenHash = auth.HashToken(claimedToken)
	}

	deviceID, _, registerErr := service.eventStore.RegisterDeviceAtomic(ctx, device, claimedTokenHash)
	if registerErr != nil {
		return nil, registerErr
	}
	return &RegisterResult{DeviceID: deviceID, Token: newToken}, nil
}

// SubmitEvents 处理一批事件：逐条校验→心跳→幂等落库→会话聚合→投递异步风险扫描。
// 整批校验前置：任一事件非法则整批拒绝（终端可整体重试）。
func (service *Service) SubmitEvents(ctx context.Context, device *store.Device, envelope BatchEnvelope) (*BatchResult, error) {
	if len(envelope.Events) == 0 {
		return nil, fmt.Errorf("%w: events 不能为空", ErrEventInvalid)
	}
	if len(envelope.Events) > maxBatchEvents {
		return nil, ErrBatchTooLarge
	}
	for eventIndex := range envelope.Events {
		candidateEvent := envelope.Events[eventIndex]
		if validateErr := candidateEvent.Validate(); validateErr != nil {
			return nil, fmt.Errorf("events[%d]: %w: %v", eventIndex, ErrEventInvalid, validateErr)
		}
		if candidateEvent.DeviceID != device.DeviceID {
			return nil, fmt.Errorf("events[%d]: %w: 设备归属不符", eventIndex, ErrEventInvalid)
		}
	}

	// 心跳：刷新 last_seen_at 与版本/插件信息
	pluginsJSON, marshalPluginsErr := json.Marshal(envelope.Plugins)
	if marshalPluginsErr != nil || envelope.Plugins == nil {
		pluginsJSON = []byte(`[]`)
	}
	if touchErr := service.eventStore.TouchDevice(ctx, device.DeviceID,
		envelope.AgentVersion, pluginsJSON); touchErr != nil {
		return nil, touchErr
	}

	acceptedRows := make([]store.EventRow, 0, len(envelope.Events))
	for eventIndex := range envelope.Events {
		acceptedRows = append(acceptedRows, toEventRow(envelope.Events[eventIndex]))
	}
	acceptedFlags, insertErr := service.eventStore.InsertEvents(ctx, acceptedRows)
	if insertErr != nil {
		return nil, insertErr
	}

	// 仅对新接受的事件做会话聚合与异步风险扫描；重复事件此前已处理过
	acceptedEvents := make([]schema.Event, 0, len(envelope.Events))
	for eventIndex, isAccepted := range acceptedFlags {
		if isAccepted {
			acceptedEvents = append(acceptedEvents, envelope.Events[eventIndex])
		}
	}
	service.aggregateSessions(ctx, device.DeviceID, acceptedEvents)
	for _, acceptedEvent := range acceptedEvents {
		service.alertService.SubmitAsync(acceptedEvent)
	}

	return &BatchResult{
		Accepted:   len(acceptedEvents),
		Duplicates: len(envelope.Events) - len(acceptedEvents),
	}, nil
}

// aggregateSessions 按 (device_id, session_key) 聚合本批新增事件计数，
// 并以批内首条 user 会话文本作为标题候选（仅当会话尚无标题时生效）。
func (service *Service) aggregateSessions(ctx context.Context, deviceID string, acceptedEvents []schema.Event) {
	sessionAccumulators := map[string]*sessionAccumulator{}
	for _, acceptedEvent := range acceptedEvents {
		accumulator, exists := sessionAccumulators[acceptedEvent.SessionID]
		if !exists {
			accumulator = &sessionAccumulator{
				agentType:      acceptedEvent.AgentType,
				lastOccurredAt: acceptedEvent.OccurredAt,
			}
			sessionAccumulators[acceptedEvent.SessionID] = accumulator
		}
		accumulator.eventCount++
		if acceptedEvent.OccurredAt.After(accumulator.lastOccurredAt) {
			accumulator.lastOccurredAt = acceptedEvent.OccurredAt
		}
		if accumulator.titleCandidate == "" && acceptedEvent.EventType == schema.EventTypeConversation &&
			acceptedEvent.Role == "user" {
			accumulator.titleCandidate = truncateRunes(acceptedEvent.Content, titleMaxRunes)
		}
	}
	for sessionKey, accumulator := range sessionAccumulators {
		upsertErr := service.eventStore.UpsertSession(ctx, store.SessionUpdate{
			DeviceID:        deviceID,
			SessionKey:      sessionKey,
			AgentType:       accumulator.agentType,
			Title:           accumulator.titleCandidate,
			LastOccurredAt:  accumulator.lastOccurredAt,
			EventCountDelta: accumulator.eventCount,
			RiskCountDelta:  0,
		})
		if upsertErr != nil {
			// 计数聚合失败不阻断主链路（事件本身已落库）；留待下次上报自然修正
			continue
		}
	}
}

// sessionAccumulator 聚合单会话在本批次内的增量。
type sessionAccumulator struct {
	agentType      string
	eventCount     int
	lastOccurredAt time.Time
	titleCandidate string
}

// toEventRow 把标准事件转换为存储行模型（payload 存完整 JSON）。
func toEventRow(event schema.Event) store.EventRow {
	payloadJSON, marshalErr := json.Marshal(event)
	if marshalErr != nil {
		panic(marshalErr)
	}
	return store.EventRow{
		EventID: event.EventID, DeviceID: event.DeviceID, SessionKey: event.SessionID,
		AgentType: event.AgentType, EventType: event.EventType, Role: event.Role,
		OccurredAt: event.OccurredAt, PayloadJSON: payloadJSON, RiskTagsJSON: []byte(`[]`),
	}
}

// generateDeviceID 生成服务端设备标识：dev- + 6 字节随机 hex。
func generateDeviceID() string {
	randomBytes := make([]byte, 6)
	if _, readErr := rand.Read(randomBytes); readErr != nil {
		panic(readErr) // 系统熵源不可用属致命环境错误
	}
	return deviceIDPrefix + hex.EncodeToString(randomBytes)
}

// truncateRunes 按 rune 数截断文本。
func truncateRunes(text string, maxRunes int) string {
	if utf8.RuneCountInString(text) <= maxRunes {
		return text
	}
	truncatedRunes := []rune(text)[:maxRunes]
	return string(truncatedRunes)
}

// BuildDeviceRules 组装终端规则下发载荷：启用规则 → 终端契约形状 + 内容摘要。
// 与告警引擎 ReloadRules 同源（ListEnabledRules + FromStoreRecord），保证
// 「服务端扫描生效集」与「终端阻断生效集」来自同一张表的同一条查询。
func (service *Service) BuildDeviceRules(ctx context.Context) (schema.DeviceRulesPayload, error) {
	enabledRecords, listErr := service.eventStore.ListEnabledRules(ctx)
	if listErr != nil {
		return schema.DeviceRulesPayload{}, listErr
	}
	definitions := make([]schema.RuleDefinition, 0, len(enabledRecords))
	for _, record := range enabledRecords {
		rule, convertErr := rules.FromStoreRecord(record)
		if convertErr != nil {
			return schema.DeviceRulesPayload{}, convertErr
		}
		definitions = append(definitions, schema.RuleDefinition{
			ID: rule.ID, Name: rule.Name, Category: rule.Category,
			Target: rule.Target, Patterns: rule.Patterns, PathGlobs: rule.PathGlobs,
			Severity: string(rule.Severity), Action: string(rule.Action),
		})
	}
	return schema.DeviceRulesPayload{
		Revision: computeRulesRevision(definitions),
		Rules:    definitions,
	}, nil
}

// computeRulesRevision 规则集规范序列化（SQL 已按 id 排序，结构体字段序固定）
// 后取 sha256；任一规则内容变化都会改变摘要。
func computeRulesRevision(ruleDefinitions []schema.RuleDefinition) string {
	canonicalBytes, marshalErr := json.Marshal(ruleDefinitions)
	if marshalErr != nil {
		return "sha256:unavailable" // 仅含字符串与字符串切片，序列化不可能失败
	}
	digest := sha256.Sum256(canonicalBytes)
	return "sha256:" + hex.EncodeToString(digest[:])
}
