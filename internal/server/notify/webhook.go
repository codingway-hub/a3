// Package notify 告警通知外送：后台 worker 轮询未通知告警，聚合成摘要推送到外部渠道。
//
// 设计要点：
//   - 轮询而非内联推送：外送失败不影响告警落库主链路；状态在库（notified_at/notify_attempts），
//     进程重启无损。
//   - 外送语义为 at-least-once：发送成功与标记落库之间进程崩溃会重发，通知场景可接受。
//   - 聚合防轰炸：每个轮询周期把捞到的告警聚成一条摘要消息，天然限速且零状态。
//   - 已知限制：钉钉机器人"加签"安全模式不支持（需 HMAC），关键词/IP 白名单模式可用。
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/codingway-hub/a3/internal/server/store"
)

// Channel 通知渠道抽象；未来 SMTP 邮件渠道实现此接口即可插入。
type Channel interface {
	Send(ctx context.Context, digest Digest) error
}

// Digest 一次外送的聚合摘要：本批告警 + 时间窗口 + 控制台入口。
type Digest struct {
	Alerts      []store.Alert
	WindowStart time.Time
	WindowEnd   time.Time
	ConsoleURL  string
}

// WebhookChannel 通过出站 HTTP POST 推送告警摘要。
type WebhookChannel struct {
	endpoint   string
	format     string // generic|wecom|dingtalk|feishu（config.Load 已校验）
	httpClient *http.Client
	logger     *slog.Logger
}

// NewWebhookChannel 构建渠道；httpClient 为 nil 时内部建 30s 超时客户端（测试注入短超时）。
func NewWebhookChannel(endpoint string, format string, httpClient *http.Client, logger *slog.Logger) *WebhookChannel {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &WebhookChannel{endpoint: endpoint, format: format, httpClient: httpClient, logger: logger}
}

// Send 渲染摘要并 POST 到 webhook；非 2xx 返回带状态码与截断响应体的错误。
func (channel *WebhookChannel) Send(ctx context.Context, digest Digest) error {
	digestText := renderDigestText(channel.format, digest)
	payloadBody, buildErr := buildPayload(channel.format, digestText, digest)
	if buildErr != nil {
		return buildErr
	}
	payloadBytes, marshalErr := json.Marshal(payloadBody)
	if marshalErr != nil {
		return marshalErr
	}

	request, requestErr := http.NewRequestWithContext(ctx, http.MethodPost,
		channel.endpoint, bytes.NewReader(payloadBytes))
	if requestErr != nil {
		return requestErr
	}
	request.Header.Set("Content-Type", "application/json")

	response, postErr := channel.httpClient.Do(request)
	if postErr != nil {
		return postErr
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 512))
		return fmt.Errorf("webhook 返回非 2xx: %d, body: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	_, _ = io.Copy(io.Discard, response.Body)
	return nil
}

// renderDigestText 中文纯文本摘要；超出渠道字节上限时截断（wecom/dingtalk text 约 2000 字节）。
func renderDigestText(format string, digest Digest) string {
	var textBuilder strings.Builder
	fmt.Fprintf(&textBuilder, "【a3 告警】%d 条新风险告警", len(digest.Alerts))
	// 预留尾部空间：截断尾注 + 控制台详情行不参与条目循环，须提前扣除
	tailReserve := len("\n…等 NNN 条详见控制台")
	if digest.ConsoleURL != "" {
		tailReserve += len("\n详情: ") + len(digest.ConsoleURL)
	}
	textBudget := digestTextBudget(format) - tailReserve
	alertCount := len(digest.Alerts)
	truncatedCount := 0
	for index, alertRow := range digest.Alerts {
		entryText := fmt.Sprintf("\n%d. [%s|%s] %s — 设备 %s / %s",
			index+1, severityLabel(alertRow.Severity), actionLabel(alertRow.Action),
			alertRow.RuleName, alertRow.DeviceID, alertRow.CreatedAt.Format("01-02 15:04:05"))
		if textBuilder.Len()+len(entryText) > textBudget && index < alertCount-1 {
			truncatedCount = alertCount - index
			break
		}
		textBuilder.WriteString(entryText)
	}
	if truncatedCount > 0 {
		fmt.Fprintf(&textBuilder, "\n…等 %d 条详见控制台", truncatedCount)
	}
	if digest.ConsoleURL != "" {
		fmt.Fprintf(&textBuilder, "\n详情: %s", digest.ConsoleURL)
	}
	return textBuilder.String()
}

// digestTextBudget 渠道文本上限（字节）：企微/钉钉 text 约 2048 字节，通用格式放宽。
func digestTextBudget(format string) int {
	if format == "wecom" || format == "dingtalk" || format == "feishu" {
		return 2000
	}
	return 8000
}

func severityLabel(severity string) string {
	switch severity {
	case "high":
		return "高"
	case "medium":
		return "中"
	default:
		return "低"
	}
}

func actionLabel(action string) string {
	if action == "block" {
		return "建议阻断"
	}
	return "提醒关注"
}

// buildPayload 按渠道信封包装消息体；generic 顶层 text 兼容 Slack，alerts 数组供自建收端消费。
func buildPayload(format string, digestText string, digest Digest) (any, error) {
	switch format {
	case "wecom", "dingtalk":
		return map[string]any{
			"msgtype": "text",
			"text":    map[string]any{"content": digestText},
		}, nil
	case "feishu":
		return map[string]any{
			"msg_type": "text",
			"content":  map[string]any{"text": digestText},
		}, nil
	default: // generic
		alertEntries := make([]map[string]any, 0, len(digest.Alerts))
		for _, alertRow := range digest.Alerts {
			alertEntries = append(alertEntries, map[string]any{
				"id": alertRow.ID, "device_id": alertRow.DeviceID, "session_key": alertRow.SessionKey,
				"event_id": alertRow.EventID, "rule_id": alertRow.RuleID, "rule_name": alertRow.RuleName,
				"severity": alertRow.Severity, "action": alertRow.Action,
				"summary": alertRow.Summary, "snippet": alertRow.Snippet,
				"status": alertRow.Status, "created_at": alertRow.CreatedAt,
			})
		}
		payload := map[string]any{
			"text": digestText, "count": len(digest.Alerts),
			"window_start": digest.WindowStart, "window_end": digest.WindowEnd,
			"alerts": alertEntries,
		}
		if digest.ConsoleURL != "" {
			payload["console_url"] = digest.ConsoleURL
		}
		return payload, nil
	}
}
