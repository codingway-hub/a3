// Package notify 告警通知外送：后台 worker 轮询通知 outbox，聚合成摘要推送到外部渠道。
//
// 设计要点：
//   - 可靠链路以 notification_outbox 为基座：入队与告警落库同事务、投递状态逐条在库、
//     领取加锁去重、失败按行退避重试、次数封顶置 dropped（详见 worker.go / store 层）。
//   - 外送语义为 at-least-once：发送成功与标记落库之间进程崩溃会重发，通知场景可接受。
//   - 聚合防轰炸：每批领取的告警聚成一条摘要消息，天然限速且零状态。
//   - SSRF 防护：默认 http.Client 在拨号前解析并校验目标地址，私有/回环/链路本地/
//     多播/保留地址段与云元数据端点一律拒绝；重定向的每一跳同样受校验约束。
//   - 已知限制：钉钉机器人"加签"安全模式不支持（需 HMAC），关键词/IP 白名单模式可用。
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
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

// NewWebhookChannel 构建渠道；httpClient 为 nil 时内部建带 SSRF 防护的直连客户端
// （测试注入普通客户端以命中本地回环收端）。
func NewWebhookChannel(endpoint string, format string, httpClient *http.Client, logger *slog.Logger) *WebhookChannel {
	if httpClient == nil {
		httpClient = safeHTTPClient()
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &WebhookChannel{endpoint: endpoint, format: format, httpClient: httpClient, logger: logger}
}

// SSRF 防护：webhook 目标必须可解析到公网可达地址。私有/回环/链路本地/多播/保留
// 地址段与云元数据端点（169.254.169.254）一律拒绝，防止 A3_NOTIFY_WEBHOOK_URL 被
// 指向内网服务、本机管理端或云元数据触发内网探测与敏感数据外带。
var bannedIPv4Networks = parseBannedNetworks([]string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16",
	"198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
})
var bannedIPv6Networks = parseBannedNetworks([]string{
	"::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32",
})

// parseBannedNetworks 解析禁用网段 CIDR 列表（字面量固定，解析失败只会留给 nil）。
func parseBannedNetworks(cidrList []string) []*net.IPNet {
	networkList := make([]*net.IPNet, 0, len(cidrList))
	for _, cidr := range cidrList {
		_, network, _ := net.ParseCIDR(cidr)
		networkList = append(networkList, network)
	}
	return networkList
}

// rejectUnsafeNetwork 判定目标 IP 是否命中禁用网段（IPv4 映射的 IPv6 同样按 IPv4 判）。
func rejectUnsafeNetwork(ip net.IP) error {
	if ipv4 := ip.To4(); ipv4 != nil {
		for _, network := range bannedIPv4Networks {
			if network.Contains(ipv4) {
				return fmt.Errorf("webhook 目标落在禁用网段 %s", network)
			}
		}
		return nil
	}
	for _, network := range bannedIPv6Networks {
		if network.Contains(ip) {
			return fmt.Errorf("webhook 目标落在禁用网段 %s", network)
		}
	}
	return nil
}

// safeHTTPClient 构建直连外发的 SSRF 防护客户端：每一次出站连接拨号前解析并校验
// 目标地址；重定向的每一跳经由同一 DialContext 受同样约束。不走环境代理——否则
// 连接先到达代理、拨号校验的将是代理而非真实目标，防护即被绕过。
func safeHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	safeDial := func(ctx context.Context, network string, address string) (net.Conn, error) {
		host, _, splitErr := net.SplitHostPort(address)
		if splitErr != nil {
			return nil, splitErr
		}
		if zoneIndex := strings.IndexByte(host, '%'); zoneIndex >= 0 {
			host = host[:zoneIndex] // 剥离链路本地 zone 标识，避免把 fe80::x%eth0 当主机名解析
		}
		targetIP := net.ParseIP(host)
		if targetIP == nil {
			resolved, resolveErr := net.DefaultResolver.LookupIPAddr(ctx, host)
			if resolveErr != nil {
				return nil, fmt.Errorf("webhook 目标解析失败 %s: %w", host, resolveErr)
			}
			if len(resolved) == 0 {
				return nil, fmt.Errorf("webhook 目标 %s 无解析结果", host)
			}
			for _, resolvedAddr := range resolved {
				if networkErr := rejectUnsafeNetwork(resolvedAddr.IP); networkErr != nil {
					return nil, networkErr
				}
			}
		} else if networkErr := rejectUnsafeNetwork(targetIP); networkErr != nil {
			return nil, networkErr
		}
		return dialer.DialContext(ctx, network, address)
	}

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:       nil, // 直连：拨号校验针对真实目标 IP
			DialContext: safeDial,
		},
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if request.URL.Scheme != "http" && request.URL.Scheme != "https" {
				return fmt.Errorf("webhook 重定向目标协议不支持: %s", request.URL.Scheme)
			}
			if len(via) >= 10 {
				return fmt.Errorf("webhook 重定向次数过多")
			}
			return nil
		},
	}
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
