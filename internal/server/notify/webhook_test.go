package notify

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/codingway-hub/a3/internal/server/store"
)

// mustDigestAlert 构造一条用于外送测试的告警。
func mustDigestAlert(t *testing.T, ruleID string, severity string) store.Alert {
	t.Helper()
	createdAt, parseErr := time.Parse(time.RFC3339, "2026-08-30T10:00:00Z")
	require.NoError(t, parseErr)
	return store.Alert{
		ID: "alert-" + ruleID, DeviceID: "dev-1", SessionKey: "sess-1", EventID: "evt-1",
		RuleID: ruleID, RuleName: "规则-" + ruleID, Severity: severity, Action: "block",
		Snippet: "snippet", Summary: "摘要", Status: "open", CreatedAt: createdAt,
	}
}

// plainHTTPClient 测试专用普通客户端：绕过 SSRF 拨号防护，以命中本地回环收端。
func plainHTTPClient() *http.Client { return &http.Client{} }

func TestWebhookChannelSendSuccess(t *testing.T) {
	var receivedHeaders http.Header
	var receivedBody []byte
	receiveServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		receivedHeaders = request.Header.Clone()
		receivedBody, _ = io.ReadAll(request.Body)
		responseWriter.WriteHeader(http.StatusOK)
	}))
	defer receiveServer.Close()

	channel := NewWebhookChannel(receiveServer.URL, "wecom", plainHTTPClient(), nil)
	digest := Digest{Alerts: []store.Alert{mustDigestAlert(t, "dlp.jwt", "high")}}
	require.NoError(t, channel.Send(context.Background(), digest))

	assert.Equal(t, "application/json", receivedHeaders.Get("Content-Type"))
	var payload struct {
		MsgType string `json:"msgtype"`
		Text    struct {
			Content string `json:"content"`
		} `json:"text"`
	}
	require.NoError(t, json.Unmarshal(receivedBody, &payload))
	assert.Equal(t, "text", payload.MsgType)
	assert.Contains(t, payload.Text.Content, "【a3 告警】1 条新风险告警")
	assert.Contains(t, payload.Text.Content, "dlp.jwt")
}

func TestWebhookChannelSendNon2xx(t *testing.T) {
	receiveServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		http.Error(responseWriter, "bad gateway", http.StatusBadGateway)
	}))
	defer receiveServer.Close()

	channel := NewWebhookChannel(receiveServer.URL, "generic", plainHTTPClient(), nil)
	sendErr := channel.Send(context.Background(), Digest{Alerts: []store.Alert{mustDigestAlert(t, "dlp.jwt", "high")}})
	require.Error(t, sendErr)
	assert.Contains(t, sendErr.Error(), "502")
	assert.Contains(t, sendErr.Error(), "bad gateway")
}

func TestWebhookChannelSendUnreachable(t *testing.T) {
	receiveServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {}))
	receiveServer.Close() // 立即关闭制造不可达地址

	channel := NewWebhookChannel(receiveServer.URL, "generic", plainHTTPClient(), nil)
	assert.Error(t, channel.Send(context.Background(), Digest{Alerts: []store.Alert{mustDigestAlert(t, "dlp.jwt", "high")}}))
}

func TestWebhookChannelSendTimeout(t *testing.T) {
	slowServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		time.Sleep(200 * time.Millisecond)
		responseWriter.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	channel := NewWebhookChannel(slowServer.URL, "generic", &http.Client{Timeout: 30 * time.Millisecond}, nil)
	assert.Error(t, channel.Send(context.Background(), Digest{Alerts: []store.Alert{mustDigestAlert(t, "dlp.jwt", "high")}}))
}

func TestBuildPayloadFourEnvelopes(t *testing.T) {
	digest := Digest{Alerts: []store.Alert{mustDigestAlert(t, "dlp.jwt", "high")}}
	digestText := "测试摘要文本"

	wecomPayload, wecomErr := buildPayload("wecom", digestText, digest)
	require.NoError(t, wecomErr)
	wecomJSON, marshalErr := json.Marshal(wecomPayload)
	require.NoError(t, marshalErr)
	assert.JSONEq(t, `{"msgtype":"text","text":{"content":"测试摘要文本"}}`, string(wecomJSON))

	dingtalkPayload, dingtalkErr := buildPayload("dingtalk", digestText, digest)
	require.NoError(t, dingtalkErr)
	dingtalkJSON, dingtalkMarshalErr := json.Marshal(dingtalkPayload)
	require.NoError(t, dingtalkMarshalErr)
	assert.JSONEq(t, `{"msgtype":"text","text":{"content":"测试摘要文本"}}`, string(dingtalkJSON))

	feishuPayload, feishuErr := buildPayload("feishu", digestText, digest)
	require.NoError(t, feishuErr)
	feishuJSON, feishuMarshalErr := json.Marshal(feishuPayload)
	require.NoError(t, feishuMarshalErr)
	assert.JSONEq(t, `{"msg_type":"text","content":{"text":"测试摘要文本"}}`, string(feishuJSON))

	genericPayload, genericErr := buildPayload("generic", digestText, digest)
	require.NoError(t, genericErr)
	genericJSON, genericMarshalErr := json.Marshal(genericPayload)
	require.NoError(t, genericMarshalErr)
	var genericDecoded struct {
		Text       string           `json:"text"`
		Count      int              `json:"count"`
		AlertsList []map[string]any `json:"alerts"`
	}
	require.NoError(t, json.Unmarshal(genericJSON, &genericDecoded))
	assert.Equal(t, "测试摘要文本", genericDecoded.Text)
	assert.Equal(t, 1, genericDecoded.Count)
	require.Len(t, genericDecoded.AlertsList, 1)
	assert.Equal(t, "alert-dlp.jwt", genericDecoded.AlertsList[0]["id"])
	assert.Equal(t, "dlp.jwt", genericDecoded.AlertsList[0]["rule_id"])
	assert.Equal(t, "high", genericDecoded.AlertsList[0]["severity"])
}

func TestRenderDigestTextTruncation(t *testing.T) {
	// 企微/钉钉 text 上限 2000 字节：30 条足长条目必然触发截断
	digestAlerts := make([]store.Alert, 0, 30)
	for index := 0; index < 30; index++ {
		digestAlerts = append(digestAlerts, mustDigestAlert(t, "rule"+string(rune('a'+index)), "high"))
	}
	digest := Digest{Alerts: digestAlerts, ConsoleURL: "https://console.example.com/alerts"}
	digestText := renderDigestText("wecom", digest)

	assert.LessOrEqual(t, len(digestText), 2000, "截断后不超渠道上限")
	assert.Contains(t, digestText, "【a3 告警】30 条")
	assert.Contains(t, digestText, "…等")
	assert.Contains(t, digestText, "详见控制台")
	assert.Contains(t, digestText, "详情: https://console.example.com/alerts")

	// generic 上限宽松不截断
	genericText := renderDigestText("generic", digest)
	assert.NotContains(t, genericText, "…等")
}

func TestRenderDigestTextEmptyConsoleURL(t *testing.T) {
	digestText := renderDigestText("generic", Digest{Alerts: []store.Alert{mustDigestAlert(t, "dlp.jwt", "high")}})
	assert.NotContains(t, digestText, "详情:")
}

// SSRF 防护：默认（未注入客户端）渠道用安全客户端，回环/内网目标在拨号前即被拒绝。
func TestWebhookChannelSendBlocksPrivateTarget(t *testing.T) {
	receiveServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		responseWriter.WriteHeader(http.StatusOK)
	}))
	defer receiveServer.Close()

	channel := NewWebhookChannel(receiveServer.URL, "generic", nil, nil)
	sendErr := channel.Send(context.Background(), Digest{Alerts: []store.Alert{mustDigestAlert(t, "dlp.jwt", "high")}})
	require.Error(t, sendErr)
	assert.Contains(t, sendErr.Error(), "禁用网段")
}

func TestRejectUnsafeNetwork(t *testing.T) {
	testCases := []struct {
		name     string
		ip       string
		rejected bool
	}{
		{"loopback v4", "127.0.0.1", true},
		{"private v4", "10.0.0.5", true},
		{"private v4-16", "172.16.8.1", true},
		{"private v4-c", "192.168.1.7", true},
		{"link-local", "169.254.169.254", true},
		{"cg nat", "100.64.0.9", true},
		{"public v4", "8.8.8.8", false},
		{"public v4-2", "1.1.1.1", false},
		{"loopback v6", "::1", true},
		{"link-local v6", "fe80::1", true},
		{"ula v6", "fc00::1", true},
		{"public v6", "2606:4700:4700::1111", false},
		{"mapped loopback", "::ffff:127.0.0.1", true},
		{"mapped private", "::ffff:10.0.0.1", true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			sendErr := rejectUnsafeNetwork(net.ParseIP(testCase.ip))
			if testCase.rejected {
				require.Error(t, sendErr)
				assert.Contains(t, sendErr.Error(), "禁用网段")
			} else {
				require.NoError(t, sendErr)
			}
		})
	}
}
