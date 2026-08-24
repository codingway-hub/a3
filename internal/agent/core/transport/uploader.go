// Package transport 提供终端统一传输层：设备注册、批量事件 HTTPS 上报与指数退避重试。
// 失败分类：网络错误/5xx 可重试；其余 4xx 视为服务端明确拒绝，重试无意义立即放弃。
package transport

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/codingway-hub/a3/internal/agent/core"
	"github.com/codingway-hub/a3/pkg/schema"
)

// 退避策略默认值：1s 起步、每次翻倍、封顶 60s。
const (
	DefaultRetryInitial = 1 * time.Second
	DefaultRetryCap     = 60 * time.Second
)

// DeviceInfo 设备注册请求信息（指纹幂等键）。
type DeviceInfo struct {
	Hostname           string `json:"hostname"`
	OS                 string `json:"os"`
	Arch               string `json:"arch"`
	MachineFingerprint string `json:"machine_fingerprint"`
}

// RegistrationResult 设备注册响应。
type RegistrationResult struct {
	DeviceID string `json:"device_id"`
	Token    string `json:"token"`
}

// BatchResult 单批上报结果（与服务端响应字段对齐）。
type BatchResult struct {
	Accepted   int `json:"accepted"`
	Duplicates int `json:"duplicates"`
}

// batchEnvelope 上报请求体（复用 core 层共用契约，别名保留测试引用）。
type batchEnvelope = core.EventEnvelope

// NonRetryableError 服务端明确拒绝（非 5xx 的 HTTP 错误），重试只会重复失败。
type NonRetryableError struct {
	StatusCode int
	Detail     string
}

func (err *NonRetryableError) Error() string {
	return fmt.Sprintf("服务端拒绝上报(状态码 %d): %s", err.StatusCode, err.Detail)
}

// Uploader HTTPS 上报客户端。
type Uploader struct {
	serverBaseURL string
	deviceToken   string
	agentVersion  string
	plugins       []string
	httpClient    *http.Client
	logger        *slog.Logger

	retryInitial time.Duration // 首次退避时长（测试注入更短值）
	retryCap     time.Duration // 退避封顶时长
}

// NewUploader 构建上报客户端；insecureTLS 仅用于自签名单机部署场景（显式开关）。
func NewUploader(serverBaseURL string, deviceToken string, agentVersion string,
	insecureTLS bool, logger *slog.Logger) (*Uploader, error) {
	if serverBaseURL == "" {
		return nil, fmt.Errorf("server_base_url 不能为空")
	}
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if insecureTLS {
		// 用户显式选择跳过证书校验（单机 compose 自签名场景），风险由部署者承担
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // 显式开关，见上注释
		}
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Uploader{
		serverBaseURL: serverBaseURL,
		deviceToken:   deviceToken,
		agentVersion:  agentVersion,
		plugins:       []string{"claude-code"},
		httpClient:    httpClient,
		logger:        logger,
		retryInitial:  DefaultRetryInitial,
		retryCap:      DefaultRetryCap,
	}, nil
}

// RegisterDevice 注册设备并换取一次性下发的设备 Token。
func (uploader *Uploader) RegisterDevice(ctx context.Context, deviceInfo DeviceInfo) (RegistrationResult, error) {
	var registrationResult RegistrationResult
	requestBody, marshalErr := json.Marshal(deviceInfo)
	if marshalErr != nil {
		return registrationResult, fmt.Errorf("序列化注册信息失败: %w", marshalErr)
	}

	registerRequest, buildErr := http.NewRequestWithContext(ctx, http.MethodPost,
		uploader.serverBaseURL+"/api/v1/devices/register", bytes.NewReader(requestBody))
	if buildErr != nil {
		return registrationResult, fmt.Errorf("构建注册请求失败: %w", buildErr)
	}
	registerRequest.Header.Set("Content-Type", "application/json")

	response, doErr := uploader.httpClient.Do(registerRequest)
	if doErr != nil {
		return registrationResult, fmt.Errorf("注册请求发送失败: %w", doErr)
	}
	defer func() { _ = response.Body.Close() }()
	responseBytes, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if readErr != nil {
		return registrationResult, fmt.Errorf("读取注册响应失败: %w", readErr)
	}
	if response.StatusCode != http.StatusOK {
		return registrationResult, &NonRetryableError{StatusCode: response.StatusCode, Detail: string(responseBytes)}
	}
	if unmarshalErr := json.Unmarshal(responseBytes, &registrationResult); unmarshalErr != nil {
		return registrationResult, fmt.Errorf("解析注册响应失败: %w", unmarshalErr)
	}
	return registrationResult, nil
}

// PostBatch 上报一批事件；可重试失败按指数退避无限重试（ctx 取消即中断），
// 不可重试错误原样返回 NonRetryableError 交调用方决策（如入 spool 或丢弃）。
func (uploader *Uploader) PostBatch(ctx context.Context, events []schema.Event) (BatchResult, error) {
	var batchResult BatchResult
	requestBody, marshalErr := json.Marshal(batchEnvelope{
		AgentVersion: uploader.agentVersion,
		Plugins:      uploader.plugins,
		Events:       events,
	})
	if marshalErr != nil {
		return batchResult, fmt.Errorf("序列化事件批次失败: %w", marshalErr)
	}

	backoffDuration := uploader.retryInitial
	for attempt := 1; ; attempt++ {
		batchResult, attemptFailure := uploader.attemptOnce(ctx, requestBody)
		if attemptFailure == nil {
			return batchResult, nil
		}

		var nonRetryableErr *NonRetryableError
		if errors.As(attemptFailure, &nonRetryableErr) {
			// 服务端明确拒绝（鉴权失效/批次非法等）：重试只会重复失败，放弃该批交调用方决策
			uploader.logger.Error("服务端拒绝上报，放弃本批事件",
				slog.Int("status_code", nonRetryableErr.StatusCode),
				slog.String("detail", nonRetryableErr.Detail))
			return batchResult, attemptFailure
		}
		uploader.logger.Warn("上报失败，将按退避重试",
			slog.Int("attempt", attempt),
			slog.Duration("next_backoff", backoffDuration),
			slog.String("reason", attemptFailure.Error()))

		wakeTimer := time.NewTimer(backoffDuration)
		select {
		case <-ctx.Done():
			wakeTimer.Stop()
			return batchResult, fmt.Errorf("上报在退避等待中被取消: %w", ctx.Err())
		case <-wakeTimer.C:
		}

		backoffDuration *= 2
		if backoffDuration > uploader.retryCap {
			backoffDuration = uploader.retryCap
		}
	}
}

// attemptOnce 执行单次上报尝试；返回 (结果, nil) 成功、(零值, nil) 不可能、(零值, err) 失败，
// 其中 *NonRetryableError 表示服务端明确拒绝不应再重试，其余错误视为可重试。
func (uploader *Uploader) attemptOnce(ctx context.Context, requestBody []byte) (BatchResult, error) {
	var batchResult BatchResult

	batchRequest, buildErr := http.NewRequestWithContext(ctx, http.MethodPost,
		uploader.serverBaseURL+"/api/v1/events/batch", bytes.NewReader(requestBody))
	if buildErr != nil {
		return batchResult, fmt.Errorf("构建上报请求失败: %w", buildErr)
	}
	batchRequest.Header.Set("Content-Type", "application/json")
	batchRequest.Header.Set("Authorization", "Bearer "+uploader.deviceToken)

	response, doErr := uploader.httpClient.Do(batchRequest)
	if doErr != nil {
		return batchResult, fmt.Errorf("上报请求发送失败: %w", doErr)
	}
	defer func() { _ = response.Body.Close() }()
	responseBytes, readErr := io.ReadAll(io.LimitReader(response.Body, 64<<10))
	if readErr != nil {
		return batchResult, fmt.Errorf("读取上报响应失败: %w", readErr)
	}

	switch {
	case response.StatusCode == http.StatusOK:
		if unmarshalErr := json.Unmarshal(responseBytes, &batchResult); unmarshalErr != nil {
			return batchResult, fmt.Errorf("解析上报响应失败: %w", unmarshalErr)
		}
		return batchResult, nil
	case response.StatusCode >= 500:
		return batchResult, fmt.Errorf("服务端暂时不可用(状态码 %d): %s", response.StatusCode, string(responseBytes))
	default:
		// 其余 4xx：鉴权失效、批次非法等，重试只会重复失败
		return batchResult, &NonRetryableError{StatusCode: response.StatusCode, Detail: string(responseBytes)}
	}
}
