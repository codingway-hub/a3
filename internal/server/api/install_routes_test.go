package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupInstallRouter 构建仅含安装托管路由的引擎（不依赖数据库）。
func setupInstallRouter(t *testing.T, agentDist string, publicURL string) *gin.Engine {
	t.Helper()
	router := NewRouter(nil, nil, RouterConfig{
		AgentDist: agentDist,
		PublicURL: publicURL,
	})
	return router.Setup()
}

// setupInstallRouterSigned 同上，但装配采集器发布签名密钥。
func setupInstallRouterSigned(t *testing.T, agentDist string, publicURL string) (*gin.Engine, ed25519.PublicKey) {
	t.Helper()
	_, privateKey, generateErr := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, generateErr)
	router := NewRouter(nil, nil, RouterConfig{
		AgentDist:  agentDist,
		PublicURL:  publicURL,
		SigningKey: privateKey,
	})
	return router.Setup(), privateKey.Public().(ed25519.PublicKey)
}

func TestInstallScriptInjectsRequestHost(t *testing.T) {
	engine := setupInstallRouter(t, "", "")

	request := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
	request.Host = "aa.bb.com:12345"
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `SERVER_URL='http://aa.bb.com:12345'`)
	assert.Contains(t, recorder.Header().Get("Content-Type"), "text/x-shellscript")
}

func TestInstallScriptRespectsForwardedProto(t *testing.T) {
	engine := setupInstallRouter(t, "", "")

	request := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
	request.Host = "aa.bb.com"
	request.Header.Set("X-Forwarded-Proto", "https")
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `SERVER_URL='https://aa.bb.com'`)
}

func TestInstallScriptPrefersConfiguredPublicURL(t *testing.T) {
	engine := setupInstallRouter(t, "", "https://a3.example.com")

	request := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
	request.Host = "internal.host:9999" // 与 PublicURL 不同：配置即权威
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `SERVER_URL='https://a3.example.com'`)
}

func TestInstallScriptRejectsEmptyHost(t *testing.T) {
	engine := setupInstallRouter(t, "", "")

	request := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
	request.Host = ""
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	assert.Equal(t, http.StatusBadRequest, recorder.Code)
}

func TestAgentDownloadWhitelist(t *testing.T) {
	distDir := t.TempDir()
	assetContent := []byte("fake-agent-binary")
	for _, assetName := range []string{"a3-agent-darwin-arm64", "a3-agent-linux-amd64"} {
		require.NoError(t, os.WriteFile(filepath.Join(distDir, assetName), assetContent, 0755))
	}
	engine := setupInstallRouter(t, distDir, "")

	// 白名单内：200 且内容一致
	request := httptest.NewRequest(http.MethodGet, "/download/agent/a3-agent-darwin-arm64", nil)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, assetContent, recorder.Body.Bytes())

	// 白名单外产物名：404（含目录遍历尝试，绝不拼路径）
	for _, blockedAsset := range []string{
		"a3-agent-unknown",
		"..%2F..%2Fetc%2Fpasswd",
		"....",
	} {
		request := httptest.NewRequest(http.MethodGet, "/download/agent/"+blockedAsset, nil)
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, request)
		assert.Equal(t, http.StatusNotFound, recorder.Code, "产物 %q 应 404", blockedAsset)
	}
}

func TestAgentDownloadMissingDistReturns404(t *testing.T) {
	// 未配置产物目录
	engine := setupInstallRouter(t, "", "")
	request := httptest.NewRequest(http.MethodGet, "/download/agent/a3-agent-linux-amd64", nil)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusNotFound, recorder.Code)

	// 已配置但文件缺失
	engine = setupInstallRouter(t, t.TempDir(), "")
	recorder = httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusNotFound, recorder.Code)
}

func TestSetupInfoIsPublic(t *testing.T) {
	engine := setupInstallRouter(t, "", "https://a3.example.com")

	request := httptest.NewRequest(http.MethodGet, "/api/v1/setup-info", nil)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code, "setup-info 必须免登录可访问（用户无控制台账号）")
	assert.JSONEq(t, `{"agent_dist_ready":false,"public_url":"https://a3.example.com",
		"agent_signing_enabled":false,"agent_signing_fingerprint":""}`,
		recorder.Body.String())
}

func TestSetupInfoSignedRouter(t *testing.T) {
	engine, _ := setupInstallRouterSigned(t, "", "https://a3.example.com")

	request := httptest.NewRequest(http.MethodGet, "/api/v1/setup-info", nil)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	var body struct {
		AgentDistReady          bool   `json:"agent_dist_ready"`
		PublicURL               string `json:"public_url"`
		AgentSigningEnabled     bool   `json:"agent_signing_enabled"`
		AgentSigningFingerprint string `json:"agent_signing_fingerprint"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
	assert.Equal(t, "https://a3.example.com", body.PublicURL)
	assert.True(t, body.AgentSigningEnabled, "签名态应上报已启用")
	assert.Regexp(t, `^[0-9a-f]{64}$`, body.AgentSigningFingerprint, "指纹应为 sha256 六十四位 hex")
}

// installFixture 写一个白名单产物文件并返回其目录。
func installFixture(t *testing.T, assetName string, content []byte) string {
	t.Helper()
	distDir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(distDir, assetName), content, 0755))
	return distDir
}

func TestAgentSigServedAndVerifies(t *testing.T) {
	binaryContent := []byte("fake-agent-binary")
	distDir := installFixture(t, "a3-agent-linux-amd64", binaryContent)
	engine, signPub := setupInstallRouterSigned(t, distDir, "")

	request := httptest.NewRequest(http.MethodGet, "/download/agent/a3-agent-linux-amd64.sig", nil)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	sigBytes := recorder.Body.Bytes()
	require.Len(t, sigBytes, ed25519.SignatureSize, ".sig 应为原始 64 字节 ed25519 签名")
	assert.True(t, ed25519.Verify(signPub, binaryContent, sigBytes), "签名必须能验签通过")
	assert.Equal(t, "application/octet-stream", recorder.Header().Get("Content-Type"))
}

func TestAgentExeSigSuffix(t *testing.T) {
	binaryContent := []byte("fake-windows-exe")
	distDir := installFixture(t, "a3-agent-windows-amd64.exe", binaryContent)
	engine, signPub := setupInstallRouterSigned(t, distDir, "")

	request := httptest.NewRequest(http.MethodGet, "/download/agent/a3-agent-windows-amd64.exe.sig", nil)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	sigBytes := recorder.Body.Bytes()
	assert.True(t, ed25519.Verify(signPub, binaryContent, sigBytes), "windows 产物信号后缀剥取后应同样可验签")
}

func TestAgentSigNoKey404(t *testing.T) {
	distDir := installFixture(t, "a3-agent-linux-amd64", []byte("fake-agent-binary"))
	engine := setupInstallRouter(t, distDir, "")

	request := httptest.NewRequest(http.MethodGet, "/download/agent/a3-agent-linux-amd64.sig", nil)
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)
	assert.Equal(t, http.StatusNotFound, recorder.Code, "未配置签名密钥时 .sig 必须 404")
}

func TestAgentSigUnknownAndTraversal404(t *testing.T) {
	distDir := installFixture(t, "a3-agent-linux-amd64", []byte("fake-agent-binary"))
	engine, _ := setupInstallRouterSigned(t, distDir, "")

	for _, assetName := range []string{
		"a3-agent-unknown.sig",
		"..%2F..%2Fetc%2Fpasswd.sig",
		"....sig",
	} {
		request := httptest.NewRequest(http.MethodGet, "/download/agent/"+assetName, nil)
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, request)
		assert.Equal(t, http.StatusNotFound, recorder.Code, "产物 %q 应 404", assetName)
	}
}

func TestAgentSigDrift409(t *testing.T) {
	distDir := installFixture(t, "a3-agent-linux-amd64", []byte("fake-agent-binary"))
	engine, _ := setupInstallRouterSigned(t, distDir, "")

	// 第一代：正常签发
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/download/agent/a3-agent-linux-amd64.sig", nil))
	require.Equal(t, http.StatusOK, recorder.Code)

	// 产物在签名后被改动（未重启服务端重新发布）→ 代际漂移判篡改
	require.NoError(t, os.WriteFile(filepath.Join(distDir, "a3-agent-linux-amd64"), []byte("tampered-binary"), 0755))
	recorder = httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/download/agent/a3-agent-linux-amd64.sig", nil))
	require.Equal(t, http.StatusConflict, recorder.Code, "代际漂移必须 409 拒绝重新签名")
	assert.Contains(t, recorder.Body.String(), "产物已变更但签名未刷新")
}
