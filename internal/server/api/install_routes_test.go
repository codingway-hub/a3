package api

import (
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

func TestInstallScriptInjectsRequestHost(t *testing.T) {
	engine := setupInstallRouter(t, "", "")

	request := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
	request.Host = "aa.bb.com:12345"
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `SERVER_URL="http://aa.bb.com:12345"`)
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
	assert.Contains(t, recorder.Body.String(), `SERVER_URL="https://aa.bb.com"`)
}

func TestInstallScriptPrefersConfiguredPublicURL(t *testing.T) {
	engine := setupInstallRouter(t, "", "https://a3.example.com")

	request := httptest.NewRequest(http.MethodGet, "/install.sh", nil)
	request.Host = "internal.host:9999" // 与 PublicURL 不同：配置即权威
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, request)

	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `SERVER_URL="https://a3.example.com"`)
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
	assert.JSONEq(t, `{"agent_dist_ready":false,"public_url":"https://a3.example.com"}`,
		recorder.Body.String())
}
