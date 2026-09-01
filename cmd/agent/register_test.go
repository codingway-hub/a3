package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPromptInstallCodeFromPipedStdin(t *testing.T) {
	var stderrBuffer bytes.Buffer
	code, promptErr := promptInstallCode(strings.NewReader("a3i_"+strings.Repeat("a", 64)+"\n"), &stderrBuffer)
	require.NoError(t, promptErr)
	assert.Equal(t, "a3i_"+strings.Repeat("a", 64), code, "凭据应整行读取并去除换行/空白")
	assert.NotContains(t, stderrBuffer.String(), "a3i_", "提示文本不得回显明文凭据")
}

func TestPromptInstallCodeTrimsTrailingWhitespace(t *testing.T) {
	var stderrBuffer bytes.Buffer
	code, promptErr := promptInstallCode(strings.NewReader("  a3i_bb\r\n"), &stderrBuffer)
	require.NoError(t, promptErr)
	assert.Equal(t, "a3i_bb", code)
}

func TestPromptInstallCodeRejectsEmptyAndEOF(t *testing.T) {
	var stderrBuffer bytes.Buffer
	_, emptyErr := promptInstallCode(strings.NewReader("\n"), &stderrBuffer)
	assert.Error(t, emptyErr, "空输入应报错而非静默跳过")

	var stderrBuffer2 bytes.Buffer
	_, eofErr := promptInstallCode(strings.NewReader(""), &stderrBuffer2)
	assert.Error(t, eofErr, "直接 EOF 应报错")
}

func TestRegisterDeviceCoreSkipsWhenIdentityExists(t *testing.T) {
	stateDir := t.TempDir()
	require.NoError(t, storeDeviceIdentity(stateDir, "a3d_existing_token", "dev-existing"))

	var stdoutBuffer, stderrBuffer bytes.Buffer
	// 身份已存在：不得触碰 stdin（空输入也会被跳过）也不得发起网络请求（server 传无效地址）
	exitCode := registerDeviceCore(stateDir, "http://127.0.0.1:1", false,
		strings.NewReader(""), &stdoutBuffer, &stderrBuffer)

	assert.Equal(t, 0, exitCode, "身份已存在应跳过注册直接成功")
	assert.Contains(t, stdoutBuffer.String(), "已在册")
	assert.Empty(t, stderrBuffer.String())
}

func TestRegisterDeviceCoreRegistersWithInstallCodeFromStdin(t *testing.T) {
	installCode := "a3i_" + strings.Repeat("b", 64)
	var seenInstallCode string
	fakeServer := httptest.NewServer(http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/api/v1/devices/register", request.URL.Path)
		var body map[string]any
		require.NoError(t, json.NewDecoder(request.Body).Decode(&body))
		seenInstallCode, _ = body["install_code"].(string)
		assert.NotContains(t, request.URL.RawQuery, "a3i_", "安装凭据不得进入 URL")
		_, _ = responseWriter.Write([]byte(`{"device_id":"dev-fresh","token":"a3d_fresh"}`))
	}))
	defer fakeServer.Close()

	stateDir := t.TempDir()
	var stdoutBuffer, stderrBuffer bytes.Buffer
	exitCode := registerDeviceCore(stateDir, fakeServer.URL, false,
		strings.NewReader(installCode+"\n"), &stdoutBuffer, &stderrBuffer)

	assert.Equal(t, 0, exitCode, "注册应成功")
	assert.Equal(t, installCode, seenInstallCode, "凭据应经请求体提交给服务端")
	assert.NotContains(t, stdoutBuffer.String()+stderrBuffer.String(),
		installCode, "整个注册输出不得泄露明文凭据")
	assert.Equal(t, `a3d_fresh`, readStoredDeviceToken(stateDir))
	assert.Equal(t, `dev-fresh`, readStoredDeviceID(stateDir))
	assert.Contains(t, stdoutBuffer.String(), "注册成功")
}

func TestRegisterDeviceCoreRejectsMissingInstallCode(t *testing.T) {
	stateDir := t.TempDir()
	var stdoutBuffer, stderrBuffer bytes.Buffer
	exitCode := registerDeviceCore(stateDir, "http://127.0.0.1:1", false,
		strings.NewReader("\n"), &stdoutBuffer, &stderrBuffer)
	assert.Equal(t, 1, exitCode, "缺凭据必须终止注册")
	assert.Contains(t, stderrBuffer.String(), "安装凭据不能为空")
}