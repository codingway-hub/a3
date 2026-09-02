package installer

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAgentShell 充当采集器二进制的最小可执行体：覆盖 install.sh 落位后自检与
// script 收尾调用的子命令（version/register/install-hook/install-service）皆成功返回。
const fakeAgentShell = "#!/bin/sh\n" +
	"command_name=\"$1\"\n" +
	"case \"$command_name\" in\n" +
	"  version) echo \"a3-agent 0.1.0\" ;;\n" +
	"  register|install-hook|install-service) exit 0 ;;\n" +
	"  *) exit 0 ;;\n" +
	"esac\n"

// e2eArtifactServer 分发单个平台产物 + 配套 .sig，伪造源文件状态（被篡改/409 拒绝）。
func e2eArtifactServer(t *testing.T, binBytes []byte, sigBytes []byte, sigStatus int) *httptest.Server {
	t.Helper()
	assetName := AssetNameFor(runtime.GOOS, runtime.GOARCH)
	require.NotEmpty(t, assetName, "e2e 运行平台需在产物支持矩阵内")

	mux := http.NewServeMux()
	mux.HandleFunc("/download/agent/"+assetName, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/octet-stream")
		_, _ = writer.Write(binBytes)
	})
	mux.HandleFunc("/download/agent/"+assetName+".sig", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(sigStatus)
		_, _ = writer.Write(sigBytes)
	})
	serverInstance := httptest.NewServer(mux)
	t.Cleanup(serverInstance.Close)
	return serverInstance
}

// runE2EInstall 把渲染出的脚本落盘后用 /bin/sh 实跑（HOME 沙箱隔离）；
// 返回合并输出与退出码。
func runE2EInstall(t *testing.T, scriptText string, homeDir string, extraEnv ...string) (string, int) {
	t.Helper()
	scriptPath := filepath.Join(t.TempDir(), "install.sh")
	require.NoError(t, os.WriteFile(scriptPath, []byte(scriptText), 0o600))
	command := exec.Command("/bin/sh", scriptPath)
	command.Env = append(command.Env, "HOME="+homeDir)
	command.Env = append(command.Env, extraEnv...)
	var outputBuffer bytes.Buffer
	command.Stdout = &outputBuffer
	command.Stderr = &outputBuffer
	runErr := command.Run()
	exitCode := 0
	if runErr != nil {
		execErr, ok := runErr.(*exec.ExitError)
		require.True(t, ok, "install 退出类型异常: %v", runErr)
		exitCode = execErr.ExitCode()
	}
	return outputBuffer.String(), exitCode
}

// storeE2EIdentity 预置设备身份，触发 install.sh 的 register「已在册」短路，
// 免去终端交互（凭据流程已由 template 渲染断言覆盖）。
func storeE2EIdentity(t *testing.T, homeDir string) {
	t.Helper()
	stateDir := filepath.Join(homeDir, ".a3")
	require.NoError(t, os.MkdirAll(stateDir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, "device-token"), []byte("a3d_e2e\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(stateDir, "device-id"), []byte("device-e2e\n"), 0o600))
}

// fakeOpensslShim 制造受控 openssl 行为：version 输出固定字符串（决定 SIG_CAPABLE 判定），
// pkeyutl 按需仿失败。PATH 前缀注入使测试对 openssl 能力的依赖确定化、与真机无关。
func fakeOpensslShim(t *testing.T, versionText string, pkeyutlExit int) string {
	t.Helper()
	shimDir := t.TempDir()
	shimSource := "#!/bin/sh\n" +
		"if [ \"$1\" = version ]; then printf '%s' \"" + versionText + "\"; exit 0; fi\n" +
		"if [ \"$1\" = pkeyutl ]; then exit " + strconv.Itoa(pkeyutlExit) + "; fi\n" +
		"exit 0\n"
	require.NoError(t, os.WriteFile(filepath.Join(shimDir, "openssl"), []byte(shimSource), 0o755))
	return shimDir
}

func agentHomeLayout(homeDir string) (binPath string, sigPath string) {
	baseDir := filepath.Join(homeDir, ".a3", "bin")
	return filepath.Join(baseDir, "a3-agent"), filepath.Join(baseDir, "a3-agent.sig")
}

// TestE2EInstallSignedDegradeHappyPath macOS 实况（LibreSSL 无 ed25519）：
// 签名态安装走降级继续，字节完整落位，保留配对签名。
func TestE2EInstallSignedDegradeHappyPath(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	storeE2EIdentity(t, homeDir)

	publicKey, privateKey, generateErr := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, generateErr)
	fakeBytes := []byte(fakeAgentShell)
	sigBytes := ed25519.Sign(privateKey, fakeBytes)
	server := e2eArtifactServer(t, fakeBytes, sigBytes, http.StatusOK)

	scriptText, renderErr := RenderInstallScript(server.URL, publicKey)
	require.NoError(t, renderErr)

	opensslShim := fakeOpensslShim(t, "LibreSSL 3.3.6", 1)
	output, exitCode := runE2EInstall(t, scriptText, homeDir, "PATH="+opensslShim+":"+os.Getenv("PATH"))

	assert.Equal(t, 0, exitCode, "降级路径应继续完成安装")
	assert.Contains(t, output, "本机无 ed25519 验签能力", "进入降级分支须显式警告")
	assert.Contains(t, output, "服务端发布指纹", "降级路径须给出指纹供人工核对")

	agentBin, agentSig := agentHomeLayout(homeDir)
	installedBytes, readErr := os.ReadFile(agentBin)
	require.NoError(t, readErr)
	assert.Equal(t, fakeBytes, installedBytes, "装上字节必须与发布产物逐字节一致")
	assert.FileExists(t, agentSig, "签名态安装应保留配对签名文件")
}

// TestE2EInstallTamperedAbortsKeepsOld 产物在签名后被改动（服务端 409 拒签）——
// 本地验签（OpenSSL 3 能力）硬失败，已装旧版原封不动。
func TestE2EInstallTamperedAbortsKeepsOld(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	oldBin, _ := agentHomeLayout(homeDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(oldBin), 0o755))
	require.NoError(t, os.WriteFile(oldBin, []byte("old-installed-bytes"), 0o755))

	publicKey, privateKey, generateErr := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, generateErr)
	originalBytes := []byte(fakeAgentShell)                      // 签名针对此字节
	sigBytes := ed25519.Sign(privateKey, originalBytes)
	tamperedBytes := []byte(fakeAgentShell + "\n# TAMPERED\n")   // 服务端字节已被改
	server := e2eArtifactServer(t, tamperedBytes, sigBytes, http.StatusOK)

	scriptText, renderErr := RenderInstallScript(server.URL, publicKey)
	require.NoError(t, renderErr)

	// OpenSSL 3 能力 + 验签不过 → 安装必须在验签环节中止
	opensslShim := fakeOpensslShim(t, "OpenSSL 3.5.0", 1)
	output, exitCode := runE2EInstall(t, scriptText, homeDir, "PATH="+opensslShim+":"+os.Getenv("PATH"))

	assert.NotEqual(t, 0, exitCode, "篡改产物必须让安装失败")
	assert.Contains(t, output, "签名校验失败", "OpenSSL 3 验签失败应立即终止")

	oldBytes, readErr := os.ReadFile(oldBin)
	require.NoError(t, readErr)
	assert.Equal(t, []byte("old-installed-bytes"), oldBytes, "安装失败后旧版必须原封不动")
}

// TestE2EInstallSigDrift409Aborts 服务端产物漂移（.sig 返回 409）——
// 签名下载即中止，与本地验签能力无关。
func TestE2EInstallSigDrift409Aborts(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	oldBin, _ := agentHomeLayout(homeDir)
	require.NoError(t, os.MkdirAll(filepath.Dir(oldBin), 0o755))
	require.NoError(t, os.WriteFile(oldBin, []byte("old-installed-bytes"), 0o755))

	publicKey, privateKey, generateErr := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, generateErr)
	fakeBytes := []byte(fakeAgentShell)
	sigBytes := ed25519.Sign(privateKey, fakeBytes)
	server := e2eArtifactServer(t, fakeBytes, sigBytes, http.StatusConflict)

	scriptText, renderErr := RenderInstallScript(server.URL, publicKey)
	require.NoError(t, renderErr)

	opensslShim := fakeOpensslShim(t, "LibreSSL 3.3.6", 1)
	output, exitCode := runE2EInstall(t, scriptText, homeDir, "PATH="+opensslShim+":"+os.Getenv("PATH"))

	assert.NotEqual(t, 0, exitCode, "签名 409 必须让安装失败")
	assert.Contains(t, output, "签名下载失败", "应点明签名服务被拒")
	assert.Contains(t, output, "409", "应提示 409 含义（产物已变未重发）")

	oldBytes, readErr := os.ReadFile(oldBin)
	require.NoError(t, readErr)
	assert.Equal(t, []byte("old-installed-bytes"), oldBytes, "安装失败后旧版必须原封不动")
}

// TestE2EInstallUnsignedDegrades 服务端未配置签名密钥：渲染无签名分支，安装照常。
func TestE2EInstallUnsignedDegrades(t *testing.T) {
	homeDir := t.TempDir()
	t.Setenv("HOME", homeDir)
	storeE2EIdentity(t, homeDir)

	fakeBytes := []byte(fakeAgentShell)
	server := e2eArtifactServer(t, fakeBytes, nil, http.StatusNotFound)

	scriptText, renderErr := RenderInstallScript(server.URL, nil)
	require.NoError(t, renderErr)

	output, exitCode := runE2EInstall(t, scriptText, homeDir)

	assert.Equal(t, 0, exitCode, "无签名态应继续安装")
	assert.Contains(t, output, "签名校验已禁用", "须显式警示本次下载未做身份校验")

	agentBin, _ := agentHomeLayout(homeDir)
	installedBytes, readErr := os.ReadFile(agentBin)
	require.NoError(t, readErr)
	assert.Equal(t, fakeBytes, installedBytes)
}