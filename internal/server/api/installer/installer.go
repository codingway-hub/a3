// Package installer 托管采集器一键安装：install.sh 模板渲染与产物文件名白名单。
// 服务端按请求地址动态注入 SERVER_URL 与采集器发布签名公钥，用户照接入指南页复制一条
// curl 命令即可完成安装。签名公钥为 nil 时渲染「签名校验已禁用」降级分支。
package installer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"text/template"
)

//go:embed install.sh.tmpl
var templateFS embed.FS

// assetName 矩阵与 Makefile release-agent 产物命名保持一致（windows 加 .exe 后缀）。
// 白名单硬编码：下载路由绝不拼接用户输入路径，防目录遍历。
var assetNames = map[string]string{
	"darwin/amd64":  "a3-agent-darwin-amd64",
	"darwin/arm64":  "a3-agent-darwin-arm64",
	"linux/amd64":   "a3-agent-linux-amd64",
	"linux/arm64":   "a3-agent-linux-arm64",
	"windows/amd64": "a3-agent-windows-amd64.exe",
}

// AssetNameFor 返回平台对应的发布产物文件名；不在支持矩阵内返回空串。
func AssetNameFor(goos string, goarch string) string {
	return assetNames[goos+"/"+goarch]
}

// SupportedAssetNames 返回全部支持产物文件名（启动期建立下载映射用）。
func SupportedAssetNames() []string {
	names := make([]string, 0, len(assetNames))
	for _, assetName := range assetNames {
		names = append(names, assetName)
	}
	return names
}

// RenderInstallScript 用服务端地址与采集器发布签名公钥渲染一键安装脚本；
// 地址需形如 http(s)://host[:port]，否则报错（路由层返回 400）。
// signPub 为 nil 时渲染「签名校验已禁用」降级分支（服务端未配置 A3_AGENT_SIGNING_KEY）。
func RenderInstallScript(serverBaseURL string, signPub ed25519.PublicKey) (string, error) {
	parsedURL, parseErr := url.Parse(serverBaseURL)
	if parseErr != nil || serverBaseURL == "" ||
		(parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return "", fmt.Errorf("服务端地址不合法: %q（需形如 http://host:port 或 https://host:port）", serverBaseURL)
	}

	templateData := map[string]any{
		"ServerURL":   shellQuote(serverBaseURL),
		"SignEnabled": signPub != nil,
	}
	if signPub != nil {
		// 内嵌 DER-base64 与指纹，sh 端 printf+fold 重建 PEM（规避 macOS base64 -D 与 GNU -d 差异）
		pubDER, derErr := x509.MarshalPKIXPublicKey(signPub)
		if derErr != nil {
			return "", derErr
		}
		pubSHA := sha256.Sum256(signPub)
		templateData["SignPubB64"] = base64.StdEncoding.EncodeToString(pubDER)
		templateData["SignFingerprint"] = hex.EncodeToString(pubSHA[:])
	}

	shellTemplate, templateErr := template.New("install.sh").Parse(templateFSText())
	if templateErr != nil {
		return "", templateErr
	}
	var scriptBuilder strings.Builder
	if executeErr := shellTemplate.Execute(&scriptBuilder, templateData); executeErr != nil {
		return "", executeErr
	}
	return scriptBuilder.String(), nil
}

// shellQuote 单引号包裹并翻倍内部单引号，供把配置/推导值安全嵌入 shell 脚本赋值——
// 防 SERVER_URL 等来自管理员的字符串经反引号/$()/" 等形态造成命令注入。
func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

func templateFSText() string {
	rawBytes, readErr := templateFS.ReadFile("install.sh.tmpl")
	if readErr != nil {
		// embed 文件编译期已保证存在
		panic(readErr)
	}
	return string(rawBytes)
}
