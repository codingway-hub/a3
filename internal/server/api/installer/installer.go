// Package installer 托管采集器一键安装：install.sh 模板渲染与产物文件名白名单。
// 服务端按请求地址动态注入 SERVER_URL，用户照接入指南页复制一条 curl 命令即可完成安装。
package installer

import (
	"embed"
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

// RenderInstallScript 用服务端地址渲染一键安装脚本；
// 地址需形如 http(s)://host[:port]，否则报错（路由层返回 400）。
func RenderInstallScript(serverBaseURL string) (string, error) {
	parsedURL, parseErr := url.Parse(serverBaseURL)
	if parseErr != nil || serverBaseURL == "" ||
		(parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return "", fmt.Errorf("服务端地址不合法: %q（需形如 http://host:port 或 https://host:port）", serverBaseURL)
	}

	shellTemplate, templateErr := template.New("install.sh").Parse(templateFSText())
	if templateErr != nil {
		return "", templateErr
	}
	var scriptBuilder strings.Builder
	if executeErr := shellTemplate.Execute(&scriptBuilder, map[string]string{
		"ServerURL": serverBaseURL,
	}); executeErr != nil {
		return "", executeErr
	}
	return scriptBuilder.String(), nil
}

func templateFSText() string {
	rawBytes, readErr := templateFS.ReadFile("install.sh.tmpl")
	if readErr != nil {
		// embed 文件编译期已保证存在
		panic(readErr)
	}
	return string(rawBytes)
}
