package api

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/api/installer"
)

// 采集器一键安装托管路由的处理器：install.sh 动态注入 / 产物白名单下载 / setup-info。
// 三条路由均公开（先例 register）：用户没有控制台账号，指南页与安装命令必须免登录可用。

// HandleInstallScript 渲染一键安装脚本（内嵌采集器发布签名公钥）；
// 服务端地址推导顺序：PublicURL 配置（反代场景，配置即权威）→ X-Forwarded-Proto + request.Host。
func (api *Router) HandleInstallScript(routerCtx *gin.Context) {
	serverBaseURL, resolveErr := api.resolvePublicBaseURL(routerCtx)
	if resolveErr != nil {
		routerCtx.String(http.StatusBadRequest, "%v\n", resolveErr)
		return
	}
	scriptText, renderErr := installer.RenderInstallScript(serverBaseURL, api.signPub)
	if renderErr != nil {
		routerCtx.String(http.StatusInternalServerError, "渲染安装脚本失败: %v\n", renderErr)
		return
	}
	routerCtx.Header("Content-Type", "text/x-shellscript; charset=utf-8")
	routerCtx.String(http.StatusOK, scriptText)
}

// HandleAgentDownload 按白名单映射提供采集器产物下载；
// 未知产物名/未配置产物目录/文件缺失一律 404，绝不拼接用户输入路径。
// 请求名以 .sig 结尾时返回该产物当前代际的 ed25519 签名；产物在签名后被改动
// （未重新发布）返回 409 并留痕——客户端验签拿旧签名对不上新字节即硬失败。
func (api *Router) HandleAgentDownload(routerCtx *gin.Context) {
	assetName := routerCtx.Param("assetName")
	requestSig := strings.HasSuffix(assetName, ".sig")
	baseName := assetName
	if requestSig {
		baseName = strings.TrimSuffix(assetName, ".sig")
	}
	diskPath, knownAsset := api.agentAssetPaths[baseName]
	if !knownAsset {
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "未知产物"})
		return
	}
	if api.agentDist == "" {
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "服务端未配置产物目录（A3_AGENT_DIST）"})
		return
	}
	if _, statErr := os.Stat(diskPath); statErr != nil {
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "产物文件不存在"})
		return
	}
	if !requestSig {
		routerCtx.File(diskPath)
		return
	}

	// .sig 分支：需已配置签名密钥，且内容须与该代际签名一致
	if api.signatures == nil {
		routerCtx.JSON(http.StatusNotFound, gin.H{"error": "服务端未配置签名密钥（A3_AGENT_SIGNING_KEY）"})
		return
	}
	sigBytes, drifted, sigErr := api.signatures.sigFor(baseName, diskPath)
	if sigErr != nil {
		routerCtx.JSON(http.StatusInternalServerError, gin.H{"error": "读取产物计算签名失败"})
		return
	}
	if drifted {
		slog.Warn("采集器产物在签名后被修改（未重新发布，视为篡改）",
			"asset", baseName, "path", diskPath)
		routerCtx.JSON(http.StatusConflict, gin.H{"error": "产物已变更但签名未刷新，请重启服务端重新发布"})
		return
	}
	routerCtx.Data(http.StatusOK, "application/octet-stream", sigBytes)
}

// HandleSetupInfo 指南页信息：产物就绪状态、公开地址与发布签名指纹（无敏感数据）。
func (api *Router) HandleSetupInfo(routerCtx *gin.Context) {
	routerCtx.JSON(http.StatusOK, gin.H{
		"agent_dist_ready":            api.agentDist != "",
		"public_url":                  api.publicURL,
		"agent_signing_enabled":       api.signatures != nil,
		"agent_signing_fingerprint":   api.signFingerprint,
	})
}

// resolvePublicBaseURL 服务端对外地址推导；供 install.sh 注入使用。
func (api *Router) resolvePublicBaseURL(routerCtx *gin.Context) (string, error) {
	if api.publicURL != "" {
		return api.publicURL, nil
	}
	requestScheme := "http"
	if forwardedProto := routerCtx.GetHeader("X-Forwarded-Proto"); forwardedProto == "https" {
		requestScheme = "https"
	}
	requestHost := routerCtx.Request.Host
	if requestHost == "" {
		return "", fmt.Errorf("无法确定服务端地址：请求缺少 Host 头")
	}
	return requestScheme + "://" + requestHost, nil
}
