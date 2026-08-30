package api

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/codingway-hub/a3/internal/server/api/installer"
)

// 采集器一键安装托管路由的处理器：install.sh 动态注入 / 产物白名单下载 / setup-info。
// 三条路由均公开（先例 register）：用户没有控制台账号，指南页与安装命令必须免登录可用。

// HandleInstallScript 渲染一键安装脚本；服务端地址推导顺序：PublicURL 配置（反代场景，配置即权威）
// → X-Forwarded-Proto + request.Host。
func (api *Router) HandleInstallScript(routerCtx *gin.Context) {
	serverBaseURL, resolveErr := api.resolvePublicBaseURL(routerCtx)
	if resolveErr != nil {
		routerCtx.String(http.StatusBadRequest, "%v\n", resolveErr)
		return
	}
	scriptText, renderErr := installer.RenderInstallScript(serverBaseURL)
	if renderErr != nil {
		routerCtx.String(http.StatusInternalServerError, "渲染安装脚本失败: %v\n", renderErr)
		return
	}
	routerCtx.Header("Content-Type", "text/x-shellscript; charset=utf-8")
	routerCtx.String(http.StatusOK, scriptText)
}

// HandleAgentDownload 按白名单映射提供采集器产物下载；
// 未知产物名/未配置产物目录/文件缺失一律 404，绝不拼接用户输入路径。
func (api *Router) HandleAgentDownload(routerCtx *gin.Context) {
	assetName := routerCtx.Param("assetName")
	diskPath, knownAsset := api.agentAssetPaths[assetName]
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
	routerCtx.File(diskPath)
}

// HandleSetupInfo 指南页信息：注册开关与产物就绪状态（仅两个布尔 + 公开地址，无敏感数据）。
func (api *Router) HandleSetupInfo(routerCtx *gin.Context) {
	routerCtx.JSON(http.StatusOK, gin.H{
		"allow_auto_register": api.allowAutoRegister,
		"agent_dist_ready":    api.agentDist != "",
		"public_url":          api.publicURL,
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
