<template>
  <div class="setup-guide">
    <el-card>
      <template #header>
        <div class="guide-header">
          <h2>接入指南</h2>
          <p>把本页发给需要接入的同事：他们照页面复制一条命令即可完成采集器安装。</p>
        </div>
      </template>

      <el-alert
        v-if="setupInfo && !setupInfo.agent_dist_ready"
        type="error"
        :closable="false"
        show-icon
        title="服务端尚未配置采集器产物目录（A3_AGENT_DIST），安装命令暂时不可用"
        description="请在服务端部署目录配置 A3_AGENT_DIST 并重启后重试。"
        class="guide-alert"
      />
      <el-alert
        type="info"
        :closable="false"
        show-icon
        title="登记需要管理员下发的安装凭据"
        description="安装前请向管理员索取一条「安装凭据」（在控制台「安装凭据」页生成）。凭据仅经终端输入提交，绝不出现于命令行或日志；执行安装命令后按提示粘贴即可。"
        class="guide-alert"
      />

      <h3>第一步：复制安装命令</h3>
      <div class="command-block">
        <code class="command-text">{{ installCommand }}</code>
        <el-button type="primary" size="small" @click="copyCommand">
          {{ copySucceeded ? '已复制' : '复制' }}
        </el-button>
      </div>

      <h3>第二步：把命令发给采集端用户，在他们的电脑终端执行</h3>
      <p class="guide-note">支持 macOS 与 Linux；脚本会自动识别平台并完成以下事项：</p>
      <ul class="guide-steps">
        <li>下载采集器并安装到 <code>~/.a3/bin/a3-agent</code></li>
        <li>注册设备（凭管理员下发的安装凭据登记；同一台机器重装自动复用原身份，无需再要凭据）</li>
        <li>安装 Claude Code 前置 Hook（高危命令拦截上报）</li>
        <li>安装常驻服务：开机自启、崩溃自动拉起</li>
      </ul>

      <h3>第三步：验证</h3>
      <p class="guide-note">安装完成后在本页「设备管理」中应能看到新设备上线；采集端可用以下命令查看状态：</p>
      <div class="command-block static">
        <code class="command-text">~/.a3/bin/a3-agent service-status</code>
      </div>

      <h3>Windows 用户</h3>
      <p class="guide-note">
        暂不支持脚本自动安装，请从
        <a :href="windowsDownloadUrl" download>这里手动下载</a>
        <code>a3-agent-windows-amd64.exe</code>，重命名为 <code>a3-agent.exe</code> 放入
        <code>%USERPROFILE%\.a3\bin</code>，然后按 Windows 指引注册并运行。
      </p>
    </el-card>
  </div>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'

import { fetchSetupInfo } from '../api/console'

const setupInfo = ref(null)
const copySucceeded = ref(false)

// 命令地址：优先服务端配置的公开地址（反代场景），否则用当前页面来源
const installCommand = computed(() => {
  const baseURL = setupInfo.value?.public_url || window.location.origin
  return `curl ${baseURL}/install.sh | sh`
})

const windowsDownloadUrl = computed(() => {
  const baseURL = setupInfo.value?.public_url || window.location.origin
  return `${baseURL}/download/agent/a3-agent-windows-amd64.exe`
})

async function copyCommand() {
  try {
    await navigator.clipboard.writeText(installCommand.value)
    copySucceeded.value = true
    setTimeout(() => {
      copySucceeded.value = false
    }, 2000)
  } catch {
    ElMessage.error('复制失败，请手动选中命令复制')
  }
}

onMounted(async () => {
  try {
    const response = await fetchSetupInfo()
    setupInfo.value = response.data
  } catch {
    ElMessage.error('加载接入信息失败，请刷新重试')
  }
})
</script>

<style scoped>
.setup-guide {
  max-width: 860px;
}

.guide-header h2 {
  margin: 0 0 4px;
}

.guide-header p {
  margin: 0;
  font-size: 13px;
  color: #909399;
}

.guide-alert {
  margin-bottom: 16px;
}

.command-block {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 16px;
  background: #1d2935;
  border-radius: 6px;
}

.command-block .command-text {
  color: #79c0ff;
  font-family: 'SFMono-Regular', Consolas, monospace;
  font-size: 15px;
  word-break: break-all;
}

.command-block.static {
  background: #f5f7fa;
  border: 1px solid #e6e8eb;
}

.command-block.static .command-text {
  color: #303133;
}

h3 {
  margin: 24px 0 8px;
  font-size: 15px;
}

.guide-note {
  margin: 0 0 8px;
  font-size: 13px;
  color: #606266;
}

.guide-steps {
  margin: 0;
  padding-left: 20px;
  font-size: 13px;
  color: #606266;
  line-height: 2;
}
</style>
