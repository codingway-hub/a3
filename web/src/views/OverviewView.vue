<template>
  <div v-loading="loading">
    <el-alert
      v-if="stats.risky_sessions > 0"
      type="warning"
      show-icon
      :closable="false"
      class="risk-banner"
    >
      <template #title>
        存在 <b>{{ stats.risky_sessions }}</b> 个含风险行为的会话，
        <router-link to="/sessions?risk_only=true">点击查看</router-link>
      </template>
    </el-alert>

    <el-row :gutter="16">
      <el-col v-for="cardItem in statCards" :key="cardItem.label" :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-body">
            <el-icon :size="36" :color="cardItem.color">
              <component :is="cardItem.icon" />
            </el-icon>
            <div class="stat-text">
              <div class="stat-value">{{ cardItem.value }}</div>
              <div class="stat-label">{{ cardItem.label }}</div>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-descriptions :column="3" border size="small" title="系统状态" class="sys-status">
      <el-descriptions-item label="服务端版本">{{ stats.server_version || '-' }}</el-descriptions-item>
      <el-descriptions-item label="运行时长">{{ formatUptimeSeconds(stats.server_uptime_seconds) }}</el-descriptions-item>
      <el-descriptions-item label="统计时间">{{ formatDateTime(stats.server_time) }}</el-descriptions-item>
    </el-descriptions>
  </div>
</template>

<script setup>
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'

import { fetchStatsOverview } from '../api/console'
import { formatDateTime } from '../utils/format'

// 概览统计自动刷新间隔（活跃设备/今日事件需要保持新鲜）
const REFRESH_INTERVAL_MS = 30 * 1000

const loading = ref(false)
const stats = reactive({
  today_event_count: 0,
  active_device_count: 0,
  open_alert_count: 0,
  total_sessions: 0,
  risky_sessions: 0,
  server_version: '',
  server_uptime_seconds: 0,
  server_time: '',
})

let refreshTimer = null
let refreshInflight = false

const statCards = computed(() => [
  { label: '今日事件', value: stats.today_event_count, icon: 'DataLine', color: '#409eff' },
  { label: '活跃设备', value: stats.active_device_count, icon: 'Monitor', color: '#67c23a' },
  { label: '开放告警', value: stats.open_alert_count, icon: 'Bell', color: '#e6a23c' },
  { label: '会话总数', value: stats.total_sessions, icon: 'ChatLineSquare', color: '#909399' },
])

// loadStats 拉取概览；首载显 loading，后台 tick 静默刷新，失败保留上次数据
//（错误提示由 request.js 拦截器统一给出，不在此叠加）。
async function loadStats({ showLoading = false } = {}) {
  if (refreshInflight) return
  refreshInflight = true
  if (showLoading) loading.value = true
  try {
    const { data } = await fetchStatsOverview()
    Object.assign(stats, data)
  } finally {
    refreshInflight = false
    loading.value = false
  }
}

// formatUptimeSeconds 秒数人类化：x天y小时 / x小时y分 / x分钟y秒 / x秒
function formatUptimeSeconds(totalSeconds) {
  if (typeof totalSeconds !== 'number' || !Number.isFinite(totalSeconds) || totalSeconds < 0) return '-'
  const seconds = Math.floor(totalSeconds)
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  if (days > 0) return `${days}天${hours}小时`
  if (hours > 0) return `${hours}小时${minutes}分`
  if (minutes > 0) return `${minutes}分钟${seconds % 60}秒`
  return `${seconds}秒`
}

onMounted(() => {
  loadStats({ showLoading: true })
  refreshTimer = setInterval(() => loadStats(), REFRESH_INTERVAL_MS)
})

onBeforeUnmount(() => {
  if (refreshTimer) clearInterval(refreshTimer)
})
</script>

<style scoped>
.risk-banner {
  margin-bottom: 16px;
}

.stat-card {
  margin-bottom: 16px;
}

.sys-status {
  margin-top: 4px;
}

.stat-body {
  display: flex;
  align-items: center;
  gap: 16px;
}

.stat-value {
  font-size: 28px;
  font-weight: 600;
  line-height: 1.2;
}

.stat-label {
  font-size: 13px;
  color: #909399;
}
</style>
