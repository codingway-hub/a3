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
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'

import { fetchStatsOverview } from '../api/console'

const loading = ref(false)
const stats = reactive({
  today_event_count: 0,
  active_device_count: 0,
  open_alert_count: 0,
  total_sessions: 0,
  risky_sessions: 0,
})

const statCards = computed(() => [
  { label: '今日事件', value: stats.today_event_count, icon: 'DataLine', color: '#409eff' },
  { label: '活跃设备', value: stats.active_device_count, icon: 'Monitor', color: '#67c23a' },
  { label: '开放告警', value: stats.open_alert_count, icon: 'Bell', color: '#e6a23c' },
  { label: '会话总数', value: stats.total_sessions, icon: 'ChatLineSquare', color: '#909399' },
])

onMounted(async () => {
  loading.value = true
  try {
    const { data } = await fetchStatsOverview()
    Object.assign(stats, data)
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.risk-banner {
  margin-bottom: 16px;
}

.stat-card {
  margin-bottom: 16px;
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
