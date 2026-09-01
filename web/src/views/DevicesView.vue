<template>
  <el-card shadow="never">
    <template #header>
      <div class="card-header">
        <span>设备清单</span>
        <el-button :icon="Refresh" circle plain size="small" title="刷新" @click="loadDevices" />
      </div>
    </template>

    <el-table :data="deviceRows" v-loading="loading">
      <el-table-column label="健康" width="210">
        <template #default="{ row }">
          <div class="health-cell">
            <span class="status-dot" :class="healthMeta(row).dotClass" :title="healthMeta(row).title" />
            <span class="health-label" :class="{ 'health-label-offline': row.health === 'offline' }">
              {{ healthMeta(row).label }}
            </span>
            <el-tag v-if="row.health === 'abnormal'" type="warning" size="small" effect="plain" class="backlog-tag"
              :title="`断网缓存 ${formatBytes(row.spool_pending_bytes)} 未送达服务端`">
              积压 {{ row.spool_pending_batches }} 批 · {{ formatBytes(row.spool_pending_bytes) }}
            </el-tag>
          </div>
        </template>
      </el-table-column>
      <el-table-column prop="hostname" label="主机名" min-width="160" show-overflow-tooltip />
      <el-table-column label="系统" width="150">
        <template #default="{ row }">{{ row.os }} / {{ row.arch }}</template>
      </el-table-column>
      <el-table-column prop="agent_version" label="Agent 版本" width="110" align="center" />
      <el-table-column label="插件" width="140">
        <template #default="{ row }">
          <el-tag v-for="pluginName in pluginNames(row.plugins)" :key="pluginName" size="small" class="plugin-tag">
            {{ pluginName }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="device_id" label="设备 ID" width="170" show-overflow-tooltip />
      <el-table-column label="状态" width="90" align="center">
        <template #default="{ row }">
          <el-tag :type="row.status === 'active' ? 'success' : 'danger'" size="small">
            {{ row.status === 'active' ? '正常' : '已吊销' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="最后心跳" width="170">
        <template #default="{ row }">{{ formatDateTime(row.last_seen_at) }}</template>
      </el-table-column>
      <el-table-column label="接入时间" width="170">
        <template #default="{ row }">{{ formatDateTime(row.first_seen_at) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="110" align="center">
        <template #default="{ row }">
          <template v-if="authStore.isAdmin">
            <el-button
              v-if="row.status === 'active'"
              type="danger"
              link
              @click="confirmRevoke(row)"
            >
              吊销
            </el-button>
            <el-button v-else type="primary" link @click="restoreDevice(row)">恢复</el-button>
          </template>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'

import { fetchDevices, patchDeviceStatus } from '../api/console'
import { formatBytes, formatDateTime } from '../utils/format'
import { useAuthStore } from '../stores/auth'

const authStore = useAuthStore()

const loading = ref(false)
const deviceRows = ref([])

// 健康三态：在线 / 数据滞留(abnormal，在线但缓存未送达) / 离线。
// 离线判定「最后心跳超在线窗口」；abnormal 由服务端依据心跳携带的 spool 积压判定。
const HEALTH_META = {
  online: { label: '在线', dotClass: 'health-online', title: '在线：最近心跳在窗口内，无积压' },
  abnormal: { label: '数据滞留', dotClass: 'health-abnormal', title: '数据滞留：在线但断网缓存尚未送达' },
  offline: { label: '离线', dotClass: 'health-offline', title: '离线：最后心跳超出在线窗口' },
}

function healthMeta(row) {
  return HEALTH_META[row.health] || HEALTH_META.offline
}

function pluginNames(pluginsValue) {
  if (Array.isArray(pluginsValue)) return pluginsValue
  return []
}

async function loadDevices() {
  loading.value = true
  try {
    const { data } = await fetchDevices()
    deviceRows.value = data.items || []
  } finally {
    loading.value = false
  }
}

async function confirmRevoke(row) {
  try {
    await ElMessageBox.confirm(
      `吊销后 ${row.hostname}（${row.device_id}）的 Token 将立即失效，无法再上报；历史审计数据原样保留。设备主可通过重新注册恢复上号。`,
      '吊销设备',
      { confirmButtonText: '吊销', cancelButtonText: '取消', type: 'warning' },
    )
  } catch {
    return // 用户取消
  }
  try {
    await patchDeviceStatus(row.device_id, 'revoked')
    ElMessage.success('已吊销')
    await loadDevices()
  } catch {
    ElMessage.error('吊销失败，请重试')
  }
}

async function restoreDevice(row) {
  try {
    await patchDeviceStatus(row.device_id, 'active')
    ElMessage.success('已恢复')
    await loadDevices()
  } catch {
    ElMessage.error('恢复失败，请重试')
  }
}

onMounted(loadDevices)
</script>

<style scoped>
.card-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.health-cell {
  display: flex;
  align-items: center;
  gap: 6px;
}

.health-label {
  color: #606266;
  white-space: nowrap;
}

.health-label-offline {
  color: #c0c4cc;
}

.backlog-tag {
  margin-left: 2px;
  max-width: 160px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.status-dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
  flex: none;
}

.status-dot.health-online {
  background: #67c23a;
  box-shadow: 0 0 0 3px rgba(103, 194, 58, 0.2);
}

.status-dot.health-abnormal {
  background: #e6a23c;
  box-shadow: 0 0 0 3px rgba(230, 162, 60, 0.2);
}

.status-dot.health-offline {
  background: #c0c4cc;
}

.plugin-tag {
  margin-right: 4px;
}
</style>