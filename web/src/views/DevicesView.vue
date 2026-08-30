<template>
  <el-card shadow="never">
    <el-table :data="deviceRows" v-loading="loading">
      <el-table-column label="在线" width="70" align="center">
        <template #default="{ row }">
          <span class="status-dot" :class="row.online ? 'online' : 'offline'" :title="row.online ? '在线' : '离线'" />
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
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'

import { fetchDevices, patchDeviceStatus } from '../api/console'
import { formatDateTime } from '../utils/format'

const loading = ref(false)
const deviceRows = ref([])

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
.status-dot {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 50%;
}

.status-dot.online {
  background: #67c23a;
  box-shadow: 0 0 0 3px rgba(103, 194, 58, 0.2);
}

.status-dot.offline {
  background: #c0c4cc;
}

.plugin-tag {
  margin-right: 4px;
}
</style>
