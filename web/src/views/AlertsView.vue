<template>
  <el-card shadow="never">
    <!-- 筛选区 -->
    <el-form inline class="filter-bar">
      <el-form-item label="状态">
        <el-select v-model="filters.status" placeholder="全部" clearable style="width: 160px" @change="applyFilters">
          <el-option label="未确认" value="open" />
          <el-option label="已确认" value="acknowledged" />
        </el-select>
      </el-form-item>
      <el-form-item label="等级">
        <el-select v-model="filters.severity" placeholder="全部" clearable style="width: 160px" @change="applyFilters">
          <el-option label="严重" value="critical" />
          <el-option label="高" value="high" />
          <el-option label="中" value="medium" />
          <el-option label="低" value="low" />
        </el-select>
      </el-form-item>
      <el-form-item>
        <el-button :icon="'Download'" @click="downloadCsv">导出 CSV</el-button>
      </el-form-item>
    </el-form>

    <!-- 告警列表 -->
    <el-table :data="alertRows" v-loading="loading">
      <el-table-column prop="created_at" label="时间" width="170">
        <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="等级" width="90" align="center">
        <template #default="{ row }">
          <el-tag :type="severityTagType(row.severity)" size="small">{{ severityLabel(row.severity) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="rule_name" label="规则" width="180" show-overflow-tooltip />
      <el-table-column prop="device_id" label="设备" width="150" show-overflow-tooltip />
      <el-table-column prop="summary" label="摘要" min-width="260" show-overflow-tooltip />
      <el-table-column label="状态" width="100" align="center">
        <template #default="{ row }">
          <el-tag v-if="row.status === 'open'" type="warning" size="small" effect="plain">未确认</el-tag>
          <el-tag v-else type="success" size="small" effect="plain">已确认</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="120" align="center">
        <template #default="{ row }">
          <el-button
            v-if="row.status === 'open'"
            link
            type="primary"
            size="small"
            :loading="acknowledgingId === row.id"
            @click="acknowledge(row)"
          >
            确认
          </el-button>
          <el-button link size="small" @click="goSession(row)">查看会话</el-button>
        </template>
      </el-table-column>
    </el-table>

    <div class="pager-bar">
      <el-pagination
        v-model:current-page="pagination.page"
        v-model:page-size="pagination.pageSize"
        :total="pagination.total"
        :page-sizes="[10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next"
        @current-change="loadAlerts"
        @size-change="onPageSizeChange"
      />
    </div>
  </el-card>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'

import { acknowledgeAlert, exportAlertsToBlob, fetchAlerts } from '../api/console'
import { formatDateTime, severityTagType } from '../utils/format'

const router = useRouter()

const loading = ref(false)
const alertRows = ref([])
const acknowledgingId = ref('')

const filters = reactive({ status: 'open', severity: '' })
const pagination = reactive({ page: 1, pageSize: 20, total: 0 })

function severityLabel(severity) {
  const labels = { critical: '严重', high: '高', medium: '中', low: '低' }
  return labels[severity] || severity || '-'
}

async function loadAlerts() {
  loading.value = true
  try {
    const queryParams = { page: pagination.page, page_size: pagination.pageSize }
    if (filters.status) queryParams.status = filters.status
    if (filters.severity) queryParams.severity = filters.severity

    const { data } = await fetchAlerts(queryParams)
    alertRows.value = data.items
    pagination.total = data.total
  } finally {
    loading.value = false
  }
}

function applyFilters() {
  pagination.page = 1
  loadAlerts()
}

function onPageSizeChange() {
  pagination.page = 1
  loadAlerts()
}

async function acknowledge(alertRow) {
  acknowledgingId.value = alertRow.id
  try {
    await acknowledgeAlert(alertRow.id)
    ElMessage.success('已确认')
    loadAlerts()
  } finally {
    acknowledgingId.value = ''
  }
}

function goSession(alertRow) {
  router.push(`/sessions/${encodeURIComponent(alertRow.device_id)}/${encodeURIComponent(alertRow.session_key)}`)
}

async function downloadCsv() {
  const queryParams = {}
  if (filters.status) queryParams.status = filters.status
  if (filters.severity) queryParams.severity = filters.severity

  const blobBody = (await exportAlertsToBlob(queryParams)).data
  const objectUrl = URL.createObjectURL(new Blob([blobBody], { type: 'text/csv;charset=utf-8' }))
  const downloadLink = document.createElement('a')
  downloadLink.href = objectUrl
  downloadLink.download = 'a3-alerts.csv'
  downloadLink.click()
  URL.revokeObjectURL(objectUrl)
}

onMounted(loadAlerts)
</script>

<style scoped>
.filter-bar {
  margin-bottom: 4px;
}

.pager-bar {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}
</style>
