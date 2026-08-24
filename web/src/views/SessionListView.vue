<template>
  <el-card shadow="never">
    <!-- 筛选区 -->
    <el-form inline class="filter-bar">
      <el-form-item label="关键词">
        <el-input
          v-model="filters.keyword"
          placeholder="标题 / 会话内容"
          clearable
          style="width: 220px"
          @keyup.enter="applyFilters"
          @clear="applyFilters"
        />
      </el-form-item>
      <el-form-item label="设备">
        <el-select v-model="filters.deviceId" placeholder="全部设备" clearable style="width: 200px" @change="applyFilters">
          <el-option v-for="deviceItem in deviceOptions" :key="deviceItem.device_id" :label="deviceItem.hostname" :value="deviceItem.device_id" />
        </el-select>
      </el-form-item>
      <el-form-item label="时间">
        <el-date-picker
          v-model="filters.dateRange"
          type="datetimerange"
          range-separator="至"
          start-placeholder="开始时间"
          end-placeholder="结束时间"
          value-format="YYYY-MM-DDTHH:mm:ss[Z]"
          style="width: 360px"
          @change="applyFilters"
        />
      </el-form-item>
      <el-form-item label="仅看风险">
        <el-switch v-model="filters.riskOnly" @change="applyFilters" />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :icon="'Search'" @click="applyFilters">查询</el-button>
      </el-form-item>
    </el-form>

    <!-- 列表 -->
    <el-table :data="sessionRows" v-loading="loading" row-key="rowKey" @row-click="goReplay" class="session-table">
      <el-table-column prop="title" label="标题" min-width="240" show-overflow-tooltip />
      <el-table-column prop="hostname" label="设备" width="140" show-overflow-tooltip />
      <el-table-column prop="agent_type" label="Agent" width="120" />
      <el-table-column label="开始时间" width="170">
        <template #default="{ row }">{{ formatDateTime(row.started_at) }}</template>
      </el-table-column>
      <el-table-column label="时长" width="90">
        <template #default="{ row }">{{ formatDuration(row.started_at, row.ended_at) }}</template>
      </el-table-column>
      <el-table-column prop="event_count" label="事件数" width="90" align="right" />
      <el-table-column label="风险数" width="100" align="center">
        <template #default="{ row }">
          <el-badge v-if="row.risk_count > 0" :value="row.risk_count" type="danger" class="risk-badge" />
          <span v-else class="risk-zero">0</span>
        </template>
      </el-table-column>
    </el-table>

    <!-- 分页 -->
    <div class="pager-bar">
      <el-pagination
        v-model:current-page="pagination.page"
        v-model:page-size="pagination.pageSize"
        :total="pagination.total"
        :page-sizes="[10, 20, 50, 100]"
        layout="total, sizes, prev, pager, next"
        @current-change="loadSessions"
        @size-change="onPageSizeChange"
      />
    </div>
  </el-card>
</template>

<script setup>
import { onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'

import { fetchDevices, fetchSessions } from '../api/console'
import { formatDateTime, formatDuration } from '../utils/format'

const route = useRoute()
const router = useRouter()

const loading = ref(false)
const sessionRows = ref([])
const deviceOptions = ref([])

const filters = reactive({
  keyword: '',
  deviceId: '',
  riskOnly: route.query.risk_only === 'true', // 支持概览页“仅看风险”直达
  dateRange: null,
})

const pagination = reactive({ page: 1, pageSize: 20, total: 0 })

async function loadSessions() {
  loading.value = true
  try {
    const queryParams = {
      page: pagination.page,
      page_size: pagination.pageSize,
    }
    if (filters.keyword) queryParams.keyword = filters.keyword
    if (filters.deviceId) queryParams.device_id = filters.deviceId
    if (filters.riskOnly) queryParams.risk_only = 'true'
    if (filters.dateRange?.[0]) queryParams.started_from = filters.dateRange[0]
    if (filters.dateRange?.[1]) queryParams.started_to = filters.dateRange[1]

    const { data } = await fetchSessions(queryParams)
    sessionRows.value = data.items.map((item) => ({ ...item, rowKey: `${item.device_id}/${item.session_key}` }))
    pagination.total = data.total
  } finally {
    loading.value = false
  }
}

function applyFilters() {
  pagination.page = 1
  loadSessions()
}

function onPageSizeChange() {
  pagination.page = 1
  loadSessions()
}

function goReplay(sessionRow) {
  router.push(`/sessions/${encodeURIComponent(sessionRow.device_id)}/${encodeURIComponent(sessionRow.session_key)}`)
}

onMounted(async () => {
  loadSessions()
  const { data } = await fetchDevices()
  deviceOptions.value = data.items
})
</script>

<style scoped>
.filter-bar {
  margin-bottom: 4px;
}

.session-table {
  cursor: pointer;
}

.risk-badge :deep(.el-badge__content) {
  position: static;
  transform: none;
}

.risk-zero {
  color: #c0c4cc;
}

.pager-bar {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}
</style>
