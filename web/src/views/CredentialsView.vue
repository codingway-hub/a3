<template>
  <el-card shadow="never">
    <el-form inline class="filter-bar">
      <el-form-item>
        <el-button type="primary" :icon="'Plus'" @click="openCreateDialog">生成安装凭据</el-button>
      </el-form-item>
      <el-form-item>
        <el-text type="info" size="small">
          采集器注册必须持有管理员下发的凭据；凭据可限时限次，吊销即时生效。
        </el-text>
      </el-form-item>
    </el-form>

    <el-table :data="credentialRows" v-loading="loading" @expand-change="onExpandChange">
      <el-table-column type="expand">
        <template #default="{ row }">
          <div v-loading="usesLoading[row.id]" class="uses-panel">
            <el-table v-if="(usesMap[row.id] || []).length" :data="usesMap[row.id]" size="small">
              <el-table-column label="结果" width="160">
                <template #default="{ row: useRow }">
                  <el-tag :type="outcomeTagType(useRow.outcome)" size="small" effect="plain">
                    {{ outcomeLabel(useRow.outcome) }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="device_id" label="消费设备" width="200" show-overflow-tooltip>
                <template #default="{ row: useRow }">
                  <span :class="{ 'muted-value': !useRow.device_id }">{{ useRow.device_id || '—' }}</span>
                </template>
              </el-table-column>
              <el-table-column prop="client_ip" label="来源 IP" width="160" />
              <el-table-column label="时间" min-width="170">
                <template #default="{ row: useRow }">{{ formatDateTime(useRow.created_at) }}</template>
              </el-table-column>
            </el-table>
            <el-empty v-else description="暂无使用记录" :image-size="60" />
          </div>
        </template>
      </el-table-column>

      <el-table-column label="凭据" min-width="200" show-overflow-tooltip>
        <template #default="{ row }">
          <span class="mono-text">{{ row.code_hint }}</span>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="110" align="center">
        <template #default="{ row }">
          <el-tag :type="statusInfo(row).type" size="small">{{ statusInfo(row).label }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="用量" width="100" align="center">
        <template #default="{ row }">{{ row.uses_count }} / {{ row.max_uses }}</template>
      </el-table-column>
      <el-table-column label="有效期至" width="170">
        <template #default="{ row }">{{ formatDateTime(row.expires_at) }}</template>
      </el-table-column>
      <el-table-column prop="created_by" label="创建人" width="140" show-overflow-tooltip />
      <el-table-column label="创建时间" width="170">
        <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="90" align="center">
        <template #default="{ row }">
          <el-popconfirm
            v-if="row.enabled"
            title="吊销后新注册立即被拒（历史使用记录保留）。确认吊销？"
            confirm-button-text="吊销"
            cancel-button-text="取消"
            @confirm="revokeCredential(row)"
          >
            <template #reference>
              <el-button link type="danger" size="small">吊销</el-button>
            </template>
          </el-popconfirm>
          <el-text v-else type="info" size="small">已吊销</el-text>
        </template>
      </el-table-column>
    </el-table>

    <!-- 生成凭据 -->
    <el-dialog v-model="createVisible" title="生成安装凭据" width="480px">
      <el-alert
        type="warning"
        :closable="false"
        show-icon
        title="凭据明文只在生成这一刻返回"
        description="请立即复制并私下发给待接入用户；本页与数据库均不保存明文。"
        class="create-warning"
      />
      <el-form :model="createForm" label-width="110px" class="create-form">
        <el-form-item label="有效期" required>
          <el-input-number v-model="createForm.expiresInMinutes" :min="1" :max="525600" :step="60" />
          <span class="unit-text">分钟（{{ ttlDays }} 天）</span>
        </el-form-item>
        <el-form-item label="最大使用次数" required>
          <el-input-number v-model="createForm.maxUses" :min="1" :max="10000" :step="1" />
        </el-form-item>
        <el-form-item label="作用域">
          <el-select v-model="createForm.scope" class="scope-select">
            <el-option label="device（设备登记）" value="device" />
          </el-select>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="submitCreate">生成</el-button>
      </template>
    </el-dialog>

    <!-- 生成结果：明文仅此一次 -->
    <el-dialog v-model="resultVisible" title="凭据已生成" width="520px" :close-on-click-modal="false">
      <el-alert
        type="danger"
        :closable="false"
        show-icon
        title="这是明文凭据最后一次完整显示，关闭后无法找回"
        description="若不慎关闭，请吊销本条并重新生成。"
        class="create-warning"
      />
      <div class="code-reveal">
        <code class="reveal-text">{{ createdCode }}</code>
        <el-button type="primary" size="small" @click="copyCreatedCode">
          {{ copySucceeded ? '已复制' : '复制' }}
        </el-button>
      </div>
      <template #footer>
        <el-button @click="closeResult">我已抄送，关闭</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup>
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'

import {
  createInstallCredential,
  fetchCredentialUses,
  fetchInstallCredentials,
  revokeInstallCredential,
} from '../api/console'
import { formatDateTime } from '../utils/format'

const loading = ref(false)
const submitting = ref(false)
const credentialRows = ref([])
const usesMap = ref({})
const usesLoading = ref({})

// 凭据状态：吊销 > 过期 > 有效
function statusInfo(credentialRow) {
  if (!credentialRow.enabled) {
    return { label: '已吊销', type: 'info' }
  }
  if (new Date(credentialRow.expires_at).getTime() < Date.now()) {
    return { label: '已过期', type: 'warning' }
  }
  return { label: '有效', type: 'success' }
}

const OUTCOME_META = {
  success: { label: '消费成功', type: 'success' },
  rejected_expired: { label: '拒绝·已过期', type: 'warning' },
  rejected_disabled: { label: '拒绝·已吊销', type: 'info' },
  rejected_used: { label: '拒绝·次数用尽', type: 'warning' },
  rejected_invalid: { label: '拒绝·无此凭据', type: 'danger' },
  rate_limited: { label: '拒绝·限流', type: 'warning' },
}

function outcomeLabel(outcome) {
  return OUTCOME_META[outcome]?.label || outcome
}

function outcomeTagType(outcome) {
  return OUTCOME_META[outcome]?.type || 'info'
}

// —— 列表 ——
async function loadCredentials() {
  loading.value = true
  try {
    const { data } = await fetchInstallCredentials()
    credentialRows.value = data.items || []
  } finally {
    loading.value = false
  }
}

// —— 展开行加载使用记录 ——
function onExpandChange(row, expandedRows) {
  const isExpanded = expandedRows.some((expandedRow) => expandedRow.id === row.id)
  if (isExpanded) {
    loadUses(row.id)
  }
}

async function loadUses(credentialId) {
  usesLoading.value[credentialId] = true
  try {
    const { data } = await fetchCredentialUses(credentialId, { page: 1, page_size: 50 })
    usesMap.value[credentialId] = data.items || []
  } catch {
    usesMap.value[credentialId] = []
    ElMessage.error('加载使用记录失败')
  } finally {
    usesLoading.value[credentialId] = false
  }
}

// —— 生成 ——
const createVisible = ref(false)
const createForm = ref({ expiresInMinutes: 1440, maxUses: 1, scope: 'device' })
const ttlDays = computed(() => Math.round(createForm.value.expiresInMinutes / 1440))

function openCreateDialog() {
  createForm.value = { expiresInMinutes: 1440, maxUses: 1, scope: 'device' }
  createVisible.value = true
}

async function submitCreate() {
  submitting.value = true
  try {
    const { data } = await createInstallCredential({
      expires_in_minutes: createForm.value.expiresInMinutes,
      max_uses: createForm.value.maxUses,
      scope: createForm.value.scope,
    })
    createVisible.value = false
    createdCode.value = data.code
    createdCredential.value = data
    resultVisible.value = true
    loadCredentials()
  } finally {
    submitting.value = false
  }
}

// —— 生成结果展示 ——
const resultVisible = ref(false)
const createdCode = ref('')
const createdCredential = ref(null)
const copySucceeded = ref(false)

async function copyCreatedCode() {
  try {
    await navigator.clipboard.writeText(createdCode.value)
    copySucceeded.value = true
    setTimeout(() => {
      copySucceeded.value = false
    }, 2000)
  } catch {
    ElMessage.error('复制失败，请手动选中复制')
  }
}

function closeResult() {
  resultVisible.value = false
  createdCode.value = ''
}

// —— 吊销 ——
async function revokeCredential(credentialRow) {
  try {
    await revokeInstallCredential(credentialRow.id)
    ElMessage.success('已吊销')
  } finally {
    loadCredentials()
  }
}

onMounted(loadCredentials)
</script>

<style scoped>
.filter-bar {
  margin-bottom: 4px;
}

.mono-text {
  font-family: 'SFMono-Regular', Consolas, monospace;
  font-size: 13px;
}

.muted-value {
  color: #c0c4cc;
}

.uses-panel {
  padding: 4px 24px 12px;
  background: #fafafa;
}

.create-warning {
  margin-bottom: 16px;
}

.create-form {
  margin-top: 8px;
}

.unit-text {
  margin-left: 8px;
  font-size: 12px;
  color: #909399;
}

.scope-select {
  width: 220px;
}

.code-reveal {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 12px 16px;
  background: #1d2935;
  border-radius: 6px;
}

.reveal-text {
  color: #79c0ff;
  font-family: 'SFMono-Regular', Consolas, monospace;
  font-size: 14px;
  word-break: break-all;
}
</style>