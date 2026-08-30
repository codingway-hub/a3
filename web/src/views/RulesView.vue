<template>
  <el-card shadow="never">
    <!-- 生效语义说明：服务端扫描即时生效；终端阻断依赖 run 进程周期拉取快照 -->
    <el-alert
      type="info"
      :closable="false"
      show-icon
      class="effect-hint"
      title="变更即时约束服务端风险扫描；终端本地阻断的生效延迟 ≤ 刷新周期（默认 5 分钟）+ 下次工具调用。"
    />

    <!-- 筛选区 -->
    <el-form inline class="filter-bar">
      <el-form-item label="类别">
        <el-select v-model="filters.category" placeholder="全部" clearable style="width: 160px">
          <el-option v-for="categoryOption in categoryOptions" :key="categoryOption" :label="categoryOption" :value="categoryOption" />
        </el-select>
      </el-form-item>
      <el-form-item label="状态">
        <el-select v-model="filters.status" placeholder="全部" clearable style="width: 130px">
          <el-option label="已启用" value="enabled" />
          <el-option label="已停用" value="disabled" />
        </el-select>
      </el-form-item>
      <el-form-item label="关键字">
        <el-input
          v-model="filters.keyword"
          placeholder="按 id / 名称搜索"
          clearable
          style="width: 200px"
          @keyup.enter="applyFilters"
        />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :icon="'Plus'" @click="openCreateDialog">新增规则</el-button>
      </el-form-item>
    </el-form>

    <!-- 规则列表 -->
    <el-table :data="filteredRuleRows" v-loading="loading">
      <el-table-column prop="id" label="ID" width="210" show-overflow-tooltip>
        <template #default="{ row }">
          <span>{{ row.id }}</span>
          <el-tag v-if="row.builtin" size="small" type="info" effect="plain" class="builtin-tag">内置</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="name" label="名称" min-width="150" show-overflow-tooltip />
      <el-table-column prop="category" label="类别" width="120" show-overflow-tooltip>
        <template #default="{ row }">{{ row.category || '-' }}</template>
      </el-table-column>
      <el-table-column label="等级" width="80" align="center">
        <template #default="{ row }">
          <el-tag :type="severityTagType(row.severity)" size="small">{{ severityLabel(row.severity) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="动作" width="80" align="center">
        <template #default="{ row }">
          <el-tag :type="row.action === 'block' ? 'danger' : 'warning'" size="small" effect="plain">
            {{ row.action === 'block' ? '拦截' : '告警' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="匹配器" min-width="200">
        <template #default="{ row }">
          <el-tooltip placement="top" :content="matcherDetail(row.matcher)">
            <span class="matcher-summary">{{ matcherSummary(row.matcher) }}</span>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column label="启用" width="90" align="center">
        <template #default="{ row }">
          <el-switch :model-value="row.enabled" @change="(nextValue) => toggleEnabled(row, nextValue)" />
        </template>
      </el-table-column>
      <el-table-column label="更新时间" width="170">
        <template #default="{ row }">{{ formatDateTime(row.updated_at) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="160" align="center">
        <template #default="{ row }">
          <el-button link type="primary" size="small" @click="openHistoryDialog(row)">历史</el-button>
          <template v-if="!row.builtin">
            <el-button link type="primary" size="small" @click="openEditDialog(row)">编辑</el-button>
            <el-button link type="danger" size="small" @click="removeRule(row)">删除</el-button>
          </template>
        </template>
      </el-table-column>
    </el-table>

    <!-- 新增/编辑对话框：matcher 结构化表单（不做 JSON textarea） -->
    <el-dialog v-model="dialogVisible" :title="dialogMode === 'create' ? '新增规则' : '编辑规则'" width="640px">
      <el-form :model="dialogForm" label-width="110px">
        <el-form-item label="规则 ID">
          <el-input
            v-model="dialogForm.id"
            :disabled="dialogMode === 'edit'"
            placeholder="3-64 位小写字母/数字/下划线/点/连字符"
          />
        </el-form-item>
        <el-form-item label="名称" required>
          <el-input v-model="dialogForm.name" placeholder="如：禁止 force push" />
        </el-form-item>
        <el-form-item label="类别">
          <el-input v-model="dialogForm.category" placeholder="如 command.safety / data.exfil，可留空" />
        </el-form-item>
        <el-form-item label="扫描目标">
          <el-radio-group v-model="dialogForm.target">
            <el-radio-button
              v-for="targetOption in targetOptions"
              :key="targetOption.value"
              :value="targetOption.value"
            >
              {{ targetOption.label }}
            </el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="showsPatterns" label="匹配正则">
          <div class="matcher-editor">
            <el-input
              v-model="dialogForm.patternsText"
              type="textarea"
              :rows="5"
              placeholder="每行一条正则表达式，命中任一条即触发"
            />
            <div v-if="patternPrecheckError" class="precheck-error">{{ patternPrecheckError }}</div>
            <div class="field-hint">浏览器预检为 JavaScript 正则（Go RE2 的超集），最终以服务端校验为准。</div>
          </div>
        </el-form-item>
        <el-form-item v-if="showsPathGlobs" label="路径 glob">
          <div class="matcher-editor">
            <el-input
              v-model="dialogForm.pathGlobsText"
              type="textarea"
              :rows="4"
              placeholder="每行一个路径通配，如 ~/.ssh/** 或 **/*.pem"
            />
          </div>
        </el-form-item>
        <el-form-item label="风险等级">
          <el-select v-model="dialogForm.severity" style="width: 160px">
            <el-option label="高" value="high" />
            <el-option label="中" value="medium" />
            <el-option label="低" value="low" />
          </el-select>
        </el-form-item>
        <el-form-item label="处置动作">
          <el-radio-group v-model="dialogForm.action">
            <el-radio value="alert">仅告警</el-radio>
            <el-radio value="block">拦截</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="dialogForm.enabled" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="submitDialog">保存</el-button>
      </template>
    </el-dialog>

    <!-- 变更历史对话框：谁在何时改了什么（规则 CRUD/启停的操作级留痕） -->
    <el-dialog v-model="historyVisible" :title="`变更历史 · ${historyRuleId}`" width="760px">
      <el-table :data="historyRows" v-loading="historyLoading" size="small">
        <el-table-column label="时间" width="170">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="operator" label="操作者" width="120" show-overflow-tooltip />
        <el-table-column label="动作" width="110">
          <template #default="{ row }">
            <el-tag size="small" effect="plain" :type="historyActionTagType(row.action)">
              {{ row.action_label || row.action }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="变更摘要" min-width="260">
          <template #default="{ row }">
            <span class="history-diff">{{ historyDiffSummary(row) }}</span>
          </template>
        </el-table-column>
      </el-table>
      <el-pagination
        v-model:current-page="historyPagination.page"
        v-model:page-size="historyPagination.pageSize"
        :total="historyPagination.total"
        layout="total, prev, pager, next"
        class="history-pagination"
        @current-change="loadHistory"
      />
    </el-dialog>
  </el-card>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'

import { createRule, deleteRule, fetchAuditLog, fetchRules, patchRuleEnabled, updateRule } from '../api/console'
import { formatDateTime, severityTagType } from '../utils/format'

// 与服务端 ruleIDPattern 同源的客户端预检
const ruleIdPattern = /^[a-z0-9_.-]{3,64}$/

const targetOptions = [
  { value: 'command', label: '命令 command' },
  { value: 'content', label: '内容 content' },
  { value: 'path', label: '路径 path' },
  { value: 'any', label: '全部 any' },
]

const loading = ref(false)
const ruleRows = ref([])
const filters = reactive({ category: '', status: '', keyword: '' })

const categoryOptions = computed(() => [
  ...new Set(ruleRows.value.map((ruleRow) => ruleRow.category).filter(Boolean)),
])

const filteredRuleRows = computed(() =>
  ruleRows.value.filter((ruleRow) => {
    if (filters.category && ruleRow.category !== filters.category) return false
    if (filters.status === 'enabled' && !ruleRow.enabled) return false
    if (filters.status === 'disabled' && ruleRow.enabled) return false
    const keywordText = filters.keyword.trim().toLowerCase()
    if (keywordText && !`${ruleRow.id} ${ruleRow.name}`.toLowerCase().includes(keywordText)) return false
    return true
  }),
)

function severityLabel(severity) {
  const labels = { high: '高', medium: '中', low: '低' }
  return labels[severity] || severity || '-'
}

// matcherSummary 表格列的单行摘要；matcherDetail tooltip 展开完整模式
function matcherSummary(matcherShape) {
  const pieces = []
  if (matcherShape?.patterns?.length) pieces.push(`正则 ×${matcherShape.patterns.length}`)
  if (matcherShape?.path_globs?.length) pieces.push(`glob ×${matcherShape.path_globs.length}`)
  return pieces.length ? `[${matcherShape.target}] ${pieces.join(' + ')}` : '-'
}

function matcherDetail(matcherShape) {
  const lines = []
  if (matcherShape?.patterns?.length) lines.push(`正则:\n${matcherShape.patterns.map((patternItem) => `  ${patternItem}`).join('\n')}`)
  if (matcherShape?.path_globs?.length) lines.push(`路径 glob:\n${matcherShape.path_globs.map((globItem) => `  ${globItem}`).join('\n')}`)
  return lines.join('\n') || '（无匹配模式）'
}

async function loadRules() {
  loading.value = true
  try {
    const { data } = await fetchRules()
    ruleRows.value = data.items || []
  } finally {
    loading.value = false
  }
}

// toggleEnabled 启停开关：成功后同步行状态；失败由全局拦截器提示并回滚开关
async function toggleEnabled(ruleRow, nextValue) {
  try {
    await patchRuleEnabled(ruleRow.id, nextValue)
    ruleRow.enabled = nextValue
    ElMessage.success(nextValue ? '已启用' : '已停用')
  } catch {
    // 行状态保持原值即可（model-value 绑定未变更）
  }
}

async function removeRule(ruleRow) {
  const confirmed = await ElMessageBox.confirm(
    `确认删除规则「${ruleRow.id}」？删除后服务端扫描与终端下发均不再包含该规则。`,
    '删除确认',
    { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
  ).then(() => true).catch(() => false)
  if (!confirmed) return
  await deleteRule(ruleRow.id)
  ElMessage.success('已删除')
  loadRules()
}

// —— 新增/编辑对话框 ——
const dialogVisible = ref(false)
const dialogMode = ref('create')
const submitting = ref(false)
const patternPrecheckError = ref('')
const dialogForm = reactive({
  id: '', name: '', category: '',
  target: 'command', patternsText: '', pathGlobsText: '',
  severity: 'medium', action: 'alert', enabled: true,
})

// 条件显示：command/content 走正则，path 走 glob，any 双通道都开放
const showsPatterns = computed(() => ['command', 'content', 'any'].includes(dialogForm.target))
const showsPathGlobs = computed(() => ['path', 'any'].includes(dialogForm.target))

function parseLines(multilineText) {
  return multilineText.split('\n').map((lineText) => lineText.trim()).filter(Boolean)
}

// precheckPatterns 提交前逐行 new RegExp 预检（JS 正则是 Go RE2 超集，最终以服务端 400 为准）
function precheckPatterns() {
  patternPrecheckError.value = ''
  for (const patternItem of parseLines(dialogForm.patternsText)) {
    try {
      new RegExp(patternItem)
    } catch {
      patternPrecheckError.value = `正则不合法：${patternItem}`
      return false
    }
  }
  return true
}

function openCreateDialog() {
  dialogMode.value = 'create'
  Object.assign(dialogForm, {
    id: '', name: '', category: '',
    target: 'command', patternsText: '', pathGlobsText: '',
    severity: 'medium', action: 'alert', enabled: true,
  })
  patternPrecheckError.value = ''
  dialogVisible.value = true
}

function openEditDialog(ruleRow) {
  dialogMode.value = 'edit'
  Object.assign(dialogForm, {
    id: ruleRow.id,
    name: ruleRow.name,
    category: ruleRow.category || '',
    target: ruleRow.matcher?.target || 'command',
    patternsText: (ruleRow.matcher?.patterns || []).join('\n'),
    pathGlobsText: (ruleRow.matcher?.path_globs || []).join('\n'),
    severity: ruleRow.severity || 'medium',
    action: ruleRow.action || 'alert',
    enabled: Boolean(ruleRow.enabled),
  })
  patternPrecheckError.value = ''
  dialogVisible.value = true
}

async function submitDialog() {
  if (dialogMode.value === 'create' && !ruleIdPattern.test(dialogForm.id.trim())) {
    ElMessage.warning('规则 ID 需为 3-64 位小写字母/数字/下划线/点/连字符')
    return
  }
  if (!dialogForm.name.trim()) {
    ElMessage.warning('请填写规则名称')
    return
  }
  const patternItems = showsPatterns.value ? parseLines(dialogForm.patternsText) : []
  const pathGlobItems = showsPathGlobs.value ? parseLines(dialogForm.pathGlobsText) : []
  if (!patternItems.length && !pathGlobItems.length) {
    ElMessage.warning('至少配置一条匹配正则或路径 glob')
    return
  }
  if (!precheckPatterns()) return

  submitting.value = true
  try {
    const ruleBody = {
      id: dialogForm.id.trim(),
      name: dialogForm.name.trim(),
      category: dialogForm.category.trim(),
      matcher: {
        target: dialogForm.target,
        patterns: patternItems,
        path_globs: pathGlobItems,
      },
      severity: dialogForm.severity,
      action: dialogForm.action,
      enabled: dialogForm.enabled,
    }
    if (dialogMode.value === 'create') {
      await createRule(ruleBody)
      ElMessage.success('规则已创建')
    } else {
      await updateRule(dialogForm.id, ruleBody)
      ElMessage.success('规则已更新')
    }
    dialogVisible.value = false
    loadRules()
  } finally {
    submitting.value = false
  }
}

// —— 变更历史对话框 ——
const historyVisible = ref(false)
const historyLoading = ref(false)
const historyRuleId = ref('')
const historyRows = ref([])
const historyPagination = reactive({ page: 1, pageSize: 10, total: 0 })

function historyActionTagType(action) {
  if (action === 'rule_delete') return 'danger'
  if (action === 'rule_create') return 'success'
  return 'info'
}

// historyDiffSummary 摘要：创建给目标形态；启停给结果；更新/删除给关键字段对照
function historyDiffSummary(row) {
  const before = row.before || {}
  const after = row.after || {}
  if (row.action === 'rule_create') {
    return `创建：${after.severity || '-'} / ${after.action === 'block' ? '拦截' : '告警'} / ${after.enabled ? '启用' : '停用'}`
  }
  if (row.action === 'rule_patch') {
    return `启停：${before.enabled ? '启用' : '停用'} → ${after.enabled ? '启用' : '停用'}`
  }
  if (row.action === 'rule_delete') {
    return '删除（软删，ID 不复用）'
  }
  const changedFields = []
  for (const field of ['name', 'severity', 'action', 'enabled']) {
    if (JSON.stringify(before[field]) !== JSON.stringify(after[field])) {
      changedFields.push(field)
    }
  }
  const beforePatterns = before.matcher?.patterns?.length || 0
  const afterPatterns = after.matcher?.patterns?.length || 0
  if (beforePatterns !== afterPatterns) changedFields.push('matcher')
  return changedFields.length ? `修改：${changedFields.join('、')}` : '更新了规则内容'
}

async function loadHistory() {
  historyLoading.value = true
  try {
    const { data } = await fetchAuditLog({
      target_type: 'rule',
      target_id: historyRuleId.value,
      page: historyPagination.page,
      page_size: historyPagination.pageSize,
    })
    historyRows.value = data.items || []
    historyPagination.total = data.total || 0
  } finally {
    historyLoading.value = false
  }
}

function openHistoryDialog(ruleRow) {
  historyRuleId.value = ruleRow.id
  historyPagination.page = 1
  historyVisible.value = true
  loadHistory()
}

onMounted(loadRules)
</script>

<style scoped>
.effect-hint {
  margin-bottom: 12px;
}

.filter-bar {
  margin-bottom: 4px;
}

.builtin-tag {
  margin-left: 6px;
}

.matcher-summary {
  cursor: help;
}

.matcher-editor {
  width: 100%;
}

.field-hint {
  font-size: 12px;
  color: #909399;
  line-height: 1.6;
  margin-top: 2px;
}

.precheck-error {
  font-size: 12px;
  color: #f56c6c;
  line-height: 1.6;
  margin-top: 2px;
}

.history-pagination {
  margin-top: 10px;
  justify-content: flex-end;
}

.history-diff {
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
