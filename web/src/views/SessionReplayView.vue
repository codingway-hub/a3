<template>
  <div v-loading="loading">
    <!-- 会话元信息条 -->
    <el-card shadow="never" class="meta-card">
      <div class="meta-bar">
        <div class="meta-info">
          <h3 class="session-title">{{ pageTitle }}</h3>
          <span class="meta-item">设备：{{ deviceId }}</span>
          <span class="meta-item">Agent：{{ agentType }}</span>
          <span class="meta-item">{{ formatDateTime(startedAt) }}</span>
          <el-tag v-if="riskEventCount > 0" type="danger" size="small">{{ riskEventCount }} 个风险点</el-tag>
        </div>
        <el-button :icon="'Download'" @click="downloadExport">导出 JSONL</el-button>
      </div>
    </el-card>

    <!-- 对话时间线 -->
    <div class="timeline">
      <template v-for="node in displayNodes" :key="node.key">
        <!-- 会话开始 / 系统提示：居中灰字 -->
        <div v-if="node.kind === 'session_start' || node.kind === 'system'" class="system-line">
          <span v-if="node.kind === 'session_start'" class="system-text">
            会话开始 · {{ node.extra.cwd }} · v{{ node.extra.version }} · {{ node.extra.git_branch }}
          </span>
          <span v-else class="system-text">{{ node.content }}</span>
        </div>

        <!-- 用户消息：右侧蓝色气泡 -->
        <div v-else-if="node.kind === 'user'" class="chat-row user-row">
          <div class="bubble user-bubble" :class="{ 'risk-bubble': node.riskTags.length > 0 }">
            <risk-tag-row :tags="node.riskTags" />
            <div class="bubble-text">{{ node.content }}</div>
          </div>
          <div class="stamp">{{ formatClock(node.occurredAt) }}</div>
        </div>

        <!-- 助手回复：左侧白底气泡 -->
        <div v-else-if="node.kind === 'assistant'" class="chat-row assistant-row">
          <div class="bubble assistant-bubble" :class="{ 'risk-bubble': node.riskTags.length > 0 }">
            <risk-tag-row :tags="node.riskTags" />
            <div class="bubble-text pre-wrap">{{ node.content }}</div>
          </div>
          <div class="stamp">{{ formatClock(node.occurredAt) }}</div>
        </div>

        <!-- 工具调用卡片（结果附着其下） -->
        <div v-else-if="node.kind === 'tool'" class="chat-row tool-row">
          <div class="tool-card" :class="{ 'risk-card': node.riskTags.length > 0 }">
            <div class="tool-head">
              <el-tag :type="toolTagType(node.toolName)" size="small">{{ node.toolName }}</el-tag>
              <span class="tool-time">{{ formatClock(node.occurredAt) }}</span>
              <el-button link type="primary" size="small" @click="toggleExpand(node.key)">
                {{ expandedKeys.has(node.key) ? '收起参数' : '展开参数' }}
              </el-button>
              <risk-tag-row :tags="node.riskTags" />
            </div>
            <pre v-show="expandedKeys.has(node.key)" class="tool-input">{{ node.inputText }}</pre>
            <div v-show="!expandedKeys.has(node.key)" class="tool-input-preview">{{ firstLine(node.inputText) }}</div>

            <div v-for="(resultItem, resultIndex) in node.results" :key="resultIndex" class="tool-result">
              <el-icon v-if="!resultItem.isError" color="#67c23a"><CircleCheckFilled /></el-icon>
              <el-icon v-else color="#f56c6c"><CircleCloseFilled /></el-icon>
              <span class="result-summary" :class="{ 'result-error': resultItem.isError }">{{ resultItem.summary || '(无输出)' }}</span>
            </div>
          </div>
        </div>

        <!-- 兜底：无法归属的孤立 tool_result -->
        <div v-else class="system-line">
          <span class="system-text">[工具结果] {{ node.summary }}</span>
        </div>
      </template>

      <el-empty v-if="!loading && displayNodes.length === 0" description="会话不存在或无事件" />
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'

import { exportSessionToBlob, fetchSessionEvents } from '../api/console'
import { formatDateTime } from '../utils/format'
import RiskTagRow from '../components/RiskTagRow.vue'

const route = useRoute()
const deviceId = String(route.params.deviceId)
const sessionKey = String(route.params.sessionKey)

const loading = ref(false)
const expandedKeys = reactive(new Set())
const eventItems = ref([])

const pageTitle = computed(() => {
  const firstUserMessage = eventItems.value.find(
    (item) => item.event_type === 'conversation' && item.role === 'user',
  )
  return firstUserMessage?.payload?.content?.slice(0, 40) || sessionKey
})
const agentType = computed(() => eventItems.value[0]?.payload?.agent_type || '-')
const startedAt = computed(() => eventItems.value[0]?.occurred_at || '')
const riskEventCount = computed(
  () => eventItems.value.filter((item) => (item.risk_tags || []).length > 0).length,
)

// ---- 回放节点构建：tool_result 附着到匹配的 tool_call 卡片之下 ----
function buildDisplayNodes(items) {
  const displayNodes = []
  const openToolCards = new Map()

  items.forEach((eventItem, index) => {
    const payload = eventItem.payload || {}
    const riskTags = eventItem.risk_tags || []
    const baseNode = {
      key: eventItem.event_id || `idx-${index}`,
      occurredAt: eventItem.occurred_at,
      riskTags,
    }

    if (eventItem.event_type === 'session_start') {
      let extraFields = {}
      try {
        extraFields = typeof payload.extra === 'object' ? payload.extra : JSON.parse(payload.extra || '{}')
      } catch {
        extraFields = {}
      }
      displayNodes.push({ ...baseNode, kind: 'session_start', extra: extraFields })
      return
    }
    if (eventItem.event_type === 'conversation') {
      if (eventItem.role === 'user') displayNodes.push({ ...baseNode, kind: 'user', content: payload.content })
      else if (eventItem.role === 'assistant')
        displayNodes.push({ ...baseNode, kind: 'assistant', content: payload.content })
      else displayNodes.push({ ...baseNode, kind: 'system', content: payload.content })
      return
    }
    if (eventItem.event_type === 'tool_call') {
      const toolNode = {
        ...baseNode,
        kind: 'tool',
        toolName: payload.tool_name,
        inputText: prettyJSON(payload.tool_input),
        results: [],
      }
      displayNodes.push(toolNode)
      if (payload.tool_call_id) openToolCards.set(payload.tool_call_id, toolNode)
      return
    }
    if (eventItem.event_type === 'tool_result') {
      const matchedCard = openToolCards.get(payload.tool_call_id)
      const resultItem = {
        isError: Boolean(payload.tool_output?.is_error),
        summary: payload.tool_output?.summary || '',
      }
      if (matchedCard) {
        matchedCard.results.push(resultItem)
        openToolCards.delete(payload.tool_call_id) // 一对一附着，避免后续同名结果误挂
      } else {
        displayNodes.push({ ...baseNode, kind: 'orphan_result', summary: resultItem.summary })
      }
      return
    }
    displayNodes.push({ ...baseNode, kind: 'system', content: '[未知事件类型]' })
  })
  return displayNodes
}

const displayNodes = computed(() => buildDisplayNodes(eventItems.value))

// ---- 展示辅助 ----
function prettyJSON(rawInput) {
  if (rawInput == null) return ''
  if (typeof rawInput === 'string') {
    try {
      return JSON.stringify(JSON.parse(rawInput), null, 2)
    } catch {
      return rawInput
    }
  }
  return JSON.stringify(rawInput, null, 2)
}

function firstLine(textValue) {
  const firstLineText = String(textValue || '').split('\n')[0]
  return firstLineText.length > 120 ? `${firstLineText.slice(0, 120)}…` : firstLineText
}

function formatClock(timeValue) {
  return formatDateTime(timeValue).slice(11)
}

function toggleExpand(nodeKey) {
  if (expandedKeys.has(nodeKey)) expandedKeys.delete(nodeKey)
  else expandedKeys.add(nodeKey)
}

function toolTagType(toolName) {
  switch (toolName) {
    case 'Bash':
      return 'warning'
    case 'Write':
    case 'Edit':
      return 'success'
    case 'Read':
      return 'primary'
    default:
      return 'info'
  }
}

async function downloadExport() {
  const blobBody = await exportSessionToBlob(deviceId, sessionKey)
  const objectUrl = URL.createObjectURL(new Blob([blobBody], { type: 'application/x-ndjson' }))
  const downloadLink = document.createElement('a')
  downloadLink.href = objectUrl
  downloadLink.download = `a3-session-${deviceId}-${sessionKey}.jsonl`
  downloadLink.click()
  URL.revokeObjectURL(objectUrl)
}

onMounted(async () => {
  loading.value = true
  try {
    const { data } = await fetchSessionEvents(deviceId, sessionKey)
    eventItems.value = data.items
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.meta-card {
  margin-bottom: 16px;
}

.meta-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.meta-info {
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
}

.session-title {
  margin: 0;
  font-size: 16px;
  max-width: 420px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.meta-item {
  color: #909399;
  font-size: 13px;
}

.timeline {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.system-line {
  text-align: center;
}

.system-text {
  font-size: 12px;
  color: #909399;
  background: #eceef1;
  border-radius: 10px;
  padding: 4px 12px;
}

.chat-row {
  display: flex;
  align-items: flex-start;
  gap: 8px;
}

.user-row {
  justify-content: flex-end;
}

.stamp {
  align-self: flex-end;
  font-size: 11px;
  color: #c0c4cc;
}

.bubble {
  max-width: 68%;
  padding: 10px 14px;
  border-radius: 12px;
  font-size: 14px;
  line-height: 1.6;
}

.user-bubble {
  background: #409eff;
  color: #fff;
  border-top-right-radius: 2px;
}

.assistant-bubble {
  background: #fff;
  border: 1px solid #e6e8eb;
  border-top-left-radius: 2px;
}

.risk-bubble {
  border: 1.5px solid #f56c6c;
}

.bubble-text.pre-wrap {
  white-space: pre-wrap;
  word-break: break-word;
}

.tool-card {
  width: 78%;
  background: #fff;
  border: 1px solid #e6e8eb;
  border-radius: 10px;
  padding: 10px 14px;
}

.risk-card {
  border-color: #f56c6c;
  box-shadow: 0 0 0 1px rgba(245, 108, 108, 0.35);
}

.tool-head {
  display: flex;
  align-items: center;
  gap: 10px;
}

.tool-time {
  font-size: 11px;
  color: #c0c4cc;
}

.tool-input {
  margin: 10px 0 0;
  padding: 10px;
  background: #282c34;
  color: #abb2bf;
  border-radius: 8px;
  font-size: 12px;
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
}

.tool-input-preview {
  margin-top: 8px;
  font-family: ui-monospace, Menlo, Consolas, monospace;
  font-size: 12px;
  color: #606266;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.tool-result {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  margin-top: 8px;
  padding-top: 8px;
  border-top: 1px dashed #ebeef5;
}

.result-summary {
  font-size: 13px;
  color: #606266;
  white-space: pre-wrap;
  word-break: break-word;
}

.result-error {
  color: #f56c6c;
}
</style>
