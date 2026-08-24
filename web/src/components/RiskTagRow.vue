<template>
  <span v-if="tags.length > 0" class="risk-tag-row">
    <el-tooltip
      v-for="(tagItem, tagIndex) in tags"
      :key="tagIndex"
      :content="tooltipText(tagItem)"
      placement="top"
    >
      <el-tag type="danger" size="small" effect="light" class="risk-chip">
        <el-icon><WarningFilled /></el-icon>
        {{ tagItem.name || tagItem.code }}
      </el-tag>
    </el-tooltip>
  </span>
</template>

<script setup>
defineProps({
  tags: { type: Array, default: () => [] },
})

function tooltipText(tagItem) {
  const parts = [tagItem.code, `等级 ${tagItem.severity}`, `动作 ${tagItem.action}`]
  if (tagItem.snippet) parts.push(`命中：${tagItem.snippet}`)
  return parts.join(' · ')
}
</script>

<style scoped>
.risk-tag-row {
  display: inline-flex;
  gap: 6px;
  margin-bottom: 6px;
}

.risk-chip {
  cursor: default;
}
</style>
