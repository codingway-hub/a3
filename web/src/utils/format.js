// 展示格式化工具集。

export function formatDateTime(value) {
  if (!value) return '-'
  const dateValue = new Date(value)
  if (Number.isNaN(dateValue.getTime())) return '-'
  const pad = (number) => String(number).padStart(2, '0')
  return (
    `${dateValue.getFullYear()}-${pad(dateValue.getMonth() + 1)}-${pad(dateValue.getDate())} ` +
    `${pad(dateValue.getHours())}:${pad(dateValue.getMinutes())}:${pad(dateValue.getSeconds())}`
  )
}

// formatDuration 由起止时间计算人类可读时长（如 1h2m3s / 45s）
export function formatDuration(startedAt, endedAt) {
  if (!startedAt || !endedAt) return '-'
  const startMs = new Date(startedAt).getTime()
  const endMs = new Date(endedAt).getTime()
  if (Number.isNaN(startMs) || Number.isNaN(endMs) || endMs < startMs) return '-'
  const totalSeconds = Math.round((endMs - startMs) / 1000)
  if (totalSeconds < 60) return `${totalSeconds}s`
  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60
  if (minutes < 60) return seconds ? `${minutes}m${seconds}s` : `${minutes}m`
  const hours = Math.floor(minutes / 60)
  const restMinutes = minutes % 60
  return restMinutes ? `${hours}h${restMinutes}m` : `${hours}h`
}

// formatBytes 字节数人类可读化（如 8.0 KB / 1.2 MB）
export function formatBytes(value) {
  if (!Number.isFinite(value) || value <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let unitIndex = 0
  let scaled = value
  while (scaled >= 1024 && unitIndex < units.length - 1) {
    scaled /= 1024
    unitIndex++
  }
  const precision = unitIndex === 0 ? 0 : 1
  return `${scaled.toFixed(precision)} ${units[unitIndex]}`
}

// severityTagType 风险等级映射 Element Plus tag 类型色
export function severityTagType(severity) {
  switch (severity) {
    case 'critical':
      return 'danger'
    case 'high':
      return 'danger'
    case 'medium':
      return 'warning'
    case 'low':
      return 'info'
    default:
      return 'info'
  }
}
