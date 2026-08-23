import apiClient from './request'

// 控制台各域 API 的集中封装；字段命名与服务端 JSON 契约（snake_case）一致。

export function fetchStatsOverview() {
  return apiClient.get('/stats/overview')
}

// fetchSessions 查询会话列表；query 支持 keyword/device_id/risk_only/started_from/started_to/page/page_size
export function fetchSessions(query = {}) {
  return apiClient.get('/sessions', { params: query })
}

// fetchSessionEvents 拉取会话回放事件流
export function fetchSessionEvents(deviceId, sessionKey) {
  return apiClient.get(`/sessions/${encodeURIComponent(deviceId)}/${encodeURIComponent(sessionKey)}/events`)
}

// sessionExportUrl 导出接口直链（浏览器下载，需自带 JWT 故走 blob 拉取）
export async function exportSessionToBlob(deviceId, sessionKey) {
  const response = await apiClient.get(
    `/sessions/${encodeURIComponent(deviceId)}/${encodeURIComponent(sessionKey)}/export`,
    { responseType: 'blob' },
  )
  return response.data
}

// fetchAlerts 查询告警列表；query 支持 status/severity/page/page_size
export function fetchAlerts(query = {}) {
  return apiClient.get('/alerts', { params: query })
}

// acknowledgeAlert 确认告警（服务端仅接受 status=acknowledged）
export function acknowledgeAlert(alertId) {
  return apiClient.patch(`/alerts/${encodeURIComponent(alertId)}`, { status: 'acknowledged' })
}

// alertsExportUrl 告警 CSV 导出直链参数拼装（由调用方以 blob 方式请求）
export function exportAlertsToBlob(query = {}) {
  return apiClient.get('/alerts/export', { params: query, responseType: 'blob' })
}

// fetchDevices 设备列表（含 online 在线判定字段）
export function fetchDevices() {
  return apiClient.get('/devices')
}
