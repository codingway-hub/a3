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

// patchDeviceStatus 吊销（revoked）/恢复（active）设备；吊销即时生效（Token 鉴权中断），历史审计数据保留
export function patchDeviceStatus(deviceId, status) {
  return apiClient.patch(`/devices/${encodeURIComponent(deviceId)}`, { status })
}

// fetchRules 规则全集（含停用，不含已软删）
export function fetchRules() {
  return apiClient.get('/rules')
}

// createRule 新建自定义规则；body 形状：{id,name,category,matcher{target,patterns,path_globs},severity,action,enabled}
export function createRule(ruleBody) {
  return apiClient.post('/rules', ruleBody)
}

// updateRule 全量更新自定义规则内容（内置规则随版本维护，仅允许启停）
export function updateRule(ruleId, ruleBody) {
  return apiClient.put(`/rules/${encodeURIComponent(ruleId)}`, ruleBody)
}

// deleteRule 软删自定义规则（审计留痕，内置规则不可删）
export function deleteRule(ruleId) {
  return apiClient.delete(`/rules/${encodeURIComponent(ruleId)}`)
}

// patchRuleEnabled 启停规则——内置与自定义通用的唯一状态变更通道
export function patchRuleEnabled(ruleId, enabled) {
  return apiClient.patch(`/rules/${encodeURIComponent(ruleId)}`, { enabled })
}

// fetchAuditLog 控制台敏感操作留痕（规则 CRUD/启停、设备吊销/恢复）；
// query 支持 target_type/target_id 过滤与 page/page_size 分页
export function fetchAuditLog(query = {}) {
  return apiClient.get('/audit-log', { params: query })
}

// fetchSetupInfo 接入指南页信息（公开端点）：产物就绪状态、公开地址
export function fetchSetupInfo() {
  return apiClient.get('/setup-info')
}

// —— 用户管理（admin-only，服务端 RequireRole 权威） ——

// fetchUsers 账号列表（不含口令哈希）
export function fetchUsers() {
  return apiClient.get('/users')
}

// createUser 新建账号；body：{username,password,role}，重名 409
export function createUser(userBody) {
  return apiClient.post('/users', userBody)
}

// patchUser 停用/启用或改角色；body：{enabled?} 或 {role?}；目标为当前登录账号时服务端 400
export function patchUser(userId, userBody) {
  return apiClient.patch(`/users/${encodeURIComponent(userId)}`, userBody)
}

// resetUserPassword 管理员重置口令；body：{password}
export function resetUserPassword(userId, password) {
  return apiClient.patch(`/users/${encodeURIComponent(userId)}/password`, { password })
}

// —— 安装凭据（admin-only 注册门禁） ——

// fetchInstallCredentials 安装凭据列表（不含明文代码，仅 code_hint 摘要）
export function fetchInstallCredentials() {
  return apiClient.get('/credentials')
}

// createInstallCredential 生成一次性安装凭据；body：{expires_in_minutes,max_uses,scope}
// 响应中的 code 明文仅此一次出现，务必即时抄送给待接入用户
export function createInstallCredential(credentialBody) {
  return apiClient.post('/credentials', credentialBody)
}

// revokeInstallCredential 吊销凭据（即时生效；后续注册消费记 rejected_disabled）
export function revokeInstallCredential(credentialId) {
  return apiClient.post(`/credentials/${encodeURIComponent(credentialId)}/revoke`)
}

// fetchCredentialUses 凭据使用记录：成功/拒绝原因/设备归属/来源 IP
export function fetchCredentialUses(credentialId, query = {}) {
  return apiClient.get(`/credentials/${encodeURIComponent(credentialId)}/uses`, { params: query })
}
