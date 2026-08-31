<template>
  <el-card shadow="never">
    <el-form inline class="filter-bar">
      <el-form-item>
        <el-button type="primary" :icon="'Plus'" @click="openCreateDialog">新建账号</el-button>
      </el-form-item>
    </el-form>

    <el-table :data="userRows" v-loading="loading">
      <el-table-column prop="username" label="用户名" min-width="140" show-overflow-tooltip />
      <el-table-column label="角色" width="110" align="center">
        <template #default="{ row }">
          <el-tag :type="row.role === 'admin' ? 'danger' : 'info'" size="small" effect="plain">
            {{ row.role === 'admin' ? '管理员' : '审计员' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="90" align="center">
        <template #default="{ row }">
          <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
            {{ row.enabled ? '启用' : '停用' }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="创建时间" width="170">
        <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="操作" width="260" align="center">
        <template #default="{ row }">
          <el-popconfirm
            v-if="row.enabled"
            title="停用后该账号无法重新登录（已签发 token 过期前仍有效）。"
            confirm-button-text="停用"
            cancel-button-text="取消"
            :disabled="isSelf(row)"
            @confirm="toggleEnabled(row, false)"
          >
            <template #reference>
              <el-button link type="danger" size="small" :disabled="isSelf(row)">停用</el-button>
            </template>
          </el-popconfirm>
          <el-button v-else link type="success" size="small" @click="toggleEnabled(row, true)">启用</el-button>
          <el-popconfirm
            v-if="row.role === 'auditor'"
            title="确认将该账号提升为管理员？"
            confirm-button-text="提升"
            cancel-button-text="取消"
            @confirm="changeRole(row, 'admin')"
          >
            <template #reference>
              <el-button link type="warning" size="small">升为管理员</el-button>
            </template>
          </el-popconfirm>
          <el-popconfirm
            v-else-if="!isSelf(row)"
            title="降级后该账号将失去管理权限。"
            confirm-button-text="降级"
            cancel-button-text="取消"
            @confirm="changeRole(row, 'auditor')"
          >
            <template #reference>
              <el-button link type="warning" size="small">降为审计员</el-button>
            </template>
          </el-popconfirm>
          <el-button link type="primary" size="small" @click="openResetDialog(row)">重置密码</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 新建账号 -->
    <el-dialog v-model="createVisible" title="新建账号" width="460px">
      <el-form :model="createForm" label-width="90px">
        <el-form-item label="用户名" required>
          <el-input v-model="createForm.username" placeholder="2-32 位字母/数字/下划线/点/连字符" />
        </el-form-item>
        <el-form-item label="初始密码" required>
          <el-input v-model="createForm.password" type="password" show-password placeholder="至少 8 位" />
        </el-form-item>
        <el-form-item label="角色" required>
          <el-radio-group v-model="createForm.role">
            <el-radio value="auditor">审计员（只读 + 确认告警）</el-radio>
            <el-radio value="admin">管理员（全权）</el-radio>
          </el-radio-group>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="submitCreate">创建</el-button>
      </template>
    </el-dialog>

    <!-- 重置密码 -->
    <el-dialog v-model="resetVisible" :title="`重置密码 · ${resetTarget?.username || ''}`" width="440px">
      <el-form label-width="90px">
        <el-form-item label="新密码" required>
          <el-input v-model="resetPassword" type="password" show-password placeholder="至少 8 位" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="resetVisible = false">取消</el-button>
        <el-button type="primary" :loading="submitting" @click="submitReset">重置</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup>
import { onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'

import { createUser, fetchUsers, patchUser, resetUserPassword } from '../api/console'
import { formatDateTime } from '../utils/format'
import { useAuthStore } from '../stores/auth'

const authStore = useAuthStore()
const loading = ref(false)
const submitting = ref(false)
const userRows = ref([])

// isSelf 当前登录账号行：禁停用/降级（与后端防自锁 400 对应）
function isSelf(userRow) {
  return userRow.username === authStore.username
}

async function loadUsers() {
  loading.value = true
  try {
    const { data } = await fetchUsers()
    userRows.value = data.items || []
  } finally {
    loading.value = false
  }
}

// —— 新建 ——
const createVisible = ref(false)
const createForm = ref({ username: '', password: '', role: 'auditor' })

function openCreateDialog() {
  createForm.value = { username: '', password: '', role: 'auditor' }
  createVisible.value = true
}

async function submitCreate() {
  const usernameValue = createForm.value.username.trim()
  if (!/^[a-zA-Z0-9_.-]{2,32}$/.test(usernameValue)) {
    ElMessage.warning('用户名需为 2-32 位字母/数字/下划线/点/连字符')
    return
  }
  if (createForm.value.password.length < 8) {
    ElMessage.warning('初始密码至少 8 位')
    return
  }
  submitting.value = true
  try {
    await createUser({ username: usernameValue, password: createForm.value.password, role: createForm.value.role })
    ElMessage.success('账号已创建')
    createVisible.value = false
    loadUsers()
  } finally {
    submitting.value = false
  }
}

// —— 停用/启用、改角色 ——
async function toggleEnabled(userRow, nextEnabled) {
  try {
    await patchUser(userRow.id, { enabled: nextEnabled })
    ElMessage.success(nextEnabled ? '已启用' : '已停用')
  } finally {
    loadUsers()
  }
}

async function changeRole(userRow, nextRole) {
  try {
    await patchUser(userRow.id, { role: nextRole })
    ElMessage.success(nextRole === 'admin' ? '已提升为管理员' : '已降为审计员')
  } finally {
    loadUsers()
  }
}

// —— 重置密码 ——
const resetVisible = ref(false)
const resetTarget = ref(null)
const resetPassword = ref('')

function openResetDialog(userRow) {
  resetTarget.value = userRow
  resetPassword.value = ''
  resetVisible.value = true
}

async function submitReset() {
  if (resetPassword.value.length < 8) {
    ElMessage.warning('新密码至少 8 位')
    return
  }
  submitting.value = true
  try {
    await resetUserPassword(resetTarget.value.id, resetPassword.value)
    ElMessage.success('密码已重置')
    resetVisible.value = false
  } finally {
    submitting.value = false
  }
}

onMounted(loadUsers)
</script>

<style scoped>
.filter-bar {
  margin-bottom: 4px;
}
</style>
