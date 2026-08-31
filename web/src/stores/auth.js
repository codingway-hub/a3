import { computed, ref } from 'vue'
import { defineStore } from 'pinia'

import apiClient, { TOKEN_STORAGE_KEY } from '../api/request'

// 用户名与角色仅用于顶栏展示与菜单裁剪，与 token 同生命周期存储。
const USERNAME_STORAGE_KEY = 'a3_console_username'
const ROLE_STORAGE_KEY = 'a3_console_role'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem(TOKEN_STORAGE_KEY) || '')
  const username = ref(localStorage.getItem(USERNAME_STORAGE_KEY) || '')
  const role = ref(localStorage.getItem(ROLE_STORAGE_KEY) || '')

  // isAdmin 驱动路由守卫与操作按钮裁剪；服务端 RequireRole 才是权威，前端仅省无效请求
  const isAdmin = computed(() => role.value === 'admin')

  async function login(loginForm) {
    const { data } = await apiClient.post('/auth/login', loginForm)
    token.value = data.token
    username.value = data.username
    role.value = data.role || ''
    localStorage.setItem(TOKEN_STORAGE_KEY, data.token)
    localStorage.setItem(USERNAME_STORAGE_KEY, data.username)
    if (data.role) {
      localStorage.setItem(ROLE_STORAGE_KEY, data.role)
    } else {
      localStorage.removeItem(ROLE_STORAGE_KEY)
    }
  }

  function logout() {
    token.value = ''
    username.value = ''
    role.value = ''
    localStorage.removeItem(TOKEN_STORAGE_KEY)
    localStorage.removeItem(USERNAME_STORAGE_KEY)
    localStorage.removeItem(ROLE_STORAGE_KEY)
  }

  return { token, username, role, isAdmin, login, logout }
})
