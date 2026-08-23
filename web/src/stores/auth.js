import { ref } from 'vue'
import { defineStore } from 'pinia'

import apiClient, { TOKEN_STORAGE_KEY } from '../api/request'

// 用户名仅用于顶栏展示，与 token 同生命周期存储。
const USERNAME_STORAGE_KEY = 'a3_console_username'

export const useAuthStore = defineStore('auth', () => {
  const token = ref(localStorage.getItem(TOKEN_STORAGE_KEY) || '')
  const username = ref(localStorage.getItem(USERNAME_STORAGE_KEY) || '')

  async function login(loginForm) {
    const { data } = await apiClient.post('/auth/login', loginForm)
    token.value = data.token
    username.value = data.username
    localStorage.setItem(TOKEN_STORAGE_KEY, data.token)
    localStorage.setItem(USERNAME_STORAGE_KEY, data.username)
  }

  function logout() {
    token.value = ''
    username.value = ''
    localStorage.removeItem(TOKEN_STORAGE_KEY)
    localStorage.removeItem(USERNAME_STORAGE_KEY)
  }

  return { token, username, login, logout }
})
