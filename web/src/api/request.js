import axios from 'axios'
import { ElMessage } from 'element-plus'

// 控制台 JWT 的 localStorage 键名；auth store（M3-2）复用同一常量语义。
export const TOKEN_STORAGE_KEY = 'a3_console_token'

// 统一 API 客户端：baseURL 指向服务端 /api/v1，生产环境同源直连，
// 开发环境由 Vite 把 /api 转发到本地服务端。
const apiClient = axios.create({
  baseURL: '/api/v1',
  timeout: 15000,
})

apiClient.interceptors.request.use((requestConfig) => {
  const token = localStorage.getItem(TOKEN_STORAGE_KEY)
  if (token) {
    requestConfig.headers.Authorization = `Bearer ${token}`
  }
  return requestConfig
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // 会话失效：清凭证并回登录页（非登录页时才跳，避免登录失败死循环）
      localStorage.removeItem(TOKEN_STORAGE_KEY)
      if (window.location.pathname !== '/login') {
        window.location.href = '/login'
      }
    } else if (window.location.pathname !== '/login') {
      // 登录页的错误由页面自行展示（如“用户名或密码错误”），全局只兜其余页面
      const detail = error.response?.data?.error || error.message || '网络异常'
      ElMessage.error(detail)
    }
    return Promise.reject(error)
  },
)

export default apiClient
