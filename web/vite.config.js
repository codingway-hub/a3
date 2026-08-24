import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// 开发期把 /api 转发到本地服务端；生产环境由服务端直接托管 dist 静态资源。
// 此处仅为开发服务器的路由转发配置，与任何网络代理无关。
export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:8080', changeOrigin: true },
    },
  },
})
