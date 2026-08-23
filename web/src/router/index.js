import { createRouter, createWebHistory } from 'vue-router'

// M3-1 阶段仅含占位路由；登录守卫与业务路由随 M3-2 起逐步就位。
const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', name: 'placeholder', component: () => import('../views/Placeholder.vue') },
  ],
})

export default router
