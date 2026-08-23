import { createRouter, createWebHistory } from 'vue-router'

import { TOKEN_STORAGE_KEY } from '../api/request'

// 路由总表：/login 公开；其余一律经主布局承载并由守卫校验 JWT。
// 业务页面（概览/会话/告警/设备）随 M3-3 起逐个挂入 MainLayout children。
const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('../views/LoginView.vue'),
      meta: { public: true },
    },
    {
      path: '/',
      component: () => import('../layout/MainLayout.vue'),
      redirect: '/overview',
      children: [
        {
          path: 'overview',
          name: 'overview',
          component: () => import('../views/OverviewView.vue'),
          meta: { title: '概览' },
        },
      ],
    },
    {
      path: '/:pathMatch(.*)*',
      component: () => import('../views/Placeholder.vue'),
    },
  ],
})

// 登录守卫：无 token 访问受保护页 → 跳登录并携带回跳地址；已登录访问登录页 → 回首页。
router.beforeEach((to) => {
  const hasToken = Boolean(localStorage.getItem(TOKEN_STORAGE_KEY))
  if (!to.meta.public && !hasToken) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }
  if (to.path === '/login' && hasToken) {
    return { path: '/' }
  }
  return true
})

export default router
