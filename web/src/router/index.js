import { createRouter, createWebHistory } from 'vue-router'

import { TOKEN_STORAGE_KEY } from '../api/request'

// 路由总表：/login 公开；其余一律经主布局承载并由守卫校验 JWT。
// meta.roles 为空 = 所有登录角色可用；指定则仅限对应角色（服务端 RequireRole 权威，前端仅省无效请求）。
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
      // 接入指南公开可访问：采集端用户没有控制台账号，管理员直接把链接发给他们
      path: '/setup-guide',
      name: 'setup-guide',
      component: () => import('../views/SetupGuideView.vue'),
      meta: { public: true, title: '接入指南' },
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
        {
          path: 'sessions',
          name: 'sessions',
          component: () => import('../views/SessionListView.vue'),
          meta: { title: '会话审计' },
        },
        {
          path: 'sessions/:deviceId/:sessionKey',
          name: 'session-replay',
          component: () => import('../views/SessionReplayView.vue'),
          meta: { title: '会话回放' },
        },
        {
          path: 'alerts',
          name: 'alerts',
          component: () => import('../views/AlertsView.vue'),
          meta: { title: '告警中心' },
        },
        {
          path: 'devices',
          name: 'devices',
          component: () => import('../views/DevicesView.vue'),
          meta: { title: '设备管理', roles: ['admin'] },
        },
        {
          path: 'rules',
          name: 'rules',
          component: () => import('../views/RulesView.vue'),
          meta: { title: '规则管理', roles: ['admin'] },
        },
        {
          path: 'users',
          name: 'users',
          component: () => import('../views/UsersView.vue'),
          meta: { title: '用户管理', roles: ['admin'] },
        },
        {
          path: 'setup-guide',
          name: 'setup-guide-console',
          component: () => import('../views/SetupGuideView.vue'),
          meta: { title: '接入指南' },
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
// 角色守卫：meta.roles 指定且当前角色不在列 → 弹回概览（auditor 直达 admin URL 场景）。
router.beforeEach((to) => {
  const hasToken = Boolean(localStorage.getItem(TOKEN_STORAGE_KEY))
  if (!to.meta.public && !hasToken) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }
  if (to.path === '/login' && hasToken) {
    return { path: '/' }
  }
  const currentRole = localStorage.getItem('a3_console_role') || ''
  if (to.meta.roles && !to.meta.roles.includes(currentRole)) {
    return { path: '/overview' }
  }
  return true
})

export default router
