<template>
  <el-container class="main-layout">
    <el-aside width="220px" class="layout-aside">
      <div class="brand">a3 审计台</div>
      <el-menu
        router
        class="layout-menu"
        :default-active="route.path"
        background-color="#1d2935"
        text-color="#a7b1c2"
        active-text-color="#ffffff"
      >
        <el-menu-item v-for="menuItem in visibleMenuItems" :key="menuItem.path" :index="menuItem.path">
          <el-icon><component :is="menuItem.icon" /></el-icon>
          <span>{{ menuItem.label }}</span>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header class="layout-header">
        <div />
        <el-dropdown @command="handleCommand">
          <span class="user-chip">
            <el-icon><UserFilled /></el-icon>
            {{ authStore.username || '管理员' }}
            <el-tag size="small" :type="authStore.isAdmin ? 'danger' : 'info'" effect="plain" class="role-tag">
              {{ authStore.isAdmin ? '管理员' : '审计员' }}
            </el-tag>
            <el-icon><ArrowDown /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="logout">
                <el-icon><SwitchButton /></el-icon>
                退出登录
              </el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </el-header>

      <el-main class="layout-main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { Bell, Connection, Key, Lock, Monitor, Odometer, Tickets, User, UserFilled } from '@element-plus/icons-vue'

import { useAuthStore } from '../stores/auth'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

// 菜单按角色裁剪：auditor 只见只读 + 告警确认入口
const menuItems = [
  { path: '/overview', label: '概览', icon: Odometer, roles: null },
  { path: '/sessions', label: '会话审计', icon: Tickets, roles: null },
  { path: '/alerts', label: '告警中心', icon: Bell, roles: null },
  { path: '/devices', label: '设备管理', icon: Monitor, roles: ['admin'] },
  { path: '/rules', label: '规则管理', icon: Lock, roles: ['admin'] },
  { path: '/users', label: '用户管理', icon: User, roles: ['admin'] },
  { path: '/credentials', label: '安装凭据', icon: Key, roles: ['admin'] },
  { path: '/setup-guide', label: '接入指南', icon: Connection, roles: null },
]

const visibleMenuItems = computed(() =>
  menuItems.filter((menuItem) => !menuItem.roles || menuItem.roles.includes(authStore.role)),
)

function handleCommand(command) {
  if (command === 'logout') {
    authStore.logout()
    router.replace('/login')
  }
}
</script>

<style scoped>
.main-layout {
  height: 100vh;
}

.layout-aside {
  background-color: #1d2935;
}

.brand {
  height: 60px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #fff;
  font-size: 18px;
  font-weight: 600;
  letter-spacing: 2px;
}

.layout-menu {
  border-right: none;
}

.layout-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  border-bottom: 1px solid #e6e8eb;
  background: #fff;
}

.user-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  cursor: pointer;
  outline: none;
}

.role-tag {
  margin-left: 2px;
}

.layout-main {
  background: #f5f7fa;
}
</style>
