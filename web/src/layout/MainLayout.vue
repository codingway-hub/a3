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
        <el-menu-item index="/overview">
          <el-icon><Odometer /></el-icon>
          <span>概览</span>
        </el-menu-item>
        <el-menu-item index="/sessions">
          <el-icon><Tickets /></el-icon>
          <span>会话审计</span>
        </el-menu-item>
        <el-menu-item index="/alerts">
          <el-icon><Bell /></el-icon>
          <span>告警中心</span>
        </el-menu-item>
        <el-menu-item index="/devices">
          <el-icon><Monitor /></el-icon>
          <span>设备管理</span>
        </el-menu-item>
        <el-menu-item index="/rules">
          <el-icon><Lock /></el-icon>
          <span>规则管理</span>
        </el-menu-item>
        <el-menu-item index="/setup-guide">
          <el-icon><Connection /></el-icon>
          <span>接入指南</span>
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
import { useRoute, useRouter } from 'vue-router'

import { useAuthStore } from '../stores/auth'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

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

.layout-main {
  background: #f5f7fa;
}
</style>
