<template>
  <div class="login-page">
    <el-card class="login-card">
      <template #header>
        <div class="login-header">
          <h2>a3 审计台</h2>
          <p>AI 编码行为审计控制台</p>
        </div>
      </template>

      <el-form ref="formRef" :model="loginForm" :rules="loginRules" label-position="top" @submit.prevent>
        <el-form-item label="用户名" prop="username">
          <el-input v-model="loginForm.username" placeholder="请输入用户名" :prefix-icon="'User'" size="large" />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input
            v-model="loginForm.password"
            type="password"
            placeholder="请输入密码"
            :prefix-icon="'Lock'"
            size="large"
            show-password
            @keyup.enter="submitLogin"
          />
        </el-form-item>
        <el-button type="primary" size="large" class="login-button" :loading="submitting" @click="submitLogin">
          登 录
        </el-button>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'

import { useAuthStore } from '../stores/auth'

const route = useRoute()
const router = useRouter()
const authStore = useAuthStore()

const formRef = ref(null)
const submitting = ref(false)
const loginForm = reactive({ username: '', password: '' })
const loginRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}

async function submitLogin() {
  const valid = await formRef.value.validate().catch(() => false)
  if (!valid) return

  submitting.value = true
  try {
    await authStore.login({ username: loginForm.username, password: loginForm.password })
    router.replace(typeof route.query.redirect === 'string' ? route.query.redirect : '/overview')
  } catch (loginError) {
    // 登录页路径下全局拦截器不弹错，由本页面负责展示服务端错误
    const detail = loginError.response?.data?.error || loginError.message || '登录失败'
    ElMessage.error(detail)
  } finally {
    submitting.value = false
  }
}
</script>

<style scoped>
.login-page {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100vh;
  background: linear-gradient(135deg, #1d2935 0%, #2b3a4b 60%, #33526b 100%);
}

.login-card {
  width: 380px;
}

.login-header {
  text-align: center;
}

.login-header h2 {
  margin: 0 0 4px;
}

.login-header p {
  margin: 0;
  font-size: 13px;
  color: #909399;
}

.login-button {
  width: 100%;
}
</style>
