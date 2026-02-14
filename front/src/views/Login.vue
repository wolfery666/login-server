<script setup lang="ts">
  import { ref } from 'vue'
  import { useRouter } from 'vue-router'
  import { apiFetch } from '@/api'
  import authState from '@/state/auth'
  import { LOGIN_MAX_LENGTH, PASSWORD_MAX_LENGTH } from '@/constants'

  const login = ref('')
  const password = ref('')

  const router = useRouter()

  async function auth() {
    const res = await apiFetch('/login', {
      method: 'POST',
      body: { login: login.value, password: password.value }
      })
    if (res.ok) {
      router.push('/')
      authState.loggedIn = true
    }    
  }
</script>
<template>
  <v-card class="mx-auto" max-width="300" title="Login">
    <v-form @submit.prevent="auth">
      <v-text-field
        v-model="login"
        :maxlength="LOGIN_MAX_LENGTH"
        label="Login"
        :rules="[(v: string) => !!v || 'Login required']">
      </v-text-field>
      <v-text-field
        v-model="password"
        :maxlength="PASSWORD_MAX_LENGTH"
        label="Password"
        :rules="[(v: string) => !!v || 'Password required']"
        type="password">
      </v-text-field>
      <v-btn type="submit" block>Login</v-btn>
    </v-form>
    <v-card-text class="text-center">
      <router-link class="text-blue text-decoration-none" to="/signup">
          Sign up <v-icon icon="mdi-chevron-right"></v-icon>
      </router-link>
    </v-card-text>
  </v-card>
</template>