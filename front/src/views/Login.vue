<script lang="ts">
  import { defineComponent } from 'vue'
  import { apiFetch } from '@/api'

  export default defineComponent({
    data() { return { login: '', password: '' } },
    methods: {
      async auth() {
        const res = await apiFetch('/login', {
          method: 'POST',
          body: { email: this.login, password: this.password }
          })
        if (res.ok) this.$router.push('/')
        else alert('Login failed')
      }
    }
  })
</script>
<template>
  <div class="form">
    <h2>Login</h2>
    <form @submit.prevent="auth">
      <input v-model="login" type="text" placeholder="Login" required />
      <input v-model="password" type="password" placeholder="Password" required />
      <button type="submit">Login</button>
    </form>
    <button @click="$router.push('/signup')">Sign up</button>
  </div>
</template>