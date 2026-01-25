<script lang="ts">
  import { defineComponent } from 'vue'
  import { apiFetch } from '@/api'

  export default defineComponent({
    data() { return { login: '', password: '' } },
    methods: {
      async auth() {
        const res = await apiFetch('/login', {
          method: 'POST',
          body: { login: this.login, password: this.password }
          })
        if (res.ok) this.$router.push('/')
        else alert('Login failed')
      }
    }
  })
</script>
<template>
  <v-app>
    <v-app-bar title="Login"></v-app-bar>
    <v-main>
      <v-container>
        <v-form @submit.prevent="auth">
          <v-text-field v-model="login" type="text" placeholder="Login" required />
          <v-text-field v-model="password" type="password" placeholder="Password" required />
          <v-btn type="submit">Login</v-btn>
        </v-form>
      </v-container>
    </v-main>
    <v-btn @click="$router.push('/signup')">Sign up</v-btn>
  </v-app>
</template>