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
  <v-card class="mx-auto" max-width="300" title="Login">
    <v-form @submit.prevent="auth">
      <v-text-field v-model="login" label="Login"></v-text-field>
      <v-text-field v-model="password" label="Password" type="password"></v-text-field>
      <v-btn type="submit" block>Login</v-btn>
    </v-form>
    <v-card-text class="text-center">
      <a class="text-blue text-decoration-none" href="/signup">Sign up <v-icon icon="mdi-chevron-right"></v-icon></a>
    </v-card-text>
  </v-card>
</template>