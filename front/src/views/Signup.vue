<script lang="ts">
  import { defineComponent } from 'vue'
  import { apiFetch } from '@/api'

  export default defineComponent({
    data() { return { login: '', password: '' } },
    methods: {
      async signup() {
        const res = await apiFetch('/signup', {
          method: 'POST',
          body: { login: this.login, password: this.password }
          })
        if (res.ok) this.$router.push('/')
        else alert('Signup failed')
      }
    }
  })
</script>
<template>
  <div class="form">
    <h2>Signup</h2>
    <form @submit.prevent="signup">
      <input v-model="login" type="text" placeholder="Login" required />
      <input v-model="password" type="password" placeholder="Password" required />
      <button type="submit">Signup</button>
    </form>
  </div>
</template>