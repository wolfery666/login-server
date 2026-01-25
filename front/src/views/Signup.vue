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
  <div>
    <h2>Signup</h2>
    <v-form @submit.prevent="signup">
      <v-text-field v-model="login" type="text" placeholder="Login" required />
      <v-text-field v-model="password" type="password" placeholder="Password" required />
      <v-btn type="submit">Signup</v-btn>
    </v-form>
  </div>
</template>