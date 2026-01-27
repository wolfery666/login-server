<script lang="ts">
  import { defineComponent } from 'vue'
  import { apiFetch } from '@/api'
  import authState from '@/state/auth'

  export default defineComponent({
    data() { return { login: '', password: '' } },
    methods: {
      async signup() {
        const res = await apiFetch('/signup', {
          method: 'POST',
          body: { login: this.login, password: this.password }
          })
        if (res.ok) {
          this.$router.push('/')
          authState.loggedIn = true
        }
      }
    }
  })
</script>
<template>
  <v-card class="mx-auto" max-width="300" title="Sign up">
    <v-form @submit.prevent="signup">
      <v-text-field v-model="login" label="Login"></v-text-field>
      <v-text-field v-model="password" label="Password" type="password"></v-text-field>
      <v-btn type="submit" block>Sign up</v-btn>
    </v-form>
  </v-card>
</template>