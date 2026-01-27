<script lang="ts">
  import { defineComponent } from 'vue'
  import { apiFetch } from '@/api'
  import authState from '@/state/auth'

  export default defineComponent({
    async mounted() {
      const res = await apiFetch('/logout', { method: 'POST' })
      if (res.ok) {
        this.$router.push('/login')
        authState.loggedIn = false
      }
    }
  })
</script>
<template>
  <h2>Logging out...</h2>
</template>