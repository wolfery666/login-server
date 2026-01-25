<script lang="ts">
  import { defineComponent } from 'vue'
  import { apiFetch } from '@/api'

  export default defineComponent({
    async mounted() {
      const res = await apiFetch('/logout', { method: 'POST' })
      if (res.ok) this.$router.push('/login')
    }
  })
</script>
<template>
  <h2>Logging out...</h2>
</template>