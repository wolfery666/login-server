<script lang="ts">
  import { defineComponent } from 'vue'
  import { apiFetch } from '@/api'

  export default defineComponent({
    data() { return { oldPassword: '', newPassword: '' } },
    methods: {
      async changePass() {
        const res = await apiFetch('/change_password', {
          method: 'POST',
          body: { password: this.oldPassword, new_password: this.newPassword }
        })
        if (res.ok) this.$router.push('/')
      }
    }
  })
</script>
<template>
  <div class="form">
    <h2>Change Password</h2>
    <form @submit.prevent="changePass">
      <input v-model="oldPassword" type="password" placeholder="Old Password" required />
      <input v-model="newPassword" type="password" placeholder="New Password" required />
      <button type="submit">Change</button>
    </form>
  </div>
</template>