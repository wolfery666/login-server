<script lang="ts">
  import { defineComponent } from 'vue'
  import { apiFetch } from '@/api'

  export default defineComponent({
    data() { return { password: '', newPassword: '' } },
    methods: {
      async changePass() {
        const res = await apiFetch('/change_password', {
          method: 'POST',
          body: { password: this.password, new_password: this.newPassword }
        })
        if (res.ok) this.$router.push('/')
      }
    }
  })
</script>
<template>
  <div>
    <v-card class="mx-auto" max-width="300" title="Change Password">
      <v-form @submit.prevent="changePass">
        <v-text-field v-model="password" type="password" placeholder="Old Password" required />
        <v-text-field v-model="newPassword" type="password" placeholder="New Password" required />
        <v-btn type="submit" block>Change</v-btn>
      </v-form>
    </v-card>
  </div>
</template>