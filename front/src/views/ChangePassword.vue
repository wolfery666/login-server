<script setup lang="ts">
  import { computed, ref, watch, type Ref } from 'vue'
  import { useRouter } from 'vue-router'
  import { apiFetch } from '@/api'
  import { PASSWORD_MAX_LENGTH, PASSWORD_RULES } from '@/constants'

  const password = ref('')
  const newPassword = ref(Array(2).fill(''))
  const newPasswordEdit = ref(Array(2).fill(false))
  const isFormValid = ref(false)
  const passwordVisible = ref(false)
  const confirmPasswordRef: Ref = ref(null)

  const passwordRequired = [
    (v: string) => !!v || 'Password required'
  ]

  const confirmPasswordRules = computed(() => [
    () => !passwordsMismatch.value || 'New passwords do not match',
  ])

  const passwordsMismatch = computed(() => {
    return newPassword.value[0] !== newPassword.value[1]
  })

  const submitDisabled = computed(() => {
    return isFormValid.value !== true
  })

  const silentValidation = computed(() => {
    return newPasswordEdit.value.some(v=>!v)
  })

  watch([newPassword, silentValidation], () => {
    confirmPasswordRef.value?.validate(silentValidation.value)
  }, {deep: true})

  watch(submitDisabled, () => {
    if (submitDisabled.value) return
    setPasswordEdit()
  })

  const router = useRouter()

  function setPasswordEdit(index: number = -1) {
    if (index === -1) {
      newPasswordEdit.value.forEach((v,i,arr)=>arr[i]=true)
    } else {
      newPasswordEdit.value[index] = true
    }
  }

  async function changePass() {  
    if (submitDisabled.value) return
    const res = await apiFetch('/change_password', {
      method: 'POST',
      body: { password: password.value, new_password: newPassword.value[0] }
    })
    if (res.ok) router.push('/')
  }
</script>
<template>
  <v-card class="mx-auto" max-width="300" title="Change Password">
    <v-form v-model="isFormValid" @submit.prevent="changePass">
      <v-text-field
        v-model="password"
        :maxlength="PASSWORD_MAX_LENGTH"
        label="Password"
        :rules="passwordRequired"
        :type="passwordVisible? 'text' : 'password'"
        :append-inner-icon="passwordVisible? 'mdi-eye-off' : 'mdi-eye'"
        @click:append-inner="passwordVisible = !passwordVisible">
      </v-text-field>
      <v-text-field
        v-model="newPassword[0]"
        :maxlength="PASSWORD_MAX_LENGTH"
        label="New password"
        :rules="PASSWORD_RULES"
        :type="passwordVisible? 'text' : 'password'"
        @blur="setPasswordEdit(0)"
        :validate-on="newPasswordEdit[0]? 'input' : 'blur'">
      </v-text-field>
      <v-text-field
        ref="confirmPasswordRef"
        v-model="newPassword[1]"
        :maxlength="PASSWORD_MAX_LENGTH"
        label="Confirm new password"
        :rules="confirmPasswordRules"
        :type="passwordVisible? 'text' : 'password'"
        @blur="setPasswordEdit(1)"
        validate-on="submit">
      </v-text-field>
      <v-btn type="submit" block :disabled="submitDisabled">Change</v-btn>
    </v-form>
  </v-card>
</template>