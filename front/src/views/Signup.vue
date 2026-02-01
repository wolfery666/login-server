<script setup lang="ts">
  import { computed, ref, watch, type Ref } from 'vue'
  import { useRouter } from 'vue-router'
  import { apiFetch } from '@/api'
  import authState from '@/state/auth'

  const login = ref('')
  const password: Ref<string[]> = ref(Array(2).fill(''))
  const passwordEdit: Ref<boolean[]> = ref(Array(2).fill(false))
  const isFormValid = ref(false)
  const passwordVisible = ref(false)
  const confirmPasswordRef: Ref = ref(null)

  const loginRules = [
    (v: string) => !!v || 'Login is required',
    (v: string) => v.length <= 20 || 'Max 20 characters',
  ]
  const passwordRules = [
    (v: string) => !!v || 'Password is required',
    (v: string) => v.length <= 20 || 'Max 20 characters',
  ]
  const confirmPasswordRules = computed(() => [
    (v: string) => !passwordsMismatch.value || 'Passwords do not match',
  ])

  const passwordsMismatch = computed(() => {
    return password.value[0] !== password.value[1]
  })

  const submitDisabled = computed(() => {
    return isFormValid.value !== true
  })

  watch([password, passwordEdit], () => {
    const silentValidation = passwordEdit.value.some(v=>!v)
    confirmPasswordRef.value?.validate(silentValidation)
  }, {deep: true})

  watch(submitDisabled, () => {
    if (submitDisabled.value) return
    setPasswordEdit()
  })

  const router = useRouter()

  function setPasswordEdit(index: number = -1) {
    if (index === -1) {
      passwordEdit.value.forEach((v,i,arr)=>arr[i]=true)
    } else {
      passwordEdit.value[index] = true
    }
  }

  async function signup() {
    setPasswordEdit()
    if (submitDisabled.value) return
    const res = await apiFetch('/signup', {
      method: 'POST',
      body: { login: login.value, password: password.value[0] }
      })
    if (res.ok) {
      router.push('/')
      authState.loggedIn = true
    }
  }
</script>
<template>
  <v-card class="mx-auto" max-width="300" title="Sign up">
    <v-form v-model="isFormValid" @submit.prevent="signup" autocomplete="off">
      <v-text-field
        v-model="login"
        maxlength="20"
        label="Login"
        :rules="loginRules"
        required>
      </v-text-field>
      <v-text-field
        v-model="password[0]"
        maxlength="20"
        :label="'Password'"
        :rules="passwordRules"
        :type="passwordVisible? 'text' : 'password'"
        :append-inner-icon="passwordVisible? 'mdi-eye-off' : 'mdi-eye'"
        @click:append-inner="passwordVisible = !passwordVisible"
        @blur="setPasswordEdit(0)">
      </v-text-field>
      <v-text-field
        ref="confirmPasswordRef"
        v-model="password[1]"
        maxlength="20"
        :label="'Confirm password'"
        :rules="confirmPasswordRules"
        :type="passwordVisible? 'text' : 'password'"
        @blur="setPasswordEdit(1)"
        validate-on="submit">
      </v-text-field>
      <v-btn type="submit" block :disabled="submitDisabled">Sign up</v-btn>
    </v-form>
  </v-card>
</template>