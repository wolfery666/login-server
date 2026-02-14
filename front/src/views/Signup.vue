<script setup lang="ts">
  import { computed, ref, watch, type Ref } from 'vue'
  import { useRouter } from 'vue-router'
  import { apiFetch } from '@/api'
  import authState from '@/state/auth'
  import { LOGIN_MAX_LENGTH, LOGIN_RULES, PASSWORD_MAX_LENGTH, PASSWORD_RULES } from '@/constants'

  const login = ref('')
  const password: Ref<string[]> = ref(Array(2).fill(''))
  const passwordEdit: Ref<boolean[]> = ref(Array(2).fill(false))
  const isFormValid = ref(false)
  const passwordVisible = ref(false)
  const confirmPasswordRef: Ref = ref(null)

  const confirmPasswordRules = computed(() => [
    () => !passwordsMismatch.value || 'Passwords do not match',
  ])

  const passwordsMismatch = computed(() => {
    return password.value[0] !== password.value[1]
  })

  const submitDisabled = computed(() => {
    return isFormValid.value !== true
  })

  const silentValidation = computed(() => {
    return passwordEdit.value.some(v=>!v)
  })

  watch([password, silentValidation], () => {
    confirmPasswordRef.value?.validate(silentValidation.value)
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
        :maxlength="LOGIN_MAX_LENGTH"
        label="Login"
        :rules="LOGIN_RULES">
      </v-text-field>
      <v-text-field
        v-model="password[0]"
        :maxlength="PASSWORD_MAX_LENGTH"
        label="Password"
        :rules="PASSWORD_RULES"
        :type="passwordVisible? 'text' : 'password'"
        :append-inner-icon="passwordVisible? 'mdi-eye-off' : 'mdi-eye'"
        @click:append-inner="passwordVisible = !passwordVisible"
        @blur="setPasswordEdit(0)">
      </v-text-field>
      <v-text-field
        ref="confirmPasswordRef"
        v-model="password[1]"
        :maxlength="PASSWORD_MAX_LENGTH"
        label="Confirm password"
        :rules="confirmPasswordRules"
        :type="passwordVisible? 'text' : 'password'"
        @blur="setPasswordEdit(1)"
        validate-on="submit">
      </v-text-field>
      <v-btn type="submit" block :disabled="submitDisabled">Sign up</v-btn>
    </v-form>
  </v-card>
</template>