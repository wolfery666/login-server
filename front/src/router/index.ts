import { createRouter, createWebHistory } from 'vue-router'
import Home from '@/views/Home.vue'
import Login from '@/views/Login.vue'
import Signup from '@/views/Signup.vue'
import Logout from '@/views/Logout.vue'
import ChangePassword from '@/views/ChangePassword.vue'
import { apiFetch } from '@/api'
import authState from '@/state/auth'

const routes = [
  { path: '/', component: Home },
  { path: '/login', component: Login },
  { path: '/signup', component: Signup },
  { path: '/logout', component: Logout },
  { path: '/change_password', component: ChangePassword }
]

const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach(async (to, from) => {
  await apiFetch('/')
  if (!authState.loggedIn && to.path !== '/login' && to.path != 'signup') {
    return { path: '/login' }
  }
})

export default router