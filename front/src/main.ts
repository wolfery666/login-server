import { createApp } from 'vue'
import router from './router'
import App from './App.vue'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import { aliases, mdi } from 'vuetify/iconsets/mdi'
import 'vuetify/styles'
import 'unfonts.css'
import '@mdi/font/css/materialdesignicons.css'

const icons = {
  defaultSet: 'mdi',
  aliases,
  sets: {
    mdi
  }
}
const vuetify = createVuetify({components, directives, icons})

createApp(App).use(router).use(vuetify).mount('#app')
