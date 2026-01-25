import { createApp } from 'vue'
import router from './router'
import App from './App.vue'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import 'vuetify/styles'

const vuetify = createVuetify({components, directives})

createApp(App).use(router).use(vuetify).mount('#app')
