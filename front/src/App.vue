<script setup lang="ts">
  import authState from '@/state/auth'
</script>
<template>
  <v-app>
    <v-app-bar>
      <v-app-bar-title>
        Login server
      </v-app-bar-title>
      <v-spacer />
      <v-btn-group v-if="authState.loggedIn">
        <v-btn to="/" variant="text">Home</v-btn>
        <v-btn to="/logout" variant="text">Logout</v-btn>       
      </v-btn-group>
      <v-btn-group v-else>
        <v-btn to="/login" variant="text">Login</v-btn>
        <v-btn to="/signup" variant="text">Sign up</v-btn>
      </v-btn-group>
    </v-app-bar>
    <v-main>
      <v-container fluid>
        <router-view />
      </v-container>
    </v-main>
  </v-app>
</template>
