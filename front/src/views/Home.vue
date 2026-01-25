<script setup lang="ts"></script>
<template>
  <v-app>
    <h2>Home</h2>
    <v-btn @click="$router.push('/change_password')">Change Password</v-btn>
    <v-btn @click="$router.push('/logout')">Logout</v-btn>
  </v-app>
</template>
