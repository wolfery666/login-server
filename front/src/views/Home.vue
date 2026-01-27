<script setup lang="ts"></script>
<template>
  <v-toolbar flat>
    <v-toolbar-title>Home</v-toolbar-title>
    <v-spacer />
    <v-btn @click="$router.push('/change_password')">Change Password</v-btn>
  </v-toolbar>
</template>
