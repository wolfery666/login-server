<script setup lang="ts"></script>
<template>
  <div>
    <h2>Home</h2>
    <button @click="$router.push('/change_password')">Change Password</button>
    <button @click="$router.push('/logout')">Logout</button>
  </div>
</template>
