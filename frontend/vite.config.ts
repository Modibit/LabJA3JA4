import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 3084,
    host: '127.0.0.1',
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:3085',
        changeOrigin: true,
      },
    },
  },
  preview: {
    port: 3084,
    host: '127.0.0.1',
  },
})
