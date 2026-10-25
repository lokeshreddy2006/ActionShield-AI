import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/health': 'http://127.0.0.1:8000',
      '/evaluate': 'http://127.0.0.1:8000',
      '/execute': 'http://127.0.0.1:8000',
      '/audit': 'http://127.0.0.1:8000',
      '/approvals': 'http://127.0.0.1:8000',
      '/crash-tests': 'http://127.0.0.1:8000',
      '/intent': 'http://127.0.0.1:8000',
    },
  },
})
