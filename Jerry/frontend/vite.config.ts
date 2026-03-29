import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Build config produces a single JS file that can be embedded via <script> tag
export default defineConfig({
  plugins: [react()],
  build: {
    // Output a single self-contained JS file
    lib: {
      entry: 'src/main.tsx',
      name: 'JerryBot',
      fileName: 'sunsetbot-widget',
      formats: ['iife'], // Immediately Invoked Function Expression — works in any browser
    },
    rollupOptions: {
      // Bundle everything — no external dependencies
      // React is small enough to bundle (~40KB gzipped)
    },
    // Output to backend/static for easy serving
    outDir: '../backend/static',
    emptyOutDir: false,
    cssCodeSplit: false, // Inline CSS into JS
  },
  define: {
    'process.env.NODE_ENV': JSON.stringify('production'),
  },
})
