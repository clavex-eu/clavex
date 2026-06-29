import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { resolve, sep } from 'path'
import fs from 'fs'

export default defineConfig({
  plugins: [
    react(),
    // Serve marketing/ static HTML files during dev (e.g. /marketing/compare.html)
    {
      name: 'serve-marketing',
      configureServer(server) {
        const marketingRoot = resolve(__dirname, '..', 'marketing')
        server.middlewares.use((req, res, next) => {
          if (req.url?.startsWith('/marketing/')) {
            // Decode and strip the query string before resolving, then confirm
            // the resolved path stays inside marketingRoot — otherwise a request
            // like /marketing/../../etc/passwd could escape the directory.
            const urlPath = decodeURIComponent(req.url.split('?')[0])
            const filePath = resolve(__dirname, '..', urlPath.slice(1))
            const contained = filePath === marketingRoot || filePath.startsWith(marketingRoot + sep)
            if (contained && fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
              res.setHeader('Content-Type', 'text/html; charset=utf-8')
              fs.createReadStream(filePath).pipe(res)
              return
            }
          }
          next()
        })
      },
    },
  ],
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8080',
      // Proxy tenant OIDC endpoints during dev
      '/healthz': 'http://localhost:8080',
    },
  },
  build: {
    outDir: '../build/frontend',
    emptyOutDir: true,
  },
})
