import { resolve } from "node:path"

import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"
import { viteSingleFile } from "vite-plugin-singlefile"

import { licenseNotices } from "./scripts/license-notices.mjs"

// The dashboard ships inside the Python package as one self-contained HTML file:
// no external requests, so it works on an air-gapped management segment.
const PACKAGE_DASHBOARD = resolve(
  import.meta.dirname,
  "../src/dnsloadforge/dashboard"
)

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
    viteSingleFile({ removeViteModuleLoader: true }),
    licenseNotices({ output: "THIRD_PARTY_NOTICES.txt" }),
  ],
  resolve: {
    alias: {
      "@": resolve(import.meta.dirname, "./src"),
    },
  },
  publicDir: false,
  build: {
    outDir: PACKAGE_DASHBOARD,
    // The folder also holds the license notices written alongside the page.
    emptyOutDir: false,
    target: "es2022",
    sourcemap: false,
    reportCompressedSize: false,
    chunkSizeWarningLimit: 4096,
  },
  server: {
    // `npm run dev` against a running `python -m dnsloadforge serve --mock`.
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8787",
        changeOrigin: true,
        configure(proxy) {
          // The server refuses writes whose Origin is not its own host, which is
          // right in production and wrong for the dev server's proxy.
          proxy.on("proxyReq", (request) => {
            request.removeHeader("origin")
            request.removeHeader("sec-fetch-site")
          })
        },
      },
    },
  },
})
