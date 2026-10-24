/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** "1" starts the mock service worker with fixture data. */
  readonly VITE_MOCK?: string
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}
