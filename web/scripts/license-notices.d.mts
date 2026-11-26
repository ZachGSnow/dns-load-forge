import type { Plugin } from "vite"

export function toAscii(text: string): string

export function licenseNotices(options?: { output?: string; root?: string }): Plugin
