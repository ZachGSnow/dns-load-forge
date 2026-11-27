// Checks, and where it safely can repairs, the built dashboard page.
//
// The page ships inside the Python package and is served to browsers on an
// isolated segment, so it must be:
//   * plain ASCII, like every file in the repository: any other character is
//     rewritten as an escape for the context it sits in (JS, CSS or HTML);
//   * self-contained: no script, stylesheet, font or image fetched from anywhere;
//   * small enough that the repository's text scans still read it (under 2 MB).
// Anything that cannot be repaired fails the build.

import { readFileSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const here = dirname(fileURLToPath(import.meta.url))
const dashboard = join(here, "..", "..", "src", "dnsloadforge", "dashboard")
const page = join(dashboard, "index.html")
const notices = join(dashboard, "THIRD_PARTY_NOTICES.txt")

const MAX_BYTES = 2 * 1024 * 1024

function hex(code, width = 4) {
  return code.toString(16).toUpperCase().padStart(width, "0")
}

/** JS: \uXXXX works in strings, templates, regexes and identifiers alike. */
function escapeJs(text) {
  let out = ""
  for (const ch of text) {
    const code = ch.codePointAt(0)
    if (code < 0x80) {
      out += ch
    } else if (code <= 0xffff) {
      out += `\\u${hex(code)}`
    } else {
      const v = code - 0x10000
      out += `\\u${hex(0xd800 + (v >> 10))}\\u${hex(0xdc00 + (v & 0x3ff))}`
    }
  }
  return out
}

/** CSS: a hex escape ended by a space, which the escape consumes. */
function escapeCss(text) {
  let out = ""
  for (const ch of text) {
    const code = ch.codePointAt(0)
    out += code < 0x80 ? ch : `\\${hex(code, 6)} `
  }
  return out
}

/** HTML text and attributes: a numeric character reference. */
function escapeHtml(text) {
  let out = ""
  for (const ch of text) {
    const code = ch.codePointAt(0)
    out += code < 0x80 ? ch : `&#x${hex(code)};`
  }
  return out
}

function asciiOnly(html) {
  const parts = html.split(
    /(<script\b[^>]*>[\s\S]*?<\/script>|<style\b[^>]*>[\s\S]*?<\/style>)/i
  )
  return parts
    .map((part) => {
      const script = /^<script\b[^>]*>/i.exec(part)
      if (script) {
        const body = part.slice(
          script[0].length,
          part.length - "</script>".length
        )
        return script[0] + escapeJs(body) + "</script>"
      }
      const style = /^<style\b[^>]*>/i.exec(part)
      if (style) {
        const body = part.slice(
          style[0].length,
          part.length - "</style>".length
        )
        return style[0] + escapeCss(body) + "</style>"
      }
      return escapeHtml(part)
    })
    .join("")
}

const problems = []
let html = readFileSync(page, "utf8")
const before = [...html].filter((ch) => ch.codePointAt(0) >= 0x80).length
html = asciiOnly(html)

if (/[^\x09\x0a\x0d\x20-\x7e]/.test(html))
  problems.push("non-ASCII or control characters remain")
for (const [label, pattern] of [
  [
    "an external script or stylesheet",
    /<(?:script|link|img|iframe|source|video|audio)\b[^>]*\b(?:src|href)\s*=\s*["']?(?:https?:)?\/\//i,
  ],
  ["a remote url() in CSS", /url\(\s*["']?(?:https?:)?\/\//i],
  ["a CSS @import", /@import\s/i],
  ["a source map reference", /sourceMappingURL=/],
  ["a build machine path", /[A-Za-z]:[\\/]+Users[\\/]+/],
]) {
  if (pattern.test(html)) problems.push(`the page contains ${label}`)
}
if (!/<div id="root">/.test(html))
  problems.push("the page has no #root element")
const bytes = Buffer.byteLength(html, "utf8")
if (bytes > MAX_BYTES)
  problems.push(`the page is ${bytes} bytes, over the ${MAX_BYTES} byte budget`)

const text = readFileSync(notices, "utf8")
if (/[^\x09\x0a\x0d\x20-\x7e]/.test(text))
  problems.push("THIRD_PARTY_NOTICES.txt is not plain ASCII")

if (problems.length) {
  console.error("dashboard build check failed:")
  for (const problem of problems) console.error(`  - ${problem}`)
  process.exit(1)
}

writeFileSync(page, html.endsWith("\n") ? html : `${html}\n`)
console.log(
  `dashboard: ${(bytes / 1024).toFixed(0)} KB, ASCII-only` +
    (before ? ` (${before} non-ASCII characters escaped)` : "") +
    `, no external references`
)
