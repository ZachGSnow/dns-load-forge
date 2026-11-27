// Captures dashboard screenshots from a running server, for the README and for
// checking a change by eye.  Drives an installed Chrome or Edge (puppeteer-core
// downloads no browser), so the images come from the real page and real data.
//
//   python -m dnsloadforge --mock                 # in one terminal
//   node scripts/screenshots.mjs --out ../docs    # in web/
//
// Options:
//   --url URL        dashboard address (default http://127.0.0.1:8787/)
//   --out DIR        where to write the PNGs (default ./screenshots)
//   --theme ID       light, dark or a palette id (default dark)
//   --wait SECONDS   how long to let data accumulate first (default 20)
//   --width PX       viewport width (default 1440)
//   --pages LIST     comma list of live,compare,lists (default live)
//   --name PREFIX    file name prefix (default dashboard)
//   --height PX      capture only the top PX of the page (default: all of it)
//   --scale N        device pixel ratio (default 2)

import { existsSync, mkdirSync } from "node:fs"
import { join, resolve } from "node:path"

import puppeteer from "puppeteer-core"

function option(name, fallback) {
  const at = process.argv.indexOf(`--${name}`)
  return at > 0 && process.argv[at + 1] ? process.argv[at + 1] : fallback
}

const url = option("url", "http://127.0.0.1:8787/")
const out = resolve(option("out", "screenshots"))
const theme = option("theme", "dark")
const waitSeconds = Number(option("wait", "20"))
const width = Number(option("width", "1440"))
const pages = option("pages", "live").split(",")
const prefix = option("name", "dashboard")
const clipHeight = Number(option("height", "0"))
const scale = Number(option("scale", "2"))

const CANDIDATES = [
  process.env.BROWSER_PATH,
  "C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Microsoft/Edge/Application/msedge.exe",
  "C:/Program Files/Google/Chrome/Application/chrome.exe",
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/usr/bin/microsoft-edge",
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
].filter(Boolean)

const executablePath = CANDIDATES.find((path) => existsSync(path))
if (!executablePath) {
  console.error("No Chrome or Edge found; set BROWSER_PATH to one.")
  process.exit(2)
}

mkdirSync(out, { recursive: true })
const browser = await puppeteer.launch({
  executablePath,
  headless: true,
  defaultViewport: { width, height: 900, deviceScaleFactor: scale },
  args: ["--hide-scrollbars", "--no-first-run", "--force-color-profile=srgb"],
})

try {
  const page = await browser.newPage()
  const problems = []
  page.on("console", (message) => {
    if (message.type() === "error") problems.push(message.text())
  })
  page.on("pageerror", (error) => problems.push(String(error)))

  // The theme is read from storage before first paint, so set it on the origin and
  // then load the page again (a hash change alone would not re-run that script).
  await page.goto(url, { waitUntil: "domcontentloaded" })
  await page.evaluate(
    (id) => window.localStorage.setItem("dlf-theme", id),
    theme
  )
  await page.reload({ waitUntil: "domcontentloaded" })

  for (const name of pages) {
    await page.evaluate((route) => {
      window.location.hash = `/${route}`
    }, name)
    await page.waitForSelector("main", { timeout: 15000 })
    await new Promise((done) => setTimeout(done, waitSeconds * 1000))
    // Grow the viewport to the whole page and let the charts re-measure before the
    // capture; a fullPage screenshot resizes at the last moment and catches them blank.
    const height =
      clipHeight ||
      (await page.evaluate(() => document.documentElement.scrollHeight))
    await page.setViewport({ width, height, deviceScaleFactor: scale })
    await new Promise((done) => setTimeout(done, 1500))
    const file = join(out, `${prefix}-${name}.png`)
    await page.screenshot({ path: file })
    await page.setViewport({ width, height: 900, deviceScaleFactor: scale })
    console.log(`wrote ${file}`)
  }

  if (problems.length) {
    console.error("the page logged errors:")
    for (const problem of problems) console.error(`  ${problem}`)
    process.exitCode = 1
  }
} finally {
  await browser.close()
}
