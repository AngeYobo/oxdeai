#!/usr/bin/env node
/**
 * capture-delegation-ui.mjs
 *
 * Records the delegation-demo browser UI as a GIF using Puppeteer.
 *
 * Requirements:
 *   node >= 18
 *   pnpm add puppeteer   (in this script's directory or project root)
 *   imagemagick          (for `convert`)
 *   gifsicle             (optional — optimize output size)
 *
 * Output: docs/media/delegation-demo-ui.gif
 *
 * Usage:
 *   # Step 1 — install puppeteer (once):
 *   npm install puppeteer --save-dev   OR   pnpm add puppeteer
 *
 *   # Step 2 — start the demo server in a separate terminal:
 *   pnpm -C examples/delegation-demo start
 *
 *   # Step 3 — run this script:
 *   node docs/media/capture-delegation-ui.mjs
 *
 * The script auto-finds the puppeteer chromium from:
 *   ~/.cache/puppeteer   (downloaded by puppeteer install)
 *   CHROMIUM_BIN env var (override)
 */

import { createRequire } from "node:module";
import fs               from "node:fs";
import path             from "node:path";
import { fileURLToPath } from "node:url";
import { execSync }     from "node:child_process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require   = createRequire(import.meta.url);

// ── Config ────────────────────────────────────────────────────────────────────
const DEMO_URL     = "http://localhost:3334/";
const VIEWPORT_W   = 1280;
const VIEWPORT_H   = 820;
const CAPTURE_MS   = 500;   // ms between screenshots (~2fps)
const DURATION_MS  = 24_000; // total capture window in ms
const FRAME_DELAY  = 50;    // GIF frame delay in 1/100 s units (= 0.5s between frames)
const OUT_FRAMES   = path.join(__dirname, ".delegation-ui-frames");
const OUT_GIF      = path.join(__dirname, "delegation-demo-ui.gif");

// ── Find puppeteer ────────────────────────────────────────────────────────────
function findPuppeteer() {
  const searchPaths = [
    // Workspace root install (pnpm add -w -D puppeteer)
    path.resolve(__dirname, "../../node_modules/puppeteer/lib/cjs/puppeteer/puppeteer.js"),
    // Local project install
    path.resolve(__dirname, "node_modules/puppeteer/lib/cjs/puppeteer/puppeteer.js"),
    // npm global fallback
    path.resolve(process.env.HOME ?? "~", ".npm-global/lib/node_modules/puppeteer/lib/cjs/puppeteer/puppeteer.js"),
  ];
  for (const p of searchPaths) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function findChromiumBin() {
  if (process.env.CHROMIUM_BIN) return process.env.CHROMIUM_BIN;
  const cacheBase = path.resolve(process.env.HOME ?? "~", ".cache/puppeteer/chrome");
  if (!fs.existsSync(cacheBase)) return null;
  // Find the newest version
  const versions = fs.readdirSync(cacheBase).sort().reverse();
  for (const ver of versions) {
    const candidate = path.join(cacheBase, ver, "chrome-linux64", "chrome");
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  // Find puppeteer
  const puppeteerPath = findPuppeteer();
  if (!puppeteerPath) {
    console.error(`
✗ puppeteer not found.

Install it:
  pnpm add puppeteer          (or npm install puppeteer)

Then re-run this script.
`);
    process.exit(1);
  }

  const chromiumBin = findChromiumBin();
  if (!chromiumBin) {
    console.error(`
✗ Puppeteer chromium not found in ~/.cache/puppeteer.

Try:
  npx puppeteer browsers install chrome
  OR set CHROMIUM_BIN=/path/to/chrome
`);
    process.exit(1);
  }

  const puppeteer = require(puppeteerPath);
  const pp = puppeteer.default ?? puppeteer;

  // Verify demo server is reachable
  console.log(`Checking demo server at ${DEMO_URL}...`);
  try {
    await fetch(DEMO_URL);
  } catch {
    console.error(`
✗ Cannot reach ${DEMO_URL}

Start the demo server first:
  pnpm -C examples/delegation-demo start
`);
    process.exit(1);
  }
  console.log("✓ Server reachable");

  // Clean / create frames directory
  if (fs.existsSync(OUT_FRAMES)) fs.rmSync(OUT_FRAMES, { recursive: true });
  fs.mkdirSync(OUT_FRAMES);

  // Launch browser
  console.log(`\nLaunching browser: ${path.basename(chromiumBin)}...`);
  const browser = await pp.launch({
    executablePath: chromiumBin,
    headless: "new",
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
    ],
  });

  const page = await browser.newPage();
  await page.setViewport({ width: VIEWPORT_W, height: VIEWPORT_H, deviceScaleFactor: 1 });

  // Navigate and wait for page + auto-play to start
  console.log(`Navigating to ${DEMO_URL}...`);
  await page.goto(DEMO_URL, { waitUntil: "networkidle2" });
  await sleep(2000); // let auto-play initialize
  console.log("✓ Page ready — capturing frames...\n");

  // Capture loop
  const startTime = Date.now();
  let frameIdx = 0;

  while (Date.now() - startTime < DURATION_MS) {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    process.stdout.write(`\r  frame ${String(frameIdx + 1).padStart(3)}  t=${elapsed}s  `);

    const framePath = path.join(OUT_FRAMES, `frame_${String(frameIdx).padStart(4, "0")}.png`);
    await page.screenshot({ path: framePath, fullPage: false });
    frameIdx++;

    await sleep(CAPTURE_MS);
  }

  process.stdout.write("\n");
  console.log(`✓ Captured ${frameIdx} frames`);
  await browser.close();

  // Assemble GIF
  console.log("\nAssembling GIF with ImageMagick...");
  const frames = fs.readdirSync(OUT_FRAMES)
    .filter(f => f.endsWith(".png"))
    .sort()
    .map(f => `"${path.join(OUT_FRAMES, f)}"`);

  // +dither = no dithering, which produces clean flat colors for CSS UIs.
  // -posterize 136 reduces bit depth before quantization for sharper palette.
  execSync(
    `convert -delay ${FRAME_DELAY} -loop 0 +dither -layers Optimize -colors 256 ` +
    frames.join(" ") + ` "${OUT_GIF}"`,
    { stdio: "pipe" }
  );
  console.log("✓ GIF assembled:", OUT_GIF);

  // Optimize
  try {
    execSync(`gifsicle -O3 --colors 256 "${OUT_GIF}" -o "${OUT_GIF}"`, { stdio: "pipe" });
    const size = (fs.statSync(OUT_GIF).size / 1024).toFixed(0);
    console.log(`✓ Optimized: ${size} KB`);
  } catch {
    console.log("  (gifsicle not available — skip optimization)");
  }

  fs.rmSync(OUT_FRAMES, { recursive: true });
  console.log("\n✓ Done:", OUT_GIF);
}

main().catch(err => {
  console.error("\n✗ Error:", err.message ?? err);
  process.exit(1);
});
