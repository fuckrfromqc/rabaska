// The service worker update flow, driven against two real builds.
//
//   ./build.sh && cp -r dist /tmp/rabaska-old
//   # change anything the build hash covers, e.g. a comment in app/style.css
//   ./build.sh && cp -r dist /tmp/rabaska-new
//   npm i playwright && node tools/update.mjs /tmp/rabaska-old /tmp/rabaska-new
//
// It serves through tools/serve.py, so the production headers apply — sw.js
// must come back with Cache-Control: no-cache or the browser will not look for
// a new one.
//
// Three things are checked, and the first two were both broken in the field:
//
//   1. A first visit must NOT offer an update. `updatefound` fires for the very
//      first install too, so the banner was greeting every new visitor with
//      news about the build they had just loaded.
//   2. A genuinely new build must be discovered, parked and offered — the app
//      asks on load, because the browser's own check is not dependable.
//   3. Activating it must land on the NEW build. postMessage then an immediate
//      location.reload() races skipWaiting, and a reload that wins serves the
//      OLD build back out of the old worker's cache.
//
// Note on (3): it is a race, so the old code can pass it on a fast local
// server. Failing here is proof of the bug; passing is not proof of its
// absence. (1) fails deterministically against the old code.
import { chromium } from 'playwright';
import { spawn } from 'child_process';
import { readFileSync, cpSync, rmSync, mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const [OLD, NEW] = process.argv.slice(2);
if (!OLD || !NEW) {
  console.error('usage: node tools/update.mjs <old-dist> <new-dist>');
  process.exit(2);
}

const buildOf = (dir) =>
  readFileSync(join(dir, 'app.js'), 'utf8').match(/const BUILD = '([0-9a-f]+)'/)?.[1];
const V1 = buildOf(OLD);
const V2 = buildOf(NEW);
if (!V1 || !V2) {
  console.error('could not read a build hash out of one of those dists');
  process.exit(2);
}
if (V1 === V2) {
  console.error(`both dists are build ${V1}: there is no update to find`);
  process.exit(2);
}

const PORT = Number(process.env.PORT || 8089);
const root = mkdtempSync(join(tmpdir(), 'rabaska-update-'));
const serveDir = join(root, 'serve');
cpSync(OLD, serveDir, { recursive: true });

// detached so the server sits in its own process group and can be killed as a
// group, and unref'd so it never holds this process open. Without both, node
// prints its result and then hangs waiting on a child it already finished with.
const server = spawn('python3', ['tools/serve.py', serveDir, String(PORT)], {
  stdio: 'ignore',
  detached: true,
});
server.unref();
let cleanedUp = false;
const cleanup = () => {
  if (cleanedUp) return;
  cleanedUp = true;
  try {
    process.kill(-server.pid, 'SIGTERM');
  } catch {
    // already gone
  }
  rmSync(root, { recursive: true, force: true });
};
process.on('exit', cleanup);
process.on('SIGINT', () => { cleanup(); process.exit(130); });

await new Promise((r) => setTimeout(r, 1500));

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || undefined,
  args: ['--use-fake-ui-for-media-stream', '--use-fake-device-for-media-stream'],
});
const ctx = await browser.newContext({ viewport: { width: 390, height: 800 } });
await ctx.grantPermissions(['camera'], { origin: `http://127.0.0.1:${PORT}` });
const page = await ctx.newPage();

const state = () => page.evaluate(async () => {
  const reg = await navigator.serviceWorker.getRegistration();
  return {
    build: document.getElementById('own-build').textContent,
    banner: !document.getElementById('update-panel').hidden,
    waiting: !!reg?.waiting,
    active: reg?.active?.state ?? null,
  };
});

const failed = [];
const check = (label, ok, detail) => {
  console.log(`${ok ? '✓' : '✗'} ${label}${detail ? '   ' + detail : ''}`);
  if (!ok) failed.push(label);
};

try {
  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: 'load' });
  await page.waitForTimeout(6000);
  let s = await state();
  check('a first visit offers no update', s.banner === false, `banner=${s.banner}`);
  check('a first visit runs the old build', s.build === V1, `build=${s.build}`);

  rmSync(serveDir, { recursive: true, force: true });
  cpSync(NEW, serveDir, { recursive: true });
  console.log(`\n(deployed ${V2} over ${V1})\n`);

  await page.reload({ waitUntil: 'load' });
  // Nothing is asked on the test's behalf any more. The app calls reg.update()
  // itself on load, so what is being checked here is the whole discovery path —
  // notice, park, offer — and not merely the banner logic once something has
  // been parked by a test that reached in and did it.
  for (let i = 0; i < 60 && !(await state()).waiting; i++) await page.waitForTimeout(500);
  await page.waitForTimeout(500);

  s = await state();
  check('the old build keeps running until it is activated', s.build === V1, `build=${s.build}`);
  check('the new build is discovered and parked', s.waiting === true);
  check('the banner is offered once it has installed', s.banner === true);

  // Stop here with something readable rather than letting the click below time
  // out on a button that was never shown. Nothing asks on this test's behalf,
  // so reaching this point with nothing parked means the app never noticed the
  // new build at all — which is a different and much worse failure than a
  // banner that failed to appear.
  if (!s.waiting || !s.banner) {
    throw new Error('the app never discovered the new build: '
      + `waiting=${s.waiting} banner=${s.banner} active=${s.active}`);
  }

  const navigated = page.waitForNavigation({ timeout: 20000 }).catch(() => null);
  await page.click('#update-now');
  await navigated;
  await page.waitForTimeout(6000);

  s = await state();
  check('activating lands on the NEW build', s.build === V2,
    `build=${s.build} (old ${V1}, new ${V2})`);
  check('the banner is gone', s.banner === false);
  check('the new worker is active', s.active === 'activated');
  check('nothing is left waiting', s.waiting === false);
} finally {
  await browser.close();
}

if (failed.length) {
  console.error(`\n=== UPDATE FLOW: ${failed.length} FAILED ===`);
  process.exit(1);
}
console.log('\n=== UPDATE FLOW: PASS ===');
process.exit(0);
