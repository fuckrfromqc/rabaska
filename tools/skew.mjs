// What happens when a browser assembles the app out of two different builds?
//
//   ./build.sh && cp -r dist /tmp/old
//   <change something> && ./build.sh && cp -r dist /tmp/new
//   node tools/skew.mjs /tmp/old /tmp/new
//
// app.js, rabaska_core.js and wasm-inline.js are three separate HTTP cache
// entries. Nothing about fetching them guarantees they came from one
// deployment, and a device that has held any of them for a while will happily
// run a shell from one build against a wasm module from another. When an
// argument list has moved in between, the failure is not graceful: it throws
// inside generated glue during startup, with nothing on screen but "Startup
// failed" and a message about a function nobody wrote.
//
// That is not hypothetical. `Startup failed: arg.charCodeAt is not a function`
// reached a real phone, from a shell predating a wasm signature change calling
// it the old way, on the one code path that runs at boot for any device holding
// a checkpoint.
//
// Two directions, and they are guarded differently on purpose:
//
//   stale shell + fresh wasm  — the shell cannot be fixed retroactively, so the
//     wasm boundary has to tolerate the old call shape. It must BOOT.
//   fresh shell + stale wasm  — the shell can check, so it must NOTICE rather
//     than crash somewhere later.
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { cpSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [OLD, NEW] = process.argv.slice(2);
if (!OLD || !NEW) {
  console.error('usage: node tools/skew.mjs <old-dist> <new-dist>');
  process.exit(2);
}

const work = mkdtempSync(join(tmpdir(), 'rabaska-skew-'));
const servers = [];
let port = 8210;

function serve(dir) {
  const p = port++;
  const s = spawn('python3', ['tools/serve.py', dir, String(p)], { stdio: 'ignore' });
  servers.push(s);
  return p;
}

/** A dist built from `base`, with `files` swapped in from `from`. */
function mix(name, base, from, files) {
  const dir = join(work, name);
  cpSync(base, dir, { recursive: true });
  for (const f of files) cpSync(join(from, f), join(dir, f));
  return dir;
}

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || undefined,
  args: ['--autoplay-policy=no-user-gesture-required'],
});

/**
 * Load the app with a camera and, crucially, a checkpoint already on disk in
 * the OLD record shape. The checkpoint is what makes this test mean anything:
 * restore() is the call that moved, and it only runs when there is something to
 * restore. A profile with an empty IndexedDB boots fine on a mismatched pair
 * and proves nothing.
 */
async function boot(p) {
  const ctx = await browser.newContext();
  await ctx.addInitScript(() => {
    const c = document.createElement('canvas');
    c.width = c.height = 512;
    const x = c.getContext('2d');
    setInterval(() => { x.fillStyle = '#909090'; x.fillRect(0, 0, 512, 512); }, 60);
    navigator.mediaDevices.getUserMedia = async () => c.captureStream(15);
    window.__planted = new Promise((res) => {
      const r = indexedDB.open('rabaska', 1);
      r.onupgradeneeded = () => {
        const d = r.result;
        for (const s of ['identity', 'peers', 'checkpoints'])
          if (!d.objectStoreNames.contains(s)) d.createObjectStore(s);
      };
      r.onsuccess = () => {
        const t = r.result.transaction('checkpoints', 'readwrite');
        t.objectStore('checkpoints').put([[1, 2, 3, 4, 5, 6, 7, 8]], 'active');
        t.oncomplete = () => res(true);
        t.onerror = () => res(false);
      };
      r.onerror = () => res(false);
    });
  });
  const page = await ctx.newPage();
  const log = [];
  page.on('console', (m) => { if (/rabaska/i.test(m.text())) log.push(m.text()); });
  await page.goto(`http://127.0.0.1:${p}/`, { waitUntil: 'load' });
  // A heal-reload can land in the middle of either of these.
  await page.evaluate(() => window.__planted).catch(() => {});
  await page.reload({ waitUntil: 'load' }).catch(() => {});
  await page.waitForTimeout(9000);
  const hint = await page.evaluate(() => document.getElementById('hint').textContent);
  await ctx.close();
  return { hint, log };
}

let failed = false;
try {
  // --- stale shell against fresh wasm ------------------------------------
  const staleShell = serve(mix('stale-shell', NEW, OLD, ['app.js']));
  const a = await boot(staleShell);
  console.log(`  stale shell + fresh wasm: ${JSON.stringify(a.hint)}`);
  if (/Startup failed/.test(a.hint)) {
    throw new Error('a shell from the previous build cannot start against this '
      + `wasm: ${a.hint}\n   The boundary has to accept the old call shape — a `
      + 'deployed shell cannot be fixed retroactively.');
  }
  console.log('✓ a shell from the previous build still boots against this wasm');

  // --- fresh shell against stale wasm ------------------------------------
  const staleWasm = serve(mix('stale-wasm', NEW, OLD, ['rabaska_core.js', 'wasm-inline.js']));
  const b = await boot(staleWasm);
  console.log(`  fresh shell + stale wasm: ${JSON.stringify(b.hint)}`);
  if (!b.log.some((l) => /build skew/.test(l))) {
    throw new Error('the shell did not notice it was running against a wasm '
      + 'module from another build. It will fail later, somewhere arbitrary.');
  }
  console.log('✓ the shell notices a wasm module from another build');
  if (/Startup failed/.test(b.hint)) {
    throw new Error(`it noticed and then crashed anyway: ${b.hint}`);
  }
  console.log('✓ and says so, instead of throwing from inside generated code');

  console.log('\n=== VERSION SKEW: PASS ===');
} catch (e) {
  failed = true;
  console.error('\n=== VERSION SKEW: FAIL ===\n' + e.message);
} finally {
  await browser.close();
  for (const s of servers) s.kill();
  rmSync(work, { recursive: true, force: true });
  process.exit(failed ? 1 : 0);
}
