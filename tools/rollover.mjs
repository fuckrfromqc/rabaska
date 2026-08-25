// Does a deploy actually reach a device that has already loaded the app?
//
//   ./build.sh && cp -r dist /tmp/a
//   <change something> && ./build.sh && cp -r dist /tmp/b
//   node tools/rollover.mjs /tmp/a /tmp/b
//
// The origin here behaves like the real one: the document is served
// must-revalidate, everything else with the four-hour max-age Cloudflare Pages
// applies. A device visits, the origin is swapped underneath it, the device
// reloads. It must come back running the new build.
//
// It did not. app.js, rabaska_core.js and wasm-inline.js sat in the HTTP cache
// under URLs that do not change between builds, so a reload refetched the
// document and nothing else — measured: exactly one request — and the device
// went on running the old shell for four hours. That is the same reload the app
// performs when it detects it is running mismatched files, which meant the
// recovery could not recover anything.
//
// The fix is that index.html names the build in the URLs it points at. It is
// the one file always taken from the origin, so what it asks for is what the
// device has to go and get.
import { chromium } from 'playwright';
import { spawn } from 'node:child_process';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [A, B] = process.argv.slice(2);
if (!A || !B) {
  console.error('usage: node tools/rollover.mjs <dist-before> <dist-after>');
  process.exit(2);
}

const work = mkdtempSync(join(tmpdir(), 'rabaska-rollover-'));
const pointer = join(work, 'root');
const PORT = 8131;

writeFileSync(pointer, A);
const srv = spawn('python3', ['-c', `
import http.server, socketserver, os, sys
POINTER = ${JSON.stringify(pointer)}
class H(http.server.SimpleHTTPRequestHandler):
    def translate_path(self, path):
        rel = path.split('?')[0].lstrip('/') or 'index.html'
        if rel.endswith('/'): rel += 'index.html'
        return os.path.join(open(POINTER).read().strip(), rel)
    def log_message(self, *a): pass
    def end_headers(self):
        p = self.path.split('?')[0]
        self.send_header('Cache-Control',
            'public, max-age=0, must-revalidate' if p in ('/', '/index.html')
            else 'public, max-age=14400, must-revalidate')
        super().end_headers()
socketserver.TCPServer.allow_reuse_address = True
socketserver.TCPServer(('127.0.0.1', ${PORT}), H).serve_forever()
`], { stdio: 'ignore' });

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || undefined,
  args: ['--autoplay-policy=no-user-gesture-required'],
});

let failed = false;
try {
  const ctx = await browser.newContext();
  await ctx.addInitScript(() => {
    const c = document.createElement('canvas');
    c.width = c.height = 512;
    const x = c.getContext('2d');
    setInterval(() => { x.fillStyle = '#909090'; x.fillRect(0, 0, 512, 512); }, 60);
    navigator.mediaDevices.getUserMedia = async () => c.captureStream(15);
    // A benign stub. The worker has its own cache and its own update path, both
    // covered by tools/update.mjs; the question here is only what the HTTP
    // cache does, and a real worker would answer for it.
    const fake = {
      waiting: null, installing: null, active: null,
      addEventListener() {}, update: async () => {},
    };
    navigator.serviceWorker.register = async () => fake;
  });
  const page = await ctx.newPage();
  const skew = [];
  page.on('console', (m) => { if (/build skew/.test(m.text())) skew.push(m.text()); });
  const shell = () => page.evaluate(() => ({
    build: document.getElementById('own-build').textContent,
    hint: document.getElementById('hint').textContent,
  }));

  await page.goto(`http://127.0.0.1:${PORT}/`, { waitUntil: 'load' });
  await page.waitForTimeout(3000);
  const first = await shell();
  if (/Startup failed/.test(first.hint)) {
    throw new Error(`the app did not start at all: ${first.hint}`);
  }
  console.log(`✓ [visit 1] running ${first.build}`);

  writeFileSync(pointer, B);              // the deploy
  await page.reload({ waitUntil: 'load' }).catch(() => {});
  await page.waitForTimeout(5000);
  const second = await shell();
  console.log(`  [visit 2] running ${second.build}`);

  if (/Startup failed/.test(second.hint)) {
    throw new Error(`the app died after the deploy: ${second.hint}`);
  }
  if (second.build === first.build) {
    throw new Error('a reload after a deploy still runs the OLD build '
      + `(${first.build}). The device is pinned to whatever it cached until the `
      + 'max-age expires, and the app cannot reload its way out of it.');
  }
  console.log('✓ one reload after a deploy lands on the new build');
  if (skew.length) {
    throw new Error('it got there through a mismatched set: ' + skew[0]);
  }
  console.log('✓ and never assembled the app out of two builds on the way');
  console.log('\n=== ROLLOVER: PASS ===');
} catch (e) {
  failed = true;
  console.error('\n=== ROLLOVER: FAIL ===\n' + e.message);
} finally {
  await browser.close();
  srv.kill();
  rmSync(work, { recursive: true, force: true });
  process.exit(failed ? 1 : 0);
}
