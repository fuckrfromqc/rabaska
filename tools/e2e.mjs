// Two instances of the built app, face to face, through the whole PAIR flow.
//
//   ./build.sh
//   python3 tools/serve.py dist 8095 &
//   python3 tools/serve.py dist 8094 &
//   npm i playwright && node tools/e2e.mjs
//
// Two ports, not two tabs: separate origins mean separate IndexedDB, so the two
// devices have separate identities. On one origin they would silently share an
// identity and the handshake being tested would not be the real one.
//
// Each page's getUserMedia is replaced by a captureStream of a local canvas, and
// a bridge loop copies each page's #display into the other page's feed. That is
// the ONLY substitution. Everything between those two canvases is the shipped
// code running the shipped wasm: QR render, decode, X25519, the commitment, the
// SAS, RaptorQ, the AEAD, both state machines.
//
// What it does not simulate is optics. No blur, no rolling shutter, no
// autofocus, no hands. It proves the protocol and the shell are correct; it
// cannot prove the ladder is fast enough at arm's length in a dim room. That
// still needs two phones.
import { chromium } from 'playwright';

const A_PORT = Number(process.env.A_PORT || 8095);
const B_PORT = Number(process.env.B_PORT || 8094);
// A real file, not a string: a name with an extension, a MIME type, and a body
// containing every one of the 256 byte values so that any UTF-8 coercion
// anywhere in the path shows up as a mismatch rather than as a file that only
// looks fine. The transfer completing is not the assertion; arriving as this
// exact file is.
const FILE_NAME = 'holiday photo.jpg';
const FILE_MIME = 'image/jpeg';
const FILE_BYTES = Buffer.concat([
  Buffer.from([0xff, 0xd8, 0xff, 0xe0]),                    // JPEG magic
  Buffer.from(Array.from({ length: 256 }, (_, i) => i)),    // every byte value
  Buffer.from('rabaska carries a lot in one crossing', 'utf8'),
  Buffer.from(Array.from({ length: 1024 }, (_, i) => (i * 37) & 0xff)),
]);

const browser = await chromium.launch({
  executablePath: process.env.CHROMIUM || undefined,
  args: ['--autoplay-policy=no-user-gesture-required'],
});

async function device(name, port) {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 900 } });
  await ctx.addInitScript(() => {
    const feed = document.createElement('canvas');
    feed.width = 1024;
    feed.height = 1024;
    const fx = feed.getContext('2d');
    fx.fillStyle = '#909090';
    fx.fillRect(0, 0, 1024, 1024);
    // Must be called continuously, including with null. A canvas captureStream
    // emits a frame only when the canvas is drawn to, so a canvas painted once
    // yields a MediaStream that never produces a frame: video.play() then never
    // resolves and the app stalls at "Starting…" having done nothing wrong. A
    // real camera is always producing frames; sometimes it is just pointed at
    // a desk. null is the desk.
    window.__setFeed = (url) => new Promise((res) => {
      const desk = () => {
        fx.fillStyle = '#909090';
        fx.fillRect(0, 0, 1024, 1024);
      };
      if (!url) { desk(); return res(); }
      const img = new Image();
      img.onload = () => {
        desk();
        fx.drawImage(img, (1024 - img.width) / 2, (1024 - img.height) / 2);
        res();
      };
      img.onerror = () => res();
      img.src = url;
    });
    // A fresh stream per call, because scanOneFrame stops its tracks and a
    // later scan has to be able to reopen — the path DEPLOY.md flags as the
    // one least trusted.
    navigator.mediaDevices.getUserMedia = async () => feed.captureStream(15);
    navigator.clipboard.readText = async () => 'unused: this run stages a file';

    // Keep the Blob the app hands to createObjectURL. Reading the bytes back
    // through fetch(blob:) is what you would reach for and it does not work
    // here: connect-src 'none' forbids fetch of any kind, which is the app
    // working as designed. Blob.text() is not a fetch, so it is the way in.
    const createObjectURL = URL.createObjectURL.bind(URL);
    URL.createObjectURL = (obj) => {
      window.__lastBlob = obj;
      return createObjectURL(obj);
    };
  });
  const page = await ctx.newPage();
  page.on('console', (m) => {
    if (m.text().includes('rabaska')) console.log(`  [${name}] ${m.text()}`);
  });
  page.on('pageerror', (e) => console.log(`  [${name}] PAGEERROR ${e.message}`));
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: 'load' });
  return page;
}

const A = await device('A', A_PORT); // receiver: the resting state
const B = await device('B', B_PORT); // sender: stages a payload
await A.waitForTimeout(2500);
await B.waitForTimeout(500);

// Both cameras run from the start; `aimed` only decides whether they are
// pointed at each other or at a bare desk. A person picks the file first and
// then lifts the phone, and with the channel already open B scans A's PAIR_REQ
// and flips to sender so fast that "N bytes ready" is gone before it can be
// observed — failing the test on a state the app passed through correctly.
let bridging = true;
let aimed = false;
const bridge = (async () => {
  while (bridging) {
    try {
      if (aimed) {
        const fromA = await A.evaluate(() => document.getElementById('display').toDataURL());
        await B.evaluate((u) => window.__setFeed(u), fromA);
        const fromB = await B.evaluate(() => document.getElementById('display').toDataURL());
        await A.evaluate((u) => window.__setFeed(u), fromB);
      } else {
        await A.evaluate(() => window.__setFeed(null));
        await B.evaluate(() => window.__setFeed(null));
      }
    } catch { /* a page mid-navigation is fine */ }
    await new Promise((r) => setTimeout(r, 60));
  }
})();

const state = (p) => p.evaluate(() => ({
  hint: document.getElementById('hint').textContent,
  sas: document.getElementById('sas').textContent,
  sasVisible: !document.getElementById('sas-panel').hidden,
  confirmVisible: !document.getElementById('sas-confirm').hidden,
  count: document.getElementById('count').textContent,
  // The viewfinder's own readout, which separates "saw nothing" from "decoded
  // frames but the protocol did not advance" without any extra instrumentation.
  word: document.getElementById('sight-word').textContent,
  peer: document.getElementById('peer-build').textContent,
  download: !document.getElementById('download').hidden,
}));

async function waitFor(page, name, desc, pred, ms) {
  const end = Date.now() + ms;
  for (;;) {
    const s = await state(page);
    if (pred(s)) {
      console.log(`✓ [${name}] ${desc}`);
      return s;
    }
    if (Date.now() > end) {
      console.log(`✗ [${name}] TIMEOUT: ${desc}`);
      console.log('   A =>', JSON.stringify(await state(A)));
      console.log('   B =>', JSON.stringify(await state(B)));
      throw new Error('timeout: ' + desc);
    }
    await new Promise((r) => setTimeout(r, 300));
  }
}

let failed = false;
try {
  await B.setInputFiles('#file', {
    name: FILE_NAME, mimeType: FILE_MIME, buffer: FILE_BYTES,
  });
  await waitFor(B, 'B', 'file staged', (s) => s.hint.includes('bytes ready'), 5000);

  aimed = true; // the two devices are now pointed at each other
  await waitFor(B, 'B', "scanned A's PAIR_REQ, flipped to sender",
    (s) => /Point this device|About/.test(s.hint), 30000);

  const a = await waitFor(A, 'A', 'beacon acquired, SAS and reveal shown',
    (s) => s.sasVisible && s.sas.length > 0, 30000);
  const b = await waitFor(B, 'B', 'reveal scanned, commitment opened',
    (s) => s.sasVisible && s.confirmVisible, 30000);

  console.log(`    SAS on A: ${a.sas}    SAS on B: ${b.sas}`);
  if (a.sas !== b.sas) throw new Error('SAS MISMATCH — the handshake is broken');
  console.log('✓ SAS matches on both screens');

  await B.click('#sas-confirm');
  await waitFor(A, 'A', 'symbols landing', (s) => /\d+ \/ \d+|verifying/.test(s.count), 30000);
  await waitFor(A, 'A', 'reassembled, authenticated, delivered',
    (s) => s.hint.includes('Verified. Delivered.'), 60000);
  await waitFor(B, 'B', 'completion frame scanned, delivery verified',
    (s) => s.hint.includes('Verified delivered'), 30000);

  const end = await state(A);
  if (!end.download) throw new Error('A never offered the payload for download');

  // The assertion everything else exists to support. "Delivered" is the app's
  // claim; this reads the bytes back out of the blob it is offering and checks
  // them against what was sent. A transfer that ends in a green message and the
  // wrong bytes is the only failure worse than one that visibly breaks.
  const got = await A.evaluate(async () => {
    if (!window.__lastBlob) throw new Error('no blob was ever created');
    const a = document.getElementById('download');
    return {
      bytes: Array.from(new Uint8Array(await window.__lastBlob.arrayBuffer())),
      type: window.__lastBlob.type,
      download: a.getAttribute('download'),
    };
  });

  const sent = Array.from(FILE_BYTES);
  if (got.bytes.length !== sent.length) {
    throw new Error(`LENGTH MISMATCH: sent ${sent.length}, received ${got.bytes.length}`);
  }
  const at = got.bytes.findIndex((b, i) => b !== sent[i]);
  if (at !== -1) {
    throw new Error(`BYTE MISMATCH at offset ${at}: sent ${sent[at]}, received ${got.bytes[at]}`);
  }
  console.log(`✓ body round-trips byte for byte (${got.bytes.length} bytes, all 256 values)`);

  if (got.download !== FILE_NAME) {
    throw new Error(`FILENAME LOST: sent ${JSON.stringify(FILE_NAME)}, `
      + `receiver offers ${JSON.stringify(got.download)}`);
  }
  console.log(`✓ filename preserved: ${JSON.stringify(got.download)}`);

  if (got.type !== FILE_MIME) {
    throw new Error(`TYPE LOST: sent ${JSON.stringify(FILE_MIME)}, `
      + `received ${JSON.stringify(got.type)}`);
  }
  console.log(`✓ type preserved: ${got.type}`);
  console.log(`✓ A offers the file, and saw peer build ${end.peer}`);
  console.log('\n=== END TO END: PASS ===');
} catch (e) {
  failed = true;
  console.error('\n=== END TO END: FAIL ===\n' + e.message);
} finally {
  bridging = false;
  await bridge;
  await browser.close();
  process.exit(failed ? 1 : 0);
}
