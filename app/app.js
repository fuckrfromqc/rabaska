// Rabaska browser shell.
//
// No framework. The whole app is a small state machine over a camera and a
// canvas, and a framework would cost more bytes than the logic.
//
// Architecture rule: this file orchestrates, it does not compute. Every byte of
// crypto, codec and reassembly happens in WASM. Private keys never cross into
// JS, because a Uint8Array in a garbage-collected heap cannot be reliably wiped.

import init, {
  Identity, Session, Receive, Send,
  render_qr, decode_qr, qr_capacity, default_symbol_size,
} from './rabaska_core.js';
import { WASM_BYTES } from './wasm-inline.js';

// Stamped by build.sh over every precached byte of the app. Displayed next to
// the peer's during a transfer: two devices running different code is then
// visible in one glance, which is the cheapest defence against an origin
// serving different JavaScript to one side of a pairing.
//
// It is also the service worker's cache key, which is why it covers the assets
// and not just the executable files. See build.sh.
const BUILD = '__BUILD_HASH__';

// ---------------------------------------------------------------------------
// density ladder
// ---------------------------------------------------------------------------

// Interleaved on a fixed schedule, never negotiated. A receiver in good light
// decodes mostly the fast rungs; one at a bad angle harvests only the QR frames
// and takes longer. Every packet at every rung counts toward the same
// reconstruction, which is why there is no step-down logic and no feedback
// channel. Phase 1 ships the QR rungs only; Phase 2 slots the tile rungs into
// this same array and nothing else changes.
const LADDER = [
  { kind: 'qr', version: 40, ecc: 0, weight: 3 }, // v40-L, max density
  { kind: 'qr', version: 30, ecc: 1, weight: 2 }, // v30-M, margin for motion
  { kind: 'qr', version: 25, ecc: 1, weight: 1 }, // v25-M, the robust floor
];

const SCHEDULE = LADDER.flatMap((r) => Array(r.weight).fill(r));
const DISPLAY_FPS = 12;      // displayed frames per second
const BEACON_ECC = 3;        // ECC-H: acquire from across the room
const STALL_MS = 3000;

// ---------------------------------------------------------------------------
// storage
// ---------------------------------------------------------------------------

const DB = 'rabaska';
let db;

async function openDb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => {
      const d = r.result;
      d.createObjectStore('identity');
      d.createObjectStore('peers');       // id_hint hex -> { pubkey, name, seen }
      d.createObjectStore('checkpoints'); // session hex -> packets
    };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}

function tx(store, mode, fn) {
  return new Promise((res, rej) => {
    const t = db.transaction(store, mode);
    const req = fn(t.objectStore(store));
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}

const get = (s, k) => tx(s, 'readonly', (o) => o.get(k));
const put = (s, k, v) => tx(s, 'readwrite', (o) => o.put(v, k));

// The identity secret is never written in the clear. It is wrapped under an
// AES-GCM key marked non-extractable, so the wrapping key itself lives in the
// browser's key store and cannot be read back out by script: an attacker who
// achieves a same-origin read of IndexedDB gets ciphertext, not a private key.
//
// This is a real but bounded improvement. There is no keychain access from the
// web, so an unlocked and compromised device still loses everything, and the UI
// says so rather than implying otherwise.
async function wrappingKey() {
  const existing = await get('identity', 'wrap');
  if (existing) return existing;
  const k = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 }, false /* non-extractable */, ['encrypt', 'decrypt']
  );
  await put('identity', 'wrap', k); // stored as a CryptoKey handle, not as bytes
  return k;
}

async function loadIdentity() {
  const key = await wrappingKey();
  const stored = await get('identity', 'device');

  if (stored) {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(stored.iv) }, key, stored.ct
    );
    const bytes = new Uint8Array(plain);
    const id = Identity.from_secret(bytes);
    bytes.fill(0);
    return id;
  }

  const id = new Identity();
  const secret = id.export_secret();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, secret);
  secret.fill(0);
  await put('identity', 'device', { iv: Array.from(iv), ct });
  return id;
}

const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

// ---------------------------------------------------------------------------
// display
// ---------------------------------------------------------------------------

const $ = (id) => document.getElementById(id);

function paint(canvas, qr) {
  const luma = qr.luma, w = qr.width, h = qr.height;
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext('2d', { alpha: false });
  const img = ctx.createImageData(w, h);
  for (let i = 0, j = 0; i < luma.length; i++, j += 4) {
    img.data[j] = img.data[j + 1] = img.data[j + 2] = luma[i];
    img.data[j + 3] = 255;
  }
  ctx.putImageData(img, 0, 0);
}

// ---------------------------------------------------------------------------
// the viewfinder
// ---------------------------------------------------------------------------

// Aiming used to be blind. The camera ran with no preview at all, and the first
// confirmation that it was pointed at anything was a click, which does not
// happen until a symbol has already landed. Everything before that — is the code
// in frame, is it in focus, is the room too dark — the user had to infer from
// silence.
//
// So: a live preview under the display, and one word that says what the decoder
// is actually doing with those pixels. The word is the point. Video alone shows
// you a QR code sitting in frame and tells you nothing about whether it decodes,
// which is the only question being asked.
//
// The rule this module lives by: it is on the camera path, so it must cost
// nothing. No second canvas, no extra pixel copy, and no DOM write on a frame
// where nothing changed.

const SIGHT_LOCK_MS = 700;     // decode gap still counted as a lock
const SIGHT_SETTLE_MS = 1200;  // steady lock before the preview stands down
// Both thresholds are guesses from the synthetic optical loop, not measurements
// from a sensor, and no camera has run this code yet. They are deliberately
// conservative: the cost of a threshold that is too shy is a word that never
// appears, and the cost of one that is too eager is a receiver being told to
// turn a light on in a room that is already lit.
const DARK_SPREAD = 46;        // luma range below which QR decoding is hopeless
const DARK_MEAN = 62;

// Seeded from the markup rather than restated here. Two defaults that can
// disagree is exactly how the first sightSize() call gets swallowed as a no-op
// and the preview opens at the wrong size for the rest of the session.
const sight = {
  word: $('sight-word').textContent,
  tone: $('sight').dataset.tone,
  size: $('sight').dataset.size,
  manual: false,
  lastDecode: 0,
  lockedSince: 0,
};

function sightSay(word, tone) {
  if (word === sight.word && tone === sight.tone) return; // no DOM per frame
  sight.word = word;
  sight.tone = tone;
  $('sight-word').textContent = word;
  $('sight').dataset.tone = tone;
}

// Two sizes. `align` is exactly 16:9, the sensor's own ratio, so the preview is
// pixel-for-pixel what the decoder is handed — that is the size to trust when
// alignment is the problem. `glance` crops to a strip for when it is not.
function sightSize(size, force = false) {
  if (size === sight.size || (sight.manual && !force)) return;
  sight.size = size;
  $('sight').dataset.size = size;
  $('sight-resize').textContent =
    size === 'align' ? 'Shrink camera preview' : 'Enlarge camera preview';
}

// One camera, one preview, one owner. Both scan paths open their stream through
// here, so there is exactly one thing on screen that knows whether the camera is
// live, and it cannot disagree with the hardware.
async function openCamera(constraints) {
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: constraints });
  } catch (e) {
    sightSay('blocked', 'warn');
    throw e;
  }
  const video = $('camera');
  video.srcObject = stream;
  await video.play();

  // Fade in when the element actually has a frame, not when play() resolves:
  // play() returns before there is anything to show, and fading up an empty
  // rectangle reads as a glitch rather than as a camera starting.
  const live = () => $('sight').classList.add('live');
  if (video.readyState >= 2) live();
  else video.addEventListener('loadeddata', live, { once: true });

  sight.lastDecode = 0;
  sight.lockedSince = 0;
  sightSay('searching', 'find');
  sightSize('align');
  return { stream, video };
}

function closeCamera(stream, word = 'off', tone = 'off') {
  stream?.getTracks().forEach((t) => t.stop());
  $('sight').classList.remove('live');
  sight.lockedSince = 0;
  sightSay(word, tone);
  // A camera that is off has nothing to aim, so it does not get to hold a third
  // of the screen. This is most of a sender's transfer: the display is the
  // surface that matters there, and the strip stays only to say the camera is
  // not running.
  sightSize('glance');
}

// Called once per camera frame from both scan loops.
function sightFrame(now, decoded, luma) {
  if (decoded) {
    if (!sight.lockedSince) sight.lockedSince = now;
    sight.lastDecode = now;
  } else if (now - sight.lastDecode > SIGHT_LOCK_MS) {
    sight.lockedSince = 0;
  }

  if (sight.lockedSince) {
    if (sight.word !== 'receiving') sightSay('locked', 'lock');
    // Stand down once the lock has held. Mid-transfer the useful readout is the
    // progress bar, and a large rectangle of handheld video competes with it.
    // It comes straight back the moment the lock breaks.
    if (now - sight.lockedSince > SIGHT_SETTLE_MS) sightSize('glance');
    return;
  }

  const dark = tooDark(luma);
  sightSay(dark ? 'too dark' : 'searching', dark ? 'warn' : 'find');
  sightSize('align');
}

// A stride sample, about 4k pixels out of two million. Not photometry: it exists
// so that "nothing is landing" can say why. QR decoding dies on dynamic range
// long before it dies on framing, and a receiver in a dim room otherwise gets a
// preview that looks fine and a transfer that never starts. Both conditions have
// to hold, so a bright scene with one dark corner never trips it.
function tooDark(luma) {
  let lo = 255, hi = 0, sum = 0, n = 0;
  const step = Math.max(1, (luma.length / 4096) | 0);
  for (let i = 0; i < luma.length; i += step) {
    const v = luma[i];
    if (v < lo) lo = v;
    if (v > hi) hi = v;
    sum += v;
    n++;
  }
  return n > 0 && hi - lo < DARK_SPREAD && sum / n < DARK_MEAN;
}

// ---------------------------------------------------------------------------
// audio feedback
// ---------------------------------------------------------------------------

// The receiver is looking at the sender's screen, not at their own, so the
// progress bar is not where the useful feedback goes. Geiger-counter clicks that
// speed up as symbols land let someone find the alignment sweet spot in about
// two seconds without being told anything. The Vibration API does not work in
// iOS Safari, so audio does this job alone.
let audio;
function click(rate) {
  if (!audio) audio = new (window.AudioContext || window.webkitAudioContext)();
  const t = audio.currentTime;
  const osc = audio.createOscillator();
  const gain = audio.createGain();
  osc.frequency.value = 420 + rate * 900;
  gain.gain.setValueAtTime(0.11, t);
  gain.gain.exponentialRampToValueAtTime(0.001, t + 0.035);
  osc.connect(gain).connect(audio.destination);
  osc.start(t);
  osc.stop(t + 0.04);
}

// ---------------------------------------------------------------------------
// receiving
// ---------------------------------------------------------------------------

let state = { role: 'idle', wakeLock: null, stop: false };

async function beReceiver() {
  const identity = await loadIdentity();
  const session = new Session(identity);

  // Read everything needed from the session BEFORE handing it to Receive.
  // wasm-bindgen passes it by value, which detaches the JS handle: any later
  // `session.x` throws "null pointer passed to rust". This is the classic
  // ownership trap at the JS/WASM boundary, and it crashed first launch.
  const pairReqBytes = session.pair_req;
  const recv = new Receive(session);

  // Resume is free with rateless coding, but only if the checkpoint is actually
  // read back. It was being written and never loaded, which meant a locked
  // phone silently restarted the whole transfer.
  const saved = await get('checkpoints', 'active');
  if (saved?.length) {
    recv.restore(saved.map((a) => new Uint8Array(a)));
    $('hint').textContent = `Resuming: ${saved.length} symbols already collected.`;
  }

  // Show the reverse QR immediately. Being a receiver is the resting state:
  // there is no role toggle to tap, and picking a file is what makes you a
  // sender instead.
  paint($('display'), render_qr(pairReqBytes, BEACON_ECC, 6));

  const { stream, video } = await openCamera({
    facingMode: 'environment', width: { ideal: 1920 }, height: { ideal: 1080 },
  });
  await takeWakeLock();

  const cv = document.createElement('canvas');
  const ctx = cv.getContext('2d', { alpha: false, willReadFrequently: true });

  let lastSymbol = performance.now();
  let sasShown = false;
  // Stall detection only means something once a transfer is actually underway.
  // A receiver at rest has nothing to receive, so counting from page load turns
  // the resting state into a permanent error message.
  let acquired = false;
  const RESTING = 'Point the sending device at this code';
  let currentHint = null;
  const setHint = (t) => {
    if (t === currentHint) return;      // avoid rewriting the DOM every frame
    currentHint = t;
    $('hint').textContent = t;
  };
  setHint(RESTING);

  // Re-arming lives in one place because forgetting it anywhere is not a
  // dropped frame, it is a receiver that never hears again.
  //
  // The .catch is the same concern generalised. onFrame is async and nothing
  // awaits it, so any throw anywhere inside it becomes an unhandled rejection
  // that skips the re-arm at the bottom and ends reception permanently, in
  // silence. Catching it here costs one frame instead of the session.
  const schedule = () => {
    if (state.stop) return;
    const run = () => onFrame().catch((e) => {
      console.warn('rabaska: frame dropped:', e.message);
      schedule();
    });
    if ('requestVideoFrameCallback' in video) video.requestVideoFrameCallback(run);
    else requestAnimationFrame(run);
  };

  const onFrame = async () => {
    if (state.stop) return;

    // A camera reports zero dimensions more often than it looks: before
    // metadata arrives, while the stream reconfigures, and on the way back from
    // a backgrounded tab. getImageData then throws IndexSizeError, and because
    // this callback is async and nothing awaits it the rejection is silent and
    // the loop below never re-arms. The receiver goes deaf for the rest of the
    // session while still displaying its code, which is indistinguishable from
    // a receiver that is simply waiting. scanOneFrame has always guarded this;
    // this loop did not.
    if (!video.videoWidth || !video.videoHeight) {
      schedule();
      return;
    }

    cv.width = video.videoWidth;
    cv.height = video.videoHeight;
    ctx.drawImage(video, 0, 0);
    const rgba = ctx.getImageData(0, 0, cv.width, cv.height).data;

    // Rec.709 luma. Doing this in JS costs a full-frame pass; Phase 2 moves it
    // into WASM alongside the homography, where it is nearly free.
    const luma = new Uint8Array(cv.width * cv.height);
    for (let i = 0, j = 0; i < luma.length; i++, j += 4) {
      luma[i] = (rgba[j] * 54 + rgba[j + 1] * 183 + rgba[j + 2] * 19) >> 8;
    }

    const frame = decode_qr(luma, cv.width, cv.height);
    sightFrame(performance.now(), frame != null, luma);

    if (frame) {
      // A staged payload plus a scanned PAIR_REQ flips this device from
      // receiver to sender. Frame type lives at offset 3, after magic and
      // version; 0x01 is PAIR_REQ. Checking it here rather than handing it to
      // ingest() keeps the receiver from logging an error for a frame that is
      // simply meant for the other role.
      if (staged && frame.length > 3 && frame[3] === 0x01) {
        state.stop = true;
        closeCamera(stream);
        $('scan-to-send').hidden = true;
        setTimeout(async () => {
          state.stop = false;
          await beSender(staged, frame);
          staged = null;
        }, 0);
        return;
      }

      const r = recv.ingest(frame);

      if (r.kind === 'beacon') {
        acquired = true;
        if (r.sas && !sasShown) {
          // First pairing. Show the digits AND the reveal frame. The reveal is
          // deliberately not displayed before this point: publishing the nonce
          // early destroys the commitment and reopens the grinding attack.
          sasShown = true;
          $('sas').textContent = r.sas;
          $('sas-panel').hidden = false;
          paint($('display'), render_qr(recv.session_reveal(), BEACON_ECC, 6));
          setHint('Let the other device scan this, then compare digits.');
        }
        const peer = recv.peer_build_hash;
        if (peer) $('peer-build').textContent = hex(peer);
      }

      if (r.kind === 'progress' || r.kind === 'beacon') {
        lastSymbol = performance.now();
        sightSay('receiving', 'lock');
        click(r.fraction);
        setProgress(r.fraction, r.received, r.needed);
      }

      if (r.kind === 'done') {
        await finish(recv, r.payload);
        return;
      }

      // An error result is not noise. AuthFailed in particular means the tag
      // rejected a fully reassembled object, which is tampering or a wrong key,
      // never ordinary channel corruption. Swallowing it hid the one signal
      // worth acting on.
      if (r.kind.startsWith('error')) {
        if (r.kind.includes('authentication')) {
          state.stop = true;
          closeCamera(stream, 'stopped', 'warn');
          currentHint = null;
          $('hint').textContent =
            'Authentication failed. The data was altered in transit, or the '
            + 'wrong device answered. Nothing was written. Start over.';
          $('hint').classList.add('danger');
          return;
        }
        console.warn('rabaska:', r.kind);
      }
    }

    if (acquired) {
      setHint(performance.now() - lastSymbol > STALL_MS
        ? 'No frames landing. Check alignment and screen brightness.'
        : 'Receiving. Hold steady.');
    }

    schedule();
  };

  schedule();

  // Rateless coding means resume is free: lock the phone, walk away, come back,
  // keep collecting. There is never a restart.
  setInterval(async () => {
    if (state.role !== 'receive') return;
    const pk = recv.checkpoint();
    if (pk.length) await put('checkpoints', 'active', pk.map((a) => Array.from(a)));
  }, 2000);

  state.role = 'receive';
}

async function finish(recv, payload) {
  closeCamera($('camera').srcObject, 'done', 'ok');
  setProgress(1, 1, 1);
  $('hint').textContent = 'Verified. Delivered.';

  // The only feedback in the whole system. Turns "probably delivered" into
  // "verified delivered", which for a key transfer is the difference that matters.
  const complete = recv.complete_frame(payload, true);
  if (complete) paint($('display'), render_qr(complete, BEACON_ECC, 8));

  const blob = new Blob([payload], { type: 'application/octet-stream' });
  const a = $('download');
  a.href = URL.createObjectURL(blob);
  a.download = 'rabaska-payload.bin';
  a.hidden = false;
  await tx('checkpoints', 'readwrite', (o) => o.delete('active'));
}

function setProgress(fraction, received, needed) {
  const bar = $('bar');
  bar.style.width = `${Math.round(fraction * 100)}%`;
  // RaptorQ wants K plus about two, so this saturates just under 1.0. Pulse
  // "verifying" rather than sticking at 99% and looking broken.
  $('count').textContent = fraction >= 0.99
    ? 'verifying'
    : `${received} / ${needed} symbols`;
}

// ---------------------------------------------------------------------------
// sending
// ---------------------------------------------------------------------------

async function beSender(payload, pairReqBytes) {
  const identity = await loadIdentity();
  const bh = currentBuildHash();

  const cap = qr_capacity(LADDER[0].version, LADDER[0].ecc);
  const send = Send.reply(pairReqBytes, payload, identity, null, bh, cap);

  if (send.sas) {
    $('sas').textContent = send.sas;
    $('sas-panel').hidden = false;
  }

  // Time estimate BEFORE the transfer, so nobody commits to three minutes of
  // holding a phone steady without knowing.
  const perFrame = cap - 19;
  const est = (send.wire_bytes / perFrame) / DISPLAY_FPS / 0.7;
  $('hint').textContent = send.wire_bytes < 4096
    ? 'About a second. Hold steady.'
    : `About ${Math.ceil(est)}s. ${send.compressed ? 'Compressed. ' : ''}Hold steady.`;

  await takeWakeLock();
  $('brightness-hint').hidden = false; // cannot set brightness from the web

  let i = 0;
  const tick = () => {
    if (state.stop) return;
    const rung = SCHEDULE[i % SCHEDULE.length];
    const f = send.next_frame(qr_capacity(rung.version, rung.ecc));
    // Beacons always go out on the robust rung regardless of the active
    // density, like an 802.11 preamble at the lowest modulation rate.
    const ecc = f.robust ? BEACON_ECC : rung.ecc;
    paint($('display'), render_qr(f.bytes, ecc, 5));
    i++;
    setTimeout(tick, 1000 / DISPLAY_FPS);
  };
  // The display loop starts FIRST and unconditionally. While the transmitter
  // is held it emits only beacons, and the receiver needs to see one before it
  // will show its reveal. Sequencing display after the scan deadlocks both
  // devices: each waits for a frame the other has not shown yet. The two
  // devices face each other during this phase, screen to camera both ways,
  // which is inherent to the handshake and lasts a second.
  tick();
  state.role = 'send';

  (async () => {
    // PAIR mode: scan the reveal, open the commitment, confirm, release. The
    // payload is already encrypted, but a screen-in-the-middle would hold the
    // key, so nothing carrying it is displayed until the human confirms.
    if (send.held) {
      $('hint').textContent = 'Point this device at the other screen.';
      const reveal = await scanOneFrame(0x05);
      if (!reveal) return;
      let digits;
      try {
        digits = send.accept_reveal(reveal);
      } catch (e) {
        state.stop = true;
        $('hint').textContent = `Aborted: ${e.message}`;
        $('hint').classList.add('danger');
        return;
      }
      // The aiming instruction has been satisfied by the time the reveal
      // lands, and leaving it up tells someone to keep pointing the phone while
      // the screen is in fact asking them to read five digits and decide. This
      // is the one step in the product where a human is the security boundary,
      // so the instruction has to be the one they are actually being given.
      $('hint').textContent = 'Compare the digits with the other screen.';
      $('sas').textContent = digits;
      $('sas-panel').hidden = false;
      $('sas-confirm').hidden = false;
      await new Promise((res) => { $('sas-confirm').onclick = res; });
      $('sas-confirm').hidden = true;
      $('sas-panel').hidden = true;
      send.release();
      $('hint').textContent = 'Sending. Hold steady.';
    }

    // Delivery verification. One camera session at a time: this scan begins
    // only after the reveal scan has released its stream.
    const complete = await scanOneFrame(0x04);
    if (!complete) return;
    state.stop = true;
    let good = false;
    try { good = send.verify_complete(complete); } catch { good = false; }
    $('hint').textContent = good
      ? 'Verified delivered. The receiver has exactly what you sent.'
      : 'Receiver reported a mismatch. Do not assume delivery.';
    if (!good) $('hint').classList.add('danger');
  })();

  return send;
}

// Open the camera just long enough to catch one frame of a given type, then
// close it. Used for the REVEAL and COMPLETE scans on the sending device.
async function scanOneFrame(wantType) {
  const { stream, video } = await openCamera({
    facingMode: 'environment', width: { ideal: 1920 },
  });
  const cv = document.createElement('canvas');
  const ctx = cv.getContext('2d', { alpha: false, willReadFrequently: true });

  try {
    for (;;) {
      await new Promise((r) => setTimeout(r, 1000 / 15));
      if (state.stop) return null;
      cv.width = video.videoWidth; cv.height = video.videoHeight;
      if (!cv.width) continue;
      ctx.drawImage(video, 0, 0);
      const d = ctx.getImageData(0, 0, cv.width, cv.height).data;
      const luma = new Uint8Array(cv.width * cv.height);
      for (let i = 0, j = 0; i < luma.length; i++, j += 4) {
        luma[i] = (d[j] * 54 + d[j + 1] * 183 + d[j + 2] * 19) >> 8;
      }
      const f = decode_qr(luma, cv.width, cv.height);
      // A decode of the wrong frame type still proves aim: the camera is on a
      // screen and reading it. Report it as a lock, then keep waiting.
      sightFrame(performance.now(), f != null, luma);
      if (f && f.length > 3 && f[3] === wantType) return f;
    }
  } finally {
    closeCamera(stream);
  }
}

// ---------------------------------------------------------------------------
// platform
// ---------------------------------------------------------------------------

async function takeWakeLock() {
  try {
    state.wakeLock = await navigator.wakeLock.request('screen');
  } catch {
    // Safari 16.4+ supports this. Older, or denied: the screen may sleep and
    // the transfer stalls rather than fails. Rateless means it resumes.
  }
}

// The chip in the header is the product's headline claim in four letters, and
// it is the two-second test a sceptical user runs. So it reports rather than
// asserts: it reads "offline" only once a worker is active, which is the only
// state in which turning the network off actually leaves a working app.
//
// It says "online only" instead of nothing when the worker never installs. That
// case is not hypothetical — the deployed CSP forbade the precache's own
// fetches, and because a rejected install is silent, the app looked perfect
// while being entirely dependent on the network.
function setOfflineChip(state) {
  $('offline-chip').dataset.state = state;
  $('offline-word').textContent = state === 'ready' ? 'offline' : 'online only';
  $('offline-chip').title = state === 'ready'
    ? 'Precached. Turn the network off and this still works.'
    : 'No service worker installed: nothing is cached and this still needs the network.';
}

async function trackOfflineReadiness(reg) {
  navigator.serviceWorker.addEventListener('message', (e) => {
    if (e.data?.precacheFailed) console.error('rabaska: precache failed:', e.data.precacheFailed);
  });
  // Polled rather than chased through statechange events. The worker moves
  // installing -> installed -> activating -> activated across three different
  // registration slots, and tracking that correctly is far more code than one
  // chip is worth.
  const deadline = performance.now() + 10000;
  while (performance.now() < deadline) {
    if (reg.active) return setOfflineChip('ready');
    await new Promise((r) => setTimeout(r, 250));
  }
  setOfflineChip('none');
}

// No fetch anywhere in this file. The CSP sets connect-src 'none', so a fetch
// would not merely be impolite, it would throw. The build hash is stamped in at
// build time instead of being recomputed at runtime.
function currentBuildHash() {
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i++) out[i] = parseInt(BUILD.substr(i * 2, 2), 16);
  return out;
}

async function main() {
  // Instantiate from the inlined bytes rather than letting the generated glue
  // fetch the .wasm file, which connect-src 'none' would block.
  await init(WASM_BYTES);
  db = await openDb();

  // Ask for durable storage. Uninstalled Safari sites are evicted after seven
  // days of non-use, which silently deletes every stored pairing. Installed
  // home-screen apps have historically been exempt, but verify rather than
  // assume, and treat uninstalled as the ephemeral tier.
  if (navigator.storage?.persist) {
    const durable = await navigator.storage.persist();
    if (!durable) $('storage-warning').hidden = false;
  }

  $('own-build').textContent = hex(currentBuildHash());
  $('symbol-size').textContent = default_symbol_size();

  // One tap on the preview resizes it, and after that tap it stops resizing
  // itself. A control that keeps moving after you have positioned it is worse
  // than one that never moved.
  $('sight-resize').onclick = () => {
    sight.manual = true;
    sightSize(sight.size === 'align' ? 'glance' : 'align', true);
  };

  if ('serviceWorker' in navigator) {
    const reg = await navigator.serviceWorker.register('./sw.js');
    // Parked update, never automatic. See sw.js.
    reg.addEventListener('updatefound', () => {
      $('update-panel').hidden = false;
    });
    $('update-now').onclick = () => {
      reg.waiting?.postMessage('rabaska:activate-update');
      location.reload();
    };
    trackOfflineReadiness(reg); // deliberately not awaited: boot does not wait
  } else {
    setOfflineChip('none');
  }

  // Role is implied, not chosen: on open you are a receiver showing your code,
  // and picking a file makes you a sender. One less decision, one less tap.
  await beReceiver();

  // Photos and paste are first class. Web Share Target is Android-only, so on
  // iOS a file cannot arrive from the system share sheet and must come through
  // a picker; making the clipboard path prominent covers keys and configs,
  // which is most of what this app moves.
  $('file').onchange = async (e) => {
    const f = e.target.files[0];
    if (f) stageSend(new Uint8Array(await f.arrayBuffer()));
  };
  $('paste').onclick = async () => {
    const t = await navigator.clipboard.readText();
    if (t) stageSend(new TextEncoder().encode(t));
  };
}

let staged = null;
function stageSend(bytes) {
  staged = bytes;
  $('hint').textContent = `${bytes.length} bytes ready. Scan the other device's code.`;
  $('scan-to-send').hidden = false;
}

main().catch((e) => {
  $('hint').textContent = `Startup failed: ${e.message}`;
});
