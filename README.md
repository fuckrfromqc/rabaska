# Rabaska

Optical air-gap courier. Move secrets between two devices with no network, no
pairing service, no accounts, and no server-side state, by pointing a camera at
a screen.

The name is the big Algonquin-style canoe: carries a lot in one crossing.

## Deploy

```bash
rustup target add wasm32-unknown-unknown && cargo install wasm-pack
cargo test --release --all && ./build.sh
cd dist && python3 -m http.server 8080
```

Full runbook in [docs/DEPLOY.md](docs/DEPLOY.md).

## Status

Phase 1. The protocol runs end to end across all four key agreement modes, and
frames now go out as real pixels and come back decoded from real pixels.

The browser shell has now been built and run. In headless Chromium, served with
the production headers: the wasm instantiates from its inlined bytes, the reverse
QR renders, `getUserMedia` opens, and a QR held in front of the camera decodes
through the wasm and reaches the receiver's pipeline. With the network cut, the
app reloads from its own precache and still does all of it.

`tools/e2e.mjs` runs the whole PAIR flow between two instances of the built app
on two origins, with each one's camera fed from the other's screen: beacon,
commitment, reveal, matching SAS on both sides, symbols, AEAD, completion frame,
and the payload asserted back byte for byte.

Still unrun: two real devices, two real cameras, one pointed at the other. A
synthetic camera feed has no blur, no rolling shutter, no autofocus and no human
holding it, and those are what the ladder exists for.

```
cargo test --release --all                       39 tests
cargo test -p rabaska-core --features wasm       45 tests
cargo run -p rabaska-harness -- modes   all four modes, end to end
cargo run -p rabaska-harness -- ladder  throughput model
cargo run -p rabaska-harness -- vectors frozen test vectors
```

## What exists

| Component | State |
|---|---|
| `docs/SPEC.md` | Wire format v1, frozen |
| `core/src/wire.rs` | Four frame types, CRC32, exhaustive bit-flip tests |
| `core/src/crypto.rs` | PAIR, SESSION, SEAL, OPEN. X25519, HKDF-SHA256, XChaCha20-Poly1305 |
| `core/src/pipeline.rs` | Sniff, zstd, AEAD, RaptorQ, transmitter and receiver state machines |
| `harness/` | End-to-end driver, channel model, vector generator |
| `vectors/v2.json` | Frozen. CI fails on any diff. |
| `core/src/qr.rs` | Byte-mode encode, luma render, decode. Measured capacities. |
| `core/src/wasm.rs` | Browser API surface. No private key crosses it. |
| `app/` | Shell, service worker, CSP. Runs: boots, decodes, works offline. |
| `app/` viewfinder | Live camera preview with a decode-state readout, for aiming. |
| `tools/serve.py` | Local server that applies `_headers`, so the CSP is enforced. |
| `tools/e2e.mjs` | Two app instances, screen to camera, full PAIR flow, byte-exact. |
| `tools/layout.mjs` | Phone layout invariants, on both the svh and no-svh branches. |
| `build.sh` | wasm-pack, base64 inlining, build stamping, precache manifest. |
| `codec/` | Not started. Phase 2. |

## Modes

| Mode | Round trips | Needs | Human step |
|---|---|---|---|
| `PAIR` | 1 (reverse QR) | nothing | compare 5 digits |
| `SESSION` | 1 (reverse QR) | stored identities | none |
| `SEAL` | 0 | receiver's identity key, out of band | none |
| `OPEN` | 0 | nothing | none, and no confidentiality |

`SEAL` is the camera-less sender path: a locked-down laptop, a headless box, an
air-gapped machine. Screen means send, camera means receive, and a device with
only a screen can send forever.

## v1 was withdrawn: the SAS was grindable

Found in review, before anything shipped. The v1 SAS hashed only the session id
and the two ephemeral public keys, and five digits is about 17 bits. The party
that reveals its key last can grind ~100k candidates in seconds until its SAS
matches the value the other leg is showing, so a screen-in-the-middle displays
identical digits on both screens while holding both halves of the conversation.
Reversing the reveal order does not help: an attacker is last on exactly one leg
either way. I had cited ZRTP for the construction and then omitted the
commitment that makes it work.

v2 adds it. The receiver commits to a nonce in `PAIR_REQ` and reveals it only
after the sender's beacon lands, and the sender withholds every payload symbol
until the digits are confirmed. `crypto::grinding_attack_is_closed` reproduces
the search and shows it finding nothing, with a negative control confirming the
search itself works.

Cost: one extra scan, on first pairing only. Every later transfer runs in
SESSION mode and skips the whole handshake.

## Two findings worth carrying forward

**Symbol size was badly chosen and it cost half the QR rung.** Phase 0 guessed
512. Measured against the real encoder, a v25-M QR holds 978 usable bytes, so a
516-byte packet fits once and wastes 462 bytes. Planning the symbol size against
all five ladder rungs gives 321: three packets in a v25-M frame, nine in a v40-L,
4.6% total idle bytes. The QR floor roughly doubled. The 1 MB tile case got about
7% worse, because the planner weights every rung equally and that favours the
small ones. For a courier whose payloads are keys and configs, that is the right
direction to lose in.

**Every QR API in circulation wants to hand back a string.** A Rabaska frame is
key material and ciphertext and will never be UTF-8. `rqrr::Grid::decode` runs
`String::from_utf8` and rejects every frame the app will ever send; jsQR's `.data`
silently substitutes replacement characters, which is worse, because it looks
like it worked. Decode to a byte sink: `decode_to` in Rust, `.binaryData` in JS.
There is a test that builds a deliberately invalid-UTF-8 frame and round-trips it
through pixels, and it asserts up front that the frame really is invalid UTF-8 so
the test cannot go vacuous.

## Measured

Simulated channel, 30 fps display, ladder of 1 QR : 2 four-colour : 4 eight-colour.
Effective rate is payload bytes per second, so it exceeds the optical rate
whenever zstd earned its keep.

| Payload | On wire | Tripod | Handheld | Dim room |
|---|---|---|---|---|
| Wireguard config (380 B) | 0.2 K | 0.07 s | 0.07 s | 0.10 s |
| SSH private key (3 KB) | 2.3 K | 0.07 s | 0.07 s | 0.10 s |
| TOTP vault, 300 entries (37 KB) | 6.9 K | 0.07 s | 0.07 s | 0.10 s |
| Photo (1 MB) | 977 K | 11.6 s | 39.1 s | 321 s |

Two readings, and both are the point:

Everything in the secrets-courier class completes in two or three frames under
every lighting condition tested, including the QR-only floor. Latency, not
throughput, is the metric that matters there, and it is under a tenth of a second.

The 1 MB row is the ergonomic ceiling made numeric. Holding two phones aligned
is pleasant for one second and miserable for forty. The protocol is correct at
100 MB; the product is not.

## Open risks

**Duplicate symbols were being counted.** The transmitter cycles a finite packet
pool forever, and the receiver counted every arrival including repeats. The
progress bar reached "verifying" well before decode could finish, and the resume
checkpoint grew without bound: roughly 100 MB of duplicates on the dim-room 1 MB
case. Now deduplicated on the RaptorQ PayloadId.

**The CSP and the wasm loader were incompatible.** `connect-src 'none'` blocks
`fetch`, which is exactly how `wasm-pack --target web` loads its module, so the
app would have died on `init()`. Rather than relax the header, which is the
mechanism behind the whole "nothing leaves this machine" claim, `build.sh`
inlines the wasm as base64 and instantiates from bytes. There is now no `fetch`
anywhere in the app, and CI fails if one reappears. It also makes the
single-file air-gap build fall out for free.

**The app shell has never executed.** Syntax is checked and every DOM id it
references exists, which is not the same as working. First run will find things,
and the iOS items below are where to look first.

**Phase 2 is the whole project.** Tile encode is a weekend. Real-time
homography, per-frame white balance inversion, and 16k tile classifications
under motion blur and OLED PWM banding at a 25 ms budget is not. The channel
model in `harness` is a model, and the per-rung decode probabilities in it are
guesses until measured on real device pairs. Build the calibration sweep first
and let it drive the tuning.

**No C in the dependency tree, deliberately.** zstd was the original choice and
it does not survive contact with a Mac: `zstd-sys` needs an LLVM with a
WebAssembly backend, which Apple's clang lacks, and separately feeds
`huf_decompress_amd64.S` to the wasm target unless its `no_asm` feature is set.
Two non-obvious requirements on every machine that ever builds this. Compression
is now `miniz_oxide` — pure Rust, no build script, ~3x on config text against
zstd's 4x. Measured cost across the real payloads: the 37 KB TOTP vault goes
from 6.9 K to 7.8 K on the wire, one extra optical frame, 0.03 s. Everything
else is unchanged, and photos are skipped by the sniffer regardless.

The decompressor is called with a 64 MB output limit so a hostile COMPRESSED
flag cannot inflate into unbounded memory.

**iOS, verify before building on it.** Camera permission persistence in
standalone PWA mode has been flaky across versions. Home-screen apps have
historically been exempt from the 7-day ITP storage eviction that would silently
delete every stored pairing, but WebKit revisits this. Web Share Target is
Android-only, so files enter through a picker. The Vibration API does not work,
so decode-rate feedback is audio only.

**`file://` is not a secure context**, so `getUserMedia` fails there. The
single-file offline build can send and can never receive. That is consistent
with the screen/camera asymmetry, but it needs saying in the UI rather than
discovering.

## Non-goals

Code secrecy. Everything shipped to a browser is readable, so security rests on
the keys. Publish it: for a tool whose pitch is "trust me with your private
keys," open source is the argument, not the leak.

Protection against a compromised device. There is no keychain access from the
web. An unlocked, compromised phone means compromised pairings, and the UI must
say so rather than imply otherwise.

Competing with AirDrop. AirDrop is faster inside the Apple boundary and always
will be. Rabaska crosses the boundary, works where radios are prohibited, and
reaches machines that have never touched a network.
