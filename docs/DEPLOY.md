# Deploying Rabaska

macOS, from a terminal, to `rabaska.favreau.xyz` on Cloudflare Pages.

---

## 0. Toolchain

Rust, the wasm target, and wasm-pack. Everything else you already have.

```bash
# rustup, not brew's rust: the brew formula has no rustup, so
# `rustup target add` would fail two lines later.
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup target add wasm32-unknown-unknown
cargo install wasm-pack

brew install gh               # GitHub CLI
npm install -g wrangler
```

Sanity check before going further, because the wasm build is the one step that
has never run:

```bash
cd rabaska
cargo test --release --all
cargo test --release -p rabaska-core --features wasm
./build.sh
```

`build.sh` calls `wasm-pack`. There is no C in the tree, so this needs nothing
beyond rustup and the wasm32 target — no Xcode, no Homebrew LLVM.

Then look at it locally:

```bash
./build.sh && python3 tools/serve.py
```

Open `http://127.0.0.1:8080`. localhost counts as a secure context, so the
camera and the service worker both work.

Then the full flow, two devices, without leaving the machine:

```bash
python3 tools/serve.py dist 8095 &
python3 tools/serve.py dist 8094 &
npm i playwright && node tools/e2e.mjs
```

Two ports because two origins means two IndexedDBs and therefore two
identities; on one origin the pair would silently share one and the handshake
under test would not be the real one. It drives PAIR from both sides — beacon,
commitment, reveal, matching SAS on both screens, symbols, AEAD, completion
frame — and asserts the payload comes back byte for byte. The only substitution
is the camera: each page's `getUserMedia` returns a canvas whose contents are
the other page's `#display`. Everything between those two canvases is the
shipped code and the shipped wasm.

It cannot replace two phones. There is no blur, no rolling shutter, no
autofocus and no hands, so it proves the protocol and the shell are correct and
says nothing about whether the ladder is fast enough at arm's length.

And the phone layout invariants, on both CSS branches:

```bash
node tools/layout.mjs
```

The card must never exceed its cap, the video must stay inside the card, and
the page must never scroll sideways — checked at five viewports, twice each:
once as-is, and once with `style.css` rewritten so `svh` is a unit the browser
does not know. That second pass is the point. A `--w` fallback written as two
custom-property declarations silently shipped a full-bleed camera preview to
every browser without `svh`, and a headless Chromium screenshot looked perfect
because Chromium takes the other branch.

And the update flow, which needs two builds because that is what it is about:

```bash
./build.sh && cp -r dist /tmp/rabaska-old
# change anything the build hash covers
./build.sh && cp -r dist /tmp/rabaska-new
node tools/update.mjs /tmp/rabaska-old /tmp/rabaska-new
```

A first visit must offer no update, a genuinely new build must be parked and
offered once installed, and activating it must land on the new build rather
than serving the old one back out of the old worker's cache. It spawns its own
server through `tools/serve.py`, so `sw.js` arrives with `Cache-Control:
no-cache` and the browser will actually look for a replacement.

**Do not use `python3 -m http.server` for this.** It serves none of the headers
in `_headers`, so the CSP that governs production is simply absent and the app
you are looking at is not the app you deploy. That gap is not theoretical. Under
`http.server` the service worker installs cleanly and caches all twelve entries.
In production the `/*` CSP also lands on the worker script, and therefore on the
worker's own scope, where `connect-src 'none'` refuses every `cache.addAll`
fetch: install rejects, no worker activates, and the offline claim quietly stops
being true — with no error anywhere, because a failed install has no symptom
until the network goes away. `tools/serve.py` applies the real headers, which is
the only way to see that locally. `/sw.js` now carries its own CSP, and
`build.sh` fails the build if that ever regresses.

---

## 1. Repository

```bash
cd rabaska
git init -b main
git add -A
git commit -m "Rabaska: optical air-gap courier, protocol v2"

gh repo create rabaska --public --source=. --remote=origin --push
```

Public is the right call. Everything shipped to a browser is readable anyway, so
secrecy buys nothing, and for a tool whose pitch is "trust me with your private
keys" the source being open is the argument rather than the leak.

---

## 2. Cloudflare, on the website

No wrangler on the laptop. GitHub Actions builds and deploys; your part is a
token, two secrets, and three clicks for the domain.

### 2.1 API token

Cloudflare dashboard -> My Profile (top right) -> **API Tokens** -> Create
Token -> **Create Custom Token**:

- Name: `rabaska-deploy`
- Permissions: **Account / Cloudflare Pages / Edit** — that one row, nothing else
- Account Resources: your account
- Continue -> Create -> copy the token now, it is shown once

Your **Account ID** is on the dashboard right-hand sidebar of any zone
overview page (favreau.xyz works).

### 2.2 Repository secrets

Either on github.com (repo -> Settings -> Secrets and variables -> Actions ->
New repository secret, twice) or from the terminal:

```bash
gh secret set CLOUDFLARE_API_TOKEN     # paste the token
gh secret set CLOUDFLARE_ACCOUNT_ID    # paste the account id
```

### 2.3 Push

```bash
git push origin main
```

Actions runs `ci` (tests, protocol vectors, CSP invariants, the boundary
contract), and on success `deploy` builds the wasm, creates the Pages project
if it does not exist yet, and publishes. First run takes a few minutes because
of the Rust toolchain; later runs are cached. When it finishes, the site is
live at `rabaska.pages.dev`. Open that on your phone and confirm it boots
before attaching the domain.

### 2.4 Custom domain — three clicks

Dashboard -> **Workers & Pages** -> **rabaska** -> **Custom domains** ->
**Set up a domain** -> `rabaska.favreau.xyz` -> Continue.

Because `favreau.xyz` is already a zone in this account, Cloudflare creates the
CNAME and provisions the certificate itself. There is no working wrangler
subcommand for this step; `wrangler pages domain add` looks plausible and fails
with `Unknown arguments`, so the dashboard is the path, not the fallback.

### 2.5 Verify the enforcement is on

```bash
curl -sI https://rabaska.favreau.xyz | grep -iE "content-security|strict-transport"
```

Both headers must appear, and the CSP must contain `connect-src 'none'`. If
they are absent, `_headers` was not picked up and the app's central claim is
not being enforced — stop and investigate before using it for anything real.

The service worker's policy is separate and must also be checked:

```bash
curl -sI https://rabaska.favreau.xyz/sw.js | grep -i content-security
```

This one must say `connect-src 'self'`. If it says `'none'`, the more specific
`_headers` rule did not take precedence over `/*`, the precache cannot fetch,
and the app still needs the network on every load. Then run the test the README
promises: load the app, turn the network off, reload. It must come back. A
browser error page means no worker installed.

The app says so itself either way. The chip in the header reads `offline` only
once a worker is actually active, and `online only` when none is — it reports
the state rather than asserting the claim.

### 2.6 Zero Trust: leave Rabaska outside

Your other subdomains sit behind Cloudflare Access, so the reflex will be to
add a policy here too. Do not. There is nothing server-side to protect — no
API, no data, no state, just static files whose source is public — and an OTP
wall breaks the product: pairing a new device, or a friend's device, would
require them to pass your email challenge before their camera can even open.
The security model is the CSP, the keys, and the SAS, not the front door.

One optional refinement, and it is the pattern Cloudflare documents: put an
Access policy on the `rabaska.pages.dev` hostname only, so the custom domain is
the single public entry and the *.pages.dev twin is not floating around
unbranded. Zero Trust -> Access -> Applications -> Add -> Self-hosted ->
`rabaska.pages.dev`.

## 3. Automatic deploys thereafter

Already wired. Every push to `main` that passes CI deploys itself; a push that
changes a protocol constant fails CI at the vectors gate and never reaches the
network. The published build hash appears in the Action summary, and rebuilding
locally with `./build.sh` must reproduce it — that is the check that the
deployed bundle is the code in the repo.

## 4. First real test

Two devices, and the first run is where the untested surface lives.

1. Open the site on both. Add to Home Screen on the phone.
2. Turn off wifi and cellular on both. **The app must still work.** If it does
   not, the service worker did not install, and the browser console will say why.
3. Phone A shows its pairing code. Phone B: paste some text, then scan A's code.
4. B shows a beacon and holds. A shows five digits and its reveal code.
5. B scans the reveal, shows five digits. Compare. Tap send on B.
6. A receives, verifies, shows the completion code.

Watch for, in rough order of likelihood:

- **Camera permission re-prompting on every launch** in standalone mode. Known
  flaky across iOS versions. If it happens, the fix is to run from Safari rather
  than the home screen icon until it is understood.
- **Nothing decoding.** Screen brightness first, then distance. The v40 frames
  need a fair number of camera pixels per module. The viewfinder under the
  display now says which of those is wrong: `searching` means the camera is on
  and nothing is decoding, `too dark` means the luma probe found neither range
  nor brightness, `locked` means frames are being read.
- **A blank viewfinder while decoding still works.** The `<video>` is composited
  by the browser, not painted by us, so this is a CSS or a CSP question, not a
  camera one. Check the console for a `media-src` violation on the MediaStream:
  `blob:` is already allowed, which covers the browsers that back `srcObject`
  with a blob URL, but if a violation appears the fix is `mediastream:` in
  `media-src` and nothing else. Do not relax `connect-src`.
- **`scanOneFrame` failing to reopen the camera** after the receive loop stopped
  the tracks. This is the code path I am least confident in.
- **Storage warning appearing**, meaning `navigator.storage.persist()` was
  denied and pairings may not survive a week.

---

## If the build fails

There is no C in the dependency tree and no build script that shells out to a
compiler, which was a deliberate change: the earlier zstd dependency needed an
LLVM with a WebAssembly backend (Apple's clang has none) *and* a feature flag to
stop it feeding x86 assembly to a wasm target. Compression is now `miniz_oxide`,
pure Rust, roughly 3x on config text instead of 4x. On the payloads this product
carries the difference is one extra optical frame on the largest of them.

So a build failure here is almost certainly a stale toolchain:

```bash
rustup update
rustup target add wasm32-unknown-unknown
cargo install wasm-pack --force
cargo clean && ./build.sh
```

## Updating a deployed build

The service worker never updates silently. A new deploy is downloaded and parked,
and the user sees a prompt. That is deliberate: an attacker who compromises the
origin cannot push code to devices that already installed.

The consequence for you is that users stay on old builds until they act. During a
transfer both screens show their build hash in the footer, so a mismatch is
visible at a glance. That is also the manual check worth doing after any deploy
that changes the protocol.
