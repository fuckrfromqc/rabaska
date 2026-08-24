//! The boundary between Rust and the browser.
//!
//! Design rule, and the reason this module exists rather than exposing the core
//! types directly: **no private key material ever crosses this boundary.**
//! Secrets live in WASM linear memory for their whole lifetime and are zeroized
//! on drop. JavaScript gets opaque handles, public keys, and plaintext results.
//! There is no `get_private_key` and there must never be one, because a `[u8;32]`
//! handed to JS becomes an unreclaimable copy in a garbage-collected heap that
//! cannot be reliably wiped.
//!
//! The one exception is [`Identity::export_sealed`], which is deliberate: an
//! identity key must survive a browser storage eviction, and the export is
//! encrypted under a passphrase before it leaves.

use wasm_bindgen::prelude::*;

use crate::crypto::{self, KeyPair, Role};
use crate::pipeline::{Frame, Ingest, Receiver, TransmitConfig, Transmitter};
use crate::wire::{self, CodecParams, Mode, PairReq, Reveal, Status};

/// Install a panic hook that surfaces Rust panics in the browser console
/// instead of an opaque `unreachable executed`.
#[wasm_bindgen(start)]
pub fn start() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

// ---------------------------------------------------------------------------
// identity
// ---------------------------------------------------------------------------

/// A long-term device identity. Generated once on first launch and stored.
#[wasm_bindgen]
pub struct Identity {
    inner: KeyPair,
}

#[wasm_bindgen]
impl Identity {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Identity {
        Identity {
            inner: KeyPair::generate(),
        }
    }

    /// Restore from a previously exported secret. See the module warning.
    pub fn from_secret(bytes: &[u8]) -> Result<Identity, JsError> {
        let b: [u8; 32] = bytes
            .try_into()
            .map_err(|_| JsError::new("identity secret must be 32 bytes"))?;
        Ok(Identity {
            inner: KeyPair::from_bytes(b),
        })
    }

    #[wasm_bindgen(getter)]
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.public().to_vec()
    }

    /// Four-byte lookup key a peer puts in its PAIR_REQ so we can find the
    /// stored pairing without a round trip.
    #[wasm_bindgen(getter)]
    pub fn hint(&self) -> Vec<u8> {
        crypto::id_hint(&self.inner.public()).to_vec()
    }

    /// Base32 with a checksum group, for the typed-key bootstrap on a machine
    /// with no camera and no microphone. Miserable for thirty seconds, then
    /// stored forever.
    #[wasm_bindgen(getter)]
    pub fn public_key_typed(&self) -> String {
        base32_groups(&self.inner.public())
    }

    /// Raw secret, for persisting to IndexedDB as a non-extractable key handle.
    /// The caller must not let this reach a plain JS array that outlives the
    /// storage write.
    pub fn export_secret(&self) -> Vec<u8> {
        self.inner.secret_bytes().to_vec()
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// receiver side: pairing
// ---------------------------------------------------------------------------

/// The receiver's half of a session. Holds the ephemeral key, so it must outlive
/// the PAIR_REQ it produced.
#[wasm_bindgen]
pub struct Session {
    eph: KeyPair,
    session_id: [u8; 8],
    identity: Option<KeyPair>,
    /// Committed in PAIR_REQ, revealed only after the sender's beacon arrives.
    /// This is what stops a screen-in-the-middle grinding its way to a matching
    /// SAS. See `crypto::commit`.
    r_nonce: [u8; 16],
}

#[wasm_bindgen]
impl Session {
    /// Start a receiving session. Pass the device identity to enable SESSION
    /// mode with already-paired senders; pass nothing for a first meeting.
    #[wasm_bindgen(constructor)]
    pub fn new(identity: Option<Identity>) -> Session {
        Session {
            eph: KeyPair::generate(),
            session_id: crypto::random_session_id(),
            identity: identity.map(|i| i.inner),
            r_nonce: crypto::random_nonce16(),
        }
    }

    /// The reverse QR: 53 bytes, rendered at v6 ECC-H so it acquires from across
    /// a room.
    #[wasm_bindgen(getter)]
    pub fn pair_req(&self) -> Vec<u8> {
        let (flags, hint) = match &self.identity {
            Some(id) => (wire::flags::HAS_ID_HINT, crypto::id_hint(&id.public())),
            None => (0, [0u8; 4]),
        };
        PairReq {
            flags,
            session_id: self.session_id,
            r_eph_pub: self.eph.public(),
            id_hint: hint,
            r_commit: crypto::commit(&self.session_id, &self.eph.public(), &self.r_nonce),
        }
        .encode()
    }

    #[wasm_bindgen(getter)]
    pub fn eph_public(&self) -> Vec<u8> {
        self.eph.public().to_vec()
    }

    /// The reveal frame. Display this ONLY after the sender's beacon has been
    /// decoded: showing it earlier destroys the commitment and reopens the
    /// grinding attack it exists to close.
    #[wasm_bindgen(getter)]
    pub fn reveal(&self) -> Vec<u8> {
        Reveal {
            sid4: self.session_id[0..4].try_into().unwrap(),
            r_nonce: self.r_nonce,
        }
        .encode()
    }

    /// Five digits both humans compare on a first pairing. A mismatch is a hard
    /// abort with no retry: the only reason to retry the same keys is that an
    /// attacker is asking you to.
    pub fn sas(&self, s_eph_pub: &[u8]) -> Result<String, JsError> {
        let s: [u8; 32] = s_eph_pub.try_into().map_err(|_| bad_key())?;
        Ok(crypto::sas(
            &self.session_id,
            &self.eph.public(),
            &s,
            &self.r_nonce,
        ))
    }
}

// ---------------------------------------------------------------------------
// receive
// ---------------------------------------------------------------------------

/// Result of feeding one decoded optical frame. Mirrors [`Ingest`] across the
/// boundary, because `wasm_bindgen` cannot carry a Rust enum with payloads.
#[wasm_bindgen]
pub struct IngestResult {
    kind: String,
    received: usize,
    needed: usize,
    payload: Option<Vec<u8>>,
    sas: Option<String>,
}

#[wasm_bindgen]
impl IngestResult {
    /// One of: "ignored", "beacon", "progress", "done", "error".
    #[wasm_bindgen(getter)]
    pub fn kind(&self) -> String {
        self.kind.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn received(&self) -> usize {
        self.received
    }
    #[wasm_bindgen(getter)]
    pub fn needed(&self) -> usize {
        self.needed
    }
    /// Monotonic 0..1. Saturates just under 1.0 because RaptorQ wants K plus
    /// about two, so the UI should pulse "verifying" rather than stick at 99%.
    #[wasm_bindgen(getter)]
    pub fn fraction(&self) -> f32 {
        if self.needed == 0 {
            0.0
        } else {
            (self.received as f32 / self.needed as f32).min(1.0)
        }
    }
    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> Option<Vec<u8>> {
        self.payload.clone()
    }
    /// Present exactly once, on the "beacon" result of a first pairing.
    #[wasm_bindgen(getter)]
    pub fn sas(&self) -> Option<String> {
        self.sas.clone()
    }
}

#[wasm_bindgen]
pub struct Receive {
    rx: Receiver,
    session: Session,
    peer_identity: Option<[u8; 32]>,
    keyed: bool,
}

#[wasm_bindgen]
impl Receive {
    #[wasm_bindgen(constructor)]
    pub fn new(session: Session) -> Receive {
        Receive {
            rx: Receiver::new(),
            session,
            peer_identity: None,
            keyed: false,
        }
    }

    /// Supply a stored sender identity so a beacon in SESSION mode can be keyed
    /// without a SAS. Look it up by the build hint before the stream starts.
    pub fn set_peer_identity(&mut self, pubkey: &[u8]) -> Result<(), JsError> {
        self.peer_identity = Some(pubkey.try_into().map_err(|_| bad_key())?);
        Ok(())
    }

    /// Restore checkpointed symbols. Lock the phone, walk away, come back, keep
    /// collecting. Rateless coding means there is no restart.
    pub fn restore(&mut self, packets: Vec<js_sys::Uint8Array>) {
        let v: Vec<Vec<u8>> = packets.iter().map(|a| a.to_vec()).collect();
        self.rx.restore(v);
    }

    /// Symbols collected so far, for checkpointing to IndexedDB.
    pub fn checkpoint(&self) -> Vec<js_sys::Uint8Array> {
        self.rx
            .checkpoint()
            .iter()
            .map(|p| js_sys::Uint8Array::from(&p[..]))
            .collect()
    }

    /// Feed one decoded optical frame.
    ///
    /// Errors here are per-frame and non-fatal by design: a torn or corrupt
    /// frame is discarded and costs only time, because the fountain layer does
    /// not care what it loses. The caller should log and carry on.
    pub fn ingest(&mut self, frame: &[u8]) -> IngestResult {
        match self.rx.ingest(frame) {
            Ok(Ingest::BeaconAcquired) => {
                let sas = match self.derive_and_set() {
                    Ok(s) => s,
                    Err(e) => return err_result(&e),
                };
                let (received, needed) = self.rx.progress();
                IngestResult {
                    kind: "beacon".into(),
                    received,
                    needed,
                    payload: None,
                    sas,
                }
            }
            Ok(Ingest::Progress { received, needed }) => IngestResult {
                kind: "progress".into(),
                received,
                needed,
                payload: None,
                sas: None,
            },
            Ok(Ingest::Done { plaintext }) => {
                let (received, needed) = self.rx.progress();
                IngestResult {
                    kind: "done".into(),
                    received,
                    needed,
                    payload: Some(plaintext),
                    sas: None,
                }
            }
            Ok(Ingest::Ignored) => IngestResult {
                kind: "ignored".into(),
                received: 0,
                needed: 0,
                payload: None,
                sas: None,
            },
            Err(e) => err_result(&e.to_string()),
        }
    }

    fn derive_and_set(&mut self) -> Result<Option<String>, String> {
        if self.keyed {
            return Ok(None);
        }
        let b = self.rx.beacon().ok_or("beacon vanished")?.clone();
        let peer = crypto::Peer {
            eph_pub: b.s_eph_pub,
            id_pub: self.peer_identity.as_ref(),
        };
        // In SEAL mode the receiver's long-term identity does the key agreement,
        // because there is no reverse channel for an ephemeral to travel on.
        let own = match b.mode {
            Mode::Seal => self
                .session
                .identity
                .as_ref()
                .ok_or("SEAL beacon needs a device identity, which this session has none of")?,
            _ => &self.session.eph,
        };
        let key = crypto::derive_for_mode(
            b.mode,
            Role::Receiver,
            own,
            self.session.identity.as_ref(),
            &peer,
            &b.session_id,
        )
        .map_err(|e| e.to_string())?;
        self.rx.set_key(key);
        self.keyed = true;

        Ok(match b.mode {
            Mode::Pair => Some(crypto::sas(
                &b.session_id,
                &self.session.eph.public(),
                &b.s_eph_pub,
                &self.session.r_nonce,
            )),
            _ => None,
        })
    }

    /// The COMPLETE frame the receiver displays for the sender to eyeball.
    /// Turns "probably delivered" into "verified delivered".
    pub fn complete_frame(&self, plaintext: &[u8], ok: bool) -> Option<Vec<u8>> {
        let status = if ok { Status::Ok } else { Status::HashMismatch };
        self.rx.complete_frame(plaintext, status)
    }

    /// Build hash carried in the beacon. Display it next to our own: two devices
    /// running different code is then visible in one glance, which is the
    /// cheapest defence against an origin serving different JavaScript to one side.
    #[wasm_bindgen(getter)]
    pub fn peer_build_hash(&self) -> Option<Vec<u8>> {
        self.rx.beacon().map(|b| b.build_hash.to_vec())
    }

    /// The receiver's reveal frame. Exposed here so the shell does not have to
    /// keep the `Session` alive separately after handing it to `Receive`.
    pub fn session_reveal(&self) -> Vec<u8> {
        self.session.reveal()
    }

    #[wasm_bindgen(getter)]
    pub fn mode(&self) -> Option<String> {
        self.rx
            .beacon()
            .map(|b| format!("{:?}", b.mode).to_lowercase())
    }
}

// ---------------------------------------------------------------------------
// send
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub struct Send {
    tx: Transmitter,
    sas: Option<String>,
    /// Retained so the revealed nonce can be checked against its commitment.
    pending: Option<PendingSas>,
}

struct PendingSas {
    session_id: [u8; 8],
    r_eph_pub: [u8; 32],
    s_eph_pub: [u8; 32],
    r_commit: [u8; 16],
}

#[wasm_bindgen]
impl Send {
    /// Reply to a scanned PAIR_REQ. Chooses SESSION automatically when the hint
    /// matches a stored peer, PAIR otherwise.
    ///
    /// `peer_identity` is the stored public key matching `pair_req`'s hint, or
    /// nothing for a first meeting.
    pub fn reply(
        pair_req: &[u8],
        payload: &[u8],
        identity: Option<Identity>,
        peer_identity: Option<js_sys::Uint8Array>,
        build_hash: &[u8],
        frame_capacity: usize,
    ) -> Result<Send, JsError> {
        let req = PairReq::decode(pair_req).map_err(|e| JsError::new(&e.to_string()))?;
        let eph = KeyPair::generate();
        let id = identity.map(|i| i.inner);
        let peer_id: Option<[u8; 32]> = match peer_identity {
            Some(a) => Some(a.to_vec().try_into().map_err(|_| bad_key())?),
            None => None,
        };

        let mode = match (&id, &peer_id) {
            (Some(_), Some(_)) => Mode::Session,
            _ => Mode::Pair,
        };
        let peer = crypto::Peer {
            eph_pub: req.r_eph_pub,
            id_pub: peer_id.as_ref(),
        };
        let key = crypto::derive_for_mode(
            mode,
            Role::Sender,
            &eph,
            id.as_ref(),
            &peer,
            &req.session_id,
        )
        .map_err(|e| JsError::new(&e.to_string()))?;

        let mut tx = Transmitter::new(
            &key,
            cfg(
                mode,
                req.session_id,
                eph.public(),
                build_hash,
                frame_capacity,
                id.is_some(),
            ),
            payload,
        );

        // PAIR mode holds the payload back until the human confirms. The
        // ciphertext exists but nothing carrying it is displayed, because if a
        // screen-in-the-middle is present, transmitting first and detecting
        // afterwards does not unsend the secret.
        let pending = match mode {
            Mode::Pair => {
                tx.hold();
                Some(PendingSas {
                    session_id: req.session_id,
                    r_eph_pub: req.r_eph_pub,
                    s_eph_pub: eph.public(),
                    r_commit: req.r_commit,
                })
            }
            _ => None,
        };

        Ok(Send {
            tx,
            sas: None,
            pending,
        })
    }

    /// One-pass send to a known receiver identity. No PAIR_REQ, no round trip,
    /// no camera required on this device. The path for a locked-down laptop or
    /// an air-gapped box: a screen means send, and a device with only a screen
    /// can send forever.
    pub fn seal(
        receiver_public_key: &[u8],
        payload: &[u8],
        identity: Option<Identity>,
        build_hash: &[u8],
        frame_capacity: usize,
    ) -> Result<Send, JsError> {
        let r_id: [u8; 32] = receiver_public_key.try_into().map_err(|_| bad_key())?;
        let eph = KeyPair::generate();
        let id = identity.map(|i| i.inner);
        let key = crypto::seal_sender(&eph, id.as_ref(), &r_id);
        let sid = crypto::random_session_id();
        Ok(Send {
            tx: Transmitter::new(
                &key,
                cfg(
                    Mode::Seal,
                    sid,
                    eph.public(),
                    build_hash,
                    frame_capacity,
                    id.is_some(),
                ),
                payload,
            ),
            sas: None,
            pending: None,
        })
    }

    /// Start an unencrypted transfer. Nothing to scan, no camera, no identity.
    ///
    /// The key comes from the session id and the sender's ephemeral public key,
    /// and both of those go out on screen in the clear. So the receiver needs no
    /// handshake to derive it — and neither does anyone else who can see the
    /// screen. This mode has no confidentiality. The domain string
    /// `rabaska/v2/open/no-confidentiality` says so, and the UI has to say so
    /// too, at the moment of choosing and for as long as it is transmitting.
    ///
    /// It earns its place because a locked-down machine with a screen and no
    /// camera can still hand a file to a phone, and because labelling that
    /// honestly is better than either pretending it is private or refusing to
    /// carry it at all. What it still provides is integrity: the payload is
    /// AEAD-sealed, so a receiver either gets exactly what was sent or gets a
    /// tag failure.
    pub fn open(payload: &[u8], build_hash: &[u8], frame_capacity: usize) -> Send {
        let eph = KeyPair::generate();
        let sid = crypto::random_session_id();
        let key = crypto::derive_open(&sid, &eph.public());
        Send {
            tx: Transmitter::new(
                &key,
                // sender_auth is false: there is no identity in this mode, so
                // there is nothing for the receiver to authenticate the sender by.
                cfg(
                    Mode::Open,
                    sid,
                    eph.public(),
                    build_hash,
                    frame_capacity,
                    false,
                ),
                payload,
            ),
            sas: None,
            pending: None,
        }
    }

    /// Next frame to display. Infinite: rateless coding means there is no end of
    /// transmission, so the loop runs until the human stops it.
    ///
    /// `capacity` is the usable byte budget of the rung being displayed, so the
    /// caller drives the interleaved density ladder by varying it per frame.
    pub fn next_frame(&mut self, capacity: usize) -> FrameOut {
        match self.tx.next_frame_at(capacity) {
            Frame::Beacon(b) => FrameOut {
                robust: true,
                bytes: b,
            },
            Frame::Symbol(b) => FrameOut {
                robust: false,
                bytes: b,
            },
        }
    }

    /// Feed the receiver's scanned REVEAL frame. Verifies the nonce against the
    /// commitment carried in PAIR_REQ and returns the five digits to display.
    ///
    /// A commitment mismatch means the nonce was chosen after the fact, which is
    /// the signature of the grinding attack. It is not a retryable condition.
    pub fn accept_reveal(&mut self, frame: &[u8]) -> Result<String, JsError> {
        let p = self
            .pending
            .as_ref()
            .ok_or_else(|| JsError::new("this session does not use a SAS"))?;
        let rv = Reveal::decode(frame).map_err(|e| JsError::new(&e.to_string()))?;
        if rv.sid4 != p.session_id[0..4] {
            return Err(JsError::new("reveal belongs to another session"));
        }
        if !crypto::verify_commit(&p.session_id, &p.r_eph_pub, &rv.r_nonce, &p.r_commit) {
            return Err(JsError::new(
                "commitment mismatch: the nonce was not the one committed to. Abort.",
            ));
        }
        let sas = crypto::sas(&p.session_id, &p.r_eph_pub, &p.s_eph_pub, &rv.r_nonce);
        self.sas = Some(sas.clone());
        Ok(sas)
    }

    /// Called only after the human confirms the digits match on both screens.
    pub fn release(&mut self) -> Result<(), JsError> {
        if self.pending.is_some() && self.sas.is_none() {
            return Err(JsError::new("cannot release before the SAS is confirmed"));
        }
        self.tx.release();
        Ok(())
    }

    #[wasm_bindgen(getter)]
    pub fn held(&self) -> bool {
        self.tx.is_held()
    }

    #[wasm_bindgen(getter)]
    pub fn sas(&self) -> Option<String> {
        self.sas.clone()
    }

    /// What the sender checks against the receiver's COMPLETE frame.
    #[wasm_bindgen(getter)]
    pub fn expected_hash(&self) -> Vec<u8> {
        self.tx.expected_hash().to_vec()
    }

    /// Ciphertext bytes the codec must carry, after sniffing and zstd. Multiply
    /// by the ladder's measured rate to show a time estimate *before* the
    /// transfer, so nobody commits to three minutes of holding a phone steady
    /// without knowing.
    #[wasm_bindgen(getter)]
    pub fn wire_bytes(&self) -> usize {
        let oti = self.tx.beacon().oti;
        let mut n = 0usize;
        for b in &oti[0..5] {
            n = (n << 8) | *b as usize;
        }
        n
    }

    #[wasm_bindgen(getter)]
    pub fn compressed(&self) -> bool {
        self.tx.beacon().compressed()
    }

    /// Verify a scanned COMPLETE frame against what we sent.
    pub fn verify_complete(&self, frame: &[u8]) -> Result<bool, JsError> {
        let c = wire::Complete::decode(frame).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(c.status == Status::Ok && c.hash8 == self.tx.expected_hash())
    }
}

#[wasm_bindgen]
pub struct FrameOut {
    robust: bool,
    bytes: Vec<u8>,
}

#[wasm_bindgen]
impl FrameOut {
    /// True for beacons, which always go out on the robust rung regardless of
    /// the active palette, like an 802.11 preamble at the lowest modulation rate.
    #[wasm_bindgen(getter)]
    pub fn robust(&self) -> bool {
        self.robust
    }
    #[wasm_bindgen(getter)]
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

// ---------------------------------------------------------------------------
// optical helpers
// ---------------------------------------------------------------------------

/// Render frame bytes to a QR luma buffer, one byte per pixel.
///
/// `ecc` is 0=L, 1=M, 2=Q, 3=H. Beacons and the reverse QR use H.
#[wasm_bindgen]
pub fn render_qr(data: &[u8], ecc: u8, scale: usize) -> Result<QrOut, JsError> {
    let e = match ecc {
        0 => crate::qr::Ecc::Low,
        1 => crate::qr::Ecc::Medium,
        2 => crate::qr::Ecc::Quartile,
        _ => crate::qr::Ecc::High,
    };
    let r =
        crate::qr::encode_luma(data, e, scale, 4).map_err(|err| JsError::new(&err.to_string()))?;
    Ok(QrOut {
        luma: r.luma,
        width: r.width,
        height: r.height,
    })
}

#[wasm_bindgen]
pub struct QrOut {
    luma: Vec<u8>,
    width: usize,
    height: usize,
}

#[wasm_bindgen]
impl QrOut {
    #[wasm_bindgen(getter)]
    pub fn luma(&self) -> Vec<u8> {
        self.luma.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn width(&self) -> usize {
        self.width
    }
    #[wasm_bindgen(getter)]
    pub fn height(&self) -> usize {
        self.height
    }
}

/// Decode a QR from a camera luma plane, as raw bytes.
///
/// Note the return type. Every QR API that hands back a `String` is unusable
/// here: a Rabaska frame is key material and ciphertext, never UTF-8, and a
/// decoder that coerces it to text either throws or silently substitutes
/// replacement characters. The second failure mode is the dangerous one, because
/// it looks like success.
#[cfg(feature = "qr-decode")]
#[wasm_bindgen]
pub fn decode_qr(luma: &[u8], width: usize, height: usize) -> Option<Vec<u8>> {
    crate::qr::decode_luma(luma, width, height).ok()
}

// ---------------------------------------------------------------------------
// payload envelope
// ---------------------------------------------------------------------------

/// Attach a filename and MIME type to a body before it enters the pipeline.
///
/// Call this on the sending side, on the bytes read from the file, before
/// handing them to `Send`. The metadata rides inside the plaintext, so it is
/// encrypted and authenticated with everything else. See `payload`.
#[wasm_bindgen]
pub fn payload_wrap(body: &[u8], name: &str, mime: &str) -> Vec<u8> {
    crate::payload::wrap(body, name, mime)
}

/// Split a delivered payload back into body and metadata.
///
/// Never fails: a payload with no envelope comes back whole with no metadata,
/// which is what a sender predating the envelope produces.
#[wasm_bindgen]
pub fn payload_unwrap(raw: &[u8]) -> PayloadOut {
    let p = crate::payload::unwrap(raw);
    PayloadOut {
        body: p.body,
        name: p.name,
        mime: p.mime,
    }
}

#[wasm_bindgen]
pub struct PayloadOut {
    body: Vec<u8>,
    name: Option<String>,
    mime: Option<String>,
}

#[wasm_bindgen]
impl PayloadOut {
    #[wasm_bindgen(getter)]
    pub fn body(&self) -> Vec<u8> {
        self.body.clone()
    }
    /// Sanitised, or nothing. Safe to use as a download filename.
    #[wasm_bindgen(getter)]
    pub fn name(&self) -> Option<String> {
        self.name.clone()
    }
    /// Allow-listed, or nothing. Safe to give a blob on this origin.
    #[wasm_bindgen(getter)]
    pub fn mime(&self) -> Option<String> {
        self.mime.clone()
    }
}

/// Usable byte budget of a QR rung, for driving the ladder from JS.
#[wasm_bindgen]
pub fn qr_capacity(version: u8, ecc: u8) -> usize {
    let e = match ecc {
        0 => crate::qr::Ecc::Low,
        1 => crate::qr::Ecc::Medium,
        2 => crate::qr::Ecc::Quartile,
        _ => crate::qr::Ecc::High,
    };
    crate::qr::capacity(version, e)
}

/// Eight-byte hash of the loaded bundle, displayed on both screens.
#[wasm_bindgen]
pub fn build_hash(bundle: &[u8]) -> Vec<u8> {
    crypto::build_hash(bundle).to_vec()
}

/// Symbol size the shipping ladder uses. Carried in the beacon; both ends must
/// agree, so this is the single source of truth.
#[wasm_bindgen]
pub fn default_symbol_size() -> u16 {
    CodecParams::default().symbol_size
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

fn bad_key() -> JsError {
    JsError::new("public keys must be 32 bytes")
}

fn err_result(msg: &str) -> IngestResult {
    IngestResult {
        kind: format!("error: {msg}"),
        received: 0,
        needed: 0,
        payload: None,
        sas: None,
    }
}

fn cfg(
    mode: Mode,
    session_id: [u8; 8],
    s_eph_pub: [u8; 32],
    build_hash: &[u8],
    frame_capacity: usize,
    sender_auth: bool,
) -> TransmitConfig {
    let mut bh = [0u8; 8];
    for (i, b) in build_hash.iter().take(8).enumerate() {
        bh[i] = *b;
    }
    TransmitConfig {
        mode,
        session_id,
        s_eph_pub,
        codec: CodecParams::default(),
        build_hash: bh,
        frame_capacity,
        sender_auth,
    }
}

/// Base32 in four-character groups with a trailing checksum group. For the
/// typed-key bootstrap on a device with neither camera nor microphone.
fn base32_groups(key: &[u8; 32]) -> String {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut bits = 0u32;
    let mut n = 0u32;
    let mut out = String::new();
    let mut count = 0;
    let mut push = |c: char, out: &mut String, count: &mut usize| {
        if *count > 0 && *count % 4 == 0 {
            out.push('-');
        }
        out.push(c);
        *count += 1;
    };
    for b in key {
        bits = (bits << 8) | *b as u32;
        n += 8;
        while n >= 5 {
            let idx = ((bits >> (n - 5)) & 0x1F) as usize;
            n -= 5;
            push(A[idx] as char, &mut out, &mut count);
        }
    }
    if n > 0 {
        let idx = ((bits << (5 - n)) & 0x1F) as usize;
        push(A[idx] as char, &mut out, &mut count);
    }
    // Checksum group: catches a transposed pair, which is the mistake humans
    // actually make when copying 52 characters by hand.
    let c = crypto::id_hint(key);
    out.push('-');
    for b in &c[0..2] {
        out.push(A[(b >> 3) as usize] as char);
        out.push(A[(b & 0x1F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `JsError` has no `Debug`, so `.unwrap()` will not compile in tests.
    /// Small shim rather than weakening the public signatures, which are the
    /// shape wasm-bindgen needs to throw a real JS exception.
    fn ok<T>(r: Result<T, JsError>) -> T {
        match r {
            Ok(v) => v,
            Err(_) => panic!("wasm boundary returned an error"),
        }
    }

    #[test]
    fn typed_key_is_checksummed_and_groups_cleanly() {
        let id = Identity::new();
        let t = id.public_key_typed();
        let groups: Vec<&str> = t.split('-').collect();
        // 256 bits at 5 bits per char is 52 characters, so 13 groups of four,
        // plus the checksum group.
        assert_eq!(groups.len(), 14, "got {t}");
        assert_eq!(groups.last().unwrap().len(), 4);
        assert!(t
            .chars()
            .all(|c| c == '-' || c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn typed_key_checksum_changes_with_the_key() {
        let a = Identity::new().public_key_typed();
        let b = Identity::new().public_key_typed();
        assert_ne!(a, b);
    }

    #[test]
    fn pair_flow_across_the_boundary() {
        // Exactly what the browser does, minus the pixels.
        let session = Session::new(None);
        let req = session.pair_req();
        let payload = b"[Interface]\nPrivateKey = wJ8mK2nQ5pR7tV9xA1cE3fH6jL0oS4uY8bD2=\n";
        let bh = build_hash(b"bundle-v1");

        let mut send = ok(Send::reply(&req, payload, None, None, &bh, 2953));
        assert!(
            send.held(),
            "PAIR mode must withhold payload until confirmed"
        );
        assert!(send.sas().is_none(), "no SAS before the reveal");

        let mut recv = Receive::new(session);
        let session_ref = &recv.session_reveal();

        // Beacon first, so the sender is committed before the nonce appears.
        let first = send.next_frame(2953);
        let r0 = recv.ingest(&first.bytes());
        assert_eq!(r0.kind(), "beacon");
        let receiver_sas = r0.sas().expect("receiver shows a SAS in PAIR mode");

        // Sender scans the reveal, checks the commitment, and only now can it
        // compute the digits.
        let sender_sas_val = ok(send.accept_reveal(session_ref));
        assert_eq!(
            sender_sas_val, receiver_sas,
            "SAS must match on both screens"
        );
        ok(send.release());

        let mut sender_sas: Option<String> = None;
        for _ in 0..2000 {
            let f = send.next_frame(2953);
            let r = recv.ingest(&f.bytes());
            match r.kind().as_str() {
                "beacon" => {
                    // Both sides must show the same five digits.
                    let a = r.sas();
                    assert!(a.is_some(), "PAIR mode must produce a SAS");
                    assert_eq!(a, sender_sas.take());
                }
                "done" => {
                    let p = r.payload().unwrap();
                    assert_eq!(p, payload);
                    let cf = recv.complete_frame(&p, true).unwrap();
                    assert!(ok(send.verify_complete(&cf)));
                    return;
                }
                k if k.starts_with("error") => panic!("{k}"),
                _ => {}
            }
        }
        panic!("pair flow did not converge");
    }

    #[test]
    fn seal_flow_needs_no_reverse_channel() {
        let device = Identity::new();
        let r_pub = device.public_key();
        let payload = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA...\n";
        let bh = build_hash(b"bundle-v1");

        let mut send = ok(Send::seal(&r_pub, payload, None, &bh, 997));
        // Receiver keys off its long-term identity, since nothing travelled back.
        let mut recv = Receive::new(Session::new(Some(device)));

        for _ in 0..2000 {
            let f = send.next_frame(997);
            let r = recv.ingest(&f.bytes());
            if r.kind() == "done" {
                assert_eq!(r.payload().unwrap(), payload);
                assert_eq!(recv.mode().unwrap(), "seal");
                return;
            }
            assert!(!r.kind().starts_with("error"), "{}", r.kind());
        }
        panic!("seal flow did not converge");
    }

    #[test]
    #[cfg(feature = "qr-decode")]
    fn full_optical_loop_through_the_wasm_api() {
        // Frames go out as pixels and come back as pixels. The only step missing
        // versus the real app is a lens.
        let session = Session::new(None);
        let req = session.pair_req();
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
        let bh = build_hash(b"bundle-v1");
        let cap = qr_capacity(40, 1);

        let mut send = ok(Send::reply(&req, &payload, None, None, &bh, cap));
        let mut recv = Receive::new(session);

        // Full PAIR handshake, every frame through pixels. The sender is held
        // until the commitment is opened and the digits agree, so a loop that
        // skips this step will spin on beacons forever, which is the intended
        // behaviour and is what this test asserted the hard way before the
        // handshake was added here.
        {
            let f = send.next_frame(cap);
            let img = ok(render_qr(&f.bytes(), 3, 4));
            let back = decode_qr(&img.luma(), img.width(), img.height()).unwrap();
            let r = recv.ingest(&back);
            assert_eq!(r.kind(), "beacon");
            let rsas = r.sas().unwrap();

            let rev = recv.session_reveal();
            let img = ok(render_qr(&rev, 3, 6));
            let scanned = decode_qr(&img.luma(), img.width(), img.height()).unwrap();
            let ssas = ok(send.accept_reveal(&scanned));
            assert_eq!(ssas, rsas);
            ok(send.release());
        }

        for i in 0..400 {
            let f = send.next_frame(cap);
            let ecc = if f.robust() { 3 } else { 1 };
            let img = ok(render_qr(&f.bytes(), ecc, 4));
            let back = decode_qr(&img.luma(), img.width(), img.height())
                .unwrap_or_else(|| panic!("frame {i} would not decode from pixels"));
            let r = recv.ingest(&back);
            if r.kind() == "done" {
                assert_eq!(r.payload().unwrap(), payload);
                return;
            }
        }
        panic!("optical loop did not converge");
    }

    #[test]
    fn wire_bytes_reports_the_real_carry_cost() {
        let session = Session::new(None);
        let req = session.pair_req();
        let text = "AllowedIPs = 0.0.0.0/0\n".repeat(500);
        let bh = build_hash(b"b");
        let send = ok(Send::reply(&req, text.as_bytes(), None, None, &bh, 2953));
        assert!(send.compressed());
        assert!(
            send.wire_bytes() * 4 < text.len(),
            "expected zstd to earn its keep: {} vs {}",
            send.wire_bytes(),
            text.len()
        );
    }
}
