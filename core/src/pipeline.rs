//! Send and receive pipelines.
//!
//! Order is fixed and load-bearing:
//!
//! ```text
//! send:  plaintext -> sniff -> [deflate] -> XChaCha20-Poly1305 -> RaptorQ -> frames
//! recv:  frames -> RaptorQ -> XChaCha20-Poly1305 verify -> [inflate] -> plaintext
//! ```
//!
//! Compress before encrypt: ciphertext is incompressible by construction.
//! Encrypt before fountain-code: the Poly1305 tag covers the whole object and can
//! only be verified once reassembly completes anyway.

use std::collections::HashSet;

use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation};

use crate::crypto::{self, SessionKey};
use crate::wire::{self, Beacon, CodecParams, Complete, Mode, Status, SymbolFrame};
use crate::{Error, Result};

/// Deflate via `miniz_oxide`, not zstd, and the reason is toolchain fragility
/// rather than compression theory.
///
/// `zstd-sys` compiles C *and* hands an x86 assembly file to the compiler
/// unconditionally, so a wasm32 build needs an LLVM with the WebAssembly backend
/// (Apple's clang ships without one) plus zstd's `no_asm` feature. Two
/// non-obvious requirements on every machine that ever builds this, forever, and
/// a build that dies with several hundred lines of `cc-rs` output when either is
/// missing.
///
/// `miniz_oxide` is pure Rust with no build script. It builds wherever rustup
/// does, which is the whole requirement. The cost is ratio: roughly 3x on config
/// text where zstd manages 4x. For the payloads this product actually carries
/// that is invisible — a Wireguard config lands in one optical frame either way,
/// and a photo is skipped by the sniffer before compression is considered at
/// all. Ratio only begins to matter at sizes past the ergonomic ceiling of
/// holding two phones steady.
///
/// Level 9 is maximum. The payloads are kilobytes, so the CPU cost sits far
/// below the file-picker latency the user is already paying.
pub const DEFLATE_LEVEL: u8 = 9;

/// Below this, framing overhead swamps any ratio gain.
const MIN_COMPRESS_BYTES: usize = 256;

/// Repair packets generated per source block. RaptorQ needs K + ~2 symbols, so
/// this is a large margin; the transmitter cycles the pool indefinitely and the
/// receiver takes whatever it catches.
const REPAIR_PER_BLOCK: u32 = 15;

// ---------------------------------------------------------------------------
// compression
// ---------------------------------------------------------------------------

/// Magic-byte sniff for containers that are already compressed. Running zstd
/// over a JPEG costs two seconds and saves half a percent, so we skip it and
/// never show the user a setting.
pub fn is_already_compressed(b: &[u8]) -> bool {
    const MAGICS: &[&[u8]] = &[
        b"\xFF\xD8\xFF",      // JPEG
        b"\x89PNG\r\n\x1a\n", // PNG
        b"GIF87a",
        b"GIF89a",
        b"PK\x03\x04",         // zip family: docx, xlsx, pptx, apk, jar, epub
        b"\x1f\x8b",           // gzip
        b"\x28\xB5\x2F\xFD",   // zstd
        b"BZh",                // bzip2
        b"\xFD7zXZ\x00",       // xz
        b"7z\xBC\xAF\x27\x1C", // 7z
        b"Rar!\x1a\x07",
        b"%PDF", // usually already Flate-compressed internally
        b"OggS",
        b"fLaC",
        b"\x00\x00\x01\xBA", // MPEG-PS
    ];
    if MAGICS.iter().any(|m| b.starts_with(m)) {
        return true;
    }
    // ISO-BMFF (MP4, MOV, HEIC, HEIF, AVIF): 4-byte size then "ftyp".
    if b.len() >= 12 && &b[4..8] == b"ftyp" {
        return true;
    }
    // RIFF containers: WebP, AVI, WAV. WAV is compressible, the others are not.
    if b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] != b"WAVE" {
        return true;
    }
    false
}

fn maybe_compress(plain: &[u8]) -> (Vec<u8>, bool) {
    if plain.len() < MIN_COMPRESS_BYTES || is_already_compressed(plain) {
        return (plain.to_vec(), false);
    }
    // Only take the win if it is a real one. Shaving 0.5% off an unrecognised
    // container buys nothing and costs a decompression step plus a failure mode,
    // so require a margin rather than a strict improvement.
    let margin = plain.len() / 32; // 3%
    let z = miniz_oxide::deflate::compress_to_vec(plain, DEFLATE_LEVEL);
    if z.len() + margin < plain.len() {
        (z, true)
    } else {
        (plain.to_vec(), false)
    }
}

fn maybe_decompress(body: Vec<u8>, compressed: bool) -> Result<Vec<u8>> {
    if !compressed {
        return Ok(body);
    }
    // Bound the output: a hostile COMPRESSED flag on a crafted payload must not
    // be able to inflate into unbounded memory. 64 MB is far above anything the
    // ergonomics allow and far below anything that hurts a phone.
    miniz_oxide::inflate::decompress_to_vec_with_limit(&body, 64 << 20)
        .map_err(|_| Error::Decompress)
}

// ---------------------------------------------------------------------------
// transmitter
// ---------------------------------------------------------------------------

/// One optical frame, ready for the codec layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// Low density, high ECC. Render as QR regardless of the active palette.
    Beacon(Vec<u8>),
    /// High density. Render at the current rung of the ladder.
    Symbol(Vec<u8>),
}

impl Frame {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Frame::Beacon(b) | Frame::Symbol(b) => b,
        }
    }
}

pub struct Transmitter {
    beacon: Beacon,
    beacon_bytes: Vec<u8>,
    packets: Vec<Vec<u8>>,
    cursor: usize,
    frame_id: u32,
    packets_per_frame: usize,
    packet_len: u16,
    /// Emit a beacon every N frames so a late joiner can acquire.
    beacon_interval: u32,
    plaintext_hash: [u8; 8],
    /// PAIR mode withholds payload symbols until the human has confirmed the
    /// SAS. The payload is already encrypted under the derived key, so if a
    /// screen-in-the-middle is present, transmitting before confirmation hands
    /// it the secret. Detecting the attack afterwards does not unsend it.
    held: bool,
}

pub struct TransmitConfig {
    pub mode: Mode,
    pub session_id: [u8; 8],
    pub s_eph_pub: [u8; 32],
    pub codec: CodecParams,
    pub build_hash: [u8; 8],
    /// Usable bytes in one optical frame at the current density.
    pub frame_capacity: usize,
    pub sender_auth: bool,
}

impl Transmitter {
    pub fn new(key: &SessionKey, cfg: TransmitConfig, plaintext: &[u8]) -> Transmitter {
        let (body, compressed) = maybe_compress(plaintext);

        let mut flags = 0u8;
        if compressed {
            flags |= wire::flags::COMPRESSED;
        }
        if cfg.sender_auth {
            flags |= wire::flags::SENDER_AUTH;
        }

        let nonce = crypto::random_nonce();

        // The AAD is computable before encryption precisely because `Beacon::aad`
        // excludes the ciphertext-derived fields. `oti` and `codec` are filled in
        // below and are protected transitively: tampering with them makes RaptorQ
        // produce garbage and the tag then rejects it.
        let mut beacon = Beacon {
            mode: cfg.mode,
            flags,
            session_id: cfg.session_id,
            s_eph_pub: cfg.s_eph_pub,
            nonce,
            plaintext_len: plaintext.len() as u32,
            oti: [0u8; 12],
            codec: cfg.codec,
            build_hash: cfg.build_hash,
        };

        let ct = crypto::encrypt(key, &nonce, &beacon.aad(), &body);

        let encoder = Encoder::with_defaults(&ct, cfg.codec.symbol_size);
        let oti = encoder.get_config();
        beacon.oti = oti.serialize();

        let packets: Vec<Vec<u8>> = encoder
            .get_encoded_packets(REPAIR_PER_BLOCK)
            .into_iter()
            .map(|p| p.serialize())
            .collect();

        let packet_len = packets
            .first()
            .map(|p| p.len() as u16)
            .unwrap_or(cfg.codec.symbol_size + 4);

        let ppf = SymbolFrame::packets_per_frame(cfg.frame_capacity, packet_len).max(1);

        Transmitter {
            beacon_bytes: beacon.encode(),
            beacon,
            packets,
            cursor: 0,
            frame_id: 0,
            packets_per_frame: ppf,
            packet_len,
            beacon_interval: 15,
            plaintext_hash: crypto::complete_hash(&cfg.session_id, plaintext),
            held: false,
        }
    }

    pub fn beacon(&self) -> &Beacon {
        &self.beacon
    }

    /// What the sender eyeballs against the receiver's COMPLETE frame.
    pub fn expected_hash(&self) -> [u8; 8] {
        self.plaintext_hash
    }

    /// Total distinct packets in the pool. The stream cycles this forever, so
    /// there is no end of transmission: the human stops when the receiver says
    /// done. Rateless means a late joiner still converges.
    pub fn pool_size(&self) -> usize {
        self.packets.len()
    }

    /// Withhold payload symbols. Only beacons go out until [`Self::release`].
    pub fn hold(&mut self) {
        self.held = true;
    }

    /// Called after the human confirms the SAS matches on both screens.
    pub fn release(&mut self) {
        self.held = false;
    }

    pub fn is_held(&self) -> bool {
        self.held
    }

    pub fn set_beacon_interval(&mut self, n: u32) {
        self.beacon_interval = n.max(1);
    }

    /// Next frame at the transmitter's default capacity. Infinite by design.
    pub fn next_frame(&mut self) -> Frame {
        let ppf = self.packets_per_frame;
        self.next_frame_packed(ppf)
    }

    /// Next frame packed for a specific rung of the density ladder.
    ///
    /// The ladder is a fixed interleaved schedule, not a negotiation: the sender
    /// cycles 8-colour, 4-colour and QR frames on a timer and never learns which
    /// ones landed. Every RaptorQ packet counts toward the same reconstruction
    /// regardless of the rung it arrived on, so a receiver in bad light simply
    /// harvests the low rungs and takes longer. This is why there is no
    /// step-down logic and no feedback channel.
    pub fn next_frame_at(&mut self, capacity: usize) -> Frame {
        let ppf = SymbolFrame::packets_per_frame(capacity, self.packet_len).max(1);
        self.next_frame_packed(ppf)
    }

    fn next_frame_packed(&mut self, packets_per_frame: usize) -> Frame {
        let id = self.frame_id;
        self.frame_id = self.frame_id.wrapping_add(1);

        // clippy suggests `id.is_multiple_of(..)`, stable only since Rust 1.87.
        // Taking it would make 1.87 this crate's implicit MSRV to satisfy a
        // style lint, which is a bad trade for a tool meant to build anywhere.
        #[allow(clippy::manual_is_multiple_of)]
        let beacon_due = id % self.beacon_interval == 0;
        if self.held || beacon_due {
            return Frame::Beacon(self.beacon_bytes.clone());
        }

        let mut chunk = Vec::with_capacity(packets_per_frame);
        for _ in 0..packets_per_frame {
            chunk.push(self.packets[self.cursor].clone());
            self.cursor = (self.cursor + 1) % self.packets.len();
        }

        let sf = SymbolFrame {
            sid4: self.beacon.session_id[0..4].try_into().unwrap(),
            frame_id: id,
            packet_len: self.packet_len,
            packets: chunk,
        };
        Frame::Symbol(sf.encode())
    }
}

// ---------------------------------------------------------------------------
// receiver
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum Ingest {
    /// Not for us, or a type we do not act on. Costs nothing but time.
    Ignored,
    /// First beacon acquired. Caller must now derive the key from
    /// `beacon().s_eph_pub` and call `set_key`, then re-feed nothing: buffered
    /// symbols are replayed automatically.
    BeaconAcquired,
    Progress {
        received: usize,
        needed: usize,
    },
    /// Reassembled, tag verified, decompressed, length checked.
    Done {
        plaintext: Vec<u8>,
    },
}

pub struct Receiver {
    beacon: Option<Beacon>,
    key: Option<SessionKey>,
    decoder: Option<Decoder>,
    /// Symbols seen before the beacon arrived, or before the key was set.
    pending: Vec<Vec<u8>>,
    /// Everything accepted, for IndexedDB checkpointing and resume.
    seen: Vec<Vec<u8>>,
    /// RaptorQ PayloadIds already absorbed. The transmitter cycles a finite pool
    /// forever, so without this a long transfer counts the same packet many
    /// times: the progress bar reaches "verifying" long before decode can
    /// finish, and the checkpoint grows without bound (the dim-room 1 MB case
    /// accumulated roughly 100 MB of duplicates).
    ids: HashSet<[u8; 4]>,
    received: usize,
    needed: usize,
    done: bool,
}

impl Default for Receiver {
    fn default() -> Self {
        Self::new()
    }
}

impl Receiver {
    pub fn new() -> Receiver {
        Receiver {
            beacon: None,
            key: None,
            decoder: None,
            pending: Vec::new(),
            seen: Vec::new(),
            ids: HashSet::new(),
            received: 0,
            needed: 0,
            done: false,
        }
    }

    pub fn beacon(&self) -> Option<&Beacon> {
        self.beacon.as_ref()
    }

    pub fn progress(&self) -> (usize, usize) {
        (self.received, self.needed)
    }

    /// Monotonic 0.0 to 1.0. RaptorQ needs K + about 2, so this saturates just
    /// under 1.0 and the UI should pulse "verifying" rather than stick at 99%.
    pub fn fraction(&self) -> f32 {
        if self.needed == 0 {
            return 0.0;
        }
        (self.received as f32 / self.needed as f32).min(1.0)
    }

    pub fn set_key(&mut self, key: SessionKey) {
        self.key = Some(key);
    }

    pub fn has_key(&self) -> bool {
        self.key.is_some()
    }

    /// Symbols collected so far, for checkpointing to IndexedDB. Lock the phone,
    /// walk away, come back, keep collecting. There is no restart.
    pub fn checkpoint(&self) -> &[Vec<u8>] {
        &self.seen
    }

    /// Distinct symbols absorbed. Equals `progress().0` by construction; exposed
    /// so a caller can assert the two never diverge.
    pub fn distinct(&self) -> usize {
        self.ids.len()
    }

    /// Feed a checkpoint back in. Safe to call before or after the beacon.
    /// Duplicates in the restored set are dropped like any other.
    pub fn restore(&mut self, packets: Vec<Vec<u8>>) {
        self.pending.extend(packets);
    }

    /// Feed one decoded optical frame. Errors are per-frame and non-fatal:
    /// a torn or corrupt frame is discarded and costs only time, because the
    /// fountain layer does not care what it loses.
    pub fn ingest(&mut self, frame: &[u8]) -> Result<Ingest> {
        if self.done {
            return Ok(Ingest::Ignored);
        }
        match wire::peek_type(frame)? {
            wire::frame_type::BEACON => {
                let b = Beacon::decode(frame)?;
                if let Some(existing) = &self.beacon {
                    // Repeated beacon. Mismatch means two senders in frame.
                    return if existing.session_id == b.session_id {
                        Ok(Ingest::Ignored)
                    } else {
                        Err(Error::ForeignSession)
                    };
                }
                let oti = ObjectTransmissionInformation::deserialize(&b.oti);
                let sym = oti.symbol_size().max(1) as u64;
                self.needed = oti.transfer_length().div_ceil(sym) as usize;
                self.decoder = Some(Decoder::new(oti));
                self.beacon = Some(b);
                Ok(Ingest::BeaconAcquired)
            }
            wire::frame_type::SYMBOL => {
                let sf = SymbolFrame::decode(frame)?;
                match &self.beacon {
                    None => {
                        // Symbols before beacon acquisition are kept, not dropped.
                        self.pending.extend(sf.packets);
                        Ok(Ingest::Ignored)
                    }
                    Some(b) => {
                        if sf.sid4 != b.session_id[0..4] {
                            return Err(Error::ForeignSession);
                        }
                        self.absorb(sf.packets)
                    }
                }
            }
            other => Err(Error::BadFrameType(other)),
        }
    }

    fn absorb(&mut self, packets: Vec<Vec<u8>>) -> Result<Ingest> {
        let queued: Vec<Vec<u8>> = self.pending.drain(..).chain(packets).collect();
        let mut finished: Option<Vec<u8>> = None;

        for raw in queued {
            if raw.len() < 4 {
                continue;
            }
            let id: [u8; 4] = raw[0..4].try_into().unwrap();
            if !self.ids.insert(id) {
                // Already have this symbol. Costs nothing to drop, and counting
                // it would make the progress bar lie.
                continue;
            }
            self.seen.push(raw.clone());
            self.received += 1;
            let dec = self
                .decoder
                .as_mut()
                .expect("decoder exists once beacon does");
            if finished.is_none() {
                if let Some(ct) = dec.decode(EncodingPacket::deserialize(&raw)) {
                    finished = Some(ct);
                }
            }
        }

        let Some(ct) = finished else {
            return Ok(Ingest::Progress {
                received: self.received,
                needed: self.needed,
            });
        };

        // RaptorQ says it reassembled something. Only the tag decides whether it
        // is the right something.
        let Some(key) = &self.key else {
            // Reassembled but cannot open yet. Caller has not supplied the key.
            return Ok(Ingest::Progress {
                received: self.received,
                needed: self.needed,
            });
        };
        let b = self.beacon.as_ref().unwrap();
        let body = crypto::decrypt(key, &b.nonce, &b.aad(), &ct)?;
        let plaintext = maybe_decompress(body, b.compressed())?;

        if plaintext.len() != b.plaintext_len as usize {
            return Err(Error::LengthMismatch {
                declared: b.plaintext_len as usize,
                got: plaintext.len(),
            });
        }

        self.done = true;
        Ok(Ingest::Done { plaintext })
    }

    /// Build the COMPLETE frame the receiver displays for the sender to eyeball.
    pub fn complete_frame(&self, plaintext: &[u8], status: Status) -> Option<Vec<u8>> {
        let b = self.beacon.as_ref()?;
        Some(
            Complete {
                sid4: b.session_id[0..4].try_into().unwrap(),
                status,
                hash8: crypto::complete_hash(&b.session_id, plaintext),
            }
            .encode(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, Role};

    fn cfg(sid: [u8; 8], s_eph_pub: [u8; 32], cap: usize) -> TransmitConfig {
        TransmitConfig {
            mode: Mode::Pair,
            session_id: sid,
            s_eph_pub,
            codec: CodecParams::default(),
            build_hash: [0xAB; 8],
            frame_capacity: cap,
            sender_auth: false,
        }
    }

    /// Drive a full transfer over a channel that drops `loss` of every 100 frames.
    fn transfer(payload: &[u8], capacity: usize, loss: usize) -> (Vec<u8>, usize) {
        let s_eph = KeyPair::generate();
        let r_eph = KeyPair::generate();
        let sid = crypto::random_session_id();

        let ks = crypto::derive_pair(Role::Sender, &s_eph, &r_eph.public(), &sid);
        let kr = crypto::derive_pair(Role::Receiver, &r_eph, &s_eph.public(), &sid);
        assert_eq!(ks.as_bytes(), kr.as_bytes());

        let mut tx = Transmitter::new(&ks, cfg(sid, s_eph.public(), capacity), payload);
        let mut rx = Receiver::new();
        let mut key = Some(kr);
        let mut frames = 0usize;

        for i in 0..200_000 {
            let f = tx.next_frame();
            frames += 1;
            // Deterministic pseudo-loss, so failures reproduce.
            if loss > 0 && (i * 37 + 11) % 100 < loss {
                continue;
            }
            match rx.ingest(f.bytes()) {
                Ok(Ingest::BeaconAcquired) => {
                    rx.set_key(key.take().expect("key set once"));
                }
                Ok(Ingest::Done { plaintext }) => return (plaintext, frames),
                Ok(_) => {}
                Err(e) => panic!("frame {i} rejected: {e}"),
            }
        }
        panic!("did not converge");
    }

    #[test]
    fn small_secret_round_trips() {
        let payload = b"[Interface]\nPrivateKey = aGVsbG8...\nAddress = 10.0.0.2/32\n";
        let (out, frames) = transfer(payload, 1050, 0);
        assert_eq!(out, payload);
        // A Wireguard config should land in a handful of frames.
        assert!(frames < 20, "took {frames} frames");
    }

    #[test]
    fn survives_thirty_percent_loss() {
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let (out, _) = transfer(&payload, 7500, 30);
        assert_eq!(out, payload);
    }

    #[test]
    fn survives_seventy_percent_loss() {
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        let (out, _) = transfer(&payload, 7500, 70);
        assert_eq!(out, payload);
    }

    #[test]
    fn late_joiner_converges() {
        // Receiver starts mid-stream, misses the first beacon entirely.
        let payload: Vec<u8> = (0..8_000u32).map(|i| (i % 251) as u8).collect();
        let s_eph = KeyPair::generate();
        let r_eph = KeyPair::generate();
        let sid = crypto::random_session_id();
        let ks = crypto::derive_pair(Role::Sender, &s_eph, &r_eph.public(), &sid);
        let kr = crypto::derive_pair(Role::Receiver, &r_eph, &s_eph.public(), &sid);

        let mut tx = Transmitter::new(&ks, cfg(sid, s_eph.public(), 7500), &payload);
        for _ in 0..40 {
            tx.next_frame();
        }
        let mut rx = Receiver::new();
        let mut key = Some(kr);
        for _ in 0..5_000 {
            let f = tx.next_frame();
            match rx.ingest(f.bytes()).unwrap() {
                Ingest::BeaconAcquired => rx.set_key(key.take().unwrap()),
                Ingest::Done { plaintext } => {
                    assert_eq!(plaintext, payload);
                    return;
                }
                _ => {}
            }
        }
        panic!("late joiner did not converge");
    }

    #[test]
    fn checkpoint_and_resume() {
        let payload: Vec<u8> = (0..12_000u32).map(|i| (i % 251) as u8).collect();
        let s_eph = KeyPair::generate();
        let r_eph = KeyPair::generate();
        let sid = crypto::random_session_id();
        let ks = crypto::derive_pair(Role::Sender, &s_eph, &r_eph.public(), &sid);

        let mut tx = Transmitter::new(&ks, cfg(sid, s_eph.public(), 7500), &payload);

        // Session one: collect a few frames, then the phone locks.
        let mut rx1 = Receiver::new();
        rx1.set_key(crypto::derive_pair(
            Role::Receiver,
            &r_eph,
            &s_eph.public(),
            &sid,
        ));
        for _ in 0..4 {
            let f = tx.next_frame();
            let _ = rx1.ingest(f.bytes());
        }
        let saved: Vec<Vec<u8>> = rx1.checkpoint().to_vec();
        assert!(!saved.is_empty(), "nothing checkpointed");
        drop(rx1);

        // Session two: restore and carry on. No restart.
        let mut rx2 = Receiver::new();
        let mut key = Some(crypto::derive_pair(
            Role::Receiver,
            &r_eph,
            &s_eph.public(),
            &sid,
        ));
        rx2.restore(saved);
        for _ in 0..5_000 {
            let f = tx.next_frame();
            match rx2.ingest(f.bytes()).unwrap() {
                Ingest::BeaconAcquired => rx2.set_key(key.take().unwrap()),
                Ingest::Done { plaintext } => {
                    assert_eq!(plaintext, payload);
                    return;
                }
                _ => {}
            }
        }
        panic!("resume did not converge");
    }

    #[test]
    fn tampered_beacon_flag_fails_the_tag() {
        // Clearing COMPRESSED changes the AAD, so the tag must reject even though
        // RaptorQ reassembles a byte-perfect ciphertext.
        let payload = vec![b'A'; 4000]; // highly compressible
        let s_eph = KeyPair::generate();
        let r_eph = KeyPair::generate();
        let sid = crypto::random_session_id();
        let ks = crypto::derive_pair(Role::Sender, &s_eph, &r_eph.public(), &sid);
        let kr = crypto::derive_pair(Role::Receiver, &r_eph, &s_eph.public(), &sid);

        let mut tx = Transmitter::new(&ks, cfg(sid, s_eph.public(), 7500), &payload);
        assert!(tx.beacon().compressed(), "test needs a compressed payload");

        let mut evil = tx.beacon().clone();
        evil.flags &= !wire::flags::COMPRESSED;
        let evil_bytes = evil.encode(); // attacker recomputes the CRC, of course

        let mut rx = Receiver::new();
        assert_eq!(rx.ingest(&evil_bytes).unwrap(), Ingest::BeaconAcquired);
        rx.set_key(kr);

        for _ in 0..5_000 {
            let f = tx.next_frame();
            if matches!(f, Frame::Beacon(_)) {
                continue;
            }
            match rx.ingest(f.bytes()) {
                Err(Error::AuthFailed) => return, // correct
                Ok(Ingest::Done { .. }) => panic!("tampered beacon accepted"),
                _ => {}
            }
        }
        panic!("tag never evaluated");
    }

    #[test]
    fn foreign_session_rejected() {
        let payload = vec![7u8; 2000];
        let s_eph = KeyPair::generate();
        let sid_a = [1u8; 8];
        let sid_b = [2u8; 8];
        let k = crypto::derive_pair(Role::Sender, &s_eph, &[9u8; 32], &sid_a);

        let mut tx_a = Transmitter::new(&k, cfg(sid_a, s_eph.public(), 7500), &payload);
        let mut tx_b = Transmitter::new(&k, cfg(sid_b, s_eph.public(), 7500), &payload);

        let mut rx = Receiver::new();
        rx.ingest(tx_a.next_frame().bytes()).unwrap();
        // Now feed a symbol frame from the other session.
        let mut foreign = tx_b.next_frame();
        while matches!(foreign, Frame::Beacon(_)) {
            foreign = tx_b.next_frame();
        }
        assert_eq!(rx.ingest(foreign.bytes()), Err(Error::ForeignSession));
    }

    #[test]
    fn duplicate_symbols_are_not_counted_twice() {
        // The transmitter cycles a finite pool, so a slow or lossy channel sees
        // the same packet many times. Progress must track distinct symbols.
        let payload: Vec<u8> = (0..6_000u32).map(|i| (i % 251) as u8).collect();
        let s_eph = KeyPair::generate();
        let r_eph = KeyPair::generate();
        let sid = crypto::random_session_id();
        let ks = crypto::derive_pair(Role::Sender, &s_eph, &r_eph.public(), &sid);
        let kr = crypto::derive_pair(Role::Receiver, &r_eph, &s_eph.public(), &sid);

        let mut tx = Transmitter::new(&ks, cfg(sid, s_eph.public(), 2000), &payload);
        let pool = tx.pool_size();
        let mut rx = Receiver::new();
        let mut key = Some(kr);

        // Run well past one full cycle of the pool.
        let mut done = false;
        for _ in 0..(pool * 4 + 100) {
            let f = tx.next_frame();
            match rx.ingest(f.bytes()).unwrap() {
                Ingest::BeaconAcquired => rx.set_key(key.take().unwrap()),
                Ingest::Done { plaintext } => {
                    assert_eq!(plaintext, payload);
                    done = true;
                    break;
                }
                _ => {}
            }
        }
        assert!(done);
        let (received, needed) = rx.progress();
        assert_eq!(received, rx.distinct(), "counted a duplicate");
        assert!(
            received <= pool,
            "counted {received} symbols from a pool of {pool}"
        );
        // And it must not have overshot: a correct run stops just past `needed`.
        assert!(
            received < needed + 32,
            "received {received} for a {needed}-symbol object"
        );
        assert_eq!(
            rx.checkpoint().len(),
            received,
            "checkpoint holds duplicates"
        );
    }

    #[test]
    fn held_transmitter_emits_no_payload() {
        // Until the SAS is confirmed, a PAIR-mode sender must leak nothing.
        let payload = vec![0xAAu8; 4000];
        let s_eph = KeyPair::generate();
        let sid = crypto::random_session_id();
        let k = crypto::derive_pair(Role::Sender, &s_eph, &[7u8; 32], &sid);
        let mut tx = Transmitter::new(&k, cfg(sid, s_eph.public(), 2000), &payload);
        tx.hold();
        for _ in 0..200 {
            assert!(
                matches!(tx.next_frame(), Frame::Beacon(_)),
                "held transmitter emitted a payload symbol"
            );
        }
        tx.release();
        let mut saw_symbol = false;
        for _ in 0..40 {
            if matches!(tx.next_frame(), Frame::Symbol(_)) {
                saw_symbol = true;
            }
        }
        assert!(saw_symbol, "release did not resume the stream");
    }

    #[test]
    fn compression_sniffing() {
        assert!(is_already_compressed(b"\xFF\xD8\xFF\xE0 jpeg"));
        assert!(is_already_compressed(b"\x89PNG\r\n\x1a\n"));
        assert!(is_already_compressed(b"PK\x03\x04 docx"));
        assert!(is_already_compressed(b"%PDF-1.7"));
        assert!(is_already_compressed(b"\x00\x00\x00\x18ftypheic"));
        assert!(is_already_compressed(b"RIFF\x00\x00\x00\x00WEBPVP8 "));
        assert!(!is_already_compressed(b"RIFF\x00\x00\x00\x00WAVEfmt "));
        assert!(!is_already_compressed(b"[Interface]\nPrivateKey ="));
        assert!(!is_already_compressed(
            b"-----BEGIN OPENSSH PRIVATE KEY-----"
        ));
    }

    #[test]
    fn compression_actually_fires_and_is_lossless() {
        let text = "PrivateKey = abc\nAllowedIPs = 0.0.0.0/0\n".repeat(200);
        let (z, did) = maybe_compress(text.as_bytes());
        assert!(did);
        assert!(
            z.len() * 3 < text.len(),
            "expected better than 3x on config text"
        );
        assert_eq!(maybe_decompress(z, true).unwrap(), text.as_bytes());
    }

    #[test]
    fn tiny_and_incompressible_inputs_skip_zstd() {
        let (_, did) = maybe_compress(b"short");
        assert!(!did);
        // Real entropy. A multiplicative hash has enough structure that zstd
        // finds a percent or two, which is exactly the case the margin rejects.
        let mut noise = vec![0u8; 4096];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut noise);
        let (out, did) = maybe_compress(&noise);
        assert!(!did, "random noise should not be shipped as 'compressed'");
        assert_eq!(out, noise);
    }

    #[test]
    fn seal_mode_one_pass() {
        // Camera-less sender: no PAIR_REQ, no round trip, receiver identity known.
        let payload = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA...\n";
        let s_eph = KeyPair::generate();
        let r_id = KeyPair::generate();
        let sid = crypto::random_session_id();

        let ks = crypto::seal_sender(&s_eph, None, &r_id.public());
        let mut c = cfg(sid, s_eph.public(), 1050);
        c.mode = Mode::Seal;
        let mut tx = Transmitter::new(&ks, c, payload);

        let mut rx = Receiver::new();
        let mut key = Some(crypto::seal_receiver(&r_id, &s_eph.public(), None));
        for _ in 0..500 {
            let f = tx.next_frame();
            match rx.ingest(f.bytes()).unwrap() {
                Ingest::BeaconAcquired => rx.set_key(key.take().unwrap()),
                Ingest::Done { plaintext } => {
                    assert_eq!(plaintext, payload);
                    let cf = rx.complete_frame(&plaintext, Status::Ok).unwrap();
                    let parsed = Complete::decode(&cf).unwrap();
                    assert_eq!(parsed.hash8, tx.expected_hash());
                    return;
                }
                _ => {}
            }
        }
        panic!("seal transfer did not converge");
    }
}
