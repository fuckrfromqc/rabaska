//! Rabaska protocol harness.
//!
//! Runs the full protocol between two in-process peers over a simulated optical
//! channel. No pixels: this validates the wire format, key agreement and
//! reassembly, and models throughput so Phase 2 has a target to beat.
//!
//! Usage:
//!   harness modes      run all four key agreement modes end to end
//!   harness ladder     simulate the interleaved density ladder under lighting
//!   harness vectors    emit frozen test vectors to vectors/v1.json

use std::fmt::Write as _;

use rabaska_core::crypto::{self, KeyPair, Role};
use rabaska_core::pipeline::{Frame, Ingest, Receiver, TransmitConfig, Transmitter};
use rabaska_core::wire::{Beacon, CodecParams, Complete, Mode, Status};

// ---------------------------------------------------------------------------
// optical channel model
// ---------------------------------------------------------------------------

/// A rung of the density ladder.
#[derive(Clone, Copy)]
struct Rung {
    name: &'static str,
    /// Usable payload bytes in one displayed frame.
    capacity: usize,
    /// Share of the display schedule, in frames out of the cycle length.
    weight: u32,
}

/// QR version 25 at ECC-M, capacity measured by `qr::capacity` rather than
/// guessed. The interoperability rung: readable by hardware wallets and generic
/// scanners, and the one that still works at a bad angle.
const RUNG_QR: Rung = Rung {
    name: "QR v25",
    capacity: 997,
    weight: 1,
};
/// 1024x1024 grid of 8px tiles, 4 bits shape in luma, 1 bit colour in chroma.
const RUNG_C4: Rung = Rung {
    name: "4-colour",
    capacity: 7500,
    weight: 2,
};
/// Same grid, 3 bits of colour. Buys 17% and costs a lot of white-balance margin.
const RUNG_C8: Rung = Rung {
    name: "8-colour",
    capacity: 11000,
    weight: 4,
};

/// Per-rung decode probability. Chroma is half resolution in both axes under
/// 4:2:0, so colour rungs degrade first and fastest as conditions worsen.
#[derive(Clone, Copy)]
struct Lighting {
    name: &'static str,
    p_qr: f64,
    p_c4: f64,
    p_c8: f64,
}

const CONDITIONS: &[Lighting] = &[
    Lighting {
        name: "bench, tripod, max brightness",
        p_qr: 0.98,
        p_c4: 0.92,
        p_c8: 0.80,
    },
    Lighting {
        name: "desk to phone, handheld",
        p_qr: 0.94,
        p_c4: 0.80,
        p_c8: 0.55,
    },
    Lighting {
        name: "phone to phone, handheld",
        p_qr: 0.88,
        p_c4: 0.62,
        p_c8: 0.30,
    },
    Lighting {
        name: "dim room, bad angle",
        p_qr: 0.55,
        p_c4: 0.18,
        p_c8: 0.02,
    },
];

/// Deterministic PRNG so a failure reproduces exactly.
struct Rng(u64);
impl Rng {
    fn next_f64(&mut self) -> f64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 11) as f64) / ((1u64 << 53) as f64)
    }
}

const DISPLAY_FPS: f64 = 30.0;

// ---------------------------------------------------------------------------
// end to end drivers
// ---------------------------------------------------------------------------

struct Peers {
    s_eph: KeyPair,
    s_id: KeyPair,
    r_eph: KeyPair,
    r_id: KeyPair,
    sid: [u8; 8],
}

impl Peers {
    fn new() -> Peers {
        Peers {
            s_eph: KeyPair::generate(),
            s_id: KeyPair::generate(),
            r_eph: KeyPair::generate(),
            r_id: KeyPair::generate(),
            sid: crypto::random_session_id(),
        }
    }
}

fn keys_for(mode: Mode, p: &Peers) -> (crypto::SessionKey, crypto::SessionKey) {
    match mode {
        Mode::Pair => (
            crypto::derive_pair(Role::Sender, &p.s_eph, &p.r_eph.public(), &p.sid),
            crypto::derive_pair(Role::Receiver, &p.r_eph, &p.s_eph.public(), &p.sid),
        ),
        Mode::Session => (
            crypto::derive_session(
                Role::Sender,
                &p.s_eph,
                &p.s_id,
                &p.r_eph.public(),
                &p.r_id.public(),
                &p.sid,
            ),
            crypto::derive_session(
                Role::Receiver,
                &p.r_eph,
                &p.r_id,
                &p.s_eph.public(),
                &p.s_id.public(),
                &p.sid,
            ),
        ),
        Mode::Seal => (
            crypto::seal_sender(&p.s_eph, Some(&p.s_id), &p.r_id.public()),
            crypto::seal_receiver(&p.r_id, &p.s_eph.public(), Some(&p.s_id.public())),
        ),
        Mode::Open => (
            crypto::derive_open(&p.sid, &p.s_eph.public()),
            crypto::derive_open(&p.sid, &p.s_eph.public()),
        ),
    }
}

/// Run one transfer over a ladder schedule. Returns (frames displayed, seconds).
fn run(
    mode: Mode,
    payload: &[u8],
    ladder: &[Rung],
    light: &Lighting,
    seed: u64,
) -> Result<(usize, f64), String> {
    let p = Peers::new();
    let (ks, kr) = keys_for(mode, &p);

    let cfg = TransmitConfig {
        mode,
        session_id: p.sid,
        s_eph_pub: p.s_eph.public(),
        codec: CodecParams {
            palette: 8,
            ..CodecParams::default()
        },
        build_hash: crypto::build_hash(b"rabaska-harness"),
        frame_capacity: RUNG_C4.capacity,
        sender_auth: matches!(mode, Mode::Seal),
    };

    let mut tx = Transmitter::new(&ks, cfg, payload);
    let mut rx = Receiver::new();
    let mut key = Some(kr);
    let mut rng = Rng(seed);

    // Expand the ladder weights into a display schedule.
    let mut schedule: Vec<Rung> = Vec::new();
    for r in ladder {
        for _ in 0..r.weight {
            schedule.push(*r);
        }
    }

    for i in 0..400_000usize {
        let rung = schedule[i % schedule.len()];
        let frame = match tx.next_frame_at(rung.capacity) {
            // Beacons always go out on the robust rung, like an 802.11 preamble.
            f @ Frame::Beacon(_) => {
                if rng.next_f64() > light.p_qr {
                    continue;
                }
                f
            }
            f => {
                let p_ok = match rung.name {
                    "QR v25" => light.p_qr,
                    "4-colour" => light.p_c4,
                    _ => light.p_c8,
                };
                if rng.next_f64() > p_ok {
                    continue;
                }
                f
            }
        };

        match rx.ingest(frame.bytes()) {
            Ok(Ingest::BeaconAcquired) => rx.set_key(key.take().expect("key set once")),
            Ok(Ingest::Done { plaintext }) => {
                if plaintext != payload {
                    return Err("reassembled payload differs".into());
                }
                // Delivery confirmation: the only feedback in the system.
                let cf = rx.complete_frame(&plaintext, Status::Ok).unwrap();
                let parsed = Complete::decode(&cf).map_err(|e| e.to_string())?;
                if parsed.hash8 != tx.expected_hash() {
                    return Err("completion hash mismatch".into());
                }
                return Ok((i + 1, (i + 1) as f64 / DISPLAY_FPS));
            }
            Ok(_) => {}
            Err(e) => return Err(format!("frame {i}: {e}")),
        }
    }
    Err("did not converge".into())
}

// ---------------------------------------------------------------------------
// commands
// ---------------------------------------------------------------------------

fn cmd_modes() {
    println!("MODES  end to end, all four key agreements, handheld phone to phone\n");
    let light = CONDITIONS[2];
    let payload: Vec<u8> = wireguard_config().into_bytes();

    for (mode, label, note) in [
        (
            Mode::Pair,
            "PAIR",
            "first meeting, ephemeral ECDH + 5-digit SAS",
        ),
        (
            Mode::Session,
            "SESSION",
            "stored identities, triple-DH, scan and go",
        ),
        (
            Mode::Seal,
            "SEAL",
            "camera-less sender, one pass, zero round trips",
        ),
        (
            Mode::Open,
            "OPEN",
            "trusted room, no confidentiality, labelled",
        ),
    ] {
        match run(
            mode,
            &payload,
            &[RUNG_QR, RUNG_C4, RUNG_C8],
            &light,
            0xC0FFEE,
        ) {
            Ok((frames, secs)) => {
                println!("  {label:<8} ok   {frames:>4} frames  {secs:>5.2}s   {note}")
            }
            Err(e) => println!("  {label:<8} FAIL {e}"),
        }
    }

    // The SAS both humans compare on a first pairing.
    let p = Peers::new();
    println!(
        "\n  SAS on this pairing: {}  (both screens must match)",
        crypto::sas(
            &p.sid,
            &p.r_eph.public(),
            &p.s_eph.public(),
            &crypto::random_nonce16()
        )
    );
}

fn cmd_ladder() {
    println!("LADDER  interleaved density schedule, no negotiation, no feedback\n");
    println!("  Schedule: 1 QR : 2 four-colour : 4 eight-colour, beacon every 15 frames");
    println!("  Display at {DISPLAY_FPS:.0} fps\n");

    let payloads = realistic_payloads();

    println!(
        "  {:<26} {:<18} {:>8} {:>7} {:>8} {:>9}",
        "conditions", "payload", "on wire", "frames", "seconds", "effective"
    );
    println!("  {}", "-".repeat(82));

    for light in CONDITIONS {
        for (label, payload) in &payloads {
            let wire_kb = wire_bytes(payload) as f64 / 1024.0;
            match run(
                Mode::Session,
                payload,
                &[RUNG_QR, RUNG_C4, RUNG_C8],
                light,
                0xBEEF,
            ) {
                Ok((frames, secs)) => {
                    println!(
                        "  {:<26} {:<18} {:>7.1}K {:>8} {:>8.2} {:>6.1} KB/s",
                        light.name,
                        label,
                        wire_kb,
                        frames,
                        secs,
                        (payload.len() as f64 / 1024.0) / secs
                    );
                }
                Err(e) => println!("  {:<26} {:<18} FAILED: {e}", light.name, label),
            }
        }
        println!();
    }

    println!("  QR-only, dim room and bad angle. The interoperability rung and the");
    println!("  floor the whole system degrades to rather than failing:\n");
    for (label, payload) in payloads.iter().take(3) {
        match run(Mode::Session, payload, &[RUNG_QR], &CONDITIONS[3], 0xBEEF) {
            Ok((frames, secs)) => println!(
                "    {:<18} {:>6} frames  {:>7.2}s  {:>6.1} KB/s",
                label,
                frames,
                secs,
                (payload.len() as f64 / 1024.0) / secs
            ),
            Err(e) => println!("    {label:<18} FAILED: {e}"),
        }
    }

    println!("\n  'effective' is payload bytes per second, so it exceeds the optical");
    println!("  channel rate whenever zstd earned its keep. 'on wire' is what the");
    println!("  codec actually has to carry.");
}

/// Payloads with realistic entropy. This matters more than it looks: synthetic
/// repetitive data compresses to nothing and produces throughput numbers that
/// are pure fiction.
fn realistic_payloads() -> Vec<(&'static str, Vec<u8>)> {
    let mut rng = Rng(0x5EED);
    let mut rand_bytes =
        |n: usize| -> Vec<u8> { (0..n).map(|_| (rng.next_f64() * 256.0) as u8).collect() };
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const B32: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    // Base64 of random key material: structured alphabet, incompressible content.
    let mut ssh = b"-----BEGIN OPENSSH PRIVATE KEY-----\n".to_vec();
    for i in 0..3_000 {
        ssh.push(B64[rand_bytes(1)[0] as usize % 64]);
        if i % 70 == 69 {
            ssh.push(b'\n');
        }
    }
    ssh.extend_from_slice(b"\n-----END OPENSSH PRIVATE KEY-----\n");

    // JSON: keys and punctuation compress, the secrets do not.
    let mut totp = b"{\"version\":2,\"entries\":[".to_vec();
    for i in 0..300 {
        let secret: Vec<u8> = (0..32)
            .map(|_| B32[rand_bytes(1)[0] as usize % 32])
            .collect();
        totp.extend_from_slice(
            format!(
                "{}{{\"issuer\":\"service{i:03}\",\"account\":\"louis@example.com\",\
                 \"secret\":\"{}\",\"digits\":6,\"period\":30}}",
                if i == 0 { "" } else { "," },
                String::from_utf8_lossy(&secret)
            )
            .as_bytes(),
        );
    }
    totp.extend_from_slice(b"]}");

    // JPEG magic then noise: the sniffer skips zstd entirely, which is correct.
    let mut photo = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01".to_vec();
    photo.extend_from_slice(&rand_bytes(1_000_000));

    vec![
        ("wireguard config", wireguard_config().into_bytes()),
        ("ssh private key", ssh),
        ("TOTP vault (300)", totp),
        ("1 MB photo", photo),
    ]
}

/// Ciphertext size the codec must actually carry, after sniffing and zstd.
fn wire_bytes(payload: &[u8]) -> usize {
    let k = crypto::derive_pair(
        Role::Sender,
        &KeyPair::from_bytes([1; 32]),
        &KeyPair::from_bytes([2; 32]).public(),
        &[0; 8],
    );
    let tx = Transmitter::new(
        &k,
        TransmitConfig {
            mode: Mode::Pair,
            session_id: [0; 8],
            s_eph_pub: [0; 32],
            codec: CodecParams {
                palette: 4,
                ..CodecParams::default()
            },
            build_hash: [0; 8],
            frame_capacity: RUNG_C4.capacity,
            sender_auth: false,
        },
        payload,
    );
    let oti = rabaska_core::wire::Beacon::decode(&tx.beacon().encode())
        .unwrap()
        .oti;
    // transfer_length is the first five bytes, big-endian.
    let mut n = 0u64;
    for b in &oti[0..5] {
        n = (n << 8) | *b as u64;
    }
    n as usize
}

fn wireguard_config() -> String {
    "[Interface]\n\
     PrivateKey = wJ8mK2nQ5pR7tV9xA1cE3fH6jL0oS4uY8bD2gN5qT7w=\n\
     Address = 10.7.0.2/32\n\
     DNS = 10.7.0.1\n\n\
     [Peer]\n\
     PublicKey = xR4tY7uI9oP2aS5dF8gH1jK3lZ6cV0bN4mQ7wE9rT2y=\n\
     Endpoint = 198.51.100.14:51820\n\
     AllowedIPs = 0.0.0.0/0, ::/0\n\
     PersistentKeepalive = 25\n"
        .to_string()
}

// ---------------------------------------------------------------------------
// test vectors
// ---------------------------------------------------------------------------

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Frozen vectors. Any change to a domain-separation string or a frame layout
/// changes these, which is exactly the point: CI diffs them and the diff is the
/// alarm. Keys are fixed scalars, not random, so the output is reproducible.
fn cmd_vectors() {
    let s_eph = KeyPair::from_bytes([0x11; 32]);
    let s_id = KeyPair::from_bytes([0x22; 32]);
    let r_eph = KeyPair::from_bytes([0x33; 32]);
    let r_id = KeyPair::from_bytes([0x44; 32]);
    let sid: [u8; 8] = [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7];
    let nonce: [u8; 24] = [0x5A; 24];

    let k_pair = crypto::derive_pair(Role::Sender, &s_eph, &r_eph.public(), &sid);
    let k_pair_r = crypto::derive_pair(Role::Receiver, &r_eph, &s_eph.public(), &sid);
    assert_eq!(k_pair.as_bytes(), k_pair_r.as_bytes(), "PAIR must agree");

    let k_sess = crypto::derive_session(
        Role::Sender,
        &s_eph,
        &s_id,
        &r_eph.public(),
        &r_id.public(),
        &sid,
    );
    let k_sess_r = crypto::derive_session(
        Role::Receiver,
        &r_eph,
        &r_id,
        &s_eph.public(),
        &s_id.public(),
        &sid,
    );
    assert_eq!(k_sess.as_bytes(), k_sess_r.as_bytes(), "SESSION must agree");

    let k_seal = crypto::seal_sender(&s_eph, None, &r_id.public());
    let k_seal_r = crypto::seal_receiver(&r_id, &s_eph.public(), None);
    assert_eq!(k_seal.as_bytes(), k_seal_r.as_bytes(), "SEAL must agree");

    let k_seal_auth = crypto::seal_sender(&s_eph, Some(&s_id), &r_id.public());
    let k_seal_auth_r = crypto::seal_receiver(&r_id, &s_eph.public(), Some(&s_id.public()));
    assert_eq!(
        k_seal_auth.as_bytes(),
        k_seal_auth_r.as_bytes(),
        "SEAL-AUTH must agree"
    );

    let beacon = Beacon {
        mode: Mode::Session,
        flags: rabaska_core::wire::flags::COMPRESSED,
        session_id: sid,
        s_eph_pub: s_eph.public(),
        nonce,
        plaintext_len: 4096,
        oti: [0x66; 12],
        codec: CodecParams {
            palette: 4,
            ..CodecParams::default()
        },
        build_hash: [0x77; 8],
    };
    let ct = crypto::encrypt(&k_sess, &nonce, &beacon.aad(), b"rabaska test payload");

    let sas_nonce: [u8; 16] = [0x3C; 16];
    let pair_req = rabaska_core::wire::PairReq {
        flags: rabaska_core::wire::flags::HAS_ID_HINT,
        session_id: sid,
        r_eph_pub: r_eph.public(),
        id_hint: crypto::id_hint(&r_id.public()),
        r_commit: crypto::commit(&sid, &r_eph.public(), &sas_nonce),
    };

    let complete = Complete {
        sid4: [sid[0], sid[1], sid[2], sid[3]],
        status: Status::Ok,
        hash8: crypto::complete_hash(&sid, b"rabaska test payload"),
    };

    println!("{{");
    println!("  \"protocol\": \"rabaska/v2\",");
    println!("  \"note\": \"FROZEN. A diff here means a breaking protocol change.\",");
    println!("  \"inputs\": {{");
    println!("    \"s_eph_priv\": \"{}\",", hex(&[0x11; 32]));
    println!("    \"s_id_priv\":  \"{}\",", hex(&[0x22; 32]));
    println!("    \"r_eph_priv\": \"{}\",", hex(&[0x33; 32]));
    println!("    \"r_id_priv\":  \"{}\",", hex(&[0x44; 32]));
    println!("    \"session_id\": \"{}\",", hex(&sid));
    println!("    \"nonce\":      \"{}\"", hex(&nonce));
    println!("  }},");
    println!("  \"public_keys\": {{");
    println!("    \"s_eph_pub\": \"{}\",", hex(&s_eph.public()));
    println!("    \"s_id_pub\":  \"{}\",", hex(&s_id.public()));
    println!("    \"r_eph_pub\": \"{}\",", hex(&r_eph.public()));
    println!("    \"r_id_pub\":  \"{}\"", hex(&r_id.public()));
    println!("  }},");
    println!("  \"derived_keys\": {{");
    println!("    \"pair\":      \"{}\",", hex(k_pair.as_bytes()));
    println!("    \"session\":   \"{}\",", hex(k_sess.as_bytes()));
    println!("    \"seal\":      \"{}\",", hex(k_seal.as_bytes()));
    println!("    \"seal_auth\": \"{}\"", hex(k_seal_auth.as_bytes()));
    println!("  }},");
    println!("  \"human_values\": {{");
    println!(
        "    \"sas\":           \"{}\",",
        crypto::sas(&sid, &r_eph.public(), &s_eph.public(), &sas_nonce)
    );
    println!("    \"sas_nonce\":     \"{}\",", hex(&sas_nonce));
    println!(
        "    \"commit\":        \"{}\",",
        hex(&crypto::commit(&sid, &r_eph.public(), &sas_nonce))
    );
    println!(
        "    \"id_hint_r\":     \"{}\",",
        hex(&crypto::id_hint(&r_id.public()))
    );
    println!("    \"complete_hash\": \"{}\"", hex(&complete.hash8));
    println!("  }},");
    println!("  \"frames\": {{");
    println!("    \"pair_req\": \"{}\",", hex(&pair_req.encode()));
    println!("    \"beacon\":   \"{}\",", hex(&beacon.encode()));
    println!("    \"complete\": \"{}\"", hex(&complete.encode()));
    println!("  }},");
    println!("  \"aead\": {{");
    println!("    \"aad\":        \"{}\",", hex(&beacon.aad()));
    println!("    \"plaintext\":  \"{}\",", hex(b"rabaska test payload"));
    println!("    \"ciphertext\": \"{}\"", hex(&ct));
    println!("  }}");
    println!("}}");
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("modes") => cmd_modes(),
        Some("ladder") => cmd_ladder(),
        Some("vectors") => cmd_vectors(),
        _ => {
            eprintln!("usage: harness <modes|ladder|vectors>");
            std::process::exit(2);
        }
    }
}
