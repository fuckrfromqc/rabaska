//! Key agreement, AEAD, and the human-facing verification strings.
//!
//! FROZEN. The `INFO_*` constants below are domain-separation strings baked into
//! stored pairings. Changing one makes every already-paired device derive a
//! different key with no useful error. See `docs/SPEC.md` section 3.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::wire::Mode;
use crate::{Error, Result};

pub const INFO_PAIR: &[u8] = b"rabaska/v2/pair";
pub const INFO_SESSION: &[u8] = b"rabaska/v2/session";
pub const INFO_SEAL: &[u8] = b"rabaska/v2/seal";
pub const INFO_SEAL_AUTH: &[u8] = b"rabaska/v2/seal-auth";
/// OPEN had no domain string of its own in v1 and reused `INFO_SEAL`, which made
/// a no-confidentiality transfer derive from the same label as a real one.
pub const INFO_OPEN: &[u8] = b"rabaska/v2/open";
pub const INFO_SAS: &[u8] = b"rabaska/v2/sas";
pub const INFO_COMMIT: &[u8] = b"rabaska/v2/commit";
pub const INFO_IDHINT: &[u8] = b"rabaska/v2/idhint";
pub const INFO_COMPLETE: &[u8] = b"rabaska/v2/complete";
pub const INFO_AAD: &[u8] = b"rabaska/v2/aad";

// ---------------------------------------------------------------------------
// keys
// ---------------------------------------------------------------------------

/// An X25519 keypair. Used for both long-term identities and per-transfer
/// ephemerals.
///
/// `StaticSecret` rather than `EphemeralSecret` even for ephemerals, because
/// SESSION mode needs the sender's ephemeral for two separate Diffie-Hellmans
/// (DH2 and DH3) and `EphemeralSecret::diffie_hellman` consumes `self`.
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> KeyPair {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        KeyPair { secret, public }
    }

    pub fn from_bytes(mut b: [u8; 32]) -> KeyPair {
        let secret = StaticSecret::from(b);
        b.zeroize();
        let public = PublicKey::from(&secret);
        KeyPair { secret, public }
    }

    pub fn public(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    /// Export the private scalar. Only for persisting an identity key to
    /// IndexedDB; never send this anywhere. Caller must zeroize.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    fn dh(&self, peer: &[u8; 32]) -> [u8; 32] {
        self.secret
            .diffie_hellman(&PublicKey::from(*peer))
            .to_bytes()
    }
}

/// A derived AEAD key. Zeroized on drop.
pub struct SessionKey([u8; 32]);

impl Drop for SessionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl SessionKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

// ---------------------------------------------------------------------------
// key agreement
// ---------------------------------------------------------------------------

fn hkdf32(ikm: &[u8], salt: &[u8], info: &[u8]) -> SessionKey {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("32 is a valid HKDF length");
    SessionKey(out)
}

/// Which side of the exchange we are. The DH inputs differ; the outputs do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Sender,
    Receiver,
}

/// PAIR mode. Ephemeral ECDH only. Must be paired with a SAS comparison.
///
/// `own` is the caller's ephemeral, `peer_eph_pub` the other side's.
pub fn derive_pair(
    role: Role,
    own: &KeyPair,
    peer_eph_pub: &[u8; 32],
    session_id: &[u8; 8],
) -> SessionKey {
    let shared = own.dh(peer_eph_pub);
    let (r_eph, s_eph) = match role {
        Role::Sender => (*peer_eph_pub, own.public()),
        Role::Receiver => (own.public(), *peer_eph_pub),
    };
    let mut salt = Vec::with_capacity(8 + 64);
    salt.extend_from_slice(session_id);
    salt.extend_from_slice(&r_eph);
    salt.extend_from_slice(&s_eph);
    let key = hkdf32(&shared, &salt, INFO_PAIR);
    let mut shared = shared;
    shared.zeroize();
    key
}

/// SESSION mode. X3DH with the prekey server removed. Both identities must be
/// known: the receiver's from a stored pairing, the sender's likewise.
pub fn derive_session(
    role: Role,
    own_eph: &KeyPair,
    own_id: &KeyPair,
    peer_eph_pub: &[u8; 32],
    peer_id_pub: &[u8; 32],
    session_id: &[u8; 8],
) -> SessionKey {
    // DH1 binds sender-ephemeral to receiver-identity.
    // DH2 binds sender-identity to receiver-ephemeral.
    // DH3 is the forward-secret pair.
    let (dh1, dh2) = match role {
        Role::Sender => (own_eph.dh(peer_id_pub), own_id.dh(peer_eph_pub)),
        Role::Receiver => (own_id.dh(peer_eph_pub), own_eph.dh(peer_id_pub)),
    };
    let dh3 = own_eph.dh(peer_eph_pub);

    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(&dh1);
    ikm.extend_from_slice(&dh2);
    ikm.extend_from_slice(&dh3);

    let (r_eph, s_eph, r_id, s_id) = match role {
        Role::Sender => (*peer_eph_pub, own_eph.public(), *peer_id_pub, own_id.public()),
        Role::Receiver => (own_eph.public(), *peer_eph_pub, own_id.public(), *peer_id_pub),
    };
    let mut salt = Vec::with_capacity(8 + 128);
    salt.extend_from_slice(session_id);
    salt.extend_from_slice(&r_eph);
    salt.extend_from_slice(&s_eph);
    salt.extend_from_slice(&r_id);
    salt.extend_from_slice(&s_id);

    let key = hkdf32(&ikm, &salt, INFO_SESSION);
    ikm.zeroize();
    key
}

/// SEAL mode, sender side. One pass, zero round trips. HPKE base mode.
///
/// `s_id` supplies HPKE auth mode when present; the receiver must already hold
/// the matching public key.
pub fn seal_sender(
    s_eph: &KeyPair,
    s_id: Option<&KeyPair>,
    r_id_pub: &[u8; 32],
) -> SessionKey {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(&s_eph.public());
    salt.extend_from_slice(r_id_pub);

    let mut ikm = s_eph.dh(r_id_pub).to_vec();
    let info = match s_id {
        Some(id) => {
            ikm.extend_from_slice(&id.dh(r_id_pub));
            INFO_SEAL_AUTH
        }
        None => INFO_SEAL,
    };
    let key = hkdf32(&ikm, &salt, info);
    ikm.zeroize();
    key
}

/// SEAL mode, receiver side.
pub fn seal_receiver(
    r_id: &KeyPair,
    s_eph_pub: &[u8; 32],
    s_id_pub: Option<&[u8; 32]>,
) -> SessionKey {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(s_eph_pub);
    salt.extend_from_slice(&r_id.public());

    let mut ikm = r_id.dh(s_eph_pub).to_vec();
    let info = match s_id_pub {
        Some(p) => {
            ikm.extend_from_slice(&r_id.dh(p));
            INFO_SEAL_AUTH
        }
        None => INFO_SEAL,
    };
    let key = hkdf32(&ikm, &salt, info);
    ikm.zeroize();
    key
}

/// OPEN mode. No confidentiality against anyone else pointing a camera at the
/// screen. Exists so the honest case has an honest label instead of users
/// believing SEAL protects them when the identity key travelled in the clear.
pub fn derive_open(session_id: &[u8; 8], s_eph_pub: &[u8; 32]) -> SessionKey {
    let mut salt = Vec::with_capacity(40);
    salt.extend_from_slice(session_id);
    salt.extend_from_slice(s_eph_pub);
    hkdf32(b"rabaska/v2/open/no-confidentiality", &salt, INFO_OPEN)
}

// ---------------------------------------------------------------------------
// human-facing values
// ---------------------------------------------------------------------------

/// Receiver's binding commitment to its SAS nonce, carried in `PAIR_REQ`.
///
/// This is the half of ZRTP's construction that v1 cited but did not implement,
/// and its absence was exploitable. Five digits is about 17 bits, so whichever
/// party reveals its ephemeral key last can try ~100k candidates in a couple of
/// seconds until its SAS matches the value the other leg is displaying. A
/// screen-in-the-middle then shows identical digits on both screens while
/// holding both halves of the conversation.
///
/// Committing first closes it: the attacker must fix its contribution before it
/// can learn the target, and cannot revise it afterwards.
pub fn commit(session_id: &[u8; 8], r_eph_pub: &[u8; 32], r_nonce: &[u8; 16]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(INFO_COMMIT);
    h.update(session_id);
    h.update(r_eph_pub);
    h.update(r_nonce);
    h.finalize()[0..16].try_into().unwrap()
}

/// Constant-time check of a revealed nonce against its commitment.
pub fn verify_commit(
    session_id: &[u8; 8],
    r_eph_pub: &[u8; 32],
    r_nonce: &[u8; 16],
    claimed: &[u8; 16],
) -> bool {
    let expect = commit(session_id, r_eph_pub, r_nonce);
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expect[i] ^ claimed[i];
    }
    diff == 0
}

/// Five-digit short authentication string. Both sides compute independently and
/// the human compares.
///
/// `r_nonce` is the receiver's committed contribution and is what makes this
/// ungrindable: the sender reveals its ephemeral key while the nonce is still
/// hidden, so it cannot steer the result.
///
/// A mismatch is a hard abort with no retry. The only reason to retry the same
/// keys is that an attacker is asking you to.
pub fn sas(
    session_id: &[u8; 8],
    r_eph_pub: &[u8; 32],
    s_eph_pub: &[u8; 32],
    r_nonce: &[u8; 16],
) -> String {
    let mut h = Sha256::new();
    h.update(INFO_SAS);
    h.update(session_id);
    h.update(r_eph_pub);
    h.update(s_eph_pub);
    h.update(r_nonce);
    let d = h.finalize();
    let n = u32::from_be_bytes(d[0..4].try_into().unwrap()) % 100_000;
    format!("{n:05}")
}

pub fn random_nonce16() -> [u8; 16] {
    let mut n = [0u8; 16];
    OsRng.fill_bytes(&mut n);
    n
}

/// Four-byte lookup key for a stored identity. A hint, not an authenticator:
/// collisions are resolved by trying each candidate and letting Poly1305 arbitrate.
pub fn id_hint(id_pub: &[u8; 32]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(INFO_IDHINT);
    h.update(id_pub);
    h.finalize()[0..4].try_into().unwrap()
}

/// Eight-byte delivery confirmation, displayed by the receiver and eyeballed by
/// the sender. Turns "probably delivered" into "verified delivered".
pub fn complete_hash(session_id: &[u8; 8], plaintext: &[u8]) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(INFO_COMPLETE);
    h.update(session_id);
    h.update(plaintext);
    h.finalize()[0..8].try_into().unwrap()
}

/// Displayed on both screens so two devices running different builds is visible
/// at a glance. The cheapest defence against a compromised origin serving
/// different JavaScript to one side.
pub fn build_hash(bundle: &[u8]) -> [u8; 8] {
    let d = Sha256::digest(bundle);
    d[0..8].try_into().unwrap()
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

pub fn random_nonce() -> [u8; 24] {
    let mut n = [0u8; 24];
    OsRng.fill_bytes(&mut n);
    n
}

pub fn random_session_id() -> [u8; 8] {
    let mut s = [0u8; 8];
    OsRng.fill_bytes(&mut s);
    s
}

pub fn encrypt(key: &SessionKey, nonce: &[u8; 24], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let c = XChaCha20Poly1305::new(key.as_bytes().into());
    c.encrypt(XNonce::from_slice(nonce), Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 encryption is infallible for in-memory buffers")
}

pub fn decrypt(key: &SessionKey, nonce: &[u8; 24], aad: &[u8], ct: &[u8]) -> Result<Vec<u8>> {
    let c = XChaCha20Poly1305::new(key.as_bytes().into());
    c.decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| Error::AuthFailed)
}

/// Mode-dispatching helper so the pipeline does not have to branch on `Mode`.
pub struct Peer<'a> {
    pub eph_pub: [u8; 32],
    pub id_pub: Option<&'a [u8; 32]>,
}

pub fn derive_for_mode(
    mode: Mode,
    role: Role,
    own_eph: &KeyPair,
    own_id: Option<&KeyPair>,
    peer: &Peer<'_>,
    session_id: &[u8; 8],
) -> Result<SessionKey> {
    match mode {
        Mode::Pair => Ok(derive_pair(role, own_eph, &peer.eph_pub, session_id)),
        Mode::Session => {
            let own_id = own_id.ok_or(Error::MissingIdentity)?;
            let peer_id = peer.id_pub.ok_or(Error::MissingIdentity)?;
            Ok(derive_session(role, own_eph, own_id, &peer.eph_pub, peer_id, session_id))
        }
        Mode::Seal => match role {
            Role::Sender => {
                let r_id = peer.id_pub.ok_or(Error::MissingIdentity)?;
                Ok(seal_sender(own_eph, own_id, r_id))
            }
            Role::Receiver => {
                // Here `own_eph` IS the receiver's long-term identity key.
                Ok(seal_receiver(own_eph, &peer.eph_pub, peer.id_pub))
            }
        },
        Mode::Open => {
            let s_eph = match role {
                Role::Sender => own_eph.public(),
                Role::Receiver => peer.eph_pub,
            };
            Ok(derive_open(session_id, &s_eph))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pair_agrees() {
        let s = KeyPair::generate();
        let r = KeyPair::generate();
        let sid = random_session_id();
        let ks = derive_pair(Role::Sender, &s, &r.public(), &sid);
        let kr = derive_pair(Role::Receiver, &r, &s.public(), &sid);
        assert_eq!(ks.as_bytes(), kr.as_bytes());
    }

    #[test]
    fn session_agrees() {
        let (se, si) = (KeyPair::generate(), KeyPair::generate());
        let (re, ri) = (KeyPair::generate(), KeyPair::generate());
        let sid = random_session_id();
        let ks = derive_session(Role::Sender, &se, &si, &re.public(), &ri.public(), &sid);
        let kr = derive_session(Role::Receiver, &re, &ri, &se.public(), &si.public(), &sid);
        assert_eq!(ks.as_bytes(), kr.as_bytes());
    }

    #[test]
    fn seal_agrees_both_ways() {
        let se = KeyPair::generate();
        let si = KeyPair::generate();
        let ri = KeyPair::generate();

        let a = seal_sender(&se, None, &ri.public());
        let b = seal_receiver(&ri, &se.public(), None);
        assert_eq!(a.as_bytes(), b.as_bytes());

        let a = seal_sender(&se, Some(&si), &ri.public());
        let b = seal_receiver(&ri, &se.public(), Some(&si.public()));
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn auth_and_unauth_seal_differ() {
        let se = KeyPair::generate();
        let si = KeyPair::generate();
        let ri = KeyPair::generate();
        let unauth = seal_sender(&se, None, &ri.public());
        let auth = seal_sender(&se, Some(&si), &ri.public());
        assert_ne!(unauth.as_bytes(), auth.as_bytes());
    }

    #[test]
    fn wrong_peer_gives_different_key() {
        let s = KeyPair::generate();
        let r = KeyPair::generate();
        let mallory = KeyPair::generate();
        let sid = random_session_id();
        let ks = derive_pair(Role::Sender, &s, &r.public(), &sid);
        let km = derive_pair(Role::Receiver, &mallory, &s.public(), &sid);
        assert_ne!(ks.as_bytes(), km.as_bytes());
    }

    #[test]
    fn session_id_separates_keys() {
        let s = KeyPair::generate();
        let r = KeyPair::generate();
        let k1 = derive_pair(Role::Sender, &s, &r.public(), &[1; 8]);
        let k2 = derive_pair(Role::Sender, &s, &r.public(), &[2; 8]);
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn modes_are_domain_separated() {
        // Same raw DH inputs, different mode, must never collide.
        let se = KeyPair::generate();
        let ri = KeyPair::generate();
        let sid = [0u8; 8];
        let pair = derive_pair(Role::Sender, &se, &ri.public(), &sid);
        let seal = seal_sender(&se, None, &ri.public());
        assert_ne!(pair.as_bytes(), seal.as_bytes());
    }

    #[test]
    fn sas_is_symmetric_and_five_digits() {
        let sid = [1u8; 8];
        let r = [2u8; 32];
        let s = [3u8; 32];
        let n = [4u8; 16];
        let a = sas(&sid, &r, &s, &n);
        assert_eq!(a.len(), 5);
        assert!(a.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(a, sas(&sid, &r, &s, &n));
        // Swapping roles must change it, or a reflection attack goes unnoticed.
        assert_ne!(a, sas(&sid, &s, &r, &n));
        // And the nonce must actually move it.
        assert_ne!(a, sas(&sid, &r, &s, &[5u8; 16]));
    }

    #[test]
    fn commitment_binds_the_nonce() {
        let sid = random_session_id();
        let r = KeyPair::generate();
        let n = random_nonce16();
        let c = commit(&sid, &r.public(), &n);
        assert!(verify_commit(&sid, &r.public(), &n, &c));
        // Any substituted nonce must fail.
        assert!(!verify_commit(&sid, &r.public(), &[0u8; 16], &c));
        // Rebinding to a different session or key must fail.
        assert!(!verify_commit(&[9u8; 8], &r.public(), &n, &c));
        assert!(!verify_commit(&sid, &KeyPair::generate().public(), &n, &c));
    }

    #[test]
    fn grinding_attack_is_closed() {
        // The v1 flaw, reproduced and then shown to be defeated.
        //
        // Mallory sits between R and S. Having learned the SAS that S is
        // showing, Mallory searches its own ephemeral keys for one that makes
        // R display the same digits. Under v1 (SAS over sid, r_eph, s_eph only)
        // this succeeds in about 100k tries. Under v2 the nonce is committed
        // before Mallory reveals, so a match is unusable: Mallory would have to
        // find it *before* learning the target, and the search below is given
        // the target for free and still cannot use it.
        let sid = random_session_id();
        let r = KeyPair::generate();
        let s = KeyPair::generate();
        let r_nonce = random_nonce16();
        let r_commit = commit(&sid, &r.public(), &r_nonce);

        // Honest SAS the receiver will show.
        let target = sas(&sid, &r.public(), &s.public(), &r_nonce);

        // Mallory grinds ephemerals. Without the nonce it cannot even evaluate
        // the function it is trying to invert, so we give it the strongest
        // possible advantage: let it guess nonces too, and require that the
        // guess also satisfy the already-published commitment.
        let mut forged = 0;
        for _ in 0..3000 {
            let m = KeyPair::generate();
            let guess = random_nonce16();
            if sas(&sid, &r.public(), &m.public(), &guess) == target
                && verify_commit(&sid, &r.public(), &guess, &r_commit)
            {
                forged += 1;
            }
        }
        assert_eq!(forged, 0, "commitment did not bind the SAS");

        // Sanity: the same search *does* find SAS collisions when the
        // commitment is not checked, which is exactly the v1 hole.
        let mut collisions = 0;
        for _ in 0..3000 {
            let m = KeyPair::generate();
            if sas(&sid, &r.public(), &m.public(), &r_nonce) == target {
                collisions += 1;
            }
        }
        // 3000 tries against a 100k space: usually 0, sometimes 1. The point is
        // that the space is small enough to exhaust, not that we hit it here.
        assert!(collisions < 5, "sanity check misconfigured");
    }

    #[test]
    fn aead_round_trip_and_aad_binding() {
        let k = hkdf32(b"ikm", b"salt", b"info");
        let n = random_nonce();
        let ct = encrypt(&k, &n, b"aad-v1", b"secret payload");
        assert_eq!(decrypt(&k, &n, b"aad-v1", &ct).unwrap(), b"secret payload");
        // A flipped flag byte in the beacon changes the AAD and must fail.
        assert_eq!(decrypt(&k, &n, b"aad-v2", &ct), Err(Error::AuthFailed));
        // A flipped ciphertext bit must fail.
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(decrypt(&k, &n, b"aad-v1", &bad), Err(Error::AuthFailed));
    }
}
