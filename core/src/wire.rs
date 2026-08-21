//! Frame layouts and serialization.
//!
//! FROZEN. Every constant here is baked into stored pairings on user devices.
//! See `docs/SPEC.md` section 2.

use crate::{Error, Result};

pub const MAGIC: [u8; 2] = *b"RB";
pub const VERSION: u8 = 2;

pub const PAIR_REQ_LEN: usize = 69;
pub const REVEAL_LEN: usize = 28;
pub const BEACON_LEN: usize = 102;
pub const COMPLETE_LEN: usize = 21;
/// Fixed bytes per SYMBOL frame, excluding packets.
pub const SYMBOL_OVERHEAD: usize = 19;

pub mod frame_type {
    pub const PAIR_REQ: u8 = 0x01;
    pub const BEACON: u8 = 0x02;
    pub const SYMBOL: u8 = 0x03;
    pub const COMPLETE: u8 = 0x04;
    /// Receiver's delayed nonce reveal. PAIR mode only. See SPEC 3.1.
    pub const REVEAL: u8 = 0x05;
}

pub mod flags {
    pub const COMPRESSED: u8 = 0b0000_0001;
    pub const SENDER_AUTH: u8 = 0b0000_0010;
    pub const HAS_ID_HINT: u8 = 0b0000_0100;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// First meeting, both cameras. Ephemeral ECDH plus 5-digit SAS.
    Pair = 0x01,
    /// Stored identities, both cameras. Triple-DH, no SAS.
    Session = 0x02,
    /// Camera-less sender. One-pass sealed box.
    Seal = 0x03,
    /// Trusted room. No confidentiality. Labelled as such in the UI.
    Open = 0x04,
}

impl Mode {
    pub fn from_u8(v: u8) -> Result<Mode> {
        match v {
            0x01 => Ok(Mode::Pair),
            0x02 => Ok(Mode::Session),
            0x03 => Ok(Mode::Seal),
            0x04 => Ok(Mode::Open),
            other => Err(Error::BadMode(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    Ok = 0x00,
    HashMismatch = 0x01,
    Aborted = 0x02,
}

/// Optical parameters. Carried in the beacon so the receiver knows what it is
/// looking at without any negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecParams {
    pub symbol_size: u16,
    /// 0 = QR fallback, 4 = four-colour tiles, 8 = eight-colour tiles.
    pub palette: u8,
    /// Tile edge in transmitter pixels.
    pub tile_px: u8,
}

impl Default for CodecParams {
    fn default() -> Self {
        // Planned by qr::plan_symbol_size against all five shipping rungs.
        // 4.6% total idle bytes, and three packets in a v25-M QR frame where
        // the Phase 0 guess of 512 managed one. Do not change this casually:
        // it is carried in the beacon and both ends must agree.
        CodecParams { symbol_size: 321, palette: 0, tile_px: 8 }
    }
}

// ---------------------------------------------------------------------------
// low-level helpers
// ---------------------------------------------------------------------------

fn crc32(bytes: &[u8]) -> u32 {
    let mut h = crc32fast::Hasher::new();
    h.update(bytes);
    h.finalize()
}

/// Append CRC32 over everything written so far.
fn seal_crc(buf: &mut Vec<u8>) {
    let c = crc32(buf);
    buf.extend_from_slice(&c.to_le_bytes());
}

/// Validate magic, version, type and CRC. Returns the body slice between the
/// 4-byte common header and the trailing CRC.
fn open_frame(bytes: &[u8], want_type: u8, want_len: Option<usize>) -> Result<&[u8]> {
    if let Some(n) = want_len {
        if bytes.len() != n {
            return Err(Error::Truncated { expected: n, got: bytes.len() });
        }
    } else if bytes.len() < 8 {
        return Err(Error::Truncated { expected: 8, got: bytes.len() });
    }
    if bytes[0..2] != MAGIC {
        return Err(Error::BadMagic);
    }
    if bytes[2] != VERSION {
        return Err(Error::BadVersion(bytes[2]));
    }
    if bytes[3] != want_type {
        return Err(Error::BadFrameType(bytes[3]));
    }
    let split = bytes.len() - 4;
    let expected = crc32(&bytes[..split]);
    let got = u32::from_le_bytes(bytes[split..].try_into().unwrap());
    if expected != got {
        return Err(Error::BadCrc { expected, got });
    }
    Ok(&bytes[4..split])
}

fn common_header(buf: &mut Vec<u8>, ty: u8) {
    buf.extend_from_slice(&MAGIC);
    buf.push(VERSION);
    buf.push(ty);
}

// ---------------------------------------------------------------------------
// PAIR_REQ
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairReq {
    pub flags: u8,
    pub session_id: [u8; 8],
    pub r_eph_pub: [u8; 32],
    pub id_hint: [u8; 4],
    /// Binding commitment to the receiver's SAS nonce, revealed later in a
    /// [`Reveal`] frame. Without this the last party to reveal an ephemeral key
    /// can grind ~2^17 candidates in seconds until its SAS matches the one the
    /// other leg is showing, and a screen-in-the-middle passes verification.
    pub r_commit: [u8; 16],
}

impl PairReq {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(PAIR_REQ_LEN);
        common_header(&mut b, frame_type::PAIR_REQ);
        b.push(self.flags);
        b.extend_from_slice(&self.session_id);
        b.extend_from_slice(&self.r_eph_pub);
        b.extend_from_slice(&self.id_hint);
        b.extend_from_slice(&self.r_commit);
        seal_crc(&mut b);
        debug_assert_eq!(b.len(), PAIR_REQ_LEN);
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<PairReq> {
        let body = open_frame(bytes, frame_type::PAIR_REQ, Some(PAIR_REQ_LEN))?;
        Ok(PairReq {
            flags: body[0],
            session_id: body[1..9].try_into().unwrap(),
            r_eph_pub: body[9..41].try_into().unwrap(),
            id_hint: body[41..45].try_into().unwrap(),
            r_commit: body[45..61].try_into().unwrap(),
        })
    }

    pub fn has_id_hint(&self) -> bool {
        self.flags & flags::HAS_ID_HINT != 0
    }
}

// ---------------------------------------------------------------------------
// BEACON
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Beacon {
    pub mode: Mode,
    pub flags: u8,
    pub session_id: [u8; 8],
    pub s_eph_pub: [u8; 32],
    pub nonce: [u8; 24],
    pub plaintext_len: u32,
    pub oti: [u8; 12],
    pub codec: CodecParams,
    pub build_hash: [u8; 8],
}

impl Beacon {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(BEACON_LEN);
        common_header(&mut b, frame_type::BEACON);
        b.push(self.mode as u8);
        b.push(self.flags);
        b.extend_from_slice(&self.session_id);
        b.extend_from_slice(&self.s_eph_pub);
        b.extend_from_slice(&self.nonce);
        b.extend_from_slice(&self.plaintext_len.to_le_bytes());
        b.extend_from_slice(&self.oti);
        b.extend_from_slice(&self.codec.symbol_size.to_le_bytes());
        b.push(self.codec.palette);
        b.push(self.codec.tile_px);
        b.extend_from_slice(&self.build_hash);
        seal_crc(&mut b);
        debug_assert_eq!(b.len(), BEACON_LEN);
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<Beacon> {
        let body = open_frame(bytes, frame_type::BEACON, Some(BEACON_LEN))?;
        Ok(Beacon {
            mode: Mode::from_u8(body[0])?,
            flags: body[1],
            session_id: body[2..10].try_into().unwrap(),
            s_eph_pub: body[10..42].try_into().unwrap(),
            nonce: body[42..66].try_into().unwrap(),
            plaintext_len: u32::from_le_bytes(body[66..70].try_into().unwrap()),
            oti: body[70..82].try_into().unwrap(),
            codec: CodecParams {
                symbol_size: u16::from_le_bytes(body[82..84].try_into().unwrap()),
                palette: body[84],
                tile_px: body[85],
            },
            build_hash: body[86..94].try_into().unwrap(),
        })
    }

    pub fn compressed(&self) -> bool {
        self.flags & flags::COMPRESSED != 0
    }

    pub fn sender_auth(&self) -> bool {
        self.flags & flags::SENDER_AUTH != 0
    }

    /// AEAD associated data. Deliberately excludes `oti` and `codec`, which are
    /// derived from the ciphertext and would make this circular. See SPEC 2.2.
    pub fn aad(&self) -> Vec<u8> {
        let mut a = Vec::with_capacity(14 + 1 + 1 + 1 + 8 + 32 + 24 + 4);
        a.extend_from_slice(crate::crypto::INFO_AAD);
        a.push(VERSION);
        a.push(self.mode as u8);
        a.push(self.flags);
        a.extend_from_slice(&self.session_id);
        a.extend_from_slice(&self.s_eph_pub);
        a.extend_from_slice(&self.nonce);
        a.extend_from_slice(&self.plaintext_len.to_le_bytes());
        a
    }
}

// ---------------------------------------------------------------------------
// SYMBOL
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymbolFrame {
    pub sid4: [u8; 4],
    pub frame_id: u32,
    pub packet_len: u16,
    pub packets: Vec<Vec<u8>>,
}

impl SymbolFrame {
    pub fn encode(&self) -> Vec<u8> {
        let n = self.packets.len();
        debug_assert!(n <= 255, "count is a single byte");
        let mut b = Vec::with_capacity(SYMBOL_OVERHEAD + n * self.packet_len as usize);
        common_header(&mut b, frame_type::SYMBOL);
        b.extend_from_slice(&self.sid4);
        b.extend_from_slice(&self.frame_id.to_le_bytes());
        b.push(n as u8);
        b.extend_from_slice(&self.packet_len.to_le_bytes());
        for p in &self.packets {
            debug_assert_eq!(p.len(), self.packet_len as usize);
            b.extend_from_slice(p);
        }
        seal_crc(&mut b);
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<SymbolFrame> {
        if bytes.len() < SYMBOL_OVERHEAD {
            return Err(Error::Truncated { expected: SYMBOL_OVERHEAD, got: bytes.len() });
        }
        let body = open_frame(bytes, frame_type::SYMBOL, None)?;
        let sid4: [u8; 4] = body[0..4].try_into().unwrap();
        let frame_id = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let count = body[8] as usize;
        let packet_len = u16::from_le_bytes(body[9..11].try_into().unwrap()) as usize;
        let need = 11 + count * packet_len;
        if body.len() != need {
            return Err(Error::Truncated {
                expected: need + SYMBOL_OVERHEAD - 11,
                got: bytes.len(),
            });
        }
        let packets = body[11..]
            .chunks_exact(packet_len)
            .map(|c| c.to_vec())
            .collect();
        Ok(SymbolFrame { sid4, frame_id, packet_len: packet_len as u16, packets })
    }

    /// Bytes a video frame must carry for `count` packets of `packet_len`.
    pub fn frame_size(count: usize, packet_len: u16) -> usize {
        SYMBOL_OVERHEAD + count * packet_len as usize
    }

    /// How many packets fit in an optical frame of `capacity` bytes.
    pub fn packets_per_frame(capacity: usize, packet_len: u16) -> usize {
        capacity
            .saturating_sub(SYMBOL_OVERHEAD)
            .checked_div(packet_len as usize)
            .unwrap_or(0)
            .min(255)
    }
}

// ---------------------------------------------------------------------------
// COMPLETE
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Complete {
    pub sid4: [u8; 4],
    pub status: Status,
    pub hash8: [u8; 8],
}

impl Complete {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(COMPLETE_LEN);
        common_header(&mut b, frame_type::COMPLETE);
        b.extend_from_slice(&self.sid4);
        b.push(self.status as u8);
        b.extend_from_slice(&self.hash8);
        seal_crc(&mut b);
        debug_assert_eq!(b.len(), COMPLETE_LEN);
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<Complete> {
        let body = open_frame(bytes, frame_type::COMPLETE, Some(COMPLETE_LEN))?;
        let status = match body[4] {
            0x00 => Status::Ok,
            0x01 => Status::HashMismatch,
            _ => Status::Aborted,
        };
        Ok(Complete {
            sid4: body[0..4].try_into().unwrap(),
            status,
            hash8: body[5..13].try_into().unwrap(),
        })
    }
}

// ---------------------------------------------------------------------------
// REVEAL
// ---------------------------------------------------------------------------

/// The receiver's SAS nonce, displayed only after the sender's beacon has been
/// seen. This is the reveal half of the commitment in [`PairReq`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reveal {
    pub sid4: [u8; 4],
    pub r_nonce: [u8; 16],
}

impl Reveal {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(REVEAL_LEN);
        common_header(&mut b, frame_type::REVEAL);
        b.extend_from_slice(&self.sid4);
        b.extend_from_slice(&self.r_nonce);
        seal_crc(&mut b);
        debug_assert_eq!(b.len(), REVEAL_LEN);
        b
    }

    pub fn decode(bytes: &[u8]) -> Result<Reveal> {
        let body = open_frame(bytes, frame_type::REVEAL, Some(REVEAL_LEN))?;
        Ok(Reveal {
            sid4: body[0..4].try_into().unwrap(),
            r_nonce: body[4..20].try_into().unwrap(),
        })
    }
}

/// Peek the frame type without validating anything else. Used by the receiver to
/// route a freshly decoded frame before it knows what it is.
pub fn peek_type(bytes: &[u8]) -> Result<u8> {
    if bytes.len() < 4 {
        return Err(Error::Truncated { expected: 4, got: bytes.len() });
    }
    if bytes[0..2] != MAGIC {
        return Err(Error::BadMagic);
    }
    if bytes[2] != VERSION {
        return Err(Error::BadVersion(bytes[2]));
    }
    Ok(bytes[3])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_sizes_match_spec() {
        let pr = PairReq {
            flags: flags::HAS_ID_HINT,
            session_id: [1; 8],
            r_eph_pub: [2; 32],
            id_hint: [3; 4],
            r_commit: [4; 16],
        };
        assert_eq!(pr.encode().len(), PAIR_REQ_LEN);
        let rv = Reveal { sid4: [1; 4], r_nonce: [9; 16] };
        assert_eq!(rv.encode().len(), REVEAL_LEN);

        let bc = Beacon {
            mode: Mode::Pair,
            flags: 0,
            session_id: [1; 8],
            s_eph_pub: [2; 32],
            nonce: [3; 24],
            plaintext_len: 4096,
            oti: [4; 12],
            codec: CodecParams::default(),
            build_hash: [5; 8],
        };
        assert_eq!(bc.encode().len(), BEACON_LEN);

        let cp = Complete { sid4: [1; 4], status: Status::Ok, hash8: [7; 8] };
        assert_eq!(cp.encode().len(), COMPLETE_LEN);
    }

    #[test]
    fn round_trips() {
        let pr = PairReq {
            flags: flags::HAS_ID_HINT,
            session_id: [9; 8],
            r_eph_pub: [8; 32],
            id_hint: [7; 4],
            r_commit: [6; 16],
        };
        assert_eq!(PairReq::decode(&pr.encode()).unwrap(), pr);
        let rv = Reveal { sid4: [3; 4], r_nonce: [2; 16] };
        assert_eq!(Reveal::decode(&rv.encode()).unwrap(), rv);

        let bc = Beacon {
            mode: Mode::Session,
            flags: flags::COMPRESSED | flags::SENDER_AUTH,
            session_id: [9; 8],
            s_eph_pub: [8; 32],
            nonce: [7; 24],
            plaintext_len: 123456,
            oti: [6; 12],
            codec: CodecParams { symbol_size: 900, palette: 4, tile_px: 8 },
            build_hash: [5; 8],
        };
        assert_eq!(Beacon::decode(&bc.encode()).unwrap(), bc);

        let sf = SymbolFrame {
            sid4: [1, 2, 3, 4],
            frame_id: 77,
            packet_len: 6,
            packets: vec![vec![1; 6], vec![2; 6], vec![3; 6]],
        };
        assert_eq!(SymbolFrame::decode(&sf.encode()).unwrap(), sf);

        let cp = Complete { sid4: [1; 4], status: Status::HashMismatch, hash8: [7; 8] };
        assert_eq!(Complete::decode(&cp.encode()).unwrap(), cp);
    }

    #[test]
    fn single_bit_flip_is_caught_everywhere() {
        let bc = Beacon {
            mode: Mode::Pair,
            flags: 0,
            session_id: [1; 8],
            s_eph_pub: [2; 32],
            nonce: [3; 24],
            plaintext_len: 4096,
            oti: [4; 12],
            codec: CodecParams::default(),
            build_hash: [5; 8],
        };
        let good = bc.encode();
        for i in 0..good.len() {
            for bit in 0..8 {
                let mut bad = good.clone();
                bad[i] ^= 1 << bit;
                assert!(
                    Beacon::decode(&bad).is_err(),
                    "flip at byte {i} bit {bit} slipped through"
                );
            }
        }
    }

    #[test]
    fn truncation_is_caught() {
        let bc = Beacon {
            mode: Mode::Pair,
            flags: 0,
            session_id: [1; 8],
            s_eph_pub: [2; 32],
            nonce: [3; 24],
            plaintext_len: 0,
            oti: [4; 12],
            codec: CodecParams::default(),
            build_hash: [5; 8],
        };
        let good = bc.encode();
        for n in 0..good.len() {
            assert!(Beacon::decode(&good[..n]).is_err(), "len {n} accepted");
        }
    }

    #[test]
    fn wrong_type_rejected() {
        let cp = Complete { sid4: [1; 4], status: Status::Ok, hash8: [7; 8] };
        assert_eq!(PairReq::decode(&cp.encode()), Err(Error::Truncated {
            expected: PAIR_REQ_LEN,
            got: COMPLETE_LEN
        }));
    }

    #[test]
    fn packing_arithmetic() {
        // A v25 QR at ECC-M holds about 1050 bytes.
        assert_eq!(SymbolFrame::packets_per_frame(1050, 516), 1);
        // A 1024x1024 tile frame at 4 colours carries roughly 7500 usable bytes.
        assert_eq!(SymbolFrame::packets_per_frame(7500, 516), 14);
        assert_eq!(SymbolFrame::packets_per_frame(10, 516), 0);
    }
}
