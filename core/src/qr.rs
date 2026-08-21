//! QR as the Phase 1 carrier and the permanent interoperability rung.
//!
//! Two reasons this stays in the codebase after the tile codec lands. It is the
//! only rung a hardware wallet or a generic scanner can read, and it is the rung
//! that still works at a bad angle in a dim room. It is not a fallback bolted on
//! for robustness; it is interleaved into the ladder from the start.
//!
//! # The binary-mode trap
//!
//! Rabaska frames are arbitrary bytes: ephemeral public keys, nonces, ciphertext.
//! They are not UTF-8 and will never be. Almost every QR decoding API in
//! circulation returns a `String`, which either throws or silently substitutes
//! replacement characters on byte-mode payloads. `rqrr::Grid::decode` does the
//! former; `jsQR`'s `.data` field does the latter, which is worse because it
//! looks like it worked.
//!
//! The rule, enforced by [`decode_luma`] here and by tests below: decode to a
//! byte sink, never to a string. In JS that means `jsQR(...).binaryData`, not
//! `.data`.

use qrcodegen::{QrCode, QrCodeEcc, QrSegment, Version};

use crate::{Error, Result};

/// Error correction level. `Medium` is the Phase 1 default for symbol frames:
/// `Low` buys about 25% more payload and gives it straight back in failed
/// decodes at handheld angles. `High` is for the beacon and the reverse QR,
/// where acquisition from across a room matters more than density.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecc {
    Low,
    Medium,
    Quartile,
    High,
}

impl Ecc {
    fn to_qrcodegen(self) -> QrCodeEcc {
        match self {
            Ecc::Low => QrCodeEcc::Low,
            Ecc::Medium => QrCodeEcc::Medium,
            Ecc::Quartile => QrCodeEcc::Quartile,
            Ecc::High => QrCodeEcc::High,
        }
    }
}

/// A rendered QR, one byte per module: 0 = dark, 255 = light.
pub struct Rendered {
    pub luma: Vec<u8>,
    pub width: usize,
    pub height: usize,
    /// Modules per side, excluding the quiet zone.
    pub modules: usize,
}

/// Largest byte-mode payload for a given version and ECC level.
///
/// Measured by asking the encoder, not transcribed from a reference chart. A
/// chart can drift from what the encoder will actually accept; a binary search
/// against `encode_segments_advanced` cannot. `boostecl` is false so the encoder
/// does not quietly upgrade the error correction level and hand back a smaller
/// number than the one we asked about.
pub fn capacity(version: u8, ecc: Ecc) -> usize {
    fn fits(len: usize, version: u8, ecc: Ecc) -> bool {
        let data = vec![0u8; len];
        let segs = [QrSegment::make_bytes(&data)];
        let v = Version::new(version);
        QrCode::encode_segments_advanced(&segs, ecc.to_qrcodegen(), v, v, None, false).is_ok()
    }
    let (mut lo, mut hi) = (0usize, 3000usize);
    while lo < hi {
        let mid = (lo + hi + 1) / 2;
        if fits(mid, version, ecc) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    lo
}

/// Smallest version that holds `len` bytes at `ecc`, or None if it does not fit
/// in a version 40 code.
pub fn smallest_version(len: usize, ecc: Ecc) -> Option<u8> {
    (1u8..=40).find(|&v| capacity(v, ecc) >= len)
}

/// Encode bytes as a byte-mode QR and render to a luma buffer.
///
/// `scale` is transmitter pixels per module. `quiet` is the quiet zone in
/// modules; the spec says 4 and anything less costs real decode rate.
pub fn encode_luma(data: &[u8], ecc: Ecc, scale: usize, quiet: usize) -> Result<Rendered> {
    let code = QrCode::encode_binary(data, ecc.to_qrcodegen())
        .map_err(|_| Error::Truncated { expected: 0, got: data.len() })?;
    let modules = code.size() as usize;
    let side = (modules + 2 * quiet) * scale;
    let mut luma = vec![255u8; side * side];

    for my in 0..modules {
        for mx in 0..modules {
            if !code.get_module(mx as i32, my as i32) {
                continue;
            }
            let x0 = (mx + quiet) * scale;
            let y0 = (my + quiet) * scale;
            for y in y0..y0 + scale {
                let row = y * side;
                for x in x0..x0 + scale {
                    luma[row + x] = 0;
                }
            }
        }
    }

    Ok(Rendered { luma, width: side, height: side, modules })
}

/// Decode the first QR found in a luma buffer, as raw bytes.
///
/// Never returns a `String`. See the module docs.
#[cfg(feature = "qr-decode")]
pub fn decode_luma(luma: &[u8], width: usize, height: usize) -> Result<Vec<u8>> {
    let mut img = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        luma[y * width + x]
    });
    let grids = img.detect_grids();
    for grid in grids {
        let mut out: Vec<u8> = Vec::new();
        // decode_to, not decode: the latter runs String::from_utf8 and rejects
        // every frame we will ever send.
        if grid.decode_to(&mut out).is_ok() {
            return Ok(out);
        }
    }
    Err(Error::BadMagic)
}

/// Payload bytes left for RaptorQ packets after the SYMBOL wire header.
///
/// For display and reasoning only. Do **not** feed this to
/// [`crate::wire::SymbolFrame::packets_per_frame`] or to [`plan_symbol_size`]:
/// both take the raw frame capacity and subtract the overhead themselves, so
/// passing a pre-subtracted number deducts it twice.
pub fn usable_payload(version: u8, ecc: Ecc) -> usize {
    capacity(version, ecc).saturating_sub(crate::wire::SYMBOL_OVERHEAD)
}

/// Choose a RaptorQ symbol size that tiles the given frame capacities with as
/// little waste as possible.
///
/// This matters more than it looks. Symbol size is fixed for the whole transfer,
/// because packets must be interchangeable across every rung of the ladder. Pick
/// it badly and a QR frame carries one packet and throws away half its payload:
/// at v25-M there are 978 usable bytes, and a 516-byte packet wastes 462 of them.
///
/// `capacities` are **raw** frame capacities, the same convention as
/// [`crate::wire::SymbolFrame::packets_per_frame`]. Returns the symbol size, not
/// the packet size; RaptorQ adds a 4-byte PayloadId on top.
///
/// Ties break toward the smaller symbol. The obvious argument runs the other way
/// (a bigger symbol pays the 4-byte PayloadId less often) but it loses: RaptorQ's
/// reception overhead is a roughly fixed number of symbols per source block, so
/// smaller symbols make that overhead a smaller fraction of the object, and a
/// torn frame costs less when a frame carries nine packets instead of one.
pub fn plan_symbol_size(capacities: &[usize], min: u16, max: u16) -> u16 {
    let mut best = min;
    let mut best_waste = f64::MAX;
    for s in min..=max {
        let packet = s as usize + 4;
        let mut waste = 0.0;
        let mut usable = false;
        for &raw in capacities {
            let cap = raw.saturating_sub(crate::wire::SYMBOL_OVERHEAD);
            let n = cap / packet;
            if n == 0 {
                // A rung that cannot carry a single packet is not merely
                // wasteful, it is dead. Disqualify.
                waste = f64::MAX;
                break;
            }
            usable = true;
            waste += (cap - n * packet) as f64 / cap as f64;
        }
        if usable && waste < best_waste {
            best_waste = waste;
            best = s;
        }
    }
    best
}

/// Raw frame capacities of every rung the shipping ladder uses: three QR
/// versions plus the two tile densities Phase 2 will add.
pub const SHIPPING_RUNGS: [usize; 5] = [997, 2331, 2953, 7500, 11000];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{self, Beacon, CodecParams, Mode, PairReq, SymbolFrame};

    fn usable_payload_of(raw: usize) -> usize {
        raw - wire::SYMBOL_OVERHEAD
    }

    #[test]
    fn measured_capacities() {
        // Sanity anchors against the published QR tables. If qrcodegen ever
        // disagrees with the standard, this is where it shows up.
        assert_eq!(capacity(40, Ecc::Low), 2953);
        assert_eq!(capacity(40, Ecc::High), 1273);
        assert_eq!(capacity(1, Ecc::Low), 17);
    }

    #[test]
    fn beacon_and_pair_req_fit_their_target_versions() {
        // SPEC 2.1 claims PAIR_REQ fits v6 at ECC-H, SPEC 2.2 claims BEACON fits
        // v10 at ECC-H. Both are load-bearing: these are the frames that must
        // acquire from across a room.
        // PAIR_REQ grew from 53 to 69 bytes when the SAS commitment landed, so
        // its target moved from v6-H to v8-H: 49 modules a side instead of 41.
        // Still comfortably acquirable across a room.
        assert!(capacity(8, Ecc::High) >= wire::PAIR_REQ_LEN, "PAIR_REQ needs v8-H");
        assert!(capacity(10, Ecc::High) >= wire::BEACON_LEN, "BEACON needs v10-H");
        assert_eq!(smallest_version(wire::PAIR_REQ_LEN, Ecc::High), Some(8));
        assert_eq!(smallest_version(wire::REVEAL_LEN, Ecc::High), Some(4));
        assert_eq!(smallest_version(wire::BEACON_LEN, Ecc::High), Some(10));
        assert_eq!(smallest_version(wire::COMPLETE_LEN, Ecc::High), Some(3));
    }

    #[test]
    #[cfg(feature = "qr-decode")]
    fn real_optical_round_trip_of_a_real_frame() {
        // Encode an actual beacon, render it to pixels, decode the pixels back,
        // assert the bytes survived. This is the CI gate that catches every
        // codec regression without a camera.
        let beacon = Beacon {
            mode: Mode::Session,
            flags: wire::flags::COMPRESSED,
            session_id: [0xA0; 8],
            s_eph_pub: [0x7B; 32],
            nonce: [0x5A; 24],
            plaintext_len: 4096,
            oti: [0x66; 12],
            codec: CodecParams { symbol_size: 512, palette: 4, tile_px: 8 },
            build_hash: [0x77; 8],
        };
        let bytes = beacon.encode();
        let r = encode_luma(&bytes, Ecc::High, 6, 4).unwrap();
        let back = decode_luma(&r.luma, r.width, r.height).unwrap();
        assert_eq!(back, bytes);
        // And it survives the full parse, not just the byte compare.
        assert_eq!(Beacon::decode(&back).unwrap(), beacon);
    }

    #[test]
    #[cfg(feature = "qr-decode")]
    fn binary_frames_are_not_utf8_which_is_the_whole_point() {
        // A frame full of key material is not text. Any decoder that hands back
        // a String will either throw or silently substitute U+FFFD, and the
        // second failure mode is the dangerous one because it looks like success.
        let pr = PairReq {
            flags: wire::flags::HAS_ID_HINT,
            session_id: [0xFF, 0xFE, 0x80, 0x81, 0x00, 0xC0, 0xC1, 0xF5],
            r_eph_pub: [0x80; 32],
            id_hint: [0xF7, 0xBF, 0xBF, 0xBF],
            r_commit: [0x90; 16],
        };
        let bytes = pr.encode();
        assert!(
            String::from_utf8(bytes.clone()).is_err(),
            "test is vacuous if the frame happens to be valid UTF-8"
        );

        let r = encode_luma(&bytes, Ecc::High, 6, 4).unwrap();
        let back = decode_luma(&r.luma, r.width, r.height).unwrap();
        assert_eq!(back, bytes);
        assert_eq!(PairReq::decode(&back).unwrap(), pr);
    }

    #[test]
    #[cfg(feature = "qr-decode")]
    fn symbol_frames_round_trip_at_every_shipping_version() {
        // The rungs the transmitter will actually use.
        for (version, ecc) in [
            (25u8, Ecc::Medium),
            (30, Ecc::Medium),
            (40, Ecc::Medium),
            (40, Ecc::Low),
        ] {
            let cap = capacity(version, ecc);
            let ppf = SymbolFrame::packets_per_frame(cap, 516);
            assert!(ppf >= 1, "v{version} holds no packets at all");

            let sf = SymbolFrame {
                sid4: [0xDE, 0xAD, 0xBE, 0xEF],
                frame_id: 4242,
                packet_len: 516,
                packets: (0..ppf)
                    .map(|i| (0..516).map(|j| (i * 7 + j * 13) as u8).collect())
                    .collect(),
            };
            let bytes = sf.encode();
            assert!(
                bytes.len() <= capacity(version, ecc),
                "v{version} overflow: {} > {}",
                bytes.len(),
                capacity(version, ecc)
            );

            let r = encode_luma(&bytes, ecc, 4, 4).unwrap();
            let back = decode_luma(&r.luma, r.width, r.height)
                .unwrap_or_else(|e| panic!("v{version} decode failed: {e}"));
            assert_eq!(back, bytes, "v{version} corrupted");
            assert_eq!(SymbolFrame::decode(&back).unwrap(), sf);
        }
    }

    #[test]
    #[cfg(feature = "qr-decode")]
    fn survives_realistic_camera_degradation() {
        // Not a substitute for a real camera, but it catches the case where the
        // pipeline only works on mathematically perfect input.
        let sf = SymbolFrame {
            sid4: [1, 2, 3, 4],
            frame_id: 9,
            packet_len: 516,
            packets: vec![(0..516).map(|j| (j * 31) as u8).collect()],
        };
        let bytes = sf.encode();
        let r = encode_luma(&bytes, Ecc::Medium, 8, 4).unwrap();

        // Gaussian-ish blur plus contrast loss plus additive noise.
        let mut dirty = r.luma.clone();
        for y in 1..r.height - 1 {
            for x in 1..r.width - 1 {
                let mut acc = 0u32;
                for dy in 0..3 {
                    for dx in 0..3 {
                        acc += r.luma[(y + dy - 1) * r.width + (x + dx - 1)] as u32;
                    }
                }
                let blurred = (acc / 9) as i32;
                // Squeeze into a 40..215 band, as a dim screen would.
                let dim = 40 + blurred * 175 / 255;
                let noise = ((x * 7919 + y * 6151) % 21) as i32 - 10;
                dirty[y * r.width + x] = (dim + noise).clamp(0, 255) as u8;
            }
        }

        let back = decode_luma(&dirty, r.width, r.height).unwrap();
        assert_eq!(back, bytes);
    }

    #[test]
    fn symbol_size_planner_beats_the_phase_0_guess() {
        let v25m = capacity(25, Ecc::Medium);
        let v40l = capacity(40, Ecc::Low);

        // Phase 0 guessed 512 and it is a poor fit for the QR rung.
        assert_eq!(SymbolFrame::packets_per_frame(v25m, 516), 1);
        let wasted = usable_payload(25, Ecc::Medium) - 516;
        assert!(wasted > 400, "the problem being solved: {wasted} bytes idle");

        // Plan against every rung the ladder will use, not just the QR ones.
        let s = plan_symbol_size(&SHIPPING_RUNGS, 200, 1400);
        let packet = s as usize + 4;

        // Triple the QR-rung throughput, and no rung left holding idle bytes.
        assert!(
            SymbolFrame::packets_per_frame(v25m, packet as u16) >= 3,
            "v25-M should carry 3 packets, not 1"
        );
        assert!(SymbolFrame::packets_per_frame(v40l, packet as u16) >= 9);
        for &raw in &SHIPPING_RUNGS {
            let idle = usable_payload_of(raw) % packet;
            assert!(
                idle * 20 < usable_payload_of(raw),
                "rung {raw} wastes {idle} bytes, over 5%"
            );
        }

        // And it must be what the shipping default actually uses.
        assert_eq!(CodecParams::default().symbol_size, s);
    }

    #[test]
    fn planner_never_kills_a_rung() {
        // A symbol too large for the smallest rung would make that rung carry
        // nothing at all, which is worse than wasteful.
        let small = capacity(20, Ecc::High);
        let s = plan_symbol_size(&[small, 7500, 11000], 200, 2000);
        assert!(SymbolFrame::packets_per_frame(small, s + 4) >= 1);
    }

    #[test]
    fn ladder_capacities_are_now_measured_not_guessed() {
        // Phase 0 assumed 1050 usable bytes for the QR rung. Check the real one.
        let v25m = usable_payload(25, Ecc::Medium);
        let v40l = usable_payload(40, Ecc::Low);
        assert!(v25m > 900 && v25m < 1300, "v25-M usable payload was {v25m}");
        assert!(v40l > 2800, "v40-L usable payload was {v40l}");
        // One RaptorQ packet at symbol_size 512 is 516 bytes on the wire.
        assert!(SymbolFrame::packets_per_frame(v25m, 516) >= 1);
        assert!(SymbolFrame::packets_per_frame(v40l, 516) >= 5);
    }
}
