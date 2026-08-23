//! What the bytes *are*, carried with the bytes.
//!
//! The pipeline moves an opaque blob. That is the right shape for a courier,
//! but it meant a photo arrived as `rabaska-payload.bin` with no name, no
//! extension and no type, which on a phone is a file the system refuses to
//! open. The bytes were always correct; the delivery was not.
//!
//! # Why a trailer and not a header
//!
//! [`crate::pipeline::is_already_compressed`] decides whether to run zstd by
//! sniffing magic bytes at offset 0. A header would put `RBKP` there for every
//! payload, so every JPEG, PDF and zip would look compressible and get run
//! through the compressor for nothing. Putting the metadata at the end leaves
//! the file's own magic exactly where the sniffer looks, and the pipeline needs
//! no knowledge of this module at all.
//!
//! # Layout
//!
//! ```text
//! [ body ][ name ][ mime ][ name_len: u8 ][ mime_len: u8 ][ VERSION: u8 ][ MAGIC: 4 ]
//! ```
//!
//! Seven bytes of overhead plus the two strings. This sits *inside* the
//! plaintext handed to the pipeline, so the name and type are encrypted and
//! authenticated exactly like the body. A filename is often the most revealing
//! part of a transfer and it does not go out in the clear.
//!
//! # This is not the wire format
//!
//! Nothing here touches `wire`, a KDF input or a domain-separation string, so
//! the frozen vectors are unaffected. It is an application envelope above the
//! protocol, not a change to it.
//!
//! It is, however, a payload-format change: a sender running this code delivers
//! a trailer that a receiver without it would write into the file. The build
//! hash shown on both screens during a transfer is what makes that visible, and
//! is why it is shown.

/// Trailer magic. Chosen to be ASCII so it is greppable in a hex dump.
const MAGIC: &[u8; 4] = b"RBKP";
const VERSION: u8 = 1;
const FIXED: usize = 7; // name_len + mime_len + version + magic

/// Longest name we will emit or accept. Long enough for any real filename,
/// short enough that a hostile peer cannot spend the optical channel on one.
const MAX_NAME: usize = 96;
const MAX_MIME: usize = 64;

/// A decoded payload: the body, plus whatever the sender said about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub body: Vec<u8>,
    /// Sanitised. `None` when absent, unusable, or from a sender that predates
    /// this envelope.
    pub name: Option<String>,
    /// Allow-listed. `None` unless it is a type that cannot script.
    pub mime: Option<String>,
}

/// Attach a name and type to a body.
///
/// Empty strings, and strings that do not survive sanitising, are simply not
/// carried: it is better to deliver a file with no name than one with a name
/// the receiver has to defend against.
pub fn wrap(body: &[u8], name: &str, mime: &str) -> Vec<u8> {
    let name = safe_name(name).unwrap_or_default();
    let mime = safe_mime(mime).unwrap_or_default();
    let (n, m) = (name.as_bytes(), mime.as_bytes());

    let mut out = Vec::with_capacity(body.len() + n.len() + m.len() + FIXED);
    out.extend_from_slice(body);
    out.extend_from_slice(n);
    out.extend_from_slice(m);
    out.push(n.len() as u8); // both are bounded by the sanitisers above
    out.push(m.len() as u8);
    out.push(VERSION);
    out.extend_from_slice(MAGIC);
    out
}

/// Split a received payload into body and metadata.
///
/// Never fails. Anything that is not a well-formed trailer — a sender that
/// predates this envelope, a version from the future, a length that does not
/// fit — is returned whole as the body with no metadata. Refusing to deliver a
/// file because its label is malformed would be the worse failure: the payload
/// is already AEAD-authenticated, so the bytes are exactly what the peer sent
/// either way.
pub fn unwrap(raw: &[u8]) -> Payload {
    let bare = || Payload {
        body: raw.to_vec(),
        name: None,
        mime: None,
    };

    if raw.len() < FIXED || &raw[raw.len() - 4..] != MAGIC || raw[raw.len() - 5] != VERSION {
        return bare();
    }
    let name_len = raw[raw.len() - FIXED] as usize;
    let mime_len = raw[raw.len() - FIXED + 1] as usize;
    let trailer = FIXED + name_len + mime_len;
    if trailer > raw.len() {
        return bare();
    }

    let split = raw.len() - trailer;
    let name = &raw[split..split + name_len];
    let mime = &raw[split + name_len..split + name_len + mime_len];

    Payload {
        body: raw[..split].to_vec(),
        // Sanitise on the way in as well as on the way out. The peer ran its
        // own copy of this code, or claimed to.
        name: std::str::from_utf8(name).ok().and_then(safe_name),
        mime: std::str::from_utf8(mime).ok().and_then(safe_mime),
    }
}

/// Reduce a claimed filename to something safe to hand a filesystem.
///
/// This is attacker-controlled text: authenticated as coming from the peer, but
/// a hostile peer is the entire threat model of a pairing tool. Browsers do
/// sanitise the `download` attribute, but that is their policy to change, not a
/// guarantee to build on.
pub fn safe_name(raw: &str) -> Option<String> {
    // Take the last path component, so `../../.ssh/authorized_keys` cannot
    // propose a directory, and neither can a Windows-style separator.
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("");

    // Control characters include NUL, which truncates a C string, and newlines,
    // which can forge a line in anything that logs the name.
    let cleaned: String = base.chars().filter(|c| !c.is_control()).collect();

    // Leading dots hide the file; a name of only dots is `.` or `..`.
    let trimmed = cleaned.trim().trim_matches('.').trim();
    if trimmed.is_empty() {
        return None;
    }

    if trimmed.chars().count() <= MAX_NAME {
        return Some(trimmed.to_string());
    }

    // Too long: keep the extension, since that is what decides whether the file
    // opens, and truncate the stem. Truncation is by chars, not bytes, so a
    // multi-byte character is never cut in half.
    let (stem, ext) = match trimmed.rsplit_once('.') {
        Some((s, e)) if !e.is_empty() && e.chars().count() <= 16 => (s, Some(e)),
        _ => (trimmed, None),
    };
    let keep = MAX_NAME - ext.map_or(0, |e| e.chars().count() + 1);
    let mut out: String = stem.chars().take(keep).collect();
    if let Some(e) = ext {
        out.push('.');
        out.push_str(e);
    }
    let out = out.trim().trim_matches('.').trim().to_string();
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Allow-list a claimed MIME type.
///
/// The received bytes become a `blob:` URL on this app's own origin, and this
/// origin's IndexedDB holds the wrapped identity key. A type the browser will
/// render and script — `text/html`, `image/svg+xml` — is therefore a way to run
/// code next to that key if the blob is ever navigated to rather than saved.
/// The CSP blocks inline script in a blob document, but that is a second lock,
/// not a reason to hand out the first key. Anything not on this list is
/// delivered as an opaque download, which loses nothing: the extension is what
/// actually decides how the file opens once saved.
pub fn safe_mime(raw: &str) -> Option<String> {
    // Drop parameters: `text/plain; charset=utf-8` is `text/plain` here.
    let base = raw
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if base.is_empty() || base.len() > MAX_MIME {
        return None;
    }
    // One `/`, and only characters a MIME token may contain.
    let (ty, sub) = base.split_once('/')?;
    let token_ok = |s: &str| {
        !s.is_empty()
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || "!#$&^_.+-".contains(c))
    };
    if !token_ok(ty) || !token_ok(sub) {
        return None;
    }

    // SVG is an image that can script. It is excluded by name, before the
    // image/ prefix would otherwise wave it through.
    if base == "image/svg+xml" {
        return None;
    }
    const SAFE_PREFIX: [&str; 3] = ["image/", "audio/", "video/"];
    const SAFE_EXACT: [&str; 2] = ["text/plain", "application/pdf"];
    if SAFE_PREFIX.iter().any(|p| base.starts_with(p)) || SAFE_EXACT.contains(&base.as_str()) {
        Some(base)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_name_type_and_bytes() {
        let body: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
        let p = unwrap(&wrap(&body, "holiday photo.jpg", "image/jpeg"));
        assert_eq!(p.body, body);
        assert_eq!(p.name.as_deref(), Some("holiday photo.jpg"));
        assert_eq!(p.mime.as_deref(), Some("image/jpeg"));
    }

    #[test]
    fn every_byte_value_survives() {
        let body: Vec<u8> = (0..=255u8).collect();
        assert_eq!(unwrap(&wrap(&body, "a.bin", "")).body, body);
    }

    #[test]
    fn empty_body_is_fine() {
        let p = unwrap(&wrap(b"", "empty.txt", "text/plain"));
        assert!(p.body.is_empty());
        assert_eq!(p.name.as_deref(), Some("empty.txt"));
    }

    /// The compatibility case that matters: a payload from a sender that knows
    /// nothing about this envelope must come back byte-identical.
    #[test]
    fn a_payload_with_no_trailer_is_returned_whole() {
        for raw in [
            &b""[..],
            &b"short"[..],
            &b"-----BEGIN OPENSSH PRIVATE KEY-----"[..],
            &[0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3][..],
        ] {
            let p = unwrap(raw);
            assert_eq!(p.body, raw);
            assert_eq!(p.name, None);
            assert_eq!(p.mime, None);
        }
    }

    #[test]
    fn a_truncated_or_lying_trailer_never_panics_and_never_eats_the_body() {
        // Magic present, lengths that run off the front of the buffer.
        let mut evil = b"body".to_vec();
        evil.extend_from_slice(&[200, 200, VERSION]);
        evil.extend_from_slice(MAGIC);
        let p = unwrap(&evil);
        assert_eq!(
            p.body, evil,
            "a bad trailer must fall back to the raw bytes"
        );

        // A version we do not know.
        let mut future = b"body".to_vec();
        future.extend_from_slice(&[0, 0, 99]);
        future.extend_from_slice(MAGIC);
        assert_eq!(unwrap(&future).body, future);

        // Every truncation of a valid envelope, for panics.
        let full = wrap(b"payload bytes", "n.txt", "text/plain");
        for i in 0..full.len() {
            let _ = unwrap(&full[..i]);
        }
    }

    #[test]
    fn path_traversal_is_reduced_to_a_bare_name() {
        assert_eq!(
            safe_name("../../.ssh/authorized_keys").as_deref(),
            Some("authorized_keys")
        );
        assert_eq!(safe_name("/etc/passwd").as_deref(), Some("passwd"));
        assert_eq!(
            safe_name(r"..\..\windows\system32\evil.dll").as_deref(),
            Some("evil.dll")
        );
        assert_eq!(safe_name(".."), None);
        assert_eq!(safe_name("."), None);
        assert_eq!(safe_name("/"), None);
        assert_eq!(safe_name(""), None);
        assert_eq!(safe_name("   "), None);
    }

    #[test]
    fn control_characters_are_stripped() {
        assert_eq!(safe_name("evil\x00.txt").as_deref(), Some("evil.txt"));
        assert_eq!(safe_name("two\nlines.txt").as_deref(), Some("twolines.txt"));
        assert_eq!(safe_name("\x07bell.txt").as_deref(), Some("bell.txt"));
    }

    #[test]
    fn hidden_files_do_not_stay_hidden() {
        assert_eq!(safe_name(".bashrc").as_deref(), Some("bashrc"));
    }

    #[test]
    fn long_names_keep_their_extension() {
        let long = format!("{}.jpg", "a".repeat(500));
        let got = safe_name(&long).unwrap();
        assert!(got.chars().count() <= MAX_NAME);
        assert!(
            got.ends_with(".jpg"),
            "the extension is what makes it open: {got}"
        );
    }

    #[test]
    fn truncation_never_splits_a_character() {
        let long = format!("{}.txt", "é".repeat(500));
        let got = safe_name(&long).unwrap();
        assert!(got.chars().count() <= MAX_NAME);
        assert!(got.ends_with(".txt"));
    }

    #[test]
    fn scripting_types_are_refused() {
        for m in [
            "text/html",
            "image/svg+xml",
            "application/xhtml+xml",
            "text/javascript",
            "application/javascript",
            "TEXT/HTML",
            "text/html; charset=utf-8",
        ] {
            assert_eq!(safe_mime(m), None, "{m} must not be handed to a blob URL");
        }
    }

    #[test]
    fn ordinary_types_are_kept() {
        assert_eq!(safe_mime("image/jpeg").as_deref(), Some("image/jpeg"));
        assert_eq!(safe_mime("image/PNG").as_deref(), Some("image/png"));
        assert_eq!(
            safe_mime("text/plain; charset=utf-8").as_deref(),
            Some("text/plain")
        );
        assert_eq!(
            safe_mime("application/pdf").as_deref(),
            Some("application/pdf")
        );
        assert_eq!(safe_mime("video/mp4").as_deref(), Some("video/mp4"));
        assert_eq!(safe_mime("").as_deref(), None);
        assert_eq!(safe_mime("nonsense").as_deref(), None);
        assert_eq!(safe_mime("image/").as_deref(), None);
    }

    /// A hostile name must not survive the round trip either, not just the
    /// direct call: sanitising only on the way out would leave a receiver that
    /// trusts `wrap`'s output exposed.
    #[test]
    fn hostile_metadata_is_sanitised_across_the_wire() {
        let raw = wrap(b"x", "../../evil\x00.sh", "text/html");
        let p = unwrap(&raw);
        assert_eq!(p.body, b"x");
        assert_eq!(p.name.as_deref(), Some("evil.sh"));
        assert_eq!(p.mime, None);
    }

    /// The trailer must not disturb what the compressor sniffs.
    #[test]
    fn the_body_magic_stays_at_offset_zero() {
        let jpeg = wrap(b"\xFF\xD8\xFF\xE0 pretend jpeg", "p.jpg", "image/jpeg");
        assert!(
            crate::pipeline::is_already_compressed(&jpeg),
            "a header would have hidden the JPEG magic from the sniffer"
        );
    }
}
