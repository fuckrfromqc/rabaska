//! Rabaska core: wire format, key agreement, and the send/receive pipeline.
//!
//! This crate is the whole protocol. It has no knowledge of pixels, cameras, or the
//! DOM. The optical codec sits on top of it and only ever sees byte slices produced
//! by [`wire`].
//!
//! See `docs/SPEC.md`. The constants in [`wire`] and the domain-separation strings in
//! [`crypto`] are frozen: they are baked into stored pairings on user devices.

pub mod crypto;
pub mod pipeline;
pub mod qr;
pub mod wire;

#[cfg(feature = "wasm")]
pub mod wasm;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Frame is shorter than its own fixed layout requires.
    Truncated { expected: usize, got: usize },
    /// Not a Rabaska frame.
    BadMagic,
    /// Frame is Rabaska but from a protocol version we do not speak.
    BadVersion(u8),
    /// Frame type byte is not one we recognise.
    BadFrameType(u8),
    /// Mode byte is not one we recognise.
    BadMode(u8),
    /// CRC32 mismatch. Transport corruption, not an attack signal.
    BadCrc { expected: u32, got: u32 },
    /// Frame belongs to a different session.
    ForeignSession,
    /// Poly1305 tag failed. Either corruption survived CRC, or tampering.
    AuthFailed,
    /// Reassembled plaintext did not match the declared length.
    LengthMismatch { declared: usize, got: usize },
    /// zstd rejected the frame.
    Decompress,
    /// Caller asked for a mode that needs state it did not supply.
    MissingIdentity,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Truncated { expected, got } => {
                write!(f, "truncated frame: expected {expected} bytes, got {got}")
            }
            Error::BadMagic => write!(f, "not a rabaska frame"),
            Error::BadVersion(v) => write!(f, "unsupported protocol version {v}"),
            Error::BadFrameType(t) => write!(f, "unknown frame type 0x{t:02x}"),
            Error::BadMode(m) => write!(f, "unknown mode 0x{m:02x}"),
            Error::BadCrc { expected, got } => {
                write!(f, "crc mismatch: expected {expected:08x}, got {got:08x}")
            }
            Error::ForeignSession => write!(f, "frame belongs to another session"),
            Error::AuthFailed => write!(f, "authentication tag failed"),
            Error::LengthMismatch { declared, got } => {
                write!(f, "length mismatch: declared {declared}, got {got}")
            }
            Error::Decompress => write!(f, "decompression failed"),
            Error::MissingIdentity => write!(f, "mode requires an identity key"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = core::result::Result<T, Error>;
