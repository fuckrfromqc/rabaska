# Rabaska Wire Protocol v2

**Status: FROZEN.** Every field, constant and domain-separation string below is baked
into stored pairings on user devices. Changing anything here without bumping `VERSION`
breaks already-paired devices with no useful error message.

Endianness is little-endian throughout. All frames are integrity-checked with CRC32
(IEEE) over every preceding byte of the frame. CRC32 catches transport corruption only;
it is not a security control. Confidentiality and authenticity come from
XChaCha20-Poly1305.

---

## 1. Constants

| Name | Value |
|---|---|
| `MAGIC` | `0x52 0x42` (`"RB"`) |
| `VERSION` | `0x02` |

### Domain separation strings

These are the values that must never drift.

```
rabaska/v2/pair          HKDF info, PAIR mode
rabaska/v2/session       HKDF info, SESSION mode
rabaska/v2/seal          HKDF info, SEAL mode (unauthenticated sender)
rabaska/v2/seal-auth     HKDF info, SEAL mode (authenticated sender)
rabaska/v2/open          HKDF info, OPEN mode
rabaska/v2/sas           SAS derivation
rabaska/v2/commit        SAS nonce commitment
rabaska/v2/idhint        identity hint derivation
rabaska/v2/complete      completion hash derivation
rabaska/v2/aad           AEAD associated data prefix
```

### Changes from v1

v1 was never released. It is superseded because its SAS was grindable.

- `PAIR_REQ` grows from 53 to 69 bytes and carries `r_commit`. Target QR version
  moves from v6-H to v8-H.
- New `REVEAL` frame, type `0x05`, 28 bytes.
- SAS takes a fourth input, the receiver's committed nonce.
- `OPEN` gains its own HKDF info string. In v1 it reused `INFO_SEAL`, so a
  transfer with no confidentiality derived under the same label as a real one.

### Frame types

| Value | Name | Direction |
|---|---|---|
| `0x01` | `PAIR_REQ` | receiver to sender (reverse QR) |
| `0x02` | `BEACON` | sender to receiver (interleaved) |
| `0x03` | `SYMBOL` | sender to receiver (bulk) |
| `0x04` | `COMPLETE` | receiver to sender (final QR) |
| `0x05` | `REVEAL` | receiver to sender (PAIR mode only) |

### Modes

| Value | Name | Meaning |
|---|---|---|
| `0x01` | `PAIR` | Both ends have cameras, first meeting. Ephemeral ECDH plus 5-digit SAS. |
| `0x02` | `SESSION` | Both ends have cameras and stored identities. Triple-DH, no SAS. |
| `0x03` | `SEAL` | Camera-less sender. One-pass sealed box to receiver's stored identity. |
| `0x04` | `OPEN` | Trusted room. Key travels in the clear. No confidentiality. |

### Flags (bitfield)

| Bit | Name | Meaning |
|---|---|---|
| 0 | `COMPRESSED` | Plaintext was zstd-compressed before encryption |
| 1 | `SENDER_AUTH` | Sender identity folded into the KDF |
| 2 | `HAS_ID_HINT` | `PAIR_REQ` carries a meaningful `id_hint` |

---

## 2. Frames

### 2.1 `PAIR_REQ` (53 bytes)

Displayed by the receiver. Sender scans this once to start a session. Low density,
high ECC: target QR version 6 at ECC level H (58-byte binary capacity).

```
offset  size  field
0       2     magic
2       1     version
3       1     type = 0x01
4       1     flags
5       8     session_id        (CSPRNG)
13      32    r_eph_pub         receiver ephemeral X25519 public key
45      4     id_hint           SHA256("rabaska/v2/idhint" || r_id_pub)[0..4],
                                zero if flags.HAS_ID_HINT is clear
49      16    r_commit          SHA256("rabaska/v2/commit" || session_id
                                       || r_eph_pub || r_nonce)[0..16]
65      4     crc32
```

`id_hint` lets a sender recognise a previously paired receiver and skip the SAS.
Four bytes is a lookup key, not an authenticator: collisions are handled by trying
each candidate identity and letting the Poly1305 tag arbitrate.

### 2.2 `BEACON` (102 bytes)

Displayed by the sender, interleaved into the symbol stream roughly every two seconds
so a late joiner can acquire. Low density, high ECC: target QR version 10 at ECC
level H (119-byte binary capacity).

```
offset  size  field
0       2     magic
2       1     version
3       1     type = 0x02
4       1     mode
5       1     flags
6       8     session_id        echoed from PAIR_REQ, or fresh in SEAL/OPEN
14      32    s_eph_pub         sender ephemeral X25519 public key
46      24    nonce             XChaCha20 nonce (CSPRNG, never reused)
70      4     plaintext_len     original length before compression, u32
74      12    oti               RaptorQ ObjectTransmissionInformation
86      2     symbol_size       u16
88      1     palette           0 = QR fallback, 4 = 4-colour tiles, 8 = 8-colour
89      1     tile_px           tile edge in transmitter pixels
90      8     build_hash        SHA256(wasm bundle)[0..8], displayed for eyeball check
98      4     crc32
```

`oti` is authoritative for ciphertext length. It is deliberately **not** covered by the
AEAD associated data, because it is derived from the ciphertext and would be circular.
It does not need to be: a tampered `oti` causes RaptorQ to fail or to reconstruct
garbage, and the Poly1305 tag then rejects it.

### 2.3 `SYMBOL` (variable)

The bulk carrier. One video frame carries `count` RaptorQ packets.

```
offset  size          field
0       2             magic
2       1             version
3       1             type = 0x03
4       4             sid4              session_id[0..4], rejects foreign frames
8       4             frame_id          u32, monotonic, for tear detection
12      1             count
13      2             packet_len        bytes per packet = 4 + symbol_size
15      count*plen    packets           RaptorQ EncodingPacket, serialized
...     4             crc32
```

Fixed overhead is 19 bytes per video frame. On a QR fallback frame carrying ~1000
useful bytes that is 2%; on a tile frame carrying 7.5 KB it is negligible.

Packets are order-independent and interchangeable across density levels. A receiver
that decodes a mix of 8-colour, 4-colour and QR frames converges on the same object.
This is what makes the interleaved density ladder work without any negotiation.

### 2.4 `REVEAL` (28 bytes)

Displayed by the receiver **only after** the sender's beacon has been decoded.
Publishing it earlier destroys the commitment and reopens the attack it exists
to close.

```
offset  size  field
0       2     magic
2       1     version
3       1     type = 0x05
4       4     sid4
8       16    r_nonce
24      4     crc32
```

### 2.5 `COMPLETE` (21 bytes)

Displayed by the receiver when reassembly finishes. The only feedback in the system.

```
offset  size  field
0       2     magic
2       1     version
3       1     type = 0x04
4       4     sid4
8       1     status            0x00 ok, 0x01 hash mismatch, 0x02 aborted
9       8     hash8             SHA256("rabaska/v2/complete" || session_id
                                       || plaintext)[0..8]
17      4     crc32
```

---

## 3. Key agreement

All modes derive a 32-byte AEAD key with `HKDF-SHA256`. `||` is concatenation.

### 3.1 PAIR

First meeting, both ends have cameras. No stored state required.

```
shared = X25519(s_eph_priv, r_eph_pub)
salt   = session_id || r_eph_pub || s_eph_pub
key    = HKDF-SHA256(ikm = shared, salt = salt, info = "rabaska/v2/pair")
```

Unauthenticated ECDH is vulnerable to an active screen-in-the-middle. This is closed
by a short authentication string, computed independently by both sides and compared
by the human:

```
h   = SHA256("rabaska/v2/sas" || session_id || r_eph_pub || s_eph_pub || r_nonce)
sas = be_u32(h[0..4]) mod 100000, rendered as five zero-padded digits
```

A mismatch is a hard abort with immediate key zeroization and no retry button. The
only reason to retry the same keys is that an attacker is asking you to.

### 3.2 SESSION

Both ends have cameras and have previously stored each other's identity public key.
This is X3DH with the prekey server removed, which is sound here because the server
only ever existed to handle asynchrony and both devices are physically co-present.

```
DH1 = X25519(s_eph_priv, r_id_pub)     authenticates receiver
DH2 = X25519(s_id_priv,  r_eph_pub)    authenticates sender
DH3 = X25519(s_eph_priv, r_eph_pub)    forward secrecy
ikm  = DH1 || DH2 || DH3
salt = session_id || r_eph_pub || s_eph_pub || r_id_pub || s_id_pub
key  = HKDF-SHA256(ikm, salt, "rabaska/v2/session")
```

No SAS. Scan and go.

### 3.3 SEAL

Camera-less sender. Strictly one-way channel, zero round trips. Requires the receiver's
identity public key to already be known to the sender (typed once, or acquired over the
audio reverse channel).

```
shared = X25519(s_eph_priv, r_id_pub)
salt   = s_eph_pub || r_id_pub
key    = HKDF-SHA256(shared, salt, "rabaska/v2/seal")
```

With sender authentication (`flags.SENDER_AUTH`), when the receiver has stored the
sender's identity:

```
ikm  = X25519(s_eph_priv, r_id_pub) || X25519(s_id_priv, r_id_pub)
key  = HKDF-SHA256(ikm, salt, "rabaska/v2/seal-auth")
```

This is HPKE base mode and auth mode respectively. What it gives up relative to
SESSION is receiver-side forward secrecy: compromise of the receiver's identity key
retroactively decrypts every SEAL transfer ever sent to it. Rotate receiver identity
keys periodically and say so in the UI.

**Structural limit.** With a strictly one-way channel and no prior shared state,
confidentiality is impossible. Anything the sender displays in order to establish a
key is equally visible to any other camera in the room. SEAL mode is only meaningful
because the receiver's identity key arrived out of band. `OPEN` mode is the honest
label for the case where it did not.

---

## 4. AEAD

XChaCha20-Poly1305. 24-byte random nonce, fresh per transfer, carried in the beacon.

Associated data is a context block computed **before** encryption, so it contains no
ciphertext-derived field:

```
aad = "rabaska/v2/aad" || version || mode || flags || session_id
      || s_eph_pub || nonce || plaintext_len
```

This binds the mode, the compression flag, the session and the sender's ephemeral key
into the tag. An attacker who flips `mode` from SESSION to OPEN, or clears the
`COMPRESSED` bit, produces a tag failure rather than a silent misparse.

---

## 5. Pipeline order

```
send:  plaintext -> sniff -> [zstd] -> XChaCha20-Poly1305 -> RaptorQ -> frames
recv:  frames -> RaptorQ -> XChaCha20-Poly1305 verify -> [zstd] -> plaintext
```

Compress before encrypt, never after: ciphertext is incompressible by construction.
Encrypt before fountain-code, never after: the Poly1305 tag covers the whole object
and can only be verified once reassembly completes anyway, and encrypting per-symbol
would leak the symbol structure.

Compression is skipped by magic-byte sniffing on already-compressed containers
(JPEG, PNG, GIF, HEIC/HEIF, MP4/MOV, zip family, gzip, zstd, PDF, WebP, Ogg, FLAC).
Running zstd over a JPEG costs two seconds and saves half a percent. The user never
sees a setting.

---

## 6. Known non-goals

- **Code secrecy.** Everything shipped to a browser is readable. Security rests on the
  keys, not on the codec being unpublished.
- **Protection against a compromised device.** There is no keychain access from the
  web. An unlocked, compromised phone means compromised pairings. The UI must say this
  rather than imply otherwise.
- **Large payloads.** The ergonomic ceiling is holding two devices aligned, which is
  pleasant for one second and miserable for three minutes. The protocol is correct at
  100 MB and the product is not.
