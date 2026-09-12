// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Streaming + seekable DEM for the shortsig-aead IBE half (the `StreamIBE_*` scopes). Port of
//! `ts-sdk/src/t-ibe/bfibe-bls12381-shortsig-aead-stream.ts`.
//!
//! The IBE half is byte-for-byte identical to the block scheme
//! (`super::bfibe_bls12381_shortsig_aead`): same G2 master key, `H_G1(id)`, per-message seed
//! `e(Q_id, pk^r)`, `c0 = r·basePoint`, and the same G1 IDK share. Streaming reuses those objects
//! verbatim; only the DEM changes — from a single ChaCha20-Poly1305 call to a **seekable segmented
//! AEAD** (STREAM construction, a la age / Tink):
//!
//!   - 32-byte ChaCha20 key = HKDF-SHA256(seed, salt=∅, info=STREAM DST, L=32).
//!   - 64 KiB plaintext segments; segment i nonce = 11-byte BE counter i ‖ 1-byte last-flag.
//!
//! There is **no ciphertext object** — output is a stream of **ciphertext chunks**:
//!
//!   header chunk  = 0x03 ‖ c0            (1-byte stream marker = the on-chain primitive, then
//!                                         96-byte G2-compressed c0, NO length prefix)
//!   segment chunk = ct_i ‖ 16B tag       (one per 64 KiB of plaintext)
//!
//! Non-final segment chunks are exactly `chunk_size + 16` bytes; the final one is the remainder.
//! Segment count + plaintext length are derivable from the total chunk-bytes length (no header
//! field), which is what makes `read_range` seeking possible.

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{AceError, Result};
use crate::group::bls12381fr::fr_to_le_bytes;
use crate::group::bls12381g2::PublicPoint as G2Point;
use crate::t_ibe::bfibe_bls12381_shortsig_aead::{
    ibe_encrypt_seed_and_c0, ibe_reconstruct_seed, IdentityDecryptionKeyShare, MasterPublicKey,
};

/// First byte of the header chunk — the on-chain primitive id, used purely as a 1-byte
/// self-identifying stream marker so a decryptor can confirm "these are stream chunks".
pub const STREAM_MARKER: u8 = 3;

pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;
pub const AEAD_TAG_BYTES: usize = 16;
pub const AEAD_KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
/// nonce = 11-byte BE counter ‖ 1-byte last-flag
pub const COUNTER_BYTES: usize = 11;
/// G2 compressed
pub const C0_BYTES: usize = 96;
/// marker ‖ c0
pub const HEADER_BYTES: usize = 1 + C0_BYTES;

pub const DST_KDF: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORTSIG_AEADSTREAM/KDF";

/// Largest segment index representable in the 11-byte counter (2^88 - 1); every `u64` fits, but
/// the check is kept so the guard mirrors the TS `segmentNonce` overflow throw.
const MAX_SEGMENT_INDEX: u128 = (1u128 << (8 * COUNTER_BYTES)) - 1;

// ── Primitives ─────────────────────────────────────────────────────────────────

pub fn derive_stream_key(seed: &[u8]) -> [u8; AEAD_KEY_BYTES] {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut key = [0u8; AEAD_KEY_BYTES];
    hk.expand(DST_KDF, &mut key)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    key
}

/// nonce = 11-byte big-endian segment counter ‖ 1-byte last-flag (0x00 non-final, 0x01 final).
pub fn segment_nonce(index: u64, is_last: bool) -> Result<[u8; NONCE_BYTES]> {
    if (index as u128) > MAX_SEGMENT_INDEX {
        return Err(AceError::crypto("stream: segment index overflow"));
    }
    let mut nonce = [0u8; NONCE_BYTES];
    let mut idx = index;
    for i in (0..COUNTER_BYTES).rev() {
        nonce[i] = (idx & 0xff) as u8;
        idx >>= 8;
    }
    nonce[COUNTER_BYTES] = if is_last { 0x01 } else { 0x00 };
    Ok(nonce)
}

fn segment_encrypt(
    key: &[u8; AEAD_KEY_BYTES],
    index: u64,
    is_last: bool,
    plain: &[u8],
) -> Result<Vec<u8>> {
    let nonce = segment_nonce(index, is_last)?;
    ChaCha20Poly1305::new(key.into())
        .encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|_| AceError::crypto("stream: ChaCha20-Poly1305 encrypt failed"))
}

fn segment_decrypt(
    key: &[u8; AEAD_KEY_BYTES],
    index: u64,
    is_last: bool,
    ct: &[u8],
) -> Result<Vec<u8>> {
    let nonce = segment_nonce(index, is_last)?;
    // Tag mismatch → error; propagate (fails closed).
    ChaCha20Poly1305::new(key.into())
        .decrypt(Nonce::from_slice(&nonce), ct)
        .map_err(|_| AceError::crypto("stream: segment authentication failed"))
}

fn random_scalar_le() -> Vec<u8> {
    fr_to_le_bytes(&crate::group::bls12381g2::sample().scalar).to_vec()
}

/// `0x03 ‖ c0` (97 bytes).
pub fn header(c0: &G2Point) -> Vec<u8> {
    let mut h = Vec::with_capacity(HEADER_BYTES);
    h.push(STREAM_MARKER);
    h.extend_from_slice(&c0.raw_bytes());
    h
}

/// Parse a header chunk: check the marker, decode c0 (extra trailing bytes are ignored).
pub fn parse_header(header: &[u8]) -> Result<G2Point> {
    if header.len() < HEADER_BYTES {
        return Err(AceError::wire("stream: header too short"));
    }
    if header[0] != STREAM_MARKER {
        return Err(AceError::wire(format!(
            "stream: expected marker {STREAM_MARKER}, got {}",
            header[0]
        )));
    }
    G2Point::from_raw_bytes(&header[1..HEADER_BYTES])
}

// ── Sync core ──────────────────────────────────────────────────────────────────

/// Segment-level encryptor: holds the derived key and the next segment index. `encrypt_segment`
/// must be called with `is_last = true` exactly once, as the final call.
pub struct StreamEncryptor {
    key: [u8; AEAD_KEY_BYTES],
    next_index: u64,
    chunk_size: usize,
}

impl StreamEncryptor {
    pub fn new(key: [u8; AEAD_KEY_BYTES], chunk_size: usize) -> Self {
        Self {
            key,
            next_index: 0,
            chunk_size,
        }
    }

    pub fn chunk_size(&self) -> usize {
        self.chunk_size
    }

    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    pub fn header(&self, c0: &G2Point) -> Vec<u8> {
        header(c0)
    }

    /// Encrypt one segment (`plaintext.len() <= chunk_size`; non-final segments must be exactly
    /// `chunk_size`) and advance the counter.
    pub fn encrypt_segment(&mut self, plaintext: &[u8], is_last: bool) -> Result<Vec<u8>> {
        if plaintext.len() > self.chunk_size {
            return Err(AceError::crypto("stream: segment larger than chunk_size"));
        }
        if !is_last && plaintext.len() != self.chunk_size {
            return Err(AceError::crypto(
                "stream: non-final segment must be exactly chunk_size bytes",
            ));
        }
        let ct = segment_encrypt(&self.key, self.next_index, is_last, plaintext)?;
        self.next_index += 1;
        Ok(ct)
    }
}

/// Segment-level decryptor (stateless: the caller supplies the index and last-flag).
pub struct StreamDecryptor {
    key: [u8; AEAD_KEY_BYTES],
}

impl StreamDecryptor {
    pub fn new(key: [u8; AEAD_KEY_BYTES]) -> Self {
        Self { key }
    }

    /// Reconstruct the stream key from IDK shares and the header's c0.
    pub fn from_shares(shares: &[IdentityDecryptionKeyShare], c0: &G2Point) -> Result<Self> {
        let seed = ibe_reconstruct_seed(shares, c0)?;
        Ok(Self::new(derive_stream_key(&seed)))
    }

    pub fn decrypt_segment(&self, index: u64, is_last: bool, ct: &[u8]) -> Result<Vec<u8>> {
        segment_decrypt(&self.key, index, is_last, ct)
    }
}

// ── Layout math (seek support) ─────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub num_segments: u64,
    pub plaintext_length: u64,
    pub chunk_size: usize,
}

/// Recover segment count and plaintext length from the length of the concatenated segment chunks
/// (total chunk bytes minus the `HEADER_BYTES` header chunk).
/// `num_segments = max(1, ceil((body_len − 16) / (chunk_size + 16)))`,
/// `plaintext_length = body_len − 16·num_segments`.
pub fn stream_layout(body_len: u64, chunk_size: usize) -> Result<Layout> {
    if chunk_size == 0 {
        return Err(AceError::crypto("stream: chunk_size must be positive"));
    }
    let tag = AEAD_TAG_BYTES as u64;
    let cipher_seg = chunk_size as u64 + tag;
    if body_len < tag {
        return Err(AceError::wire(format!(
            "stream: body too short ({body_len} < {tag})"
        )));
    }
    let num_segments = ((body_len - tag).div_ceil(cipher_seg)).max(1);
    let plaintext_length = body_len
        .checked_sub(tag * num_segments)
        .ok_or_else(|| AceError::wire(format!("stream: inconsistent body length {body_len}")))?;
    let final_seg_len = body_len - (num_segments - 1) * cipher_seg;
    if final_seg_len < tag || final_seg_len > cipher_seg {
        return Err(AceError::wire(format!(
            "stream: inconsistent final segment length {final_seg_len}"
        )));
    }
    Ok(Layout {
        num_segments,
        plaintext_length,
        chunk_size,
    })
}

// ── Whole-buffer, byte-exact (concatenated ciphertext chunks) ──────────────────

/// Segmented-encrypt an entire plaintext buffer into the concatenated segment chunks (no header).
pub fn encode_segments(
    key: &[u8; AEAD_KEY_BYTES],
    plaintext: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>> {
    if chunk_size == 0 {
        return Err(AceError::crypto("stream: chunk_size must be positive"));
    }
    let num_segments = if plaintext.is_empty() {
        1
    } else {
        plaintext.len().div_ceil(chunk_size)
    };
    let mut enc = StreamEncryptor::new(*key, chunk_size);
    let mut out = Vec::with_capacity(plaintext.len() + num_segments * AEAD_TAG_BYTES);
    for j in 0..num_segments {
        let start = j * chunk_size;
        let end = (start + chunk_size).min(plaintext.len());
        out.extend_from_slice(&enc.encrypt_segment(&plaintext[start..end], j == num_segments - 1)?);
    }
    Ok(out)
}

/// Inverse of `encode_segments`. Fails closed on any segment tag mismatch.
pub fn decode_segments(
    key: &[u8; AEAD_KEY_BYTES],
    body: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>> {
    let Layout {
        num_segments,
        plaintext_length,
        ..
    } = stream_layout(body.len() as u64, chunk_size)?;
    let cipher_seg = chunk_size + AEAD_TAG_BYTES;
    let dec = StreamDecryptor::new(*key);
    let mut out = Vec::with_capacity(plaintext_length as usize);
    for j in 0..num_segments as usize {
        let start = j * cipher_seg;
        let is_last = j as u64 == num_segments - 1;
        let end = if is_last {
            body.len()
        } else {
            start + cipher_seg
        };
        out.extend_from_slice(&dec.decrypt_segment(j as u64, is_last, &body[start..end])?);
    }
    Ok(out)
}

/// Byte-exact whole-buffer encrypt producing the **concatenated ciphertext chunks**
/// (`header ‖ segments`) with an explicit segment size (cross-impl vectors use a tiny one).
pub fn encrypt_to_concat_chunks_with_randomness(
    mpk: &MasterPublicKey,
    id: &[u8],
    plaintext: &[u8],
    randomness: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>> {
    let (seed, c0) = ibe_encrypt_seed_and_c0(mpk, id, randomness)?;
    let body = encode_segments(&derive_stream_key(&seed), plaintext, chunk_size)?;
    let mut out = header(&c0);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Byte-exact whole-buffer decrypt of concatenated ciphertext chunks (`header ‖ segments`).
pub fn decrypt_from_concat_chunks(
    idk_shares: &[IdentityDecryptionKeyShare],
    chunks: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>> {
    if chunks.len() < HEADER_BYTES + AEAD_TAG_BYTES {
        return Err(AceError::wire("stream: ciphertext chunks too short"));
    }
    let c0 = parse_header(chunks)?;
    let dec = StreamDecryptor::from_shares(idk_shares, &c0)?;
    decode_segments(&dec.key, &chunks[HEADER_BYTES..], chunk_size)
}

/// One-shot encrypt with caller-supplied randomness and the default 64 KiB segment size.
pub fn encrypt_with_randomness(
    mpk: &MasterPublicKey,
    id: &[u8],
    plaintext: &[u8],
    randomness: &[u8],
) -> Result<Vec<u8>> {
    encrypt_to_concat_chunks_with_randomness(mpk, id, plaintext, randomness, DEFAULT_CHUNK_SIZE)
}

/// One-shot encrypt with fresh randomness and the default 64 KiB segment size.
pub fn encrypt(mpk: &MasterPublicKey, id: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_with_randomness(mpk, id, plaintext, &random_scalar_le())
}

/// One-shot decrypt of `header ‖ segments` with the default 64 KiB segment size.
pub fn decrypt(idk_shares: &[IdentityDecryptionKeyShare], ciphertext: &[u8]) -> Result<Vec<u8>> {
    decrypt_from_concat_chunks(idk_shares, ciphertext, DEFAULT_CHUNK_SIZE)
}

// ── Bounded-memory streaming (iterators of chunks) ─────────────────────────────

/// Encrypt an iterator of plaintext byte chunks into an iterator of **ciphertext chunks** (header
/// chunk, then one segment chunk per `chunk_size`), in bounded memory. A segment is only emitted
/// as non-final once at least one further byte is known to follow (strict `>` hold-back), so the
/// last segment is flagged correctly without buffering the whole input. An exact multiple of
/// `chunk_size` therefore ends with a *full* final segment; empty plaintext yields one empty
/// final segment.
pub struct EncryptChunks<I: Iterator<Item = Vec<u8>>> {
    source: I,
    enc: StreamEncryptor,
    header: Option<Vec<u8>>,
    buf: Vec<u8>,
    done: bool,
}

impl<I: Iterator<Item = Vec<u8>>> EncryptChunks<I> {
    pub fn new(
        mpk: &MasterPublicKey,
        id: &[u8],
        randomness: Option<&[u8]>,
        chunk_size: usize,
        plaintext: I,
    ) -> Result<Self> {
        if chunk_size == 0 {
            return Err(AceError::crypto("stream: chunk_size must be positive"));
        }
        let rand;
        let randomness = match randomness {
            Some(r) => r,
            None => {
                rand = random_scalar_le();
                &rand
            }
        };
        let (seed, c0) = ibe_encrypt_seed_and_c0(mpk, id, randomness)?;
        Ok(Self {
            source: plaintext,
            enc: StreamEncryptor::new(derive_stream_key(&seed), chunk_size),
            header: Some(header(&c0)),
            buf: Vec::new(),
            done: false,
        })
    }
}

impl<I: Iterator<Item = Vec<u8>>> Iterator for EncryptChunks<I> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        if let Some(h) = self.header.take() {
            return Some(Ok(h));
        }
        let cs = self.enc.chunk_size();
        // Hold back until strictly more than one segment is buffered, so the last segment is
        // always emitted as final (a full one for exact multiples of `chunk_size`).
        while self.buf.len() <= cs {
            match self.source.next() {
                Some(chunk) => self.buf.extend_from_slice(&chunk),
                None => {
                    self.done = true;
                    let seg = std::mem::take(&mut self.buf);
                    return Some(self.enc.encrypt_segment(&seg, true));
                }
            }
        }
        let rest = self.buf.split_off(cs);
        let seg = std::mem::replace(&mut self.buf, rest);
        let out = self.enc.encrypt_segment(&seg, false);
        if out.is_err() {
            self.done = true;
        }
        Some(out)
    }
}

/// Convenience constructor for [`EncryptChunks`] with the default 64 KiB segment size and
/// fresh randomness.
pub fn encrypt_chunks_default<I: Iterator<Item = Vec<u8>>>(
    mpk: &MasterPublicKey,
    id: &[u8],
    plaintext: I,
) -> Result<EncryptChunks<I>> {
    EncryptChunks::new(mpk, id, None, DEFAULT_CHUNK_SIZE, plaintext)
}

/// Decrypt an iterator of ciphertext byte chunks (arbitrary boundaries; `header ‖ segments`)
/// into an iterator of plaintext segments, in bounded memory. Mirrors the hold-back rule of
/// [`EncryptChunks`]: a segment is only treated as non-final once strictly more than
/// `chunk_size + 16` bytes are buffered; whatever remains at end-of-source is the final segment.
pub struct DecryptChunks<'a, I: Iterator<Item = Vec<u8>>> {
    source: I,
    shares: &'a [IdentityDecryptionKeyShare],
    dec: Option<StreamDecryptor>,
    chunk_size: usize,
    buf: Vec<u8>,
    next_index: u64,
    exhausted: bool,
    done: bool,
}

/// [`EncryptChunks`] with an explicit segment size and optional caller-supplied randomness.
pub fn encrypt_chunks<I: Iterator<Item = Vec<u8>>>(
    mpk: &MasterPublicKey,
    id: &[u8],
    randomness: Option<&[u8]>,
    chunk_size: usize,
    plaintext: I,
) -> Result<EncryptChunks<I>> {
    EncryptChunks::new(mpk, id, randomness, chunk_size, plaintext)
}

impl<'a, I: Iterator<Item = Vec<u8>>> DecryptChunks<'a, I> {
    pub fn new(
        shares: &'a [IdentityDecryptionKeyShare],
        chunk_size: usize,
        chunks: I,
    ) -> Result<Self> {
        if chunk_size == 0 {
            return Err(AceError::crypto("stream: chunk_size must be positive"));
        }
        Ok(Self {
            source: chunks,
            shares,
            dec: None,
            chunk_size,
            buf: Vec::new(),
            next_index: 0,
            exhausted: false,
            done: false,
        })
    }

    /// Pull one source chunk into the buffer; returns false once the source is exhausted.
    fn pull(&mut self) -> bool {
        if self.exhausted {
            return false;
        }
        match self.source.next() {
            Some(c) => {
                self.buf.extend_from_slice(&c);
                true
            }
            None => {
                self.exhausted = true;
                false
            }
        }
    }

    fn step(&mut self) -> Result<Option<Vec<u8>>> {
        if self.dec.is_none() {
            while self.buf.len() < HEADER_BYTES {
                if !self.pull() {
                    return Err(AceError::wire("stream: ciphertext ends before header"));
                }
            }
            let c0 = parse_header(&self.buf[..HEADER_BYTES])?;
            self.dec = Some(StreamDecryptor::from_shares(self.shares, &c0)?);
            self.buf.drain(..HEADER_BYTES);
        }
        let seg_len = self.chunk_size + AEAD_TAG_BYTES;
        while self.buf.len() <= seg_len {
            if !self.pull() {
                break;
            }
        }
        let dec = self.dec.as_ref().expect("decryptor initialised");
        if self.buf.len() > seg_len {
            let rest = self.buf.split_off(seg_len);
            let seg = std::mem::replace(&mut self.buf, rest);
            let pt = dec.decrypt_segment(self.next_index, false, &seg)?;
            self.next_index += 1;
            return Ok(Some(pt));
        }
        // Source exhausted: the remainder is the final segment.
        self.done = true;
        if self.buf.len() < AEAD_TAG_BYTES || self.buf.len() > seg_len {
            return Err(AceError::wire("stream: inconsistent final segment length"));
        }
        let seg = std::mem::take(&mut self.buf);
        let pt = dec.decrypt_segment(self.next_index, true, &seg)?;
        self.next_index += 1;
        Ok(Some(pt))
    }
}

impl<'a, I: Iterator<Item = Vec<u8>>> Iterator for DecryptChunks<'a, I> {
    type Item = Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        match self.step() {
            Ok(Some(pt)) => Some(Ok(pt)),
            Ok(None) => None,
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// [`DecryptChunks`] with an explicit segment size.
pub fn decrypt_chunks<'a, I: Iterator<Item = Vec<u8>>>(
    shares: &'a [IdentityDecryptionKeyShare],
    chunk_size: usize,
    chunks: I,
) -> Result<DecryptChunks<'a, I>> {
    DecryptChunks::new(shares, chunk_size, chunks)
}

/// [`DecryptChunks`] with the default 64 KiB segment size.
pub fn decrypt_chunks_default<'a, I: Iterator<Item = Vec<u8>>>(
    shares: &'a [IdentityDecryptionKeyShare],
    chunks: I,
) -> Result<DecryptChunks<'a, I>> {
    DecryptChunks::new(shares, DEFAULT_CHUNK_SIZE, chunks)
}

// ── Random access (seekable) decryption ───────────────────────────────────────────────────

/// Random-access decryptor over a `header ‖ segments` ciphertext of known total length. Only the
/// header bytes are needed up front; `read_range` fetches exactly the ciphertext segments that
/// cover the requested plaintext range via a caller-supplied byte-range reader.
pub struct SeekableDecryptor {
    dec: StreamDecryptor,
    layout: Layout,
    byte_length: u64,
}

impl SeekableDecryptor {
    /// `byte_length` is the total ciphertext length (header included); `header_bytes` are at
    /// least the first `HEADER_BYTES` bytes of the ciphertext.
    pub fn open(
        shares: &[IdentityDecryptionKeyShare],
        byte_length: u64,
        header_bytes: &[u8],
        chunk_size: usize,
    ) -> Result<Self> {
        if header_bytes.len() < HEADER_BYTES {
            return Err(AceError::wire("stream: header too short"));
        }
        let body_len = byte_length
            .checked_sub(HEADER_BYTES as u64)
            .ok_or_else(|| AceError::wire("stream: ciphertext shorter than header"))?;
        let layout = stream_layout(body_len, chunk_size)?;
        let c0 = parse_header(&header_bytes[..HEADER_BYTES])?;
        let dec = StreamDecryptor::from_shares(shares, &c0)?;
        Ok(Self {
            dec,
            layout,
            byte_length,
        })
    }

    /// [`Self::open`] with the default 64 KiB segment size.
    pub fn open_default(
        shares: &[IdentityDecryptionKeyShare],
        byte_length: u64,
        header_bytes: &[u8],
    ) -> Result<Self> {
        Self::open(shares, byte_length, header_bytes, DEFAULT_CHUNK_SIZE)
    }

    pub fn plaintext_length(&self) -> u64 {
        self.layout.plaintext_length
    }

    pub fn layout(&self) -> Layout {
        self.layout
    }

    pub fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// Decrypt plaintext bytes `[offset, min(offset + len, plaintext_length))`. `read_ct(start,
    /// length)` must return exactly `length` ciphertext bytes starting at absolute offset `start`.
    pub fn read_range(
        &self,
        offset: u64,
        len: u64,
        mut read_ct: impl FnMut(u64, u64) -> Result<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let end = offset.saturating_add(len).min(self.layout.plaintext_length);
        if offset >= end {
            return Ok(Vec::new());
        }
        let cs = self.layout.chunk_size as u64;
        let seg = cs + AEAD_TAG_BYTES as u64;
        let n = self.layout.num_segments;
        let body_len = self.byte_length - HEADER_BYTES as u64;
        let first = offset / cs;
        let last = (end - 1) / cs;
        let ct_start = HEADER_BYTES as u64 + first * seg;
        let ct_end = HEADER_BYTES as u64
            + if last == n - 1 {
                body_len
            } else {
                (last + 1) * seg
            };
        let ct = read_ct(ct_start, ct_end - ct_start)?;
        if ct.len() as u64 != ct_end - ct_start {
            return Err(AceError::wire(format!(
                "stream: ciphertext source returned {} bytes, expected {}",
                ct.len(),
                ct_end - ct_start
            )));
        }
        let mut out = Vec::with_capacity(((last - first + 1) * cs) as usize);
        let mut pos = 0usize;
        for index in first..=last {
            let is_last = index == n - 1;
            let this_len = if is_last {
                ct.len() - pos
            } else {
                seg as usize
            };
            out.extend_from_slice(&self.dec.decrypt_segment(
                index,
                is_last,
                &ct[pos..pos + this_len],
            )?);
            pos += this_len;
        }
        let lo = (offset - first * cs) as usize;
        let hi = (end - first * cs) as usize;
        Ok(out[lo..hi].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::super::bfibe_bls12381_shortsig_aead::{
        derive_public_key, extract, keygen_for_testing, IdentityDecryptionKeyShare, MasterPublicKey,
    };
    use super::*;
    use crate::wire::Wire;

    fn hex_field(v: &serde_json::Value, k: &str) -> Vec<u8> {
        hex::decode(v[k].as_str().unwrap()).unwrap()
    }

    #[test]
    fn stream_cross_impl_fixture() {
        let fx: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-fixtures/python-sdk-cross-impl.json"
        ))
        .unwrap();
        let f = &fx["t_ibe_shortsig_aead_stream"];
        let mpk_tagged = hex_field(f, "master_public_key_hex");
        let idk_tagged = hex_field(f, "identity_decryption_key_hex");
        assert_eq!(mpk_tagged[0], 1);
        assert_eq!(idk_tagged[0], 1);
        let mpk = MasterPublicKey::from_bytes(&mpk_tagged[1..]).unwrap();
        let idk = IdentityDecryptionKeyShare::from_bytes(&idk_tagged[1..]).unwrap();
        let id = f["identity_utf8"].as_str().unwrap().as_bytes();
        let randomness = hex_field(f, "randomness_hex");
        let cs = f["chunk_size"].as_u64().unwrap() as usize;
        assert_eq!(cs, 16);

        for case in f["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let pt = case["plaintext_utf8"].as_str().unwrap().as_bytes().to_vec();
            let ts_ct = hex_field(case, "typescript_ciphertext_hex");
            let py_ct = hex_field(case, "python_ciphertext_hex");
            assert_eq!(ts_ct, py_ct, "{name}: ts vs py");
            assert_eq!(ts_ct[0], STREAM_MARKER, "{name}: marker");

            let ours =
                encrypt_to_concat_chunks_with_randomness(&mpk, id, &pt, &randomness, cs).unwrap();
            assert_eq!(ours, ts_ct, "{name}: encrypt");
            assert_eq!(
                decrypt_from_concat_chunks(&[idk.clone()], &ts_ct, cs).unwrap(),
                pt,
                "{name}: decrypt"
            );

            // Seekable random access.
            let sd = SeekableDecryptor::open(
                &[idk.clone()],
                ts_ct.len() as u64,
                &ts_ct[..HEADER_BYTES],
                cs,
            )
            .unwrap();
            assert_eq!(sd.plaintext_length(), pt.len() as u64, "{name}: length");
            let read = |s: u64, l: u64| -> Result<Vec<u8>> {
                Ok(ts_ct[s as usize..(s + l) as usize].to_vec())
            };
            let n = pt.len() as u64;
            for (off, len) in [(0, n), (3, 5), (n.saturating_sub(1), 10), (n, 4), (0, 0)] {
                let end = (off + len).min(n);
                let want: &[u8] = if off >= end {
                    &[]
                } else {
                    &pt[off as usize..end as usize]
                };
                assert_eq!(
                    sd.read_range(off, len, read).unwrap(),
                    want,
                    "{name}: range {off}+{len}"
                );
            }
        }
    }

    fn keys() -> (MasterPublicKey, IdentityDecryptionKeyShare) {
        let msk = keygen_for_testing();
        let mpk = derive_public_key(&msk);
        let idk = extract(&msk.scalar, b"stream-id").unwrap();
        (mpk, idk)
    }

    fn collect_enc(mpk: &MasterPublicKey, pt: &[u8], cs: usize, src: usize) -> Vec<Vec<u8>> {
        let src_chunks: Vec<Vec<u8>> = pt.chunks(src.max(1)).map(|c| c.to_vec()).collect();
        encrypt_chunks(mpk, b"stream-id", None, cs, src_chunks.into_iter())
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .unwrap()
    }

    fn dec_all(
        idk: &IdentityDecryptionKeyShare,
        cs: usize,
        chunks: Vec<Vec<u8>>,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for seg in decrypt_chunks(&[idk.clone()], cs, chunks.into_iter())? {
            out.extend_from_slice(&seg?);
        }
        Ok(out)
    }

    #[test]
    fn stream_iterator_roundtrip_and_tamper() {
        let (mpk, idk) = keys();
        let cs = 64usize;
        for size in [0usize, 1, cs - 1, cs, cs + 1, 3 * cs] {
            let pt: Vec<u8> = (0..size).map(|i| (i * 7 % 251) as u8).collect();
            let chunks = collect_enc(&mpk, &pt, cs, 13);
            let expected_segments = (size.div_ceil(cs)).max(1);
            assert_eq!(
                chunks.len(),
                1 + expected_segments,
                "size {size}: segment count"
            );
            assert_eq!(chunks[0].len(), HEADER_BYTES);
            if size > 0 && size % cs == 0 {
                assert_eq!(
                    chunks.last().unwrap().len(),
                    cs + AEAD_TAG_BYTES,
                    "size {size}: full final"
                );
            }
            // Matches the whole-buffer encoder up to randomness: same layout.
            let concat: Vec<u8> = chunks.concat();
            assert_eq!(
                decrypt_from_concat_chunks(&[idk.clone()], &concat, cs).unwrap(),
                pt
            );
            // Decrypt via iterator with re-chunked boundaries.
            for src in [1usize, 5, 97, 4096] {
                let rechunked: Vec<Vec<u8>> = concat.chunks(src).map(|c| c.to_vec()).collect();
                assert_eq!(
                    dec_all(&idk, cs, rechunked).unwrap(),
                    pt,
                    "size {size} src {src}"
                );
            }
            assert_eq!(dec_all(&idk, cs, chunks.clone()).unwrap(), pt);

            // Truncation by one byte.
            let mut t = concat.clone();
            t.pop();
            assert!(
                dec_all(&idk, cs, vec![t]).is_err(),
                "size {size}: truncated"
            );
            // Flipped byte in the body.
            let mut fl = concat.clone();
            let i = HEADER_BYTES + 3;
            fl[i] ^= 0x55;
            assert!(dec_all(&idk, cs, vec![fl]).is_err(), "size {size}: flipped");
            if chunks.len() >= 4 {
                // Dropped middle segment.
                let mut d = chunks.clone();
                d.remove(1);
                assert!(dec_all(&idk, cs, d).is_err(), "size {size}: dropped");
                // Swapped segments.
                let mut s = chunks.clone();
                s.swap(1, 2);
                assert!(dec_all(&idk, cs, s).is_err(), "size {size}: swapped");
            }
        }
        // Stream ending before a full header.
        assert!(dec_all(&idk, cs, vec![vec![3u8; 50]]).is_err());
        assert!(dec_all(&idk, cs, vec![]).is_err());
    }

    #[test]
    fn stream_segment_nonce_layout() {
        assert!(segment_nonce(u64::MAX, false).is_ok());
        let n = segment_nonce(5, true).unwrap();
        assert_eq!(n[NONCE_BYTES - 1], 0x01);
        let mut want = [0u8; COUNTER_BYTES];
        want[COUNTER_BYTES - 8..].copy_from_slice(&5u64.to_be_bytes());
        assert_eq!(&n[..COUNTER_BYTES], &want);
        assert_eq!(segment_nonce(5, false).unwrap()[NONCE_BYTES - 1], 0x00);
    }
}
