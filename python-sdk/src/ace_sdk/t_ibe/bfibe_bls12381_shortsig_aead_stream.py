# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Mirrors ts-sdk/src/t-ibe/bfibe-bls12381-shortsig-aead-stream.ts.

Streaming + seekable DEM for the shortsig-aead IBE half (the StreamIBE_* scopes).

The IBE half is byte-for-byte identical to the block scheme (`bfibe_bls12381_shortsig_aead`):
same G2 master key, H_G1(id), per-message seed e(Q_id, pk^r), c0, and the same G1 IDK share.
Streaming reuses those objects verbatim; only the DEM changes, from one ChaCha20-Poly1305 call to
a seekable segmented AEAD (STREAM construction):

  - 32-byte ChaCha20 key = HKDF-SHA256(seed, salt="", info=STREAM DST, L=32).
  - 64 KiB plaintext segments; segment i nonce = 11-byte BE counter i || 1-byte last-flag.

There is no ciphertext object -- output is a stream of ciphertext chunks:

  header chunk  = 0x03 || c0            (1-byte stream marker = the on-chain primitive, then
                                         96-byte G2-compressed c0)
  segment chunk = ct_i || 16B tag       (one per 64 KiB of plaintext)

Non-final segment chunks are exactly chunk_size + 16 bytes; the final one is the remainder.
Segment count + plaintext length are derivable from the total chunk-bytes length (no header field).
"""

from __future__ import annotations

from typing import Iterable, Iterator, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ace_sdk.group.bls12381fr import fr_mod
from ace_sdk.group.bls12381g2 import _g2_from_compressed, _g2_to_compressed
from ace_sdk.t_ibe.bfibe_bls12381_shortsig_aead import (
    IdentityDecryptionKeyShare,
    MasterPublicKey,
    ibe_encrypt_seed_and_c0,
    ibe_reconstruct_seed,
)
from ace_sdk.utils import rand_bytes

# First byte of the header chunk — the on-chain primitive id, used as a 1-byte stream marker.
STREAM_MARKER = 3

DEFAULT_CHUNK_SIZE = 64 * 1024
AEAD_TAG_BYTES = 16
AEAD_KEY_BYTES = 32
COUNTER_BYTES = 11  # nonce = 11-byte BE counter || 1-byte last-flag
C0_BYTES = 96  # G2 compressed
HEADER_BYTES = 1 + C0_BYTES

DST_KDF = b"BONEH_FRANKLIN_BLS12381_SHORTSIG_AEADSTREAM/KDF"


# == Primitives ================================================================


def _derive_stream_key(seed: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=AEAD_KEY_BYTES, salt=b"", info=DST_KDF
    ).derive(seed)


def _segment_nonce(index: int, is_last: bool) -> bytes:
    if index < 0 or index >> (COUNTER_BYTES * 8) != 0:
        raise ValueError(f"stream: segment index out of range {index}")
    return index.to_bytes(COUNTER_BYTES, "big") + (b"\x01" if is_last else b"\x00")


def _segment_encrypt(key: bytes, index: int, is_last: bool, plain_chunk: bytes) -> bytes:
    return ChaCha20Poly1305(key).encrypt(_segment_nonce(index, is_last), plain_chunk, None)


def _segment_decrypt(key: bytes, index: int, is_last: bool, cipher_chunk: bytes) -> bytes:
    # ChaCha20Poly1305.decrypt raises InvalidTag on mismatch; propagate (fails closed).
    return ChaCha20Poly1305(key).decrypt(_segment_nonce(index, is_last), cipher_chunk, None)


def _random_scalar_le() -> bytes:
    return fr_mod(int.from_bytes(rand_bytes(64), "big")).to_bytes(32, "little")


# == Layout math (seek support) ================================================


def stream_layout(body_len: int, chunk_size: int = DEFAULT_CHUNK_SIZE) -> tuple[int, int]:
    """Recover (num_segments, plaintext_length) from the concatenated segment-chunk length (total
    chunk bytes minus the HEADER_BYTES header chunk)."""
    cipher_seg = chunk_size + AEAD_TAG_BYTES
    if body_len < AEAD_TAG_BYTES:
        raise ValueError(f"stream: body too short ({body_len} < {AEAD_TAG_BYTES})")
    num_segments = max(1, -(-(body_len - AEAD_TAG_BYTES) // cipher_seg))  # ceil division
    plaintext_length = body_len - AEAD_TAG_BYTES * num_segments
    if plaintext_length < 0:
        raise ValueError(f"stream: inconsistent body length {body_len}")
    final_seg_len = body_len - (num_segments - 1) * cipher_seg
    if final_seg_len < AEAD_TAG_BYTES or final_seg_len > cipher_seg:
        raise ValueError(f"stream: inconsistent final segment length {final_seg_len}")
    return num_segments, plaintext_length


# == Whole-buffer, byte-exact (concatenated ciphertext chunks, for vectors only) ==


def encode_segments(key: bytes, plaintext: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    num_segments = 1 if len(plaintext) == 0 else -(-len(plaintext) // chunk_size)
    out = bytearray()
    for j in range(num_segments):
        start = j * chunk_size
        chunk = plaintext[start : min(start + chunk_size, len(plaintext))]
        out += _segment_encrypt(key, j, j == num_segments - 1, chunk)
    return bytes(out)


def decode_segments(key: bytes, body: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE) -> bytes:
    num_segments, _ = stream_layout(len(body), chunk_size)
    cipher_seg = chunk_size + AEAD_TAG_BYTES
    out = bytearray()
    for j in range(num_segments):
        start = j * cipher_seg
        end = len(body) if j == num_segments - 1 else start + cipher_seg
        out += _segment_decrypt(key, j, j == num_segments - 1, body[start:end])
    return bytes(out)


def encrypt_to_concat_chunks_with_randomness(
    mpk: MasterPublicKey,
    identity: bytes,
    plaintext: bytes,
    randomness: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    """Byte-exact whole-buffer encrypt producing the concatenated ciphertext chunks
    (header || segments). For cross-impl test vectors."""
    seed, c0 = ibe_encrypt_seed_and_c0(mpk, identity, randomness)
    body = encode_segments(_derive_stream_key(seed), plaintext, chunk_size)
    return bytes([STREAM_MARKER]) + _g2_to_compressed(c0) + body


def decrypt_from_concat_chunks(
    idk_shares: list[IdentityDecryptionKeyShare],
    chunks: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    """Byte-exact whole-buffer decrypt of concatenated ciphertext chunks (header || segments)."""
    if len(chunks) < HEADER_BYTES + AEAD_TAG_BYTES:
        raise ValueError("stream: ciphertext chunks too short")
    if chunks[0] != STREAM_MARKER:
        raise ValueError(f"stream: expected marker {STREAM_MARKER}, got {chunks[0]}")
    c0 = _g2_from_compressed(chunks[1:HEADER_BYTES])
    seed = ibe_reconstruct_seed(idk_shares, c0)
    return decode_segments(_derive_stream_key(seed), chunks[HEADER_BYTES:], chunk_size)


# == Bounded-memory streaming (generators) =====================================


def encrypt_chunks(
    mpk: MasterPublicKey,
    identity: bytes,
    plaintext: Iterable[bytes],
    randomness: bytes | None = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Iterator[bytes]:
    """Encrypt an iterable of plaintext byte chunks into an iterable of ciphertext chunks (header
    chunk, then segment chunks) in bounded memory."""
    seed, c0 = ibe_encrypt_seed_and_c0(mpk, identity, randomness or _random_scalar_le())
    key = _derive_stream_key(seed)
    yield bytes([STREAM_MARKER]) + _g2_to_compressed(c0)

    buf = bytearray()
    index = 0
    for incoming in plaintext:
        if not incoming:
            continue
        buf += incoming
        # Hold back a full chunk (strict '>') so a chunk landing exactly at EOF is flagged final.
        while len(buf) > chunk_size:
            yield _segment_encrypt(key, index, False, bytes(buf[:chunk_size]))
            index += 1
            del buf[:chunk_size]
    yield _segment_encrypt(key, index, True, bytes(buf))


def decrypt_chunks(
    idk_shares: list[IdentityDecryptionKeyShare],
    ciphertext_chunks: Iterable[bytes],
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> Iterator[bytes]:
    """Decrypt an iterable of ciphertext chunks (any re-chunking) into plaintext byte chunks in
    bounded memory. Fails closed on tamper, truncation, reorder, or a short stream."""
    cipher_seg = chunk_size + AEAD_TAG_BYTES
    it = iter(ciphertext_chunks)
    buf = bytearray()

    while len(buf) < HEADER_BYTES:
        try:
            buf += next(it)
        except StopIteration:
            break
    if len(buf) < HEADER_BYTES:
        raise ValueError("stream: ciphertext chunks ended before header")
    if buf[0] != STREAM_MARKER:
        raise ValueError(f"stream: expected marker {STREAM_MARKER}, got {buf[0]}")
    c0 = _g2_from_compressed(bytes(buf[1:HEADER_BYTES]))
    key = _derive_stream_key(ibe_reconstruct_seed(idk_shares, c0))
    del buf[:HEADER_BYTES]

    index = 0

    def drain(final: bool) -> Iterator[bytes]:
        nonlocal index
        while len(buf) > cipher_seg:
            seg = bytes(buf[:cipher_seg])
            del buf[:cipher_seg]
            yield _segment_decrypt(key, index, False, seg)
            index += 1
        if final:
            if len(buf) < AEAD_TAG_BYTES:
                raise ValueError("stream: truncated final segment")
            yield _segment_decrypt(key, index, True, bytes(buf))
            index += 1
            buf.clear()

    for incoming in it:
        buf += incoming
        yield from drain(False)
    yield from drain(True)


# == Seekable / random-access decryptor (web video) ============================


class CiphertextSource(Protocol):
    """Random-access byte source over the stored ciphertext chunks (HTTP Range, file, …)."""

    byte_length: int

    def read_range(self, offset: int, length: int) -> bytes: ...


class SeekableDecryptor:
    """Decrypt arbitrary plaintext byte ranges from stored ciphertext chunks, fetching only the
    covered segments."""

    def __init__(self, key: bytes, source: CiphertextSource, chunk_size: int) -> None:
        self._key = key
        self._source = source
        self._chunk_size = chunk_size
        self._cipher_seg = chunk_size + AEAD_TAG_BYTES
        self._body_len = source.byte_length - HEADER_BYTES
        self._num_segments, self.plaintext_length = stream_layout(self._body_len, chunk_size)

    def read_range(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise ValueError(f"stream: bad range offset={offset} length={length}")
        end = min(offset + length, self.plaintext_length)
        if offset >= end:
            return b""
        first_seg = offset // self._chunk_size
        last_seg = (end - 1) // self._chunk_size
        c_start = first_seg * self._cipher_seg
        c_end = self._body_len if last_seg == self._num_segments - 1 else (last_seg + 1) * self._cipher_seg
        chunk = self._source.read_range(HEADER_BYTES + c_start, c_end - c_start)

        out = bytearray()
        for j in range(first_seg, last_seg + 1):
            s = (j - first_seg) * self._cipher_seg
            e = (c_end - c_start) if j == self._num_segments - 1 else s + self._cipher_seg
            out += _segment_decrypt(self._key, j, j == self._num_segments - 1, chunk[s:e])
        off_in_first = offset - first_seg * self._chunk_size
        return bytes(out[off_in_first : off_in_first + (end - offset)])


def create_seekable_decryptor(
    idk_shares: list[IdentityDecryptionKeyShare],
    source: CiphertextSource,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> SeekableDecryptor:
    if source.byte_length < HEADER_BYTES + AEAD_TAG_BYTES:
        raise ValueError("stream: ciphertext too short")
    header = source.read_range(0, HEADER_BYTES)
    if header[0] != STREAM_MARKER:
        raise ValueError(f"stream: expected marker {STREAM_MARKER}, got {header[0]}")
    c0 = _g2_from_compressed(bytes(header[1:HEADER_BYTES]))
    key = _derive_stream_key(ibe_reconstruct_seed(idk_shares, c0))
    return SeekableDecryptor(key, source, chunk_size)
