# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Mirrors ts-sdk/src/t-ibe-stream/index.ts.

Generic streaming + seekable t-IBE API — the chunk-oriented sibling of the object-oriented `t_ibe`
API, wrapped by the `StreamIBE_*` scopes.

Streaming reuses the shortsig-aead (block) key/share objects verbatim — the crypto is identical;
only the DEM differs. So this module takes ordinary `t_ibe.MasterPublicKey` /
`t_ibe.IdentityDecryptionKeyShare` (scheme shortsig-aead) and applies the segmented DEM.

There is no Ciphertext type here: output is a stream of ciphertext chunks. The primitive=3 that
distinguishes stream from block on the ACE-node wire lives in the StreamIBE_* scopes.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from ace_sdk import t_ibe as tibe
from ace_sdk.t_ibe import bfibe_bls12381_shortsig_aead_stream as _stream

DEFAULT_CHUNK_SIZE = _stream.DEFAULT_CHUNK_SIZE
STREAM_MARKER = _stream.STREAM_MARKER

CiphertextSource = _stream.CiphertextSource
SeekableDecryptor = _stream.SeekableDecryptor


def _require_shortsig_mpk(mpk: "tibe.MasterPublicKey"):
    if mpk.scheme != tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
        raise ValueError(
            "t_ibe_stream: expected a shortsig-aead master public key "
            f"(scheme {tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD}), got {mpk.scheme}"
        )
    return mpk.inner


def _require_shortsig_shares(idk_shares: list["tibe.IdentityDecryptionKeyShare"]):
    out = []
    for s in idk_shares:
        if s.scheme != tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
            raise ValueError(
                "t_ibe_stream: expected shortsig-aead IDK shares "
                f"(scheme {tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD}), got {s.scheme}"
            )
        out.append(s.inner)
    return out


# The segment size is a fixed part of the wire format (not stored in the ciphertext), so it is
# intentionally not a public parameter here: encrypt and decrypt must agree, and the caller's input
# chunking is re-segmented internally. It remains a knob only on the low-level DEM + the vector
# helpers (below) that the cross-impl fixtures need.


def encrypt_stream(
    mpk: "tibe.MasterPublicKey",
    identity: bytes,
    plaintext: Iterable[bytes],
    randomness: bytes | None = None,
) -> Iterator[bytes]:
    """Encrypt plaintext byte chunks into ciphertext chunks (header chunk, then segments)."""
    return _stream.encrypt_chunks(
        _require_shortsig_mpk(mpk), identity, plaintext, randomness=randomness
    )


def decrypt_stream(
    idk_shares: list["tibe.IdentityDecryptionKeyShare"],
    ciphertext_chunks: Iterable[bytes],
) -> Iterator[bytes]:
    """Decrypt ciphertext chunks (any re-chunking) into plaintext byte chunks. Fails closed."""
    return _stream.decrypt_chunks(_require_shortsig_shares(idk_shares), ciphertext_chunks)


def create_seekable_decryptor(
    idk_shares: list["tibe.IdentityDecryptionKeyShare"],
    source: CiphertextSource,
) -> SeekableDecryptor:
    """Build a seekable decryptor over a random-access ciphertext source (see CiphertextSource)."""
    return _stream.create_seekable_decryptor(_require_shortsig_shares(idk_shares), source)


# -- Byte-exact whole-buffer helpers (concatenated ciphertext chunks, for cross-impl vectors) ----
# These keep an explicit `chunk_size` so fixtures can pin compact multi-segment vectors.


def encrypt_to_concat_chunks_with_randomness(
    mpk: "tibe.MasterPublicKey",
    identity: bytes,
    plaintext: bytes,
    randomness: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    return _stream.encrypt_to_concat_chunks_with_randomness(
        _require_shortsig_mpk(mpk), identity, plaintext, randomness, chunk_size
    )


def decrypt_from_concat_chunks(
    idk_shares: list["tibe.IdentityDecryptionKeyShare"],
    chunks: bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    return _stream.decrypt_from_concat_chunks(_require_shortsig_shares(idk_shares), chunks, chunk_size)
