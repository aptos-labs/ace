# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Self-contained StreamIBE demo (no network / no ACE deployment).

Demonstrates the streaming mechanics — chunk-in / chunk-out encryption, bounded-memory
decryption, and random-access (`read_range`) seeking that powers encrypted <video> playback —
using a locally-generated key.

In a real app you use the network-backed scope instead: `ace_sdk.StreamIBE_Aptos.encrypt_stream`
and `ace_sdk.StreamIBE_Aptos.create_stream_decryptor_custom_flow(...)`, which talk to the ACE
nodes but yield/consume ciphertext CHUNKS and expose a seekable decryptor. See
docs/developers/app-developer-guide/ibe-aptos-stream.md.

Run:  python scenarios/stream_demo.py   (from the python-sdk dir, with deps installed)
"""

from __future__ import annotations

from ace_sdk import t_ibe, t_ibe_stream

CHUNK = 64 * 1024  # production default


def _chunked(b: bytes, size: int):
    for i in range(0, len(b), size):
        yield b[i : i + size]


def main() -> None:
    # Local key material (stands in for the on-chain DKG keypair + a threshold IDK share).
    # Streaming reuses the shortsig-aead (scheme 1) objects verbatim.
    scheme = t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    msk = t_ibe.keygen_for_testing(scheme).unwrap_or_throw(ValueError("keygen"))
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw(ValueError("derive"))
    identity = b"demo/big-video.mp4"
    share = t_ibe.extract(scheme=scheme, msk_scalar=msk.inner.scalar, identity=identity).unwrap_or_throw(
        ValueError("extract")
    )

    plaintext = bytes((i * 131 + 7) & 0xFF for i in range(300 * 1024))  # ~300 KiB "media file"
    print(f"Plaintext: {len(plaintext)} bytes")

    # 1) Encrypt as a stream of ciphertext CHUNKS (bounded memory).
    cipher_chunks = list(
        t_ibe_stream.encrypt_stream(mpk, identity, _chunked(plaintext, CHUNK), chunk_size=CHUNK)
    )
    print(f"Encrypted into {len(cipher_chunks)} ciphertext chunks (1 header + segments)")

    # 2) Forward-decrypt the chunk stream back to plaintext chunks.
    stored = b"".join(cipher_chunks)
    round_trip = b"".join(
        t_ibe_stream.decrypt_stream([share], _chunked(stored, 9000), chunk_size=CHUNK)
    )
    assert round_trip == plaintext, "stream round-trip mismatch"
    print("OK Forward stream round-trip matches")

    # 3) Seek: decrypt an arbitrary plaintext byte range, fetching only the covered segments.
    fetched = {"bytes": 0}

    class Source:
        byte_length = len(stored)

        def read_range(self, offset: int, length: int) -> bytes:
            fetched["bytes"] += length
            return stored[offset : offset + length]

    seek = t_ibe_stream.create_seekable_decryptor([share], Source(), chunk_size=CHUNK)
    start, length = 200 * 1024 + 123, 4096
    clip = seek.read_range(start, length)
    assert clip == plaintext[start : start + length], "seek read_range mismatch"
    print(
        f"OK Seek read_range({start}, {length}) matches — fetched only "
        f"{fetched['bytes']} of {len(stored)} ciphertext bytes"
    )
    print("\nThis is the mechanic behind encrypted <video> seeking: each scrub -> one read_range().")


if __name__ == "__main__":
    main()
