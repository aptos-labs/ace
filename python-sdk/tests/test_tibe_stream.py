# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Streaming + seekable DEM (StreamIBE) round-trip, seek, and fail-closed tests.

Uses a tiny chunk_size to exercise multi-segment boundaries. Mirrors
ts-sdk/tests/bfibe-bls12381-shortsig-aead-stream.test.ts.
"""

from __future__ import annotations

import pytest

from ace_sdk import t_ibe as tibe
from ace_sdk import t_ibe_stream
from ace_sdk.t_ibe import bfibe_bls12381_shortsig_aead as aead
from ace_sdk.t_ibe import bfibe_bls12381_shortsig_aead_stream as st

CHUNK = 16
HEADER = 1 + 96
SIZES = [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 7]


def _fixture():
    msk = aead.keygen_for_testing()
    mpk = aead.derive_public_key(msk)
    identity = b"alice@example.com"
    share = aead.extract(msk.scalar, identity)
    return mpk, identity, [share]


def _bytes(n: int) -> bytes:
    return bytes((i * 37 + 11) & 0xFF for i in range(n))


def _pieces(b: bytes, size: int):
    for i in range(0, len(b), size):
        yield b[i : i + size]


def test_whole_buffer_round_trip_across_boundary_sizes():
    mpk, identity, shares = _fixture()
    r = (12345).to_bytes(32, "little")
    for n in SIZES:
        pt = _bytes(n)
        ct = st.encrypt_to_concat_chunks_with_randomness(mpk, identity, pt, r, CHUNK)
        assert ct[0] == st.STREAM_MARKER
        assert st.decrypt_from_concat_chunks(shares, ct, CHUNK) == pt


def test_stream_layout_recovers_plaintext_length():
    mpk, identity, _ = _fixture()
    r = (7).to_bytes(32, "little")
    for n in SIZES:
        ct = st.encrypt_to_concat_chunks_with_randomness(mpk, identity, _bytes(n), r, CHUNK)
        assert st.stream_layout(len(ct) - HEADER, CHUNK)[1] == n


def test_async_path_is_byte_identical_to_whole_buffer():
    mpk, identity, _ = _fixture()
    pt = _bytes(3 * CHUNK + 7)
    r = (999).to_bytes(32, "little")
    expected = st.encrypt_to_concat_chunks_with_randomness(mpk, identity, pt, r, CHUNK)
    got = b"".join(st.encrypt_chunks(mpk, identity, _pieces(pt, 5), randomness=r, chunk_size=CHUNK))
    assert got == expected


def test_bounded_memory_round_trip_with_rechunking():
    mpk, identity, shares = _fixture()
    for n in SIZES:
        pt = _bytes(n)
        ctb = b"".join(st.encrypt_chunks(mpk, identity, _pieces(pt, 7), chunk_size=CHUNK))
        got = b"".join(st.decrypt_chunks(shares, _pieces(ctb, 13), chunk_size=CHUNK))
        assert got == pt


def test_seekable_read_range_matches_slices_and_fetches_only_covered_segments():
    mpk, identity, shares = _fixture()
    pt = _bytes(5 * CHUNK + 3)
    r = (42).to_bytes(32, "little")
    ctb = st.encrypt_to_concat_chunks_with_randomness(mpk, identity, pt, r, CHUNK)

    fetches: list[int] = []

    class Src:
        byte_length = len(ctb)

        def read_range(self, offset: int, length: int) -> bytes:
            fetches.append(length)
            return ctb[offset : offset + length]

    dec = st.create_seekable_decryptor(shares, Src(), CHUNK)
    assert dec.plaintext_length == len(pt)
    for off, ln in [(0, 4), (CHUNK - 2, 5), (CHUNK, CHUNK), (2 * CHUNK + 1, 3), (0, len(pt)), (5 * CHUNK, 3)]:
        fetches.clear()
        assert dec.read_range(off, ln) == pt[off : min(off + ln, len(pt))]
        if 0 < off and off + ln < len(pt):
            assert sum(fetches) < len(ctb) - HEADER


def test_fails_closed_on_tamper_truncation_reorder_dropped_segment():
    mpk, identity, shares = _fixture()
    pt = _bytes(3 * CHUNK + 5)
    r = (1).to_bytes(32, "little")
    ct = st.encrypt_to_concat_chunks_with_randomness(mpk, identity, pt, r, CHUNK)
    cipher_seg = CHUNK + 16

    tampered = bytearray(ct)
    tampered[HEADER + 3] ^= 0x01
    with pytest.raises(Exception):
        st.decrypt_from_concat_chunks(shares, bytes(tampered), CHUNK)

    with pytest.raises(Exception):
        st.decrypt_from_concat_chunks(shares, ct[:-4], CHUNK)

    reordered = bytearray(ct)
    reordered[HEADER : HEADER + cipher_seg] = ct[HEADER + cipher_seg : HEADER + 2 * cipher_seg]
    reordered[HEADER + cipher_seg : HEADER + 2 * cipher_seg] = ct[HEADER : HEADER + cipher_seg]
    with pytest.raises(Exception):
        st.decrypt_from_concat_chunks(shares, bytes(reordered), CHUNK)

    dropped = ct[:HEADER] + ct[HEADER + cipher_seg :]
    with pytest.raises(Exception):
        st.decrypt_from_concat_chunks(shares, dropped, CHUNK)


def test_generic_api_round_trip_and_rejects_non_shortsig():
    scheme = tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    msk = tibe.keygen_for_testing(scheme).unwrap_or_throw(ValueError("keygen"))
    mpk = tibe.derive_public_key(msk).unwrap_or_throw(ValueError("derive"))
    identity = b"stream@example.com"
    share = tibe.extract(scheme=scheme, msk_scalar=msk.inner.scalar, identity=identity).unwrap_or_throw(
        ValueError("extract")
    )
    # The generic API fixes the segment size at 64 KiB (no chunk_size param); use a >64 KiB payload
    # to still cross segment boundaries. Boundary edge cases are covered above via the low-level DEM.
    pt = _bytes(3 * st.DEFAULT_CHUNK_SIZE + 7)
    ct = b"".join(t_ibe_stream.encrypt_stream(mpk, identity, _pieces(pt, 4096)))
    assert b"".join(t_ibe_stream.decrypt_stream([share], _pieces(ct, 5000))) == pt

    otp_msk = tibe.keygen_for_testing(tibe.SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC).unwrap_or_throw(
        ValueError("otp")
    )
    otp_mpk = tibe.derive_public_key(otp_msk).unwrap_or_throw(ValueError("otp mpk"))
    with pytest.raises(ValueError):
        list(t_ibe_stream.encrypt_stream(otp_mpk, identity, [b"hi"]))
