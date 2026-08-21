# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0

import json
from pathlib import Path

from aptos_sdk.account_address import AccountAddress

from ace_sdk import (
    group,
    ibe_aptos,
    pke,
    sig,
    t_ibe,
    vss,
)
from ace_sdk._internal.common import ContractID, FullDecryptionDomain
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk.group import bls12381g1, bls12381g2
from ace_sdk.pke import _ristretto255


def test_pke_hpke_round_trip_default_scheme() -> None:
    encryption_key, decryption_key = pke.keygen()
    plaintext = b"hello pke"

    ciphertext = pke.encrypt(encryption_key, plaintext)
    decrypted = pke.decrypt(decryption_key, ciphertext)

    assert decrypted.is_ok
    assert decrypted.ok_value == plaintext


def test_default_hpke_does_not_require_libsodium_until_ristretto_use(monkeypatch) -> None:
    def fail_load_libsodium():
        raise AssertionError("libsodium should not load for default HPKE")

    monkeypatch.setattr(_ristretto255, "_lib", None)
    monkeypatch.setattr(_ristretto255, "_load_libsodium", fail_load_libsodium)

    pke.keygen()

    assert _ristretto255.group_identity() == bytes(_ristretto255.RISTRETTO_BYTES)


def test_pke_elgamal_golden_vector_and_hex_roundtrip() -> None:
    golden_dec_key = bytes.fromhex(
        "0020f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e174"
        "120d2874c3b7e5d7576c64b8a346b84159100ad978864319e880c249a54ae5d3708"
    )
    golden_enc_key_hex = (
        "0020f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e174"
        "1209e441d841f1c37c7104a3eb43f51447306c8cb2294cc6ac1be23f32f23c72b71"
    )
    golden_ciphertext = bytes.fromhex(
        "0020ec9d964805902bc6966b04ef1d54e655bb4356ad67029958e4af28b3dab49563"
        "20fe2416a85535cbd637b93487527a6427a0c632d6c66d3b3f71d82d625f3ba07e"
        "107b7b4a4ec372436a02589fe86b5d0eff2080b95f09e629565a296a7dcaadba664"
        "8f8f286633c9747774e453f5b2427540d"
    )

    decryption_key = pke.DecryptionKey.from_bytes(golden_dec_key).unwrap_or_throw("dk")
    ciphertext = pke.Ciphertext.from_bytes(golden_ciphertext).unwrap_or_throw("ct")
    encryption_key = pke.derive_encryption_key(decryption_key)

    assert encryption_key.to_hex() == golden_enc_key_hex
    assert pke.DecryptionKey.from_hex("0x" + decryption_key.to_hex()).is_ok
    assert pke.decrypt(decryption_key, ciphertext).unwrap_or_throw("decrypt") == b"golden-plaintext"
    assert not pke.Ciphertext.from_bytes(golden_ciphertext + b"\x00").is_ok


def _cross_impl_fixture() -> dict:
    path = Path(__file__).resolve().parents[2] / "test-fixtures" / "python-sdk-cross-impl.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_cross_impl_fixture_decrypts_typescript_default_hpke_ciphertext() -> None:
    fixture = _cross_impl_fixture()["hpke"]
    decryption_key = pke.DecryptionKey.from_hex(
        fixture["decryption_key_hex"]
    ).unwrap_or_throw("hpke dk")
    ciphertext = pke.Ciphertext.from_hex(
        fixture["typescript_ciphertext_hex"]
    ).unwrap_or_throw("ts hpke ct")
    encryption_key = pke.derive_encryption_key(decryption_key)

    assert encryption_key.to_hex() == fixture["encryption_key_hex"]
    assert pke.decrypt(decryption_key, ciphertext).unwrap_or_throw("hpke decrypt") == fixture[
        "plaintext_utf8"
    ].encode()


def test_sig_ed25519_round_trip_and_bcs_hex() -> None:
    signing_key = sig.SigningKey(sig.SCHEME_ED25519, bytes(range(32)))
    public_key = signing_key.public_key()
    message = b"hello sig"
    signature = signing_key.sign(message)

    assert sig.verify(message, signature, public_key)
    assert not sig.verify(b"wrong", signature, public_key)
    assert public_key.to_bytes()[:2] == b"\x00\x20"
    assert signature.to_bytes()[:2] == b"\x00\x40"
    assert signing_key.to_bytes() == b"\x00\x20" + bytes(range(32))
    assert sig.PublicKey.from_hex("0x" + public_key.to_hex()).unwrap_or_throw("pk").to_bytes() == public_key.to_bytes()
    assert sig.Signature.from_hex(signature.to_hex()).unwrap_or_throw("sig").to_bytes() == signature.to_bytes()
    assert sig.SigningKey.from_hex(signing_key.to_hex()).unwrap_or_throw("sk").public_key().to_bytes() == public_key.to_bytes()
    assert not sig.SigningKey.from_bytes(signing_key.to_bytes() + b"\x00").is_ok


def test_vss_public_api_reconstructs_g2_shares() -> None:
    secret = b"\x42" + bytes(31)
    share_bytes = bls12381g2.split(secret, threshold=3, total=5).unwrap_or_throw("split")

    indexed_shares = []
    for i in [0, 2, 4]:
        share = bls12381g2.SecretShare.from_bigint(
            int.from_bytes(share_bytes[i], "little")
        ).unwrap_or_throw("share")
        indexed_shares.append((i + 1, vss.SecretShare(group.SCHEME_BLS12381G2, share)))

    recovered = vss.reconstruct(indexed_shares).unwrap_or_throw("reconstruct")

    assert recovered.scheme == group.SCHEME_BLS12381G2
    assert recovered.inner.scalar == 0x42


def test_tibe_admin_extract_decrypts_production_ciphertext() -> None:
    identity = b"admin-recovery-label"
    plaintext = b"reconstructed master secret works"
    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")

    ciphertext = t_ibe.encrypt(mpk, identity, plaintext).unwrap_or_throw("encrypt")
    idk = t_ibe.extract(msk_scalar=msk.inner.scalar, identity=identity).unwrap_or_throw("extract")
    restored_idk = t_ibe.IdentityDecryptionKeyShare.from_hex(
        "0x" + idk.to_hex()
    ).unwrap_or_throw("idk hex")
    restored_ct = t_ibe.Ciphertext.from_hex("0x" + ciphertext.to_hex()).unwrap_or_throw("ct hex")

    decrypted = t_ibe.decrypt([restored_idk], restored_ct).unwrap_or_throw("decrypt")

    assert decrypted == plaintext
    assert not t_ibe.extract(
        scheme=t_ibe.SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
        msk_scalar=msk.inner.scalar,
        identity=identity,
    ).is_ok


def test_cross_impl_fixture_decrypts_typescript_tibe_shortsig_aead_ciphertext() -> None:
    fixture = _cross_impl_fixture()["t_ibe_shortsig_aead"]
    mpk = t_ibe.MasterPublicKey.from_hex(
        fixture["master_public_key_hex"]
    ).unwrap_or_throw("mpk")
    idk = t_ibe.IdentityDecryptionKeyShare.from_hex(
        fixture["identity_decryption_key_hex"]
    ).unwrap_or_throw("idk")
    expected_ct = t_ibe.encrypt_with_randomness(
        mpk,
        fixture["identity_utf8"].encode(),
        fixture["plaintext_utf8"].encode(),
        bytes.fromhex(fixture["randomness_hex"]),
    ).unwrap_or_throw("deterministic t-ibe ct")
    ciphertext = t_ibe.Ciphertext.from_hex(
        fixture["typescript_ciphertext_hex"]
    ).unwrap_or_throw("ts t-ibe ct")

    assert expected_ct.to_hex() == fixture["typescript_ciphertext_hex"]
    assert t_ibe.decrypt([idk], ciphertext).unwrap_or_throw("t-ibe decrypt") == fixture[
        "plaintext_utf8"
    ].encode()


def test_cross_impl_fixture_streaming_shortsig_aead() -> None:
    from ace_sdk import t_ibe_stream

    fixture = _cross_impl_fixture()["t_ibe_shortsig_aead_stream"]
    # Streaming reuses the shortsig-aead (scheme 1) key + share objects verbatim.
    mpk = t_ibe.MasterPublicKey.from_hex(fixture["master_public_key_hex"]).unwrap_or_throw("mpk")
    idk = t_ibe.IdentityDecryptionKeyShare.from_hex(
        fixture["identity_decryption_key_hex"]
    ).unwrap_or_throw("idk")
    identity = fixture["identity_utf8"].encode()
    randomness = bytes.fromhex(fixture["randomness_hex"])
    chunk_size = fixture["chunk_size"]

    for case in fixture["cases"]:
        plaintext = case["plaintext_utf8"].encode()
        recomputed = t_ibe_stream.encrypt_to_concat_chunks_with_randomness(
            mpk, identity, plaintext, randomness, chunk_size
        ).hex()
        assert recomputed == case["python_ciphertext_hex"], case["name"]
        assert case["python_ciphertext_hex"] == case["typescript_ciphertext_hex"], case["name"]
        decrypted = t_ibe_stream.decrypt_from_concat_chunks(
            [idk], bytes.fromhex(case["typescript_ciphertext_hex"]), chunk_size
        )
        assert decrypted == plaintext, case["name"]


def test_ibe_aptos_encrypt_uses_full_decryption_domain() -> None:
    keypair_id = AccountAddress.from_str(
        "0x00000000000000000000000000000000000000000000000000000000000000c1"
    )
    module_addr = AccountAddress.from_str("0x1")
    label = b"object-id"
    plaintext = b"aptos ibe plaintext"
    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")
    deployment = AceDeployment(
        "https://unused.example/v1",
        AccountAddress.from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000ace"
        ),
    )

    ciphertext_bytes = ibe_aptos.encrypt(
        ace_deployment=deployment,
        keypair_id=keypair_id,
        chain_id=42,
        module_addr=module_addr,
        module_name="example",
        label=label,
        plaintext=plaintext,
        pk=mpk,
    ).unwrap_or_throw("encrypt")

    ciphertext = t_ibe.Ciphertext.from_bytes(ciphertext_bytes).unwrap_or_throw("ct")
    fdd = FullDecryptionDomain(
        keypair_id,
        ContractID.new_aptos(42, module_addr, "example"),
        label,
    )
    assert FullDecryptionDomain.from_hex("0x" + fdd.to_hex()).unwrap_or_throw("fdd").to_bytes() == fdd.to_bytes()
    idk = t_ibe.extract(msk_scalar=msk.inner.scalar, identity=fdd.to_bytes()).unwrap_or_throw("idk")

    assert t_ibe.decrypt([idk], ciphertext).unwrap_or_throw("decrypt") == plaintext


def test_bls12381_deserialization_rejects_non_prime_order_points() -> None:
    non_subgroup_g1 = bytes.fromhex(
        "8000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000004"
    )
    non_subgroup_g2 = bytes.fromhex(
        "a000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000010"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000"
    )

    assert not bls12381g1.PublicPoint.from_raw_bytes(non_subgroup_g1).is_ok
    assert not bls12381g2.PublicPoint.from_raw_bytes(non_subgroup_g2).is_ok
    assert bls12381g1.PublicPoint.from_raw_bytes(bls12381g1.g1_generator().raw_bytes()).is_ok
    assert bls12381g2.PublicPoint.from_raw_bytes(bls12381g2.g2_generator().raw_bytes()).is_ok
