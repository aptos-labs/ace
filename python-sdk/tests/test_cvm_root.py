# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0

from aptos_sdk.account_address import AccountAddress
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from ace_sdk import ContractID, cvm_root, pke, vrf_aptos


def sample_payload() -> vrf_aptos.ThresholdVrfRequestPayload:
    return vrf_aptos.ThresholdVrfRequestPayload(
        keypair_id=AccountAddress.from_str("0x" + "01" * 32),
        epoch=7,
        contract_id=ContractID.new_aptos(
            119,
            AccountAddress.from_str("0x" + "02" * 32),
            "confidential_worker",
        ),
        label=cvm_root.ROOT_LABEL,
        account_address=AccountAddress.from_str("0x" + "03" * 32),
        response_enc_key=pke.EncryptionKey.from_hex("0120" + "04" * 32).unwrap_or_throw("ek"),
    )


def sample_binding(payload: vrf_aptos.ThresholdVrfRequestPayload) -> cvm_root.CvmRootBinding:
    key = Ed25519PrivateKey.from_private_bytes(bytes([7] * 32))
    worker_pk = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    worker_addr = bytes([5] * 32)
    tls_spki_sha256 = bytes([6] * 32)
    signature = key.sign(cvm_root.worker_signature_message(payload, worker_addr, worker_pk, tls_spki_sha256))
    return cvm_root.CvmRootBinding(worker_addr, worker_pk, tls_spki_sha256, signature)


def test_cvm_root_bcs_and_attestation_nonce_known_answer() -> None:
    payload = sample_payload()
    binding = sample_binding(payload)
    assert cvm_root.CvmRootVrfRequest(payload, binding, "test.jwt").to_bytes().hex() == (
        "04" + "01" * 32 + "0700000000000000" + "00" + "77" + "02" * 32
        + "13636f6e666964656e7469616c5f776f726b6572" + "0c633236742f726f6f742f7631"
        + "03" * 32 + "0120" + "04" * 32
        + "05" * 32 + binding.worker_pk.hex() + "06" * 32
        + "40" + binding.worker_signature.hex() + "08746573742e6a7774"
    )
    assert cvm_root.attestation_nonce(payload, binding) == "TUlW5QIbVxjiomgeFYQASwvhk8K6fKoM6Ab-BiEcsaQ"


def test_cvm_root_client_rejects_wrong_label_before_network() -> None:
    payload = sample_payload()
    bad = vrf_aptos.ThresholdVrfRequestPayload(
        keypair_id=payload.keypair_id,
        epoch=payload.epoch,
        contract_id=payload.contract_id,
        label=b"unrelated",
        account_address=payload.account_address,
        response_enc_key=payload.response_enc_key,
    )
    _ek, dk = pke.keygen()
    with pytest.raises(ValueError, match="c26t/root/v1"):
        cvm_root.derive_core(None, None, bad, sample_binding(bad), "jwt", dk)  # type: ignore[arg-type]


def test_cvm_root_client_rejects_response_key_mismatch_before_network() -> None:
    _ek, dk = pke.keygen()
    with pytest.raises(ValueError, match="does not match"):
        cvm_root.derive_core(None, None, sample_payload(), sample_binding(sample_payload()), "jwt", dk)  # type: ignore[arg-type]


def test_cvm_root_nonce_changes_with_tls_key_and_worker_signature() -> None:
    payload = sample_payload()
    binding = sample_binding(payload)
    changed_tls = cvm_root.CvmRootBinding(
        binding.worker_addr, binding.worker_pk, bytes([8] * 32), binding.worker_signature
    )
    changed_signature = cvm_root.CvmRootBinding(
        binding.worker_addr, binding.worker_pk, binding.tls_spki_sha256, bytes([9] * 64)
    )
    assert cvm_root.attestation_nonce(payload, binding) != cvm_root.attestation_nonce(payload, changed_tls)
    assert cvm_root.attestation_nonce(payload, binding) != cvm_root.attestation_nonce(payload, changed_signature)
