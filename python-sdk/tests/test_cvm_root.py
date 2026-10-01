# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0

from aptos_sdk.account_address import AccountAddress
import pytest

from ace_sdk import ContractID, cvm_root, pke, vrf_aptos


def sample_payload() -> vrf_aptos.ThresholdVrfRequestPayload:
    return vrf_aptos.ThresholdVrfRequestPayload(
        keypair_id=AccountAddress.from_str("0x" + "01" * 32),
        epoch=7,
        contract_id=ContractID.new_aptos(
            119,
            AccountAddress.from_str("0x" + "02" * 32),
            "c26t_vault",
        ),
        label=cvm_root.ROOT_LABEL,
        account_address=AccountAddress.from_str("0x" + "03" * 32),
        response_enc_key=pke.EncryptionKey.from_hex("0120" + "04" * 32).unwrap_or_throw("ek"),
    )


def test_cvm_root_bcs_and_attestation_nonce_known_answer() -> None:
    payload = sample_payload()
    assert cvm_root.CvmRootVrfRequest(payload, "test.jwt").to_bytes().hex() == (
        "04" + "01" * 32 + "0700000000000000" + "00" + "77" + "02" * 32
        + "0a633236745f7661756c74" + "0c633236742f726f6f742f7631"
        + "03" * 32 + "0120" + "04" * 32 + "08746573742e6a7774"
    )
    assert cvm_root.attestation_nonce(payload) == "V5aLE5kkgTxD2AaOrc1IoUbpslJFUPfsnprk0tJUqCU"


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
        cvm_root.derive_core(None, None, bad, "jwt", dk)  # type: ignore[arg-type]


def test_cvm_root_client_rejects_response_key_mismatch_before_network() -> None:
    _ek, dk = pke.keygen()
    with pytest.raises(ValueError, match="does not match"):
        cvm_root.derive_core(None, None, sample_payload(), "jwt", dk)  # type: ignore[arg-type]
