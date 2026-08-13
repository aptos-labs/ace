# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0

import hashlib
import io
from urllib.error import HTTPError

from aptos_sdk.account_address import AccountAddress
from py_ecc.bls.hash_to_curve import hash_to_G1
import pytest

from ace_sdk import (
    decryption,
    group,
    network,
    pke,
    t_ibe,
    vrf_aptos,
)
from ace_sdk._internal import http as internal_http
from ace_sdk._internal.common import ContractID
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk._internal import discovery
from ace_sdk.group import bls12381g1, bls12381g2

from tests.helpers import BytesResponse, SessionPksFixture, SingleNodeReader


def test_vrf_aptos_payload_share_verify_and_reconstruct() -> None:
    response_ek = pke.EncryptionKey.from_hex("0120" + "07" * 32).unwrap_or_throw("ek")
    keypair_id = AccountAddress.from_str("0x" + "ab" * 32)
    account = AccountAddress.from_str("0x" + "cd" * 32)
    contract_id = ContractID.new_aptos(
        4, AccountAddress.from_str("0x" + "ef" * 32), "presigned_access"
    )
    payload = vrf_aptos.ThresholdVrfRequestPayload(
        keypair_id=keypair_id,
        epoch=5,
        contract_id=contract_id,
        label=b"label-1",
        account_address=account,
        response_enc_key=response_ek,
    )
    restored = vrf_aptos.ThresholdVrfRequestPayload.from_hex("0x" + payload.to_hex())

    assert restored.to_bytes() == payload.to_bytes()
    assert payload.to_webauthn_challenge().hex() == (
        "9808d30bb5e86a74b8a4823055747f23ca88e5b2a3d21648e663c41d6a019f1c"
    )
    assert payload.to_vrf_input_bytes().startswith(bytes([len("ace.threshold-vrf.input.v1")]))

    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")
    input_point = bls12381g1.PublicPoint(
        hash_to_G1(payload.to_vrf_input_bytes(), vrf_aptos.DST_THRESHOLD_VRF_G1, hashlib.sha256)
    )
    scalar = bls12381g1.PrivateScalar.from_bigint(msk.inner.scalar).unwrap_or_throw("scalar")
    share = vrf_aptos.ThresholdVrfShare(
        eval_point=1,
        share=group.Element.from_bls12381_g1(input_point.scale(scalar)),
    )
    session = discovery.SessionPks(
        base_point=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.base_point)),
        share_pks=[group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk))],
        result_pk=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk)),
    )

    assert vrf_aptos.ThresholdVrfShare.from_bytes(share.to_bytes()).to_bytes() == share.to_bytes()
    assert vrf_aptos.verify_threshold_vrf_share(
        share, 0, session, payload.to_vrf_input_bytes()
    )
    expected = hashlib.sha3_256(
        hashlib.sha3_256(b"ACE::ThresholdVrfOutput").digest() + share.share.inner.raw_bytes()
    ).digest()
    assert vrf_aptos.reconstruct_threshold_vrf([share]) == expected


def test_vrf_aptos_derive_core_with_fake_worker(monkeypatch) -> None:
    node = AccountAddress.from_str("0x1")
    account = AccountAddress.from_str("0x2")
    keypair_id = AccountAddress.from_str("0x" + "11" * 32)
    contract_id = ContractID.new_aptos(42, AccountAddress.from_str("0x1"), "example")
    response_ek, response_dk = pke.keygen()
    node_ek, node_dk = pke.keygen()
    ace_deployment = AceDeployment(
        "https://unused.example/v1",
        AccountAddress.from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000ace"
        ),
    )
    payload = vrf_aptos.ThresholdVrfRequestPayload(
        keypair_id=keypair_id,
        epoch=8,
        contract_id=contract_id,
        label=b"vrf-label",
        account_address=account,
        response_enc_key=response_ek,
    )
    auth_proof = vrf_aptos.AptosProofOfPermission.new_ed25519(
        user_addr=account,
        public_key_bytes=bytes(32),
        signature_bytes=bytes(64),
        full_message="0x" + payload.to_hex(),
    )
    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")
    state = network.State(
        epoch=8,
        epoch_start_time_micros=0,
        epoch_duration_micros=0,
        cur_nodes=[node],
        cur_threshold=1,
        secrets=[
            network.SecretInfo(
                current_session=keypair_id,
                keypair_id=keypair_id,
                scheme=network.PRIMITIVE_BLS12381_THRESHOLD_VRF,
                expected_usage=network.USAGE_BLS12381_THRESHOLD_VRF,
                note="vrf",
            )
        ],
        proposals=[],
        epoch_change_info=None,
    )
    session = discovery.SessionPks(
        base_point=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.base_point)),
        share_pks=[group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk))],
        result_pk=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk)),
    )
    input_point = bls12381g1.PublicPoint(
        hash_to_G1(payload.to_vrf_input_bytes(), vrf_aptos.DST_THRESHOLD_VRF_G1, hashlib.sha256)
    )
    scalar = bls12381g1.PrivateScalar.from_bigint(msk.inner.scalar).unwrap_or_throw("scalar")
    share = vrf_aptos.ThresholdVrfShare(
        eval_point=1,
        share=group.Element.from_bls12381_g1(input_point.scale(scalar)),
    )
    reader = SingleNodeReader(
        node=node,
        node_enc_key=node_ek,
        session_pks=SessionPksFixture(keypair_id, session),
    )

    seen_request = []

    def fake_urlopen(request, timeout):
        del timeout
        request_ct = pke.Ciphertext.from_hex(request.data.decode("utf-8")).unwrap_or_throw("ct")
        plain = pke.decrypt(node_dk, request_ct).unwrap_or_throw("plain")
        seen_request.append(plain)
        return BytesResponse(pke.encrypt(response_ek, share.to_bytes()).to_hex().encode("utf-8"))

    monkeypatch.setattr(vrf_aptos, "get_chain_reader", lambda _deployment: reader)
    monkeypatch.setattr(decryption, "get_chain_reader", lambda _deployment: reader)
    monkeypatch.setattr(internal_http, "urlopen", fake_urlopen)

    output = vrf_aptos.derive_core(
        ace_deployment=ace_deployment,
        network_state=state,
        payload=payload,
        auth_proof=auth_proof,
        response_decryption_key=response_dk,
    )

    assert len(output) == 32
    assert seen_request[0][0] == vrf_aptos.SCHEME_THRESHOLD_VRF


def test_vrf_aptos_derive_core_reports_worker_not_implemented(monkeypatch) -> None:
    node = AccountAddress.from_str("0x1")
    account = AccountAddress.from_str("0x2")
    keypair_id = AccountAddress.from_str("0x" + "22" * 32)
    contract_id = ContractID.new_aptos(42, AccountAddress.from_str("0x1"), "example")
    response_ek, response_dk = pke.keygen()
    node_ek, _node_dk = pke.keygen()
    ace_deployment = AceDeployment(
        "https://unused.example/v1",
        AccountAddress.from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000ace"
        ),
    )
    payload = vrf_aptos.ThresholdVrfRequestPayload(
        keypair_id=keypair_id,
        epoch=8,
        contract_id=contract_id,
        label=b"vrf-label",
        account_address=account,
        response_enc_key=response_ek,
    )
    auth_proof = vrf_aptos.AptosProofOfPermission.new_ed25519(
        user_addr=account,
        public_key_bytes=bytes(32),
        signature_bytes=bytes(64),
        full_message="0x" + payload.to_hex(),
    )
    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")
    state = network.State(
        epoch=8,
        epoch_start_time_micros=0,
        epoch_duration_micros=0,
        cur_nodes=[node],
        cur_threshold=1,
        secrets=[
            network.SecretInfo(
                current_session=keypair_id,
                keypair_id=keypair_id,
                scheme=network.PRIMITIVE_BLS12381_THRESHOLD_VRF,
                expected_usage=network.USAGE_BLS12381_THRESHOLD_VRF,
                note="vrf",
            )
        ],
        proposals=[],
        epoch_change_info=None,
    )
    session = discovery.SessionPks(
        base_point=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.base_point)),
        share_pks=[group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk))],
        result_pk=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk)),
    )
    reader = SingleNodeReader(
        node=node,
        node_enc_key=node_ek,
        session_pks=SessionPksFixture(keypair_id, session),
    )

    def fake_urlopen(request, timeout):
        del timeout
        raise HTTPError(
            request.full_url,
            501,
            "Not Implemented",
            {},
            io.BytesIO(b"handler missing"),
        )

    monkeypatch.setattr(vrf_aptos, "get_chain_reader", lambda _deployment: reader)
    monkeypatch.setattr(decryption, "get_chain_reader", lambda _deployment: reader)
    monkeypatch.setattr(internal_http, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="threshold VRF worker handler is not implemented"):
        vrf_aptos.derive_core(
            ace_deployment=ace_deployment,
            network_state=state,
            payload=payload,
            auth_proof=auth_proof,
            response_decryption_key=response_dk,
        )
