# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0

from aptos_sdk.account_address import AccountAddress

from ace_sdk import (
    decryption,
    group,
    ibe_aptos,
    network,
    pke,
    t_ibe,
)
from ace_sdk._internal.common import ContractID, FullDecryptionDomain
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk._internal import http as internal_http
from ace_sdk._internal import discovery
from ace_sdk.group import bls12381g2

from tests.helpers import BytesResponse, SessionPksFixture, SingleNodeReader


def test_decryption_request_wire_formats_and_webauthn_challenge() -> None:
    eph_ek = pke.EncryptionKey.from_hex("0120" + "07" * 32).unwrap_or_throw("ek")
    keypair_id = AccountAddress.from_str("0x" + "ab" * 32)
    module_addr = AccountAddress.from_str("0x" + "09" * 32)
    contract_id = ContractID.new_aptos(4, module_addr, "m")
    payload = decryption.DecryptionRequestPayload(
        keypair_id=keypair_id,
        epoch=5,
        contract_id=contract_id,
        domain=b"label",
        ephemeral_enc_key=eph_ek,
    )

    expected = (
        "ab" * 32
        + "0500000000000000"
        + "00"
        + "04"
        + "09" * 32
        + "016d"
        + "056c6162656c"
        + "0120"
        + "07" * 32
    )
    assert payload.to_bytes().hex() == expected
    assert payload.to_webauthn_challenge().hex() == (
        "8b3d52f10fdbaf0aa78f966edf8ae21db10939bf7aca2c815626b825548006fa"
    )
    assert decryption.DecryptionRequestPayload.from_hex("0x" + expected).unwrap_or_throw(
        "payload"
    ).to_bytes() == payload.to_bytes()

    proof = decryption.ProofOfPermission.create_aptos_raw(b"\xaa\xbb")
    worker = decryption.WorkerRequest.new_decryption_basic_flow(
        payload, proof, t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).to_bytes()
    assert worker[0] == decryption.SCHEME_DECRYPTION_BASIC_FLOW
    assert worker.endswith(b"\x00\xaa\xbb\x01")

    custom = decryption.CustomFlowRequest(
        keypair_id=keypair_id,
        epoch=5,
        contract_id=contract_id,
        label=b"label",
        enc_pk=eph_ek,
        proof=decryption.CustomFlowProof.create_aptos(b"zk"),
    )
    custom_worker = decryption.WorkerRequest.new_decryption_custom_flow(
        custom, t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).to_bytes()
    assert custom_worker[0] == decryption.SCHEME_DECRYPTION_CUSTOM_FLOW
    assert custom_worker.endswith(b"\x00\x02zk\x01")


def test_decryption_core_fetches_verified_share_and_decrypts(monkeypatch) -> None:
    node = AccountAddress.from_str("0x1")
    keypair_id = AccountAddress.from_str("0x" + "cd" * 32)
    contract_id = ContractID.new_aptos(42, AccountAddress.from_str("0x1"), "example")
    fdd = FullDecryptionDomain(keypair_id, contract_id, b"object-id")
    plaintext = b"worker share decrypts"
    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")
    ciphertext = t_ibe.encrypt(mpk, fdd.to_bytes(), plaintext).unwrap_or_throw("encrypt")
    idk = t_ibe.extract(msk_scalar=msk.inner.scalar, identity=fdd.to_bytes()).unwrap_or_throw("idk")
    eph_ek, eph_dk = pke.keygen()
    node_ek, node_dk = pke.keygen()
    ace_deployment = AceDeployment(
        "https://unused.example/v1",
        AccountAddress.from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000ace"
        ),
    )
    state = network.State(
        epoch=9,
        epoch_start_time_micros=0,
        epoch_duration_micros=0,
        cur_nodes=[node],
        cur_threshold=1,
        secrets=[
            network.SecretInfo(
                current_session=keypair_id,
                keypair_id=keypair_id,
                scheme=network.PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD,
                expected_usage=network.USAGE_BFIBE_BLS12381_SHORTSIG_AEAD,
                note="ibe",
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
        network_state_value=state,
    )

    seen_request_plaintexts = []

    def fake_urlopen(request, timeout):
        del timeout
        request_ct = pke.Ciphertext.from_hex(request.data.decode("utf-8")).unwrap_or_throw("ct")
        request_plain = pke.decrypt(node_dk, request_ct).unwrap_or_throw("plain")
        seen_request_plaintexts.append(request_plain)
        return BytesResponse(pke.encrypt(eph_ek, idk.to_bytes()).to_hex().encode("utf-8"))

    monkeypatch.setattr(decryption, "get_chain_reader", lambda _deployment: reader)
    monkeypatch.setattr(internal_http, "urlopen", fake_urlopen)
    monkeypatch.setattr(ibe_aptos, "get_chain_reader", lambda _deployment: reader)

    request = decryption.DecryptionRequestPayload(
        keypair_id=fdd.keypair_id,
        epoch=state.epoch,
        contract_id=fdd.contract_id,
        domain=fdd.label,
        ephemeral_enc_key=eph_ek,
    )
    proof = decryption.ProofOfPermission.create_aptos_raw(b"proof")
    result = decryption.decrypt_core(
        ace_deployment=ace_deployment,
        network_state=state,
        request=request,
        proof=proof,
        ephemeral_decryption_key=eph_dk,
        ciphertext=ciphertext.to_bytes(),
    )

    assert result.unwrap_or_throw("decrypt") == plaintext
    assert seen_request_plaintexts[0][0] == decryption.SCHEME_DECRYPTION_BASIC_FLOW

    per_node = decryption.build_per_node_request_core(
        ace_deployment=ace_deployment,
        network_state=state,
        request=request,
        proof=proof,
        primitive=t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
        target_endpoint="https://node.example/",
    ).unwrap_or_throw("per-node")
    assert per_node.epoch == state.epoch
    assert per_node.sdk_idx == 0

    custom_result = ibe_aptos.decrypt_custom_flow(
        ace_deployment=ace_deployment,
        keypair_id=keypair_id,
        chain_id=42,
        module_addr=AccountAddress.from_str("0x1"),
        module_name="example",
        label=b"object-id",
        enc_pk=eph_ek.to_bytes(),
        enc_sk=eph_dk.to_bytes(),
        payload=b"custom-proof",
        ciphertext=ciphertext.to_bytes(),
    )

    assert custom_result.unwrap_or_throw("custom decrypt") == plaintext
    assert seen_request_plaintexts[-1][0] == decryption.SCHEME_DECRYPTION_CUSTOM_FLOW
