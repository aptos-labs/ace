# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0

import io
from urllib.error import HTTPError

from aptos_sdk.account_address import AccountAddress
import pytest

from ace_sdk import (
    admin_recovery,
    group,
    network,
    pke,
    sig,
)
from ace_sdk._internal import http as internal_http
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk.bcs import Serializer
from ace_sdk.result import Result

from tests.helpers import AdminRecoveryReader, BytesResponse


def test_admin_recovery_wire_formats_match_ts_rust_known_answer() -> None:
    eph_ek = pke.EncryptionKey.from_hex("0120" + "07" * 32).unwrap_or_throw("ek")
    payload = admin_recovery.ReconstructionRequestPayload(
        chain_id=4,
        ace_addr=AccountAddress.from_str("0x" + "09" * 32),
        keypair_id=AccountAddress.from_str("0x" + "ab" * 32),
        epoch=5,
        eph_pke_ek=eph_ek,
    )

    expected = (
        "04"
        + "09" * 32
        + "ab" * 32
        + "0500000000000000"
        + "0120"
        + "07" * 32
    )
    assert payload.to_bytes().hex() == expected

    signing_key = sig.SigningKey(sig.SCHEME_ED25519, bytes(range(32)))
    request = admin_recovery.ReconstructionRequest(payload, signing_key.sign(payload.to_bytes()))
    worker_bytes = admin_recovery.WorkerRequest.new_reconstruction(request).to_bytes()
    assert worker_bytes[0] == admin_recovery.WorkerRequest.SCHEME_RECONSTRUCTION == 3
    assert signing_key.public_key().verify(payload.to_bytes(), request.signature)

    response_serializer = Serializer()
    response_serializer.serialize_u64(3)
    response_serializer.serialize_u8(group.SCHEME_BLS12381G2)
    response_serializer.serialize_fixed_bytes((123456789).to_bytes(32, "little"))
    response = admin_recovery.parse_reconstruction_response(response_serializer.to_bytes())
    assert response.eval_point == 3
    assert response.group_scheme == group.SCHEME_BLS12381G2
    assert int.from_bytes(response.scalar, "little") == 123456789
    try:
        admin_recovery.parse_reconstruction_response(response_serializer.to_bytes() + b"\x00")
    except ValueError as err:
        assert "trailing bytes" in str(err)
    else:
        raise AssertionError("expected trailing bytes rejection")


def test_admin_recovery_worker_http_errors_include_response_body(monkeypatch) -> None:
    def fake_urlopen(request, timeout):
        del timeout
        raise HTTPError(
            request.full_url,
            500,
            "Internal Server Error",
            {},
            io.BytesIO(b"reconstruction failed"),
        )

    monkeypatch.setattr(internal_http, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="HTTP 500: reconstruction failed"):
        internal_http.post_hex("https://node.example/", "00", 1.0)


def test_admin_recovery_reconstruct_secret_with_fake_workers(monkeypatch) -> None:
    nodes = [AccountAddress.from_str("0x1"), AccountAddress.from_str("0x2")]
    keypair_id = AccountAddress.from_str("0x" + "ab" * 32)
    ace_deployment = AceDeployment(
        "https://unused.example/v1",
        AccountAddress.from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000ace"
        ),
    )
    node_enc_key, node_dec_key = pke.keygen()
    eph_ek, eph_dk = pke.keygen()
    reader = AdminRecoveryReader(
        nodes=nodes,
        node_enc_key=node_enc_key,
        network_state_value=network.State(
            epoch=7,
            epoch_start_time_micros=0,
            epoch_duration_micros=0,
            cur_nodes=nodes,
            cur_threshold=2,
            secrets=[],
            proposals=[],
            epoch_change_info=None,
        ),
    )

    requests_seen = []

    def encrypted_response(eval_point: int, scalar: int) -> str:
        serializer = Serializer()
        serializer.serialize_u64(eval_point)
        serializer.serialize_u8(group.SCHEME_BLS12381G2)
        serializer.serialize_fixed_bytes(scalar.to_bytes(32, "little"))
        return pke.encrypt(eph_ek, serializer.to_bytes()).to_hex()

    def fake_urlopen(request, timeout):
        del timeout
        requests_seen.append(request)
        body = request.data.decode("utf-8")
        ciphertext = pke.Ciphertext.from_hex(body).unwrap_or_throw("request ct")
        plain = pke.decrypt(node_dec_key, ciphertext).unwrap_or_throw("request plain")
        assert plain[0] == admin_recovery.SCHEME_RECONSTRUCTION
        if request.full_url == "https://node-1.example/":
            return BytesResponse(encrypted_response(1, 47).encode("utf-8"))
        return BytesResponse(encrypted_response(2, 52).encode("utf-8"))

    monkeypatch.setattr(admin_recovery, "get_chain_reader", lambda _deployment: reader)
    monkeypatch.setattr(admin_recovery.pke, "keygen", lambda: (eph_ek, eph_dk))
    monkeypatch.setattr(admin_recovery, "fetch_tibe_public_key", lambda **_kwargs: Result.Err("skip"))
    monkeypatch.setattr(internal_http, "urlopen", fake_urlopen)

    result = admin_recovery.reconstruct_secret(
        ace_deployment=ace_deployment,
        keypair_id=keypair_id,
        signing_key=sig.SigningKey(sig.SCHEME_ED25519, bytes(range(32))),
        chain_id=4,
    )

    assert result.secret_hex == "0x" + (42).to_bytes(32, "little").hex()
    assert result.epoch == 7
    assert result.shares_used == 2
    assert result.verified is None
    assert len(requests_seen) == 2
