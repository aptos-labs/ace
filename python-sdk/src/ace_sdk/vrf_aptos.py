# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Aptos threshold-VRF helpers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from aptos_sdk.account_address import AccountAddress
from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.optimized_bls12_381 import add as _g1_add

from ace_sdk import group, pke
from ace_sdk._internal.common import ContractID, get_chain_reader
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk.bcs import Deserializer, Serializer, deserialize_account_address, serialize_account_address
from ace_sdk.decryption import AptosProofOfPermission, fetch_current_session_pks
from ace_sdk.group import bls12381g1
from ace_sdk.group.bls12381_pairing import (
    fp12_eq,
    g1_jacobian_to_affine,
    g2_jacobian_to_affine,
    pairing,
)
from ace_sdk.group.bls12381fr import fr_inv, fr_mod, fr_mul

PURPOSE = "ace.threshold-vrf.derive.v1"
DST_THRESHOLD_VRF_G1 = b"ACE_THRESHOLD_VRF_BLS12381G1/HASH_TO_CURVE/v1"
SCHEME_THRESHOLD_VRF = 2


def _addr_key(addr: str | AccountAddress) -> str:
    if isinstance(addr, str):
        account_addr = AccountAddress.from_str(addr)
    else:
        account_addr = addr
    return "0x" + account_addr.address.hex()


def _hex_string_to_bytes(hex_str: str) -> bytes:
    h = hex_str.strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return bytes.fromhex(h)


@dataclass(frozen=True)
class ThresholdVrfRequestPayload:
    keypair_id: AccountAddress
    epoch: int
    contract_id: ContractID
    label: bytes
    account_address: AccountAddress
    response_enc_key: pke.EncryptionKey

    def serialize(self, serializer: Serializer) -> None:
        serialize_account_address(serializer, self.keypair_id)
        serializer.serialize_u64(self.epoch)
        self.contract_id.serialize(serializer)
        serializer.serialize_bytes(self.label)
        serialize_account_address(serializer, self.account_address)
        self.response_enc_key.serialize(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "ThresholdVrfRequestPayload":
        return ThresholdVrfRequestPayload(
            keypair_id=deserialize_account_address(deserializer),
            epoch=deserializer.deserialize_u64(),
            contract_id=ContractID.deserialize(deserializer).unwrap_or_throw(
                ValueError("ThresholdVrfRequestPayload.deserialize: contractId")
            ),
            label=deserializer.deserialize_bytes(),
            account_address=deserialize_account_address(deserializer),
            response_enc_key=pke.EncryptionKey.deserialize(deserializer).unwrap_or_throw(
                ValueError("ThresholdVrfRequestPayload.deserialize: responseEncKey")
            ),
        )

    @staticmethod
    def from_bytes(data: bytes) -> "ThresholdVrfRequestPayload":
        deserializer = Deserializer(data)
        payload = ThresholdVrfRequestPayload.deserialize(deserializer)
        if deserializer.remaining() != 0:
            raise ValueError("ThresholdVrfRequestPayload.from_bytes: trailing bytes")
        return payload

    @staticmethod
    def from_hex(hex_str: str) -> "ThresholdVrfRequestPayload":
        return ThresholdVrfRequestPayload.from_bytes(_hex_string_to_bytes(hex_str))

    def to_webauthn_challenge(self) -> bytes:
        seed = hashlib.sha3_256(b"ACE::ThresholdVrfRequestPayload").digest()
        return hashlib.sha3_256(seed + self.to_bytes()).digest()

    def to_vrf_input_bytes(self) -> bytes:
        serializer = Serializer()
        serializer.serialize_str("ace.threshold-vrf.input.v1")
        serialize_account_address(serializer, self.keypair_id)
        self.contract_id.serialize(serializer)
        serialize_account_address(serializer, self.account_address)
        serializer.serialize_bytes(self.label)
        return serializer.to_bytes()


@dataclass(frozen=True)
class ThresholdVrfRequest:
    payload: ThresholdVrfRequestPayload
    auth_proof: AptosProofOfPermission

    def serialize(self, serializer: Serializer) -> None:
        self.payload.serialize(serializer)
        self.auth_proof.serialize(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()


@dataclass(frozen=True)
class ThresholdVrfShare:
    eval_point: int
    share: group.Element

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u64(self.eval_point)
        self.share.serialize(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "ThresholdVrfShare":
        return ThresholdVrfShare(
            eval_point=deserializer.deserialize_u64(),
            share=group.Element.deserialize(deserializer).unwrap_or_throw(
                ValueError("ThresholdVrfShare.deserialize: parse share")
            ),
        )

    @staticmethod
    def from_bytes(data: bytes) -> "ThresholdVrfShare":
        deserializer = Deserializer(data)
        share = ThresholdVrfShare.deserialize(deserializer)
        if deserializer.remaining() != 0:
            raise ValueError("ThresholdVrfShare.from_bytes: trailing bytes")
        return share


class _WorkerRequest:
    def __init__(self, request: ThresholdVrfRequest) -> None:
        self.request = request

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        serializer.serialize_u8(SCHEME_THRESHOLD_VRF)
        self.request.serialize(serializer)
        return serializer.to_bytes()


def _post_hex(endpoint: str, body_hex: str, timeout: float) -> str:
    request = Request(endpoint, data=body_hex.encode("utf-8"), method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            body = response.read().decode("utf-8", errors="replace").strip()
    except HTTPError as err:
        body = err.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"HTTP {err.code}: {body[:120]}") from err
    if status < 200 or status >= 300:
        raise RuntimeError(f"HTTP {status}: {body[:120]}")
    return body


def verify_threshold_vrf_share(
    share: ThresholdVrfShare,
    sdk_idx: int,
    session_pks,
    vrf_input: bytes,
    node_addr: str = "",
    endpoint: str = "",
    log: Callable[[str], None] | None = None,
) -> bool:
    log_fn = log or (lambda _msg: None)
    expected_eval = sdk_idx + 1
    if share.eval_point != expected_eval:
        log_fn(
            f"  [tVRF] worker {node_addr} ({endpoint}): evalPoint mismatch "
            f"(got {share.eval_point}, expected {expected_eval})"
        )
        return False
    if share.share.scheme != group.SCHEME_BLS12381G1:
        log_fn(
            f"  [tVRF] worker {node_addr} ({endpoint}): share scheme mismatch "
            f"(got {share.share.scheme}, expected G1)"
        )
        return False
    if session_pks.base_point.scheme != group.SCHEME_BLS12381G2:
        raise ValueError(
            "ACE.VRF_Aptos: threshold VRF requires a G2 keypair, "
            f"got basePoint scheme {session_pks.base_point.scheme}"
        )
    share_pk = session_pks.share_pks[sdk_idx]
    if share_pk.scheme != group.SCHEME_BLS12381G2:
        log_fn(
            f"  [tVRF] worker {node_addr} ({endpoint}): sharePk scheme mismatch "
            f"(got {share_pk.scheme}, expected G2)"
        )
        return False

    input_point = hash_to_G1(vrf_input, DST_THRESHOLD_VRF_G1, hashlib.sha256)
    lhs = pairing(
        g1_jacobian_to_affine(share.share.inner.pt),
        g2_jacobian_to_affine(session_pks.base_point.inner.pt),
    )
    rhs = pairing(g1_jacobian_to_affine(input_point), g2_jacobian_to_affine(share_pk.inner.pt))
    if not fp12_eq(lhs, rhs):
        log_fn(f"  [tVRF] worker {node_addr} ({endpoint}): share failed verification")
        return False
    return True


def reconstruct_threshold_vrf(shares: list[ThresholdVrfShare]) -> bytes:
    if not shares:
        raise ValueError("ACE.VRF_Aptos.reconstruct_threshold_vrf: no shares")
    xs = [fr_mod(share.eval_point) for share in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("ACE.VRF_Aptos.reconstruct_threshold_vrf: duplicate evalPoint")

    full = None
    for i, share in enumerate(shares):
        lam = 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            lam = fr_mul(lam, fr_mul(fr_mod(-xj), fr_inv(fr_mod(xs[i] - xj))))
        if lam == 0:
            continue
        scaled = share.share.inner.scale(bls12381g1.PrivateScalar.from_bigint(lam).unwrap_or_throw("lambda")).pt
        full = scaled if full is None else _g1_add(full, scaled)
    if full is None:
        raise ValueError("ACE.VRF_Aptos.reconstruct_threshold_vrf: all coefficients were zero")

    point_bytes = bls12381g1.PublicPoint(full).raw_bytes()
    seed = hashlib.sha3_256(b"ACE::ThresholdVrfOutput").digest()
    return hashlib.sha3_256(seed + point_bytes).digest()


def derive_core(
    ace_deployment: AceDeployment,
    network_state,
    payload: ThresholdVrfRequestPayload,
    auth_proof: AptosProofOfPermission,
    response_decryption_key: pke.DecryptionKey,
    per_node_timeout_ms: int = 8000,
    log: Callable[[str], None] | None = None,
) -> bytes:
    reader = get_chain_reader(ace_deployment)
    log_fn = log or (lambda _msg: None)
    session_pks = fetch_current_session_pks(ace_deployment, network_state, payload.keypair_id)
    if len(session_pks.share_pks) != len(network_state.cur_nodes):
        raise ValueError(
            "ACE.VRF_Aptos.derive_core: sharePks length "
            f"{len(session_pks.share_pks)} != curNodes length {len(network_state.cur_nodes)}"
        )
    if session_pks.base_point.scheme != group.SCHEME_BLS12381G2:
        raise ValueError(
            "ACE.VRF_Aptos.derive_core: threshold VRF requires a G2 keypair, "
            f"got basePoint scheme {session_pks.base_point.scheme}"
        )
    request_bytes = _WorkerRequest(ThresholdVrfRequest(payload, auth_proof)).to_bytes()
    vrf_input = payload.to_vrf_input_bytes()
    shares: list[ThresholdVrfShare] = []
    errors: list[str] = []
    saw_not_implemented = False
    timeout_s = per_node_timeout_ms / 1000

    for sdk_idx, node_addr in enumerate(network_state.cur_nodes):
        node_key = _addr_key(node_addr)
        try:
            endpoint = reader.worker_endpoint(node_key)
            node_enc_key = reader.worker_enc_key(node_key)
            enc_req_hex = pke.encrypt(node_enc_key, request_bytes).to_hex()
            response_hex = _post_hex(endpoint, enc_req_hex, timeout_s)
            response_ct = pke.Ciphertext.from_hex(response_hex).unwrap_or_throw(
                ValueError("response ciphertext parse failed")
            )
            share_bytes = pke.decrypt(response_decryption_key, response_ct).unwrap_or_throw(
                ValueError("response decryption failed")
            )
            share = ThresholdVrfShare.from_bytes(share_bytes)
            if not verify_threshold_vrf_share(
                share, sdk_idx, session_pks, vrf_input, node_key, endpoint, log_fn
            ):
                errors.append(f"{node_key}: invalid tVRF share")
                continue
            shares.append(share)
            log_fn(f"  [tVRF] worker {node_key} ({endpoint}): OK")
        except RuntimeError as caught:
            if "HTTP 501" in str(caught):
                saw_not_implemented = True
            errors.append(f"{node_key}: {caught}")
            log_fn(f"  [tVRF] worker {node_key}: error - {caught}")
        except Exception as caught:  # noqa: BLE001 - keep collecting from peers
            errors.append(f"{node_key}: {caught}")
            log_fn(f"  [tVRF] worker {node_key}: error - {caught}")

    if saw_not_implemented:
        raise RuntimeError("ACE.VRF_Aptos.derive_core: threshold VRF worker handler is not implemented yet")
    if len(shares) >= network_state.cur_threshold:
        return reconstruct_threshold_vrf(shares[: network_state.cur_threshold])
    raise RuntimeError(
        "ACE.VRF_Aptos.derive_core: need "
        f"{network_state.cur_threshold} valid shares, got {len(shares)} ({'; '.join(errors)})"
    )


__all__ = [
    "AptosProofOfPermission",
    "DST_THRESHOLD_VRF_G1",
    "PURPOSE",
    "SCHEME_THRESHOLD_VRF",
    "ThresholdVrfRequest",
    "ThresholdVrfRequestPayload",
    "ThresholdVrfShare",
    "derive_core",
    "reconstruct_threshold_vrf",
    "verify_threshold_vrf_share",
]
