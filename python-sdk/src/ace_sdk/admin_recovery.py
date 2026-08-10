# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Disaster-recovery master-secret reconstruction helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from urllib.request import Request, urlopen

from aptos_sdk.account_address import AccountAddress

from ace_sdk import group, pke, sig, t_ibe
from ace_sdk._internal.common import fetch_tibe_public_key, get_chain_reader
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk.bcs import Deserializer, Serializer, serialize_account_address
from ace_sdk.group import bls12381g1, bls12381g2
from ace_sdk.vss.dealing import lagrange_at_zero

SCHEME_RECONSTRUCTION = 3


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
class ReconstructionRequestPayload:
    chain_id: int
    ace_addr: AccountAddress
    keypair_id: AccountAddress
    epoch: int
    eph_pke_ek: pke.EncryptionKey

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.chain_id)
        serialize_account_address(serializer, self.ace_addr)
        serialize_account_address(serializer, self.keypair_id)
        serializer.serialize_u64(self.epoch)
        self.eph_pke_ek.serialize(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()


@dataclass(frozen=True)
class ReconstructionRequest:
    payload: ReconstructionRequestPayload
    signature: sig.Signature

    def serialize(self, serializer: Serializer) -> None:
        self.payload.serialize(serializer)
        self.signature.serialize(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()


@dataclass(frozen=True)
class ReconstructionResponse:
    eval_point: int
    group_scheme: int
    scalar: bytes


class WorkerRequest:
    SCHEME_RECONSTRUCTION = SCHEME_RECONSTRUCTION

    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner

    @staticmethod
    def new_reconstruction(request: ReconstructionRequest) -> "WorkerRequest":
        return WorkerRequest(SCHEME_RECONSTRUCTION, request)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        self.inner.serialize(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


@dataclass(frozen=True)
class ReconstructResult:
    secret_hex: str
    epoch: int
    shares_used: int
    verified: bool | None


def parse_reconstruction_response(data: bytes) -> ReconstructionResponse:
    deserializer = Deserializer(data)
    response = ReconstructionResponse(
        eval_point=deserializer.deserialize_u64(),
        group_scheme=deserializer.deserialize_u8(),
        scalar=deserializer.deserialize_fixed_bytes(32),
    )
    if deserializer.remaining() != 0:
        raise ValueError("parse_reconstruction_response: trailing bytes")
    return response


def _post_hex(endpoint: str, body_hex: str, timeout: float) -> str:
    request = Request(endpoint, data=body_hex.encode("utf-8"), method="POST")
    with urlopen(request, timeout=timeout) as response:
        status = getattr(response, "status", 200)
        body = response.read().decode("utf-8").strip()
    if status < 200 or status >= 300:
        raise RuntimeError(f"HTTP {status}: {body[:120]}")
    return body


def _verify_secret_against_mpk(
    ace_deployment: AceDeployment,
    keypair_id: AccountAddress,
    secret: int,
    tibe_scheme: int | None,
) -> bool | None:
    scheme = (
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
        if tibe_scheme is None
        else tibe_scheme
    )
    mpk_result = fetch_tibe_public_key(
        ace_deployment=ace_deployment,
        keypair_id=keypair_id,
        tibe_scheme=scheme,
        context="reconstruct_secret",
    )
    if not mpk_result.is_ok or mpk_result.ok_value is None:
        return None
    mpk = mpk_result.ok_value
    if scheme == t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
        base = group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.base_point))
        expected = group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk))
        scalar = group.Scalar(
            group.SCHEME_BLS12381G2,
            bls12381g2.PrivateScalar.from_bigint(secret).unwrap_or_throw(
                ValueError("reconstruct_secret: secret scalar out of range")
            ),
        )
        return base.scale(scalar).equals(expected)
    if scheme == t_ibe.SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
        base = group.Element.from_bls12381_g1(bls12381g1.PublicPoint(mpk.inner.base_point))
        expected = group.Element.from_bls12381_g1(bls12381g1.PublicPoint(mpk.inner.pk))
        scalar = group.Scalar(
            group.SCHEME_BLS12381G1,
            bls12381g1.PrivateScalar.from_bigint(secret).unwrap_or_throw(
                ValueError("reconstruct_secret: secret scalar out of range")
            ),
        )
        return base.scale(scalar).equals(expected)
    return None


def reconstruct_secret(
    ace_deployment: AceDeployment,
    keypair_id: AccountAddress,
    signing_key: sig.SigningKey,
    chain_id: int,
    tibe_scheme: int | None = None,
    per_node_timeout_ms: int = 8000,
    log: Callable[[str], None] | None = None,
) -> ReconstructResult:
    """Collect raw Shamir shares from workers and reconstruct the master secret."""

    log_fn = log or (lambda _msg: None)
    reader = get_chain_reader(ace_deployment)
    network_state = reader.network_state()
    epoch = network_state.epoch
    threshold = network_state.cur_threshold
    cur_nodes = network_state.cur_nodes

    eph_encryption_key, eph_decryption_key = pke.keygen()
    payload = ReconstructionRequestPayload(
        chain_id=chain_id,
        ace_addr=ace_deployment.contract_addr,
        keypair_id=keypair_id,
        epoch=epoch,
        eph_pke_ek=eph_encryption_key,
    )
    request = ReconstructionRequest(payload, signing_key.sign(payload.to_bytes()))
    request_bytes = WorkerRequest.new_reconstruction(request).to_bytes()

    log_fn(
        "Requesting shares for keypair "
        f"{_addr_key(keypair_id)} at epoch {epoch} from {len(cur_nodes)} nodes "
        f"(threshold {threshold})..."
    )

    points: list[tuple[int, int]] = []
    timeout_s = per_node_timeout_ms / 1000
    for node_addr in cur_nodes:
        node_key = _addr_key(node_addr)
        try:
            endpoint = reader.worker_endpoint(node_key)
            node_enc_key = reader.worker_enc_key(node_key)
            enc_req_hex = pke.encrypt(node_enc_key, request_bytes).to_hex()
            response_hex = _post_hex(endpoint, enc_req_hex, timeout_s)
            response_ct = pke.Ciphertext.from_hex(response_hex).unwrap_or_throw(
                ValueError(f"reconstruct_secret: response ciphertext parse failed for {node_key}")
            )
            plain = pke.decrypt(eph_decryption_key, response_ct).unwrap_or_throw(
                ValueError(f"reconstruct_secret: response decryption failed for {node_key}")
            )
            response = parse_reconstruction_response(plain)
            points.append((response.eval_point, int.from_bytes(response.scalar, "little")))
            log_fn(f"  node {node_key}: OK (eval_point={response.eval_point})")
        except Exception as caught:  # noqa: BLE001 - collect enough shares from remaining nodes
            log_fn(f"  node {node_key}: error - {caught}")

    unique: dict[int, tuple[int, int]] = {}
    for point in points:
        unique[point[0]] = point
    unique_points = list(unique.values())
    if len(unique_points) < threshold:
        raise RuntimeError(
            f"reconstruct_secret: collected {len(unique_points)} shares, need threshold {threshold}"
        )

    secret = lagrange_at_zero(unique_points)
    secret_hex = "0x" + secret.to_bytes(32, "little").hex()

    try:
        verified = _verify_secret_against_mpk(ace_deployment, keypair_id, secret, tibe_scheme)
    except Exception:  # noqa: BLE001 - verification is best-effort, matching ts-sdk
        verified = None

    return ReconstructResult(
        secret_hex=secret_hex,
        epoch=epoch,
        shares_used=len(unique_points),
        verified=verified,
    )


__all__ = [
    "ReconstructResult",
    "ReconstructionRequest",
    "ReconstructionRequestPayload",
    "ReconstructionResponse",
    "SCHEME_RECONSTRUCTION",
    "WorkerRequest",
    "parse_reconstruction_response",
    "reconstruct_secret",
]
