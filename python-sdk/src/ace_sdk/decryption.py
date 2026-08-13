# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Worker decryption request helpers and IDK-share collection."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Callable

from aptos_sdk.account_address import AccountAddress

from ace_sdk import pke, t_ibe
from ace_sdk._internal.common import ContractID, FullDecryptionDomain, get_chain_reader
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk._internal.http import post_hex as _post_hex
from ace_sdk.bcs import (
    Deserializer,
    Serializer,
    deserialize_account_address,
    serialize_account_address,
)
from ace_sdk.result import Result

SCHEME_DECRYPTION_BASIC_FLOW = 0
SCHEME_DECRYPTION_CUSTOM_FLOW = 1
SCHEME_THRESHOLD_VRF = 2
SCHEME_RECONSTRUCTION = 3


def _hex_string_to_bytes(hex_str: str) -> bytes:
    h = hex_str.strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return bytes.fromhex(h)


def _addr_key(addr: str | AccountAddress) -> str:
    if isinstance(addr, str):
        account_addr = AccountAddress.from_str(addr)
    else:
        account_addr = addr
    return "0x" + account_addr.address.hex()


def _serialize_inner(serializer: Serializer, inner: bytes | object) -> None:
    if isinstance(inner, (bytes, bytearray)):
        serializer.serialize_fixed_bytes(bytes(inner))
    else:
        inner.serialize(serializer)  # type: ignore[attr-defined]


@dataclass(frozen=True)
class AptosProofOfPermission:
    user_addr: AccountAddress
    public_key_scheme: int
    public_key_bytes: bytes
    signature_scheme: int
    signature_bytes: bytes
    full_message: str

    @staticmethod
    def new_ed25519(
        user_addr: AccountAddress,
        public_key_bytes: bytes,
        signature_bytes: bytes,
        full_message: str,
    ) -> "AptosProofOfPermission":
        return AptosProofOfPermission(user_addr, 0, public_key_bytes, 0, signature_bytes, full_message)

    def serialize(self, serializer: Serializer) -> None:
        serialize_account_address(serializer, self.user_addr)
        serializer.serialize_u8(self.public_key_scheme)
        serializer.serialize_bytes(self.public_key_bytes)
        serializer.serialize_u8(self.signature_scheme)
        serializer.serialize_bytes(self.signature_bytes)
        serializer.serialize_str(self.full_message)


@dataclass(frozen=True)
class ProofOfPermission:
    scheme: int
    inner: bytes | object

    SCHEME_APTOS = 0
    SCHEME_SOLANA = 1

    @staticmethod
    def create_aptos(
        user_addr: AccountAddress,
        public_key_bytes: bytes,
        signature_bytes: bytes,
        full_message: str,
    ) -> "ProofOfPermission":
        return ProofOfPermission(
            ProofOfPermission.SCHEME_APTOS,
            AptosProofOfPermission.new_ed25519(
                user_addr=user_addr,
                public_key_bytes=public_key_bytes,
                signature_bytes=signature_bytes,
                full_message=full_message,
            ),
        )

    @staticmethod
    def create_aptos_raw(inner_bcs: bytes) -> "ProofOfPermission":
        return ProofOfPermission(ProofOfPermission.SCHEME_APTOS, inner_bcs)

    @staticmethod
    def create_solana_raw(inner_bcs: bytes) -> "ProofOfPermission":
        return ProofOfPermission(ProofOfPermission.SCHEME_SOLANA, inner_bcs)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        _serialize_inner(serializer, self.inner)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


@dataclass(frozen=True)
class DecryptionRequestPayload:
    keypair_id: AccountAddress
    epoch: int
    contract_id: ContractID
    domain: bytes
    ephemeral_enc_key: pke.EncryptionKey

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["DecryptionRequestPayload"]:
        def task(_extra: dict) -> "DecryptionRequestPayload":
            keypair_id = deserialize_account_address(deserializer)
            epoch = deserializer.deserialize_u64()
            contract_id = ContractID.deserialize(deserializer).unwrap_or_throw(
                ValueError(
                    "ACE.DecryptionRequestPayload.deserialize failed with ContractID error"
                )
            )
            domain = deserializer.deserialize_bytes()
            ephemeral_enc_key = pke.EncryptionKey.deserialize(deserializer).unwrap_or_throw(
                ValueError(
                    "ACE.DecryptionRequestPayload.deserialize failed with ephemeralEncKey error"
                )
            )
            return DecryptionRequestPayload(
                keypair_id, epoch, contract_id, domain, ephemeral_enc_key
            )

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["DecryptionRequestPayload"]:
        def task(_extra: dict) -> "DecryptionRequestPayload":
            deserializer = Deserializer(data)
            request = DecryptionRequestPayload.deserialize(deserializer).unwrap_or_throw(
                ValueError("ACE.DecryptionRequestPayload.from_bytes failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("ACE.DecryptionRequestPayload.from_bytes failed with trailing bytes")
            return request

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["DecryptionRequestPayload"]:
        return DecryptionRequestPayload.from_bytes(_hex_string_to_bytes(hex_str))

    def serialize(self, serializer: Serializer) -> None:
        serialize_account_address(serializer, self.keypair_id)
        serializer.serialize_u64(self.epoch)
        self.contract_id.serialize(serializer)
        serializer.serialize_bytes(self.domain)
        self.ephemeral_enc_key.serialize(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    def to_webauthn_challenge(self) -> bytes:
        seed = hashlib.sha3_256(b"ACE::DecryptionRequestPayload").digest()
        return hashlib.sha3_256(seed + self.to_bytes()).digest()


@dataclass(frozen=True)
class CustomFlowProof:
    scheme: int
    aptos_payload: bytes | None = None
    solana_inner_scheme: int | None = None
    solana_txn_bytes: bytes | None = None

    SCHEME_APTOS = 0
    SCHEME_SOLANA = 1

    @staticmethod
    def create_aptos(payload: bytes) -> "CustomFlowProof":
        return CustomFlowProof(CustomFlowProof.SCHEME_APTOS, aptos_payload=payload)

    @staticmethod
    def create_solana(txn: bytes, inner_scheme: int) -> "CustomFlowProof":
        return CustomFlowProof(
            CustomFlowProof.SCHEME_SOLANA,
            solana_inner_scheme=inner_scheme,
            solana_txn_bytes=txn,
        )

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        if self.scheme == CustomFlowProof.SCHEME_APTOS:
            serializer.serialize_bytes(self.aptos_payload or b"")
        elif self.scheme == CustomFlowProof.SCHEME_SOLANA:
            if self.solana_inner_scheme is None or self.solana_txn_bytes is None:
                raise ValueError("CustomFlowProof.serialize: missing solana proof data")
            serializer.serialize_u8(self.solana_inner_scheme)
            serializer.serialize_bytes(self.solana_txn_bytes)
        else:
            raise ValueError(f"CustomFlowProof.serialize: unknown scheme {self.scheme}")


@dataclass(frozen=True)
class CustomFlowRequest:
    keypair_id: AccountAddress
    epoch: int
    contract_id: ContractID
    label: bytes
    enc_pk: pke.EncryptionKey
    proof: CustomFlowProof

    def serialize(self, serializer: Serializer) -> None:
        serialize_account_address(serializer, self.keypair_id)
        serializer.serialize_u64(self.epoch)
        self.contract_id.serialize(serializer)
        serializer.serialize_bytes(self.label)
        self.enc_pk.serialize(serializer)
        self.proof.serialize(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()


@dataclass(frozen=True)
class DecryptionBasicFlowRequest:
    request: DecryptionRequestPayload
    proof: ProofOfPermission
    tibe_scheme: int

    def serialize(self, serializer: Serializer) -> None:
        self.request.serialize(serializer)
        self.proof.serialize(serializer)
        serializer.serialize_u8(self.tibe_scheme)


@dataclass(frozen=True)
class DecryptionCustomFlowRequest:
    keypair_id: AccountAddress
    epoch: int
    contract_id: ContractID
    label: bytes
    enc_pk: pke.EncryptionKey
    proof: CustomFlowProof
    tibe_scheme: int

    @staticmethod
    def from_custom_request(
        custom_request: CustomFlowRequest, tibe_scheme: int
    ) -> "DecryptionCustomFlowRequest":
        return DecryptionCustomFlowRequest(
            keypair_id=custom_request.keypair_id,
            epoch=custom_request.epoch,
            contract_id=custom_request.contract_id,
            label=custom_request.label,
            enc_pk=custom_request.enc_pk,
            proof=custom_request.proof,
            tibe_scheme=tibe_scheme,
        )

    def serialize(self, serializer: Serializer) -> None:
        serialize_account_address(serializer, self.keypair_id)
        serializer.serialize_u64(self.epoch)
        self.contract_id.serialize(serializer)
        serializer.serialize_bytes(self.label)
        self.enc_pk.serialize(serializer)
        self.proof.serialize(serializer)
        serializer.serialize_u8(self.tibe_scheme)


class WorkerRequest:
    SCHEME_DECRYPTION_BASIC_FLOW = SCHEME_DECRYPTION_BASIC_FLOW
    SCHEME_DECRYPTION_CUSTOM_FLOW = SCHEME_DECRYPTION_CUSTOM_FLOW
    SCHEME_THRESHOLD_VRF = SCHEME_THRESHOLD_VRF
    SCHEME_RECONSTRUCTION = SCHEME_RECONSTRUCTION

    def __init__(self, scheme: int, inner: object) -> None:
        self.scheme = scheme
        self.inner = inner

    @staticmethod
    def new_decryption_basic_flow(
        request: DecryptionRequestPayload,
        proof: ProofOfPermission,
        tibe_scheme: int,
    ) -> "WorkerRequest":
        return WorkerRequest(
            SCHEME_DECRYPTION_BASIC_FLOW,
            DecryptionBasicFlowRequest(request, proof, tibe_scheme),
        )

    @staticmethod
    def new_decryption_custom_flow(
        custom_request: CustomFlowRequest, tibe_scheme: int
    ) -> "WorkerRequest":
        return WorkerRequest(
            SCHEME_DECRYPTION_CUSTOM_FLOW,
            DecryptionCustomFlowRequest.from_custom_request(custom_request, tibe_scheme),
        )

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        self.inner.serialize(serializer)  # type: ignore[attr-defined]

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


@dataclass(frozen=True)
class PerNodeRequest:
    enc_req_hex: str
    epoch: int
    sdk_idx: int


def fetch_network_state_and_build_request(
    ace_deployment: AceDeployment,
    full_decryption_domain: FullDecryptionDomain,
    ephemeral_encryption_key: pke.EncryptionKey,
) -> tuple[object, DecryptionRequestPayload]:
    network_state = get_chain_reader(ace_deployment).network_state()
    request = DecryptionRequestPayload(
        keypair_id=full_decryption_domain.keypair_id,
        epoch=network_state.epoch,
        contract_id=full_decryption_domain.contract_id,
        domain=full_decryption_domain.label,
        ephemeral_enc_key=ephemeral_encryption_key,
    )
    return network_state, request


def fetch_current_session_pks(
    ace_deployment: AceDeployment,
    network_state,
    keypair_id: AccountAddress,
):
    keypair_id_key = _addr_key(keypair_id)
    secret = next(
        (s for s in network_state.secrets if _addr_key(s.keypair_id) == keypair_id_key),
        None,
    )
    if secret is None:
        raise ValueError(f"ACE: keypairId {keypair_id_key} not found in network state secrets")
    session_key = _addr_key(secret.current_session)
    is_initial_dkg = session_key == keypair_id_key
    return get_chain_reader(ace_deployment).session(session_key, is_initial_dkg)


def _verify_idk_share(
    share: t_ibe.IdentityDecryptionKeyShare,
    sdk_idx: int,
    session_pks,
    identity: bytes,
    node_addr: str,
    endpoint: str,
    label: str,
    log: Callable[[str], None],
) -> bool:
    expected_eval = sdk_idx + 1
    actual_eval = getattr(share.inner, "eval_point", None)
    if actual_eval != expected_eval:
        log(
            f"  [{label}] worker {node_addr} ({endpoint}): evalPoint mismatch "
            f"(got {actual_eval}, expected {expected_eval})"
        )
        return False
    ok = t_ibe.verify_share(
        session_pks.base_point,
        session_pks.share_pks[sdk_idx],
        identity,
        share,
    ).ok_value
    if not ok:
        log(f"  [{label}] worker {node_addr} ({endpoint}): share failed verification")
        return False
    return True


def decrypt_with_identity_key_shares(
    ciphertext: bytes,
    identity_key_shares: list[t_ibe.IdentityDecryptionKeyShare],
) -> Result[bytes]:
    def task(_extra: dict) -> bytes:
        parsed = t_ibe.Ciphertext.from_bytes(ciphertext).unwrap_or_throw(
            ValueError("ACE.decrypt_with_identity_key_shares: parse ciphertext")
        )
        return t_ibe.decrypt(identity_key_shares, parsed).unwrap_or_throw(
            ValueError("ACE.decrypt_with_identity_key_shares: tibe.decrypt failed")
        )

    return Result.capture(task, records_execution_time_ms=True)


def fetch_identity_key_shares_core(
    ace_deployment: AceDeployment,
    network_state,
    request: DecryptionRequestPayload,
    proof: ProofOfPermission,
    ephemeral_decryption_key: pke.DecryptionKey,
    tibe_scheme: int,
    per_node_timeout_ms: int = 8000,
    log: Callable[[str], None] | None = None,
) -> Result[list[t_ibe.IdentityDecryptionKeyShare]]:
    def task(_extra: dict) -> list[t_ibe.IdentityDecryptionKeyShare]:
        reader = get_chain_reader(ace_deployment)
        log_fn = log or (lambda _msg: None)
        identity = FullDecryptionDomain(
            request.keypair_id, request.contract_id, request.domain
        ).to_bytes()
        session_pks = fetch_current_session_pks(
            ace_deployment, network_state, request.keypair_id
        )
        if len(session_pks.share_pks) != len(network_state.cur_nodes):
            raise ValueError(
                "ACE.fetch_identity_key_shares_core: sharePks length "
                f"{len(session_pks.share_pks)} != curNodes length {len(network_state.cur_nodes)}"
            )
        req_bytes = WorkerRequest.new_decryption_basic_flow(
            request, proof, tibe_scheme
        ).to_bytes()
        shares: list[t_ibe.IdentityDecryptionKeyShare] = []
        timeout_s = per_node_timeout_ms / 1000
        for i, node_addr in enumerate(network_state.cur_nodes):
            node_key = _addr_key(node_addr)
            try:
                endpoint = reader.worker_endpoint(node_key)
                node_enc_key = reader.worker_enc_key(node_key)
                enc_req_hex = pke.encrypt(node_enc_key, req_bytes).to_hex()
                response_hex = _post_hex(endpoint, enc_req_hex, timeout_s)
                response_ct = pke.Ciphertext.from_hex(response_hex).unwrap_or_throw(
                    ValueError("response ciphertext parse failed")
                )
                share_bytes = pke.decrypt(ephemeral_decryption_key, response_ct).unwrap_or_throw(
                    ValueError("response decryption failed")
                )
                share = t_ibe.IdentityDecryptionKeyShare.from_bytes(
                    share_bytes
                ).unwrap_or_throw(ValueError("share parse failed"))
                if not _verify_idk_share(
                    share, i, session_pks, identity, node_key, endpoint, "decrypt", log_fn
                ):
                    continue
                log_fn(f"  [decrypt] worker {node_key} ({endpoint}): OK")
                shares.append(share)
            except Exception as caught:  # noqa: BLE001 - continue collecting from peers
                log_fn(f"  [decrypt] worker {node_key}: error - {caught}")
        if len(shares) < network_state.cur_threshold:
            raise RuntimeError(
                "ACE.fetch_identity_key_shares_core: need "
                f"{network_state.cur_threshold} identity key shares, got {len(shares)}"
            )
        return shares

    return Result.capture(task, records_execution_time_ms=True)


def decrypt_core(
    ace_deployment: AceDeployment,
    network_state,
    request: DecryptionRequestPayload,
    proof: ProofOfPermission,
    ephemeral_decryption_key: pke.DecryptionKey,
    ciphertext: bytes,
    log: Callable[[str], None] | None = None,
) -> Result[bytes]:
    parsed = t_ibe.Ciphertext.from_bytes(ciphertext)
    if not parsed.is_ok or parsed.ok_value is None:
        return Result.Err({"error": parsed.err_value, "extra": parsed.extra})
    shares = fetch_identity_key_shares_core(
        ace_deployment=ace_deployment,
        network_state=network_state,
        request=request,
        proof=proof,
        ephemeral_decryption_key=ephemeral_decryption_key,
        tibe_scheme=parsed.ok_value.scheme,
        log=log,
    )
    if not shares.is_ok or shares.ok_value is None:
        return Result.Err({"error": shares.err_value, "extra": shares.extra})
    return decrypt_with_identity_key_shares(ciphertext, shares.ok_value)


def fetch_identity_key_shares_core_custom(
    ace_deployment: AceDeployment,
    network_state,
    custom_request: CustomFlowRequest,
    caller_decryption_key: pke.DecryptionKey,
    tibe_scheme: int,
    per_node_timeout_ms: int = 8000,
    log: Callable[[str], None] | None = None,
) -> Result[list[t_ibe.IdentityDecryptionKeyShare]]:
    def task(_extra: dict) -> list[t_ibe.IdentityDecryptionKeyShare]:
        reader = get_chain_reader(ace_deployment)
        log_fn = log or (lambda _msg: None)
        identity = FullDecryptionDomain(
            custom_request.keypair_id,
            custom_request.contract_id,
            custom_request.label,
        ).to_bytes()
        session_pks = fetch_current_session_pks(
            ace_deployment, network_state, custom_request.keypair_id
        )
        if len(session_pks.share_pks) != len(network_state.cur_nodes):
            raise ValueError(
                "ACE.fetch_identity_key_shares_core_custom: sharePks length "
                f"{len(session_pks.share_pks)} != curNodes length {len(network_state.cur_nodes)}"
            )
        req_bytes = WorkerRequest.new_decryption_custom_flow(
            custom_request, tibe_scheme
        ).to_bytes()
        shares: list[t_ibe.IdentityDecryptionKeyShare] = []
        timeout_s = per_node_timeout_ms / 1000
        for i, node_addr in enumerate(network_state.cur_nodes):
            node_key = _addr_key(node_addr)
            try:
                endpoint = reader.worker_endpoint(node_key)
                node_enc_key = reader.worker_enc_key(node_key)
                enc_req_hex = pke.encrypt(node_enc_key, req_bytes).to_hex()
                response_hex = _post_hex(endpoint, enc_req_hex, timeout_s)
                response_ct = pke.Ciphertext.from_hex(response_hex).unwrap_or_throw(
                    ValueError("response ciphertext parse failed")
                )
                share_bytes = pke.decrypt(caller_decryption_key, response_ct).unwrap_or_throw(
                    ValueError("response decryption failed")
                )
                share = t_ibe.IdentityDecryptionKeyShare.from_bytes(
                    share_bytes
                ).unwrap_or_throw(ValueError("share parse failed"))
                if not _verify_idk_share(
                    share,
                    i,
                    session_pks,
                    identity,
                    node_key,
                    endpoint,
                    "decrypt-custom",
                    log_fn,
                ):
                    continue
                log_fn(f"  [decrypt-custom] worker {node_key} ({endpoint}): OK")
                shares.append(share)
            except Exception as caught:  # noqa: BLE001 - continue collecting from peers
                log_fn(f"  [decrypt-custom] worker {node_key}: error - {caught}")
        if len(shares) < network_state.cur_threshold:
            raise RuntimeError(
                "ACE.fetch_identity_key_shares_core_custom: need "
                f"{network_state.cur_threshold} identity key shares, got {len(shares)}"
            )
        return shares

    return Result.capture(task, records_execution_time_ms=True)


def decrypt_core_custom(
    ace_deployment: AceDeployment,
    network_state,
    custom_request: CustomFlowRequest,
    caller_decryption_key: pke.DecryptionKey,
    ciphertext: bytes,
    log: Callable[[str], None] | None = None,
) -> Result[bytes]:
    parsed = t_ibe.Ciphertext.from_bytes(ciphertext)
    if not parsed.is_ok or parsed.ok_value is None:
        return Result.Err({"error": parsed.err_value, "extra": parsed.extra})
    shares = fetch_identity_key_shares_core_custom(
        ace_deployment=ace_deployment,
        network_state=network_state,
        custom_request=custom_request,
        caller_decryption_key=caller_decryption_key,
        tibe_scheme=parsed.ok_value.scheme,
        log=log,
    )
    if not shares.is_ok or shares.ok_value is None:
        return Result.Err({"error": shares.err_value, "extra": shares.extra})
    return decrypt_with_identity_key_shares(ciphertext, shares.ok_value)


def build_per_node_request_core(
    ace_deployment: AceDeployment,
    network_state,
    request: DecryptionRequestPayload,
    proof: ProofOfPermission,
    tibe_scheme: int,
    target_endpoint: str,
) -> Result[PerNodeRequest]:
    def task(_extra: dict) -> PerNodeRequest:
        reader = get_chain_reader(ace_deployment)
        node_infos = []
        for node_addr in network_state.cur_nodes:
            node_key = _addr_key(node_addr)
            node_infos.append(
                {
                    "endpoint": reader.worker_endpoint(node_key),
                    "node_enc_key": reader.worker_enc_key(node_key),
                }
            )
        sdk_idx = next(
            (i for i, info in enumerate(node_infos) if info["endpoint"] == target_endpoint),
            -1,
        )
        if sdk_idx < 0:
            endpoints = ", ".join(info["endpoint"] for info in node_infos)
            raise ValueError(
                "ACE.build_per_node_request_core: targetEndpoint "
                f"{target_endpoint} is not in the current committee. "
                f"Registered endpoints: {endpoints}"
            )
        req_bytes = WorkerRequest.new_decryption_basic_flow(
            request, proof, tibe_scheme
        ).to_bytes()
        enc_req_hex = pke.encrypt(node_infos[sdk_idx]["node_enc_key"], req_bytes).to_hex()
        return PerNodeRequest(enc_req_hex, network_state.epoch, sdk_idx)

    return Result.capture(task, records_execution_time_ms=True)


__all__ = [
    "AptosProofOfPermission",
    "CustomFlowProof",
    "CustomFlowRequest",
    "DecryptionBasicFlowRequest",
    "DecryptionCustomFlowRequest",
    "DecryptionRequestPayload",
    "PerNodeRequest",
    "ProofOfPermission",
    "SCHEME_DECRYPTION_BASIC_FLOW",
    "SCHEME_DECRYPTION_CUSTOM_FLOW",
    "SCHEME_RECONSTRUCTION",
    "SCHEME_THRESHOLD_VRF",
    "WorkerRequest",
    "build_per_node_request_core",
    "decrypt_core",
    "decrypt_core_custom",
    "decrypt_with_identity_key_shares",
    "fetch_current_session_pks",
    "fetch_identity_key_shares_core",
    "fetch_identity_key_shares_core_custom",
    "fetch_network_state_and_build_request",
]
