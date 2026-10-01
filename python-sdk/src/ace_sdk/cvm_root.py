# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Attested c26t CVM root-unlock client for ACE worker request variant 4.

The caller must obtain the Google Confidential Space OIDC token from the
launcher inside the measured guest using ``attestation_nonce(payload,
binding)`` as the sole custom nonce. The response decryption key and worker
Ed25519 signing key must be generated inside that guest and kept only in
volatile memory.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from typing import Callable

from ace_sdk import pke, vrf_aptos
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk.bcs import Serializer

SCHEME_CVM_ROOT_VRF = 4
ROOT_LABEL = b"c26t/root/v1"
_NONCE_DOMAIN = b"ace/c26t/cvm-root/attestation/v1\0"
_WORKER_SIGNATURE_DOMAIN = b"ace/c26t/cvm-root/worker-signature/v1\0"


def _fixed_bytes(name: str, value: bytes, length: int) -> bytes:
    if not isinstance(value, bytes) or len(value) != length:
        raise ValueError(f"{name} must be {length} bytes")
    return value


def worker_signature_message(
    payload: vrf_aptos.ThresholdVrfRequestPayload,
    worker_addr: bytes,
    worker_pk: bytes,
    tls_spki_sha256: bytes,
) -> bytes:
    """Bytes to sign using the Ed25519 key registered by the c26t worker."""
    return (
        _WORKER_SIGNATURE_DOMAIN
        + payload.to_bytes()
        + _fixed_bytes("worker_addr", worker_addr, 32)
        + _fixed_bytes("worker_pk", worker_pk, 32)
        + _fixed_bytes("tls_spki_sha256", tls_spki_sha256, 32)
    )


@dataclass(frozen=True)
class CvmRootBinding:
    worker_addr: bytes
    worker_pk: bytes
    tls_spki_sha256: bytes
    worker_signature: bytes

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_fixed_bytes(_fixed_bytes("worker_addr", self.worker_addr, 32))
        serializer.serialize_fixed_bytes(_fixed_bytes("worker_pk", self.worker_pk, 32))
        serializer.serialize_fixed_bytes(_fixed_bytes("tls_spki_sha256", self.tls_spki_sha256, 32))
        serializer.serialize_bytes(_fixed_bytes("worker_signature", self.worker_signature, 64))


def attestation_nonce(payload: vrf_aptos.ThresholdVrfRequestPayload, binding: CvmRootBinding) -> str:
    """Return the Google ``nonces`` entry bound to the worker and TLS SPKI."""
    preimage = (
        _NONCE_DOMAIN
        + payload.to_bytes()
        + _fixed_bytes("worker_addr", binding.worker_addr, 32)
        + _fixed_bytes("worker_pk", binding.worker_pk, 32)
        + _fixed_bytes("tls_spki_sha256", binding.tls_spki_sha256, 32)
        + _fixed_bytes("worker_signature", binding.worker_signature, 64)
    )
    digest = hashlib.sha256(preimage).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


@dataclass(frozen=True)
class CvmRootVrfRequest:
    payload: vrf_aptos.ThresholdVrfRequestPayload
    binding: CvmRootBinding
    attestation_jwt: str

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        serializer.serialize_u8(SCHEME_CVM_ROOT_VRF)
        self.payload.serialize(serializer)
        self.binding.serialize(serializer)
        serializer.serialize_str(self.attestation_jwt)
        return serializer.to_bytes()


def derive_core(
    ace_deployment: AceDeployment,
    network_state,
    payload: vrf_aptos.ThresholdVrfRequestPayload,
    binding: CvmRootBinding,
    attestation_jwt: str,
    response_decryption_key: pke.DecryptionKey,
    per_node_timeout_ms: int = 8000,
    log: Callable[[str], None] | None = None,
) -> bytes:
    """Verify and combine attested ACE shares into the stable 32-byte root.

    ACE itself checks the signed JWT, exact root input, and current VRF usage.
    The client additionally pairing-verifies every returned share against the
    current ACE public commitments before interpolating the root.
    """
    if payload.label != ROOT_LABEL:
        raise ValueError("CVM root payload must use c26t/root/v1")
    if payload.response_enc_key.scheme != pke.SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305:
        raise ValueError("CVM root response key must use X25519 HPKE")
    if pke.derive_encryption_key(response_decryption_key).to_bytes() != payload.response_enc_key.to_bytes():
        raise ValueError("CVM root response private key does not match attested public key")
    if not attestation_jwt:
        raise ValueError("CVM root attestation token is required")
    # Reject malformed worker/TLS bindings before contacting ACE nodes.
    attestation_nonce(payload, binding)
    return vrf_aptos._derive_core_with_request_bytes(
        ace_deployment,
        network_state,
        payload,
        CvmRootVrfRequest(payload, binding, attestation_jwt).to_bytes(),
        response_decryption_key,
        per_node_timeout_ms,
        log,
    )


__all__ = [
    "SCHEME_CVM_ROOT_VRF", "ROOT_LABEL", "CvmRootBinding", "CvmRootVrfRequest",
    "worker_signature_message", "attestation_nonce", "derive_core",
]
