# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""StreamIBE_Aptos — streaming + seekable IBE for Aptos (Python).

Chunk-in / chunk-out; no scheme param, no ciphertext object. Internally the streaming primitive
(3) is set on the ACE-node request. Mirrors ts-sdk `StreamIBE_Aptos`.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from aptos_sdk.account_address import AccountAddress

from ace_sdk import ibe_aptos, pke, t_ibe, t_ibe_stream
from ace_sdk._internal.common import (
    ContractID,
    FullDecryptionDomain,
    fetch_tibe_public_key,
)
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk.result import Result

# The streaming primitive id (3) — set internally on the ACE-node request; callers never see it.
_STREAM_PRIMITIVE = t_ibe_stream.STREAM_MARKER


def fetch_pk(
    ace_deployment: AceDeployment,
    keypair_id: AccountAddress,
) -> Result[t_ibe.MasterPublicKey]:
    """Fetch the streaming master public key (the shortsig-aead G2 key — streaming reuses it)."""
    return fetch_tibe_public_key(
        ace_deployment=ace_deployment,
        keypair_id=keypair_id,
        tibe_scheme=t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
        context="StreamIBE_Aptos.fetch_pk",
    )


def encrypt_stream(
    ace_deployment: AceDeployment,
    keypair_id: AccountAddress,
    chain_id: int,
    module_addr: AccountAddress,
    module_name: str,
    label: bytes,
    plaintext: Iterable[bytes],
    pk: t_ibe.MasterPublicKey | None = None,
    randomness: bytes | None = None,
) -> Iterator[bytes]:
    """Streaming, bounded-memory encryption. Consumes an iterable of plaintext byte chunks (any
    sizes; re-segmented internally) and yields ciphertext chunks (a header chunk, then segments)."""
    mpk = pk or fetch_pk(ace_deployment, keypair_id).unwrap_or_throw(
        ValueError("StreamIBE_Aptos.encrypt_stream: fetch_pk failed")
    )
    contract_id = ContractID.new_aptos(chain_id, module_addr, module_name)
    fdd = FullDecryptionDomain(keypair_id, contract_id, label)
    yield from t_ibe_stream.encrypt_stream(mpk, fdd.to_bytes(), plaintext, randomness=randomness)


class StreamDecryptor:
    """Streaming decryptor bound to already-fetched IDK shares. Authenticate once (fetch shares),
    then stream-decrypt or seek arbitrarily many times over the same shares."""

    def __init__(self, idk_shares: list[t_ibe.IdentityDecryptionKeyShare]) -> None:
        self.idk_shares = idk_shares

    def decrypt_stream(self, ciphertext_chunks: Iterable[bytes]) -> Iterator[bytes]:
        return t_ibe_stream.decrypt_stream(self.idk_shares, ciphertext_chunks)

    def create_seekable_decryptor(self, source: "t_ibe_stream.CiphertextSource"):
        return t_ibe_stream.create_seekable_decryptor(self.idk_shares, source)


def create_stream_decryptor_custom_flow(
    ace_deployment: AceDeployment,
    keypair_id: AccountAddress,
    chain_id: int,
    module_addr: AccountAddress,
    module_name: str,
    label: bytes,
    enc_pk: bytes | pke.EncryptionKey,
    enc_sk: bytes | pke.DecryptionKey,
    payload: bytes,
    per_node_timeout_ms: int = 8000,
) -> Result[StreamDecryptor]:
    """Custom-flow (app-supplied proof) streaming decrypt: fetch the streaming-primitive (3) IDK
    shares and return a `StreamDecryptor` over them. No ciphertext needed to fetch shares."""

    def task(_extra: dict) -> StreamDecryptor:
        shares = ibe_aptos.fetch_identity_key_shares_custom_flow(
            ace_deployment=ace_deployment,
            keypair_id=keypair_id,
            chain_id=chain_id,
            module_addr=module_addr,
            module_name=module_name,
            label=label,
            enc_pk=enc_pk,
            enc_sk=enc_sk,
            payload=payload,
            # The public param forwards into the request's `primitive` field.
            tibe_scheme=_STREAM_PRIMITIVE,
            per_node_timeout_ms=per_node_timeout_ms,
        ).unwrap_or_throw(ValueError("StreamIBE_Aptos.custom_flow: fetch shares failed"))
        return StreamDecryptor(shares)

    return Result.capture(task, records_execution_time_ms=True)


__all__ = [
    "StreamDecryptor",
    "create_stream_decryptor_custom_flow",
    "encrypt_stream",
    "fetch_pk",
]
