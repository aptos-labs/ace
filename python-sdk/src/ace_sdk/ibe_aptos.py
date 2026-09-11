# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Aptos IBE helpers, mirroring ts-sdk/src/ibe-for-aptos."""

from __future__ import annotations

from aptos_sdk.account_address import AccountAddress

from ace_sdk import decryption, pke, t_ibe
from ace_sdk._internal.common import (
    ContractID,
    FullDecryptionDomain,
    fetch_tibe_public_key,
    get_chain_reader,
)
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk.result import Result


def _parse_encryption_key(enc_pk: bytes | pke.EncryptionKey) -> pke.EncryptionKey:
    if isinstance(enc_pk, pke.EncryptionKey):
        return enc_pk
    return pke.EncryptionKey.from_bytes(enc_pk).unwrap_or_throw(
        ValueError("AptosCustomFlow.fetch_identity_key_shares_custom_flow: parse enc_pk")
    )


def _parse_decryption_key(enc_sk: bytes | pke.DecryptionKey) -> pke.DecryptionKey:
    if isinstance(enc_sk, pke.DecryptionKey):
        return enc_sk
    return pke.DecryptionKey.from_bytes(enc_sk).unwrap_or_throw(
        ValueError("AptosCustomFlow.fetch_identity_key_shares_custom_flow: parse enc_sk")
    )


def fetch_pk(
    ace_deployment: AceDeployment,
    keypair_id: AccountAddress,
    tibe_scheme: int | None = None,
) -> Result[t_ibe.MasterPublicKey]:
    return fetch_tibe_public_key(
        ace_deployment=ace_deployment,
        keypair_id=keypair_id,
        tibe_scheme=tibe_scheme,
        context="AptosEncrypt.fetch_pk",
    )


def encrypt(
    ace_deployment: AceDeployment,
    keypair_id: AccountAddress,
    chain_id: int,
    module_addr: AccountAddress,
    module_name: str,
    label: bytes,
    plaintext: bytes,
    tibe_scheme: int | None = None,
    pk: t_ibe.MasterPublicKey | None = None,
) -> Result[bytes]:
    effective_scheme = (
        tibe_scheme
        if tibe_scheme is not None
        else pk.scheme
        if pk is not None
        else t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    )

    def task(_extra: dict) -> bytes:
        contract_id = ContractID.new_aptos(chain_id, module_addr, module_name)
        fdd = FullDecryptionDomain(keypair_id, contract_id, label)
        mpk = pk or fetch_pk(ace_deployment, keypair_id, effective_scheme).unwrap_or_throw(
            ValueError("AptosEncrypt: fetch_pk failed")
        )
        if mpk.scheme != effective_scheme:
            raise ValueError(
                f"AptosEncrypt: pk.scheme {mpk.scheme} does not match "
                f"tibe_scheme={effective_scheme}"
            )
        return t_ibe.encrypt(mpk, fdd.to_bytes(), plaintext).unwrap_or_throw(
            ValueError("AptosEncrypt: t_ibe.encrypt failed")
        ).to_bytes()

    return Result.capture(task)


def fetch_identity_key_shares_custom_flow(
    ace_deployment: AceDeployment,
    keypair_id: AccountAddress,
    chain_id: int,
    module_addr: AccountAddress,
    module_name: str,
    label: bytes,
    enc_pk: bytes | pke.EncryptionKey,
    enc_sk: bytes | pke.DecryptionKey,
    payload: bytes,
    tibe_scheme: int | None = None,
    per_node_timeout_ms: int = 8000,
) -> Result[list[t_ibe.IdentityDecryptionKeyShare]]:
    def task(_extra: dict) -> list[t_ibe.IdentityDecryptionKeyShare]:
        caller_enc_pk = _parse_encryption_key(enc_pk)
        caller_dec_sk = _parse_decryption_key(enc_sk)
        network_state = get_chain_reader(ace_deployment).network_state()
        custom_request = decryption.CustomFlowRequest(
            keypair_id=keypair_id,
            epoch=network_state.epoch,
            contract_id=ContractID.new_aptos(chain_id, module_addr, module_name),
            label=label,
            enc_pk=caller_enc_pk,
            proof=decryption.CustomFlowProof.create_aptos(payload),
        )
        return decryption.fetch_identity_key_shares_core_custom(
            ace_deployment=ace_deployment,
            network_state=network_state,
            custom_request=custom_request,
            caller_decryption_key=caller_dec_sk,
            # The public param stays `tibe_scheme` (0/1); it forwards into the request's `primitive`
            # field (which equals it for block, and is 3 for the streaming scope).
            primitive=(
                t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
                if tibe_scheme is None
                else tibe_scheme
            ),
            per_node_timeout_ms=per_node_timeout_ms,
        ).unwrap_or_throw(ValueError("AptosCustomFlow.fetch_identity_key_shares_custom_flow failed"))

    return Result.capture(task, records_execution_time_ms=True)


def decrypt_custom_flow(
    ace_deployment: AceDeployment,
    keypair_id: AccountAddress,
    chain_id: int,
    module_addr: AccountAddress,
    module_name: str,
    label: bytes,
    enc_pk: bytes | pke.EncryptionKey,
    enc_sk: bytes | pke.DecryptionKey,
    payload: bytes,
    ciphertext: bytes,
    per_node_timeout_ms: int = 8000,
) -> Result[bytes]:
    def task(_extra: dict) -> bytes:
        parsed_ciphertext = t_ibe.Ciphertext.from_bytes(ciphertext).unwrap_or_throw(
            ValueError("AptosCustomFlow.decrypt_custom_flow: parse ciphertext")
        )
        shares = fetch_identity_key_shares_custom_flow(
            ace_deployment=ace_deployment,
            keypair_id=keypair_id,
            chain_id=chain_id,
            module_addr=module_addr,
            module_name=module_name,
            label=label,
            enc_pk=enc_pk,
            enc_sk=enc_sk,
            payload=payload,
            tibe_scheme=parsed_ciphertext.scheme,
            per_node_timeout_ms=per_node_timeout_ms,
        ).unwrap_or_throw(ValueError("AptosCustomFlow.decrypt_custom_flow: fetch shares failed"))
        return decryption.decrypt_with_identity_key_shares(ciphertext, shares).unwrap_or_throw(
            ValueError("AptosCustomFlow.decrypt_custom_flow: decrypt failed")
        )

    return Result.capture(task, records_execution_time_ms=True)


__all__ = [
    "decrypt_custom_flow",
    "encrypt",
    "fetch_identity_key_shares_custom_flow",
    "fetch_pk",
]
