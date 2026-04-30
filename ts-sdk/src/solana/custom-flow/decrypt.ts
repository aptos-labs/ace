// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Serializer } from "@aptos-labs/ts-sdk";
import * as pke from "../../pke";
import {
    AceDeployment,
    ContractID,
    CustomFlowProof,
    CustomFlowRequest,
    fetchNetworkState,
    decryptCoreCustom,
} from "../../_internal/common";

export async function decrypt({
    ciphertext, label, encPk, encSk, epoch, txn,
    aceDeployment, keypairId, knownChainName, programId,
}: {
    ciphertext: Uint8Array,
    label: Uint8Array,
    encPk: Uint8Array,
    encSk: Uint8Array,
    epoch: number,
    txn: Uint8Array,
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    knownChainName: string,
    programId: string,
}): Promise<Uint8Array> {
    const callerEncPk = pke.EncryptionKey.fromBytes(encPk)
        .unwrapOrThrow('SolanaCustomFlow.decrypt: parse encPk');
    const callerDecSk = pke.DecryptionKey.fromBytes(encSk)
        .unwrapOrThrow('SolanaCustomFlow.decrypt: parse encSk');

    const networkState = await fetchNetworkState(aceDeployment);
    const contractId = ContractID.newSolana({knownChainName, programId});
    const proof = CustomFlowProof.createSolana(txn);
    const customRequest = new CustomFlowRequest({
        keypairId,
        epoch,
        contractId,
        label,
        encPk: callerEncPk,
        proof,
    });

    return (await decryptCoreCustom({
        aceDeployment,
        networkState,
        customRequest,
        callerDecryptionKey: callerDecSk,
        ciphertext,
    })).unwrapOrThrow('SolanaCustomFlow.decrypt failed');
}

// ── Utilities for building Solana custom-flow instruction data ────────────────

/**
 * Build the BCS-encoded `CustomFullRequestBytes` to embed in the Solana
 * `assert_custom_acl` instruction data.
 *
 * Call this before building the transaction so you have the bytes ready to
 * sign, then pass the epoch used here to `decrypt`.
 */
export function buildCustomRequestBytes({keypairId, epoch, encPk, label, payload}: {
    keypairId: AccountAddress,
    epoch: number,
    encPk: Uint8Array,
    label: Uint8Array,
    payload: Uint8Array,
}): Uint8Array {
    const s = new Serializer();
    keypairId.serialize(s);              // [u8; 32] — fixed, no length prefix in BCS
    s.serializeU64(BigInt(epoch));        // u64 LE
    s.serializeBytes(encPk);             // Vec<u8>
    s.serializeBytes(label);             // Vec<u8>
    s.serializeBytes(payload);           // Vec<u8>
    return s.toUint8Array();
}

/**
 * Fetch the current epoch from the ACE contract.
 * Use this to obtain the epoch before building and signing the Solana transaction,
 * then pass the same epoch value to `decrypt`.
 */
export async function fetchCurrentEpoch(aceDeployment: AceDeployment): Promise<number> {
    return (await fetchNetworkState(aceDeployment)).epoch;
}
