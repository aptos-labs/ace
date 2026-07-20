// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import {
    ContractID,
    ProofOfPermission,
    PublicKey,
    inferTransactionScheme,
} from "../src/_internal/solana";

describe("Solana wire helpers", () => {
    it("round-trips base58 program IDs without @solana/web3.js", () => {
        const zeroProgramId = "11111111111111111111111111111111";
        expect(Array.from(new PublicKey(zeroProgramId).toBytes())).toEqual(new Array(32).fill(0));
        expect(new PublicKey(zeroProgramId).toBase58()).toBe(zeroProgramId);

        const tokenProgramId = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        expect(new PublicKey(tokenProgramId).toBase58()).toBe(tokenProgramId);

        const contractId = new ContractID({
            knownChainName: "devnet",
            programId: tokenProgramId,
        });
        const restored = ContractID.fromBytes(contractId.toBytes())
            .unwrapOrThrow("ContractID round-trip failed");
        expect(restored.knownChainName).toBe("devnet");
        expect(restored.programId.toBase58()).toBe(tokenProgramId);
    });

    it("infers transaction version from the serialized message prefix", () => {
        const legacyTxn = new Uint8Array(1 + 64 + 1);
        legacyTxn[0] = 1; // signature count
        legacyTxn[65] = 0x01; // legacy message header: required signature count

        const versionedTxn = new Uint8Array(1 + 64 + 1);
        versionedTxn[0] = 1; // signature count
        versionedTxn[65] = 0x80; // versioned message prefix

        expect(inferTransactionScheme(legacyTxn)).toBe(ProofOfPermission.SCHEME_UNVERSIONED);
        expect(inferTransactionScheme(versionedTxn)).toBe(ProofOfPermission.SCHEME_VERSIONED);
    });

    it("serializes proof transaction bytes unchanged", () => {
        const txn = new Uint8Array([1, ...new Array(64).fill(7), 0x80, 2, 3, 4]);
        const proof = ProofOfPermission.newVersioned(txn);
        const restored = ProofOfPermission.fromBytes(proof.toBytes())
            .unwrapOrThrow("ProofOfPermission round-trip failed");

        expect(restored.scheme).toBe(ProofOfPermission.SCHEME_VERSIONED);
        expect(Array.from(restored.txnBytes)).toEqual(Array.from(txn));
    });
});
