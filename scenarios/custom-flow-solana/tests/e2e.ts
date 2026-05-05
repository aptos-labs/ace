// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Shelby Custom Flow - Solana End-to-End Test
 *
 * Demonstrates the ACE custom-flow on Solana using a simple code-based ACL:
 *
 * SETUP (admin):
 *   1. Call `register_code(label, code)` to store an access code on-chain.
 *
 * ENCRYPT (anyone):
 *   2. Generate a PKE keypair (enc_pk / enc_sk).
 *   3. Encrypt a plaintext with `SolanaCustomFlow.encrypt`, using `label` as
 *      the IBE domain and the `custom_acl` program as the contract.
 *
 * DECRYPT (consumer):
 *   4. Fetch the current epoch.
 *   5. Build `CustomFullRequestBytes` with `buildCustomRequestBytes`, embedding
 *      the candidate payload.
 *   6. Build a Solana transaction calling `assert_custom_acl` with those bytes.
 *   7. Sign and submit to `SolanaCustomFlow.decrypt`.
 *
 * Workers:
 *   - decode `CustomFullRequestBytes` from the instruction data
 *   - verify label / epoch / encPk match the outer request
 *   - simulate the transaction: if `assert_custom_acl` succeeds (payload ==
 *     stored code) they release the key share; otherwise they refuse
 *
 * Prerequisites:
 *   - ACE global network running (see scenarios/test-custom-flow-solana.ts)
 *     which writes /tmp/ace-localnet-config.json
 */

import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { CustomAcl } from "../target/types/custom_acl";
import {
    Connection,
    Keypair,
    LAMPORTS_PER_SOL,
    PublicKey,
    TransactionMessage,
    VersionedTransaction,
} from "@solana/web3.js";
import { expect } from "chai";
import * as ACE from "@aptos-labs/ace-sdk";
import { AccountAddress } from "@aptos-labs/ts-sdk";
import { readFileSync } from "fs";

// ── Test Suite ────────────────────────────────────────────────────────────────

describe("custom-acl", () => {
    anchor.setProvider(anchor.AnchorProvider.env());

    const program = anchor.workspace.customAcl as Program<CustomAcl>;
    const provider = anchor.AnchorProvider.env();
    const connection = provider.connection;

    it("Custom flow: wrong payload rejected, correct payload accepted", async () => {

        // ── Setup accounts ───────────────────────────────────────────────────
        const admin = Keypair.generate();
        const payer = Keypair.generate();
        const minBalance = 0.1 * LAMPORTS_PER_SOL;

        await fundAccounts(connection, [admin, payer], minBalance);

        // ── Read ACE config written by the scenario ──────────────────────────
        let apiEndpoint: string;
        let contractAddr: string;
        let keypairId: AccountAddress;
        if (process.env.ACE_CONTRACT && process.env.KEYPAIR_ID) {
            apiEndpoint = "http://localhost:8080/v1";
            contractAddr = process.env.ACE_CONTRACT;
            keypairId = AccountAddress.fromString(process.env.KEYPAIR_ID);
        } else {
            const cfg = JSON.parse(readFileSync("/tmp/ace-localnet-config.json", "utf8")) as
                { apiEndpoint: string; contractAddr: string; keypairId: string };
            apiEndpoint = cfg.apiEndpoint;
            contractAddr = cfg.contractAddr;
            keypairId = AccountAddress.fromString(cfg.keypairId);
        }
        console.log(`ACE contract: ${contractAddr}`);
        console.log(`Keypair ID:   ${keypairId.toString()}`);

        const aceDeployment = new ACE.AceDeployment({
            apiEndpoint,
            contractAddr: AccountAddress.fromString(contractAddr),
        });

        const isLocalnet =
            connection.rpcEndpoint.includes("localhost") ||
            connection.rpcEndpoint.includes("127.0.0.1");
        const knownChainName = isLocalnet ? "localnet" : "testnet";
        const programId = program.programId.toBase58();

        // ── Register access code on-chain ────────────────────────────────────
        console.log("\n=== Admin: Register access code ===");
        const label = Buffer.from("custom-test-label");
        const correctCode = Buffer.from("open-sesame");
        const wrongCode = Buffer.from("wrong-password");

        const registerTxn = await program.methods
            .registerCode(label, correctCode)
            .accounts({ admin: admin.publicKey })
            .signers([admin])
            .rpc();
        await confirmTransaction(connection, registerTxn);
        console.log(`✓ Code registered (label="${label.toString()}")`);

        // ── Generate caller PKE keypair ───────────────────────────────────────
        const callerKeypair = await ACE.pke.keygen();
        const encPk = callerKeypair.encryptionKey.toBytes();
        const encSk = callerKeypair.decryptionKey.toBytes();

        // ── Encrypt plaintext ─────────────────────────────────────────────────
        console.log("\n=== Encrypt plaintext ===");
        const plaintext = Buffer.from("HELLO CUSTOM FLOW");
        const ciphertext = (
            await ACE.SolanaCustomFlow.encrypt({
                aceDeployment,
                keypairId,
                knownChainName,
                programId,
                domain: label,
                plaintext,
            })
        ).unwrapOrThrow("encrypt failed");
        console.log("✓ Plaintext encrypted");

        // ── Fetch epoch ───────────────────────────────────────────────────────
        const epoch = await ACE.SolanaCustomFlow.fetchCurrentEpoch(aceDeployment);
        console.log(`Epoch: ${epoch}`);

        // ── Helper: attempt decrypt using a legacy (v0) transaction ──────────
        async function tryDecryptV0(payload: Buffer): Promise<{ ok: boolean; value?: Uint8Array }> {
            const requestBytes = ACE.SolanaCustomFlow.buildCustomRequestBytes({
                keypairId,
                epoch,
                encPk,
                label,
                payload,
            });

            const codeEntryPda = deriveCodeEntryPda(label, program.programId);
            const txn = await program.methods
                .assertCustomAcl(Buffer.from(requestBytes))
                .accounts({ codeEntry: codeEntryPda })
                .transaction();
            txn.feePayer = payer.publicKey;
            const { blockhash } = await connection.getLatestBlockhash();
            txn.recentBlockhash = blockhash;
            txn.sign(payer);

            try {
                const value = await ACE.SolanaCustomFlow.decrypt({
                    ciphertext,
                    label,
                    encPk,
                    encSk,
                    epoch,
                    txn: txn.serialize(),
                    aceDeployment,
                    keypairId,
                    knownChainName,
                    programId,
                });
                return { ok: true, value };
            } catch (_e) {
                return { ok: false };
            }
        }

        // ── Helper: attempt decrypt using a versioned (v1) transaction ────────
        async function tryDecryptV1(payload: Buffer): Promise<{ ok: boolean; value?: Uint8Array }> {
            const requestBytes = ACE.SolanaCustomFlow.buildCustomRequestBytes({
                keypairId,
                epoch,
                encPk,
                label,
                payload,
            });

            const codeEntryPda = deriveCodeEntryPda(label, program.programId);
            const instruction = await program.methods
                .assertCustomAcl(Buffer.from(requestBytes))
                .accounts({ codeEntry: codeEntryPda })
                .instruction();
            const { blockhash } = await connection.getLatestBlockhash();
            const messageV0 = new TransactionMessage({
                payerKey: payer.publicKey,
                recentBlockhash: blockhash,
                instructions: [instruction],
            }).compileToV0Message();
            const versionedTxn = new VersionedTransaction(messageV0);
            versionedTxn.sign([payer]);

            try {
                const value = await ACE.SolanaCustomFlow.decrypt({
                    ciphertext,
                    label,
                    encPk,
                    encSk,
                    epoch,
                    txn: versionedTxn.serialize(),
                    aceDeployment,
                    keypairId,
                    knownChainName,
                    programId,
                });
                return { ok: true, value };
            } catch (_e) {
                return { ok: false };
            }
        }

        // ── Wrong payload: must be rejected ──────────────────────────────────
        console.log("\n=== Wrong payload (should fail) ===");
        const wrongResult = await tryDecryptV0(wrongCode);
        expect(wrongResult.ok).to.equal(false, "Wrong payload should be rejected");
        console.log("✓ Correctly rejected wrong payload");

        // ── Correct payload: legacy transaction ───────────────────────────────
        console.log("\n=== Correct payload — legacy transaction ===");
        const result0 = await tryDecryptV0(correctCode);
        expect(result0.ok).to.equal(true, "Correct payload (v0) should succeed");
        expect(Buffer.from(result0.value!).toString()).to.equal("HELLO CUSTOM FLOW");
        console.log("✓ Decrypted with legacy transaction");

        // ── Correct payload: versioned transaction ────────────────────────────
        console.log("\n=== Correct payload — versioned transaction ===");
        const result1 = await tryDecryptV1(correctCode);
        expect(result1.ok).to.equal(true, "Correct payload (v1) should succeed");
        expect(Buffer.from(result1.value!).toString()).to.equal("HELLO CUSTOM FLOW");
        console.log("✓ Decrypted with versioned transaction");

        console.log("\n=== All tests passed! ===");
    });
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function deriveCodeEntryPda(label: Buffer, programId: PublicKey): PublicKey {
    const [pda] = PublicKey.findProgramAddressSync(
        [Buffer.from("code"), label],
        programId,
    );
    return pda;
}

async function fundAccounts(
    connection: Connection,
    accounts: Keypair[],
    minBalance: number,
): Promise<void> {
    const isLocalnet =
        connection.rpcEndpoint.includes("localhost") ||
        connection.rpcEndpoint.includes("127.0.0.1");
    if (isLocalnet) {
        for (const account of accounts) {
            const sig = await connection.requestAirdrop(account.publicKey, minBalance);
            await connection.confirmTransaction(sig);
        }
    } else {
        console.log("Please fund these addresses manually:");
        for (const account of accounts) console.log(" ", account.publicKey.toString());
    }
}

async function confirmTransaction(connection: Connection, signature: string): Promise<void> {
    const latest = await connection.getLatestBlockhash();
    await connection.confirmTransaction({
        signature,
        blockhash: latest.blockhash,
        lastValidBlockHeight: latest.lastValidBlockHeight,
    });
}
