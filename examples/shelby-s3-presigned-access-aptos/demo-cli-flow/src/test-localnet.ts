// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * End-to-end localnet demo for shelby-s3-presigned-access.
 *
 * Flow:
 *   1. Deploy `presigned_access` to the localnet admin address.
 *   2. Alice (owner): encrypt a blob; derive (accessToken, accessPk) via ACE's threshold
 *      VRF over (keypair_id, contract_id, owner_addr, blob_suffix); register
 *      accessPk on-chain. Saves `accessToken` in-memory.
3. Alice hands accessToken to Bob (here just in-memory; in real life this is the
 *      "pre-signed URL" that gets emailed/whatever).
 *   4. Bob with accessToken: sign over BCS(SignableRequest { dst, label, user_epk,
 *      origin }), wrap into payload = BCS({ origin, sig }), decrypt → ok.
 *   5. Alice overwrites accessPk (= revoke + reissue under a new accessToken). Bob's old
 *      accessToken must no longer verify — this is also the "wrong scalar → reject"
 *      case, so the demo doesn't need a separate negative test for that.
 *
 * Prerequisites: a running ACE localnet with a G2 keypair. Bring one up via
 * `pnpm --filter ace-scenarios run-local-network-forever` (wait for the
 * "ACE local network is READY" banner). This demo reads
 * `/tmp/ace-localnet-config.json` to find the chain RPC, the ACE worker
 * contract, and the DKG'd keypair id.
 */

import { execSync } from "child_process";
import { readFileSync } from "fs";
import {
    Account,
    AccountAddress,
    Aptos,
    AptosConfig,
    Ed25519PrivateKey,
    Network,
    Serializer,
} from "@aptos-labs/ts-sdk";
import * as ACE from "@aptos-labs/ace-sdk";
import { bls12_381 } from "@noble/curves/bls12-381";
import { bytesToHex, utf8ToBytes } from "@noble/hashes/utils";

// ── Constants ────────────────────────────────────────────────────────────────

/** Matches `admin = 0xcafe` in the demo contract's Move.toml. */
const DEPLOYER_PRIVATE_KEY_HEX =
    "0x1111111111111111111111111111111111111111111111111111111111111111";

/** Matches `EXPECTED_APP_ORIGIN` in `presigned_access.move`. */
const APP_ORIGIN = "https://shelby.example";

/** Matches `SIGNABLE_REQUEST_DST` in `presigned_access.move`. */
const SIGNABLE_REQUEST_DST = "ACE_PRESIGNED_ACCESS_v2";

/** IETF BLS-min-pubkey-size DST — same one `aptos_std::bls12381` uses,
 *  confirmed by a Move-side round-trip spike. */
const BLS_HASH_DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

const enc = new TextEncoder();
const dec = new TextDecoder();

// ── Utilities ────────────────────────────────────────────────────────────────

function log(...args: any[]): void {
    console.log(`[${new Date().toISOString()}]`, ...args);
}

async function fundViaFaucet(addr: AccountAddress, octas: number): Promise<void> {
    const r = await fetch(
        `http://localhost:8081/mint?amount=${octas}&address=${addr.toStringLong()}`,
        { method: "POST" },
    );
    if (!r.ok) throw new Error(`faucet ${r.status}: ${await r.text()}`);
    await new Promise(res => setTimeout(res, 1000));
}

async function runTxn(
    aptos: Aptos,
    signer: Account,
    func: `${string}::${string}::${string}`,
    functionArguments: any[],
): Promise<string> {
    const txn = await aptos.transaction.build.simple({
        sender: signer.accountAddress,
        data: { function: func, typeArguments: [], functionArguments },
    });
    const resp = await aptos.signAndSubmitTransaction({ signer, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: resp.hash });
    return resp.hash;
}

/** Mirrors AIP-62 `aptos:signMessage` output for the labeled multi-line layout
 *  the worker parses (`APTOS` prefix + `<field>: <value>\n` lines). The same
 *  helper lives in `examples/tutorial-aptos/scripts/common.ts`; pulled inline
 *  here so the demo has no cross-package import. */
function buildAptosWalletFullMessage(args: {
    accountAddress: AccountAddress;
    chainId: number;
    message: string;
    nonce: string;
}): string {
    return [
        "APTOS",
        `address: ${args.accountAddress.toStringLong()}`,
        `application: ${APP_ORIGIN}`,
        `chainId: ${args.chainId}`,
        `message: ${args.message}`,
        `nonce: ${args.nonce}`,
    ].join("\n");
}

// ── Bearer-token crypto (mirrors presigned_access.move) ──────────────────────

/** Reduce the 32-byte tVRF output to a BLS12-381 Fr scalar. The bias from a
 *  256-bit-mod-r reduction is ~2^-255 — negligible for this use case. */
function vrfOutputToAsk(vrfBytes: Uint8Array): bigint {
    if (vrfBytes.length !== 32) throw new Error(`vrfBytes: expected 32, got ${vrfBytes.length}`);
    return BigInt("0x" + bytesToHex(vrfBytes)) % bls12_381.fields.Fr.ORDER;
}

function accessPkFromAsk(accessToken: bigint): Uint8Array {
    return bls12_381.G1.ProjectivePoint.BASE.multiply(accessToken).toRawBytes(true);
}

/** Build the bytes the reader's `accessToken` actually signs. Must match
 *  `bcs::to_bytes(&SignableRequest { dst, label, user_epk, origin })`
 *  on-chain — struct BCS = concat of fields, each `vector<u8>` =
 *  ULEB128(len)||bytes. */
function buildSignableMessage(args: {
    label: Uint8Array;
    userEpk: Uint8Array;
    origin: Uint8Array;
}): Uint8Array {
    const s = new Serializer();
    s.serializeBytes(enc.encode(SIGNABLE_REQUEST_DST));
    s.serializeBytes(args.label);
    s.serializeBytes(args.userEpk);
    s.serializeBytes(args.origin);
    return s.toUint8Array();
}

function signWithAsk(accessToken: bigint, msg: Uint8Array): Uint8Array {
    return (bls12_381.G2.hashToCurve(msg, { DST: BLS_HASH_DST }) as any)
        .multiply(accessToken)
        .toRawBytes(true);
}

/** Build the `payload: vector<u8>` the worker passes opaquely to the contract:
 *  `BCS({ origin, sig })`. */
function buildPayload(origin: Uint8Array, sig: Uint8Array): Uint8Array {
    const s = new Serializer();
    s.serializeBytes(origin);
    s.serializeBytes(sig);
    return s.toUint8Array();
}

// ── tVRF derive: owner-side, runs once at register time ──────────────────────

async function deriveAsk(args: {
    aceDeployment: ACE.AceDeployment;
    keypairId: AccountAddress;
    contractId: ACE.ContractID;
    owner: Account;
    blobSuffix: string;
    chainId: number;
}): Promise<bigint> {
    const session = await ACE.tVRF.DerivationSession.create({
        aceDeployment: args.aceDeployment,
        keypairId: args.keypairId,
        contractId: args.contractId,
        label: enc.encode(args.blobSuffix),
        accountAddress: args.owner.accountAddress,
    });
    const message = await session.getRequestToSign();
    const fullMessage = buildAptosWalletFullMessage({
        accountAddress: args.owner.accountAddress,
        chainId: args.chainId,
        message,
        nonce: `presigned-derive-${args.blobSuffix}`,
    });
    const vrfBytes = await session.deriveWithSignature({
        pubKey: args.owner.publicKey,
        signature: args.owner.sign(fullMessage),
        fullMessage,
    });
    return vrfOutputToAsk(vrfBytes);
}

// ── Main ─────────────────────────────────────────────────────────────────────

interface AceConfig {
    apiEndpoint: string;
    contractAddr: string;
    keypairId: string;
}

/** Different scenarios write the localnet config under slightly different
 *  schemas: `run-local-network-forever` writes singular `keypairId`,
 *  `test-solana-example` writes plural `keypairIds: [...]`. Accept either. */
function loadAceConfig(): AceConfig {
    if (process.env.ACE_CONTRACT && process.env.KEYPAIR_ID) {
        return {
            apiEndpoint: "http://localhost:8080/v1",
            contractAddr: process.env.ACE_CONTRACT,
            keypairId: process.env.KEYPAIR_ID,
        };
    }
    const path = "/tmp/ace-localnet-config.json";
    let raw: any;
    try {
        raw = JSON.parse(readFileSync(path, "utf8"));
    } catch {
        throw new Error(
            `Could not read ${path}. Bring up an ACE localnet first via ` +
            `\`pnpm --filter ace-scenarios run-local-network-forever\` and ` +
            `wait for the "ACE local network is READY" banner.`,
        );
    }
    const keypairId = raw.keypairId ?? (Array.isArray(raw.keypairIds) ? raw.keypairIds[0] : undefined);
    if (!raw.apiEndpoint || !raw.contractAddr || !keypairId) {
        throw new Error(`Malformed ${path}: need {apiEndpoint, contractAddr, keypairId|keypairIds[]}`);
    }
    return { apiEndpoint: raw.apiEndpoint, contractAddr: raw.contractAddr, keypairId };
}

async function main(): Promise<void> {
    log("=== Shelby S3 pre-signed access — localnet demo ===");

    const aptos = new Aptos(new AptosConfig({
        network: Network.LOCAL,
        fullnode: "http://localhost:8080/v1",
        faucet: "http://localhost:8081",
    }));
    try {
        await aptos.getLedgerInfo();
    } catch {
        throw new Error("Localnet not reachable at http://localhost:8080/v1");
    }
    const chainId = await aptos.getChainId();
    log(`Connected to localnet (chainId=${chainId})`);

    // ── 1. Deploy + initialize the presigned_access contract ─────────────────
    const deployer = Account.fromPrivateKey({
        privateKey: new Ed25519PrivateKey(DEPLOYER_PRIVATE_KEY_HEX),
    });
    log(`Deployer = ${deployer.accountAddress.toStringLong()} (must match \`admin\` in Move.toml)`);
    await fundViaFaucet(deployer.accountAddress, 500_000_000);

    const contractDir = new URL("../../contract", import.meta.url).pathname;
    log("Publishing presigned_access...");
    execSync(`rm -rf build`, { cwd: contractDir, stdio: "inherit" });
    execSync(
        `aptos move publish --language-version 2.2 --assume-yes ` +
        `--url http://localhost:8080 --private-key ${deployer.privateKey.toString()} ` +
        `--named-addresses admin=${deployer.accountAddress.toStringLong()}`,
        { cwd: contractDir, stdio: "inherit" },
    );
    await runTxn(aptos, deployer, `${deployer.accountAddress.toStringLong()}::presigned_access::init`, []);
    log("✓ Contract deployed + initialized");

    // ── 2. Connect to ACE workers ────────────────────────────────────────────
    const cfg = loadAceConfig();
    const aceDeployment = new ACE.AceDeployment({
        apiEndpoint: cfg.apiEndpoint,
        contractAddr: AccountAddress.fromString(cfg.contractAddr),
    });
    const keypairId = AccountAddress.fromString(cfg.keypairId);
    log(`ACE contract = ${cfg.contractAddr}`);
    log(`keypair_id   = ${cfg.keypairId}`);

    const moduleAddr = deployer.accountAddress;
    const moduleName = "presigned_access";
    const contractId = ACE.ContractID.newAptos({ chainId, moduleAddr, moduleName });

    // ── 3. Alice (owner) prepares the grant ──────────────────────────────────
    const alice = Account.generate();
    await fundViaFaucet(alice.accountAddress, 100_000_000);
    const blobSuffix = "song-1.mp3";
    const plaintext = enc.encode("Lyrics for song 1: hello sunshine!");
    // blob_id matches Shelby's canonical form `@<canon-owner>/<suffix>` and is
    // what the contract stores entries under + what the worker passes as `label`.
    const blobId = `@${alice.accountAddress.toStringLong().slice(2)}/${blobSuffix}`;
    const labelBytes = enc.encode(blobId);
    log(`Alice = ${alice.accountAddress.toStringLong()}`);
    log(`blob_id = "${blobId}"`);

    log("Alice encrypting blob via ACE custom flow...");
    const ciphertext = (await ACE.AptosCustomFlow.encrypt({
        aceDeployment,
        keypairId,
        chainId,
        moduleAddr,
        moduleName,
        domain: labelBytes,
        plaintext,
    })).unwrapOrThrow("encrypt failed");

    log("Alice deriving (accessToken, accessPk) via threshold VRF...");
    const accessToken = await deriveAsk({
        aceDeployment, keypairId, contractId, owner: alice, blobSuffix, chainId,
    });
    const accessPk = accessPkFromAsk(accessToken);
    log(`  accessPk = 0x${bytesToHex(accessPk)}`);

    log("Alice registering accessPk on-chain...");
    await runTxn(
        aptos, alice,
        `${moduleAddr.toStringLong()}::${moduleName}::register`,
        [blobSuffix, accessPk],
    );
    log("✓ Registered");

    // ── 4. Alice hands accessToken to Bob (in-memory; in real life out-of-band) ─────
    const bob = Account.generate();
    await fundViaFaucet(bob.accountAddress, 100_000_000);
    log(`Bob = ${bob.accountAddress.toStringLong()}`);

    async function bobAttemptToDecrypt(accessTokenForBob: bigint): Promise<Uint8Array | null> {
        const { encryptionKey: epk, decryptionKey: edk } = await ACE.pke.keygen();
        const userEpkBytes = epk.toBytes();
        const originBytes = enc.encode(APP_ORIGIN);
        const signableMsg = buildSignableMessage({
            label: labelBytes,
            userEpk: userEpkBytes,
            origin: originBytes,
        });
        const sig = signWithAsk(accessTokenForBob, signableMsg);
        const payload = buildPayload(originBytes, sig);
        try {
            return await ACE.AptosCustomFlow.decrypt({
                ciphertext, label: labelBytes,
                encPk: userEpkBytes, encSk: edk.toBytes(),
                payload,
                aceDeployment, keypairId, chainId, moduleAddr, moduleName,
            });
        } catch {
            return null;
        }
    }

    log("Alice hands `accessToken` to Bob (out-of-band — emailed, stored in wallet, …)");
    const bobWithAccess = await bobAttemptToDecrypt(accessToken);
    if (bobWithAccess === null) throw new Error("Bob should have decrypted with the real accessToken");
    const got = dec.decode(bobWithAccess);
    if (got !== dec.decode(plaintext)) {
        throw new Error(`plaintext mismatch: ${got}`);
    }
    log(`✓ Bob decrypted with accessToken: "${got}"`);

    // ── 5. Alice rotates accessPk → Bob's old accessToken must stop working ──────────────
    // Rotation doesn't have to re-use tVRF — the only property the contract
    // enforces at `register` is that `accessPk` is a well-formed G1 point. Alice
    // could swap in any fresh keypair (or re-derive tVRF under a different
    // keypair_id/contract). Here we just pick a deterministic-but-different
    // scalar so the demo stays self-contained.
    log("Alice rotating: register a fresh accessPk → invalidates the old accessToken...");
    const accessTokenPrime = vrfOutputToAsk(
        new Uint8Array(32).map((_, i) => i + 100),
    );
    const accessPkPrime = accessPkFromAsk(accessTokenPrime);
    await runTxn(
        aptos, alice,
        `${moduleAddr.toStringLong()}::${moduleName}::register`,
        [blobSuffix, accessPkPrime],
    );
    log("✓ Overwritten");

    const bobAfterRotate = await bobAttemptToDecrypt(accessToken);
    if (bobAfterRotate !== null) throw new Error("Bob's old accessToken should NOT work after rotation");
    log("✓ Denied — Bob's old accessToken no longer matches the rotated accessPk");

    log("");
    log("=== Demo complete ===");
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
