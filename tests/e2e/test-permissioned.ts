// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * E2E test for the permissioned ACE network with threshold IBE.
 *
 * Requires:
 *   - Aptos localnet running at http://localhost:8080
 *     (cd examples/shelby-access-control-aptos && pnpm localnet)
 *   - Aptos CLI installed and in PATH
 *   - pnpm install run from repo root
 *
 * Run:
 *   cd tests/e2e && pnpm test:permissioned
 */

import {
    Account,
    AccountAddress,
    Aptos,
    AptosConfig,
    Ed25519PrivateKey,
    Network,
    Serializer,
} from '@aptos-labs/ts-sdk';
import { ace, ace_threshold } from '@aptos-labs/ace-sdk';
import { execSync, spawn, ChildProcess } from 'child_process';
import { existsSync, rmSync } from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '../..');
const CONTRACT_DIR = path.join(REPO_ROOT, 'contract');
const ACCESS_CONTROL_CONTRACT_DIR = path.join(REPO_ROOT, 'examples/shelby-access-control-aptos/contract');
const WORKER_CLI = path.join(REPO_ROOT, 'worker/src/cli.ts');

const LOCALNET_URL = 'http://localhost:8080/v1';
const FAUCET_URL = 'http://localhost:8081';
const CHAIN_ID = 4; // localnet

const NUM_WORKERS = 4;
const THRESHOLD = 3;
const WORKER_BASE_PORT = 9000;

// ============================================================================
// Helpers
// ============================================================================

function log(step: string, msg: string) {
    console.log(`\n[Step ${step}] ${msg}`);
}

function assert(condition: boolean, msg: string) {
    if (!condition) throw new Error(`Assertion failed: ${msg}`);
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitFor(
    label: string,
    checkFn: () => Promise<boolean>,
    timeoutMs = 30_000,
    intervalMs = 1_000,
): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (await checkFn()) return;
        await sleep(intervalMs);
    }
    throw new Error(`Timeout waiting for: ${label}`);
}

function createAptos(): Aptos {
    return new Aptos(new AptosConfig({
        network: Network.CUSTOM,
        fullnode: LOCALNET_URL,
        faucet: FAUCET_URL,
    }));
}

async function fundAccount(aptos: Aptos, account: Account): Promise<void> {
    // Call the faucet directly so we can wait on the REST API (no indexer needed).
    const resp = await fetch(
        `${FAUCET_URL}/mint?amount=1000000000&address=${account.accountAddress.toStringLong()}`,
        { method: 'POST' },
    );
    if (!resp.ok) throw new Error(`Faucet error: ${resp.status} ${await resp.text()}`);
    const hashes: string[] = await resp.json();
    for (const hash of hashes) {
        await aptos.waitForTransaction({ transactionHash: hash });
    }
}

async function callView(aptos: Aptos, contractAddr: string, mod: string, fn: string, extraArgs: any[]): Promise<any[]> {
    return aptos.view({
        payload: {
            function: `${contractAddr}::${mod}::${fn}` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [contractAddr, ...extraArgs],
        },
    });
}

async function submitTxn(
    aptos: Aptos,
    account: Account,
    contractAddr: string,
    mod: string,
    fn: string,
    args: any[],
): Promise<void> {
    const txn = await aptos.transaction.build.simple({
        sender: account.accountAddress,
        data: {
            function: `${contractAddr}::${mod}::${fn}` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: args,
        },
    });
    const pending = await aptos.signAndSubmitTransaction({ signer: account, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: pending.hash });
}

// ============================================================================
// Deploy Move contract
// ============================================================================

function deployContract(contractDir: string, adminAddress: string, privateKeyHex: string, overrideAdmin = true): void {
    const parts = [
        'aptos', 'move', 'publish',
        '--package-dir', contractDir,
        '--private-key', `0x${privateKeyHex}`,
        '--url', LOCALNET_URL,
        '--assume-yes',
        '--skip-fetch-latest-git-deps',
    ];
    // Only pass --named-addresses when the Move.toml uses admin="_" (needs overriding).
    // Skip when the address is already hardcoded in Move.toml.
    if (overrideAdmin) {
        parts.splice(3, 0, '--named-addresses', `admin=${adminAddress}`);
    }
    const cmd = parts.join(' ');
    console.log(`  $ ${cmd}`);
    execSync(cmd, { stdio: 'inherit' });
}

// ============================================================================
// Worker process management
// ============================================================================

function spawnWorker(privateKey: Ed25519PrivateKey, port: number, contractAddr: string): ChildProcess {
    const privateKeyHex = Buffer.from(privateKey.toUint8Array()).toString('hex');
    const proc = spawn('tsx', [WORKER_CLI, 'run-worker-v2',
        '--port', String(port),
        '--rpc-url', LOCALNET_URL,
        '--ace-contract', contractAddr,
    ], {
        env: {
            ...process.env,
            ACE_WORKER_V2_PRIVATE_KEY: `0x${privateKeyHex}`,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    proc.stdout?.on('data', (d: Buffer) => console.log(`  [worker:${port}] ${d.toString().trim()}`));
    proc.stderr?.on('data', (d: Buffer) => console.error(`  [worker:${port}] ERR: ${d.toString().trim()}`));
    return proc;
}

async function waitWorkerHealthy(port: number): Promise<void> {
    await waitFor(`worker:${port} healthy`, async () => {
        try {
            const r = await fetch(`http://localhost:${port}/health`, { signal: AbortSignal.timeout(1000) });
            return r.status === 200;
        } catch { return false; }
    }, 20_000);
}

// ============================================================================
// Main test
// ============================================================================

async function main() {
    const workers: ChildProcess[] = [];

    // Clean up any stale share files from previous runs
    for (let i = 0; i < NUM_WORKERS; i++) {
        const jsonPath = path.join(process.cwd(), `worker_shares_${WORKER_BASE_PORT + i}.json`);
        if (existsSync(jsonPath)) rmSync(jsonPath);
    }

    let exitCode = 0;
    try {
        const aptos = createAptos();

        // ── Step 1: Fund admin account ──────────────────────────────────────
        log('1', 'Fund admin account');
        // Use the same key as the working localnet test so it matches the
        // hardcoded address in examples/shelby-access-control-aptos/contract/Move.toml.
        const adminKey = new Ed25519PrivateKey('0x1111111111111111111111111111111111111111111111111111111111111111');
        const adminAccount = Account.fromPrivateKey({ privateKey: adminKey });
        await fundAccount(aptos, adminAccount);
        const adminAddr = adminAccount.accountAddress.toStringLong();
        console.log(`  Admin: ${adminAddr}`);

        // ── Step 2: Fund Alice and Bob ──────────────────────────────────────
        log('2', 'Fund Alice and Bob');
        const aliceKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 100)));
        const bobKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 200)));
        const alice = Account.fromPrivateKey({ privateKey: aliceKey });
        const bob = Account.fromPrivateKey({ privateKey: bobKey });
        await Promise.all([fundAccount(aptos, alice), fundAccount(aptos, bob)]);
        console.log(`  Alice: ${alice.accountAddress.toStringLong()}`);
        console.log(`  Bob:   ${bob.accountAddress.toStringLong()}`);

        // ── Step 3: Deploy ACE network contract ──────────────────────────────
        log('3', 'Deploy ACE network contract');
        const adminKeyHex = Buffer.from(adminAccount.privateKey.toUint8Array()).toString('hex');
        deployContract(CONTRACT_DIR, adminAddr, adminKeyHex);
        console.log(`  Deployed ace_network at ${adminAddr}`);

        // ── Step 4: Initialize ACE network contract ──────────────────────────
        log('4', 'Initialize ACE network contract');
        await submitTxn(aptos, adminAccount, adminAddr, 'ace_network', 'initialize', []);
        console.log('  Initialized');

        // ── Step 5: Deploy access_control contract ───────────────────────────
        log('5', 'Deploy access_control contract');
        // access_control/Move.toml has admin hardcoded to match our key — don't override.
        deployContract(ACCESS_CONTROL_CONTRACT_DIR, adminAddr, adminKeyHex, false);
        console.log(`  Deployed access_control at ${adminAddr}`);

        await submitTxn(aptos, adminAccount, adminAddr, 'access_control', 'initialize', []);
        console.log('  access_control initialized');

        // ── Step 6: Fund worker accounts ────────────────────────────────────
        log('6', 'Fund 4 worker accounts');
        const workerKeys: Ed25519PrivateKey[] = [];
        const workerAccounts: Account[] = [];
        for (let i = 0; i < NUM_WORKERS; i++) {
            const key = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, j) => j + 10 + i)));
            const acc = Account.fromPrivateKey({ privateKey: key });
            await fundAccount(aptos, acc);
            workerKeys.push(key);
            workerAccounts.push(acc);
            console.log(`  Worker ${i}: ${acc.accountAddress.toStringLong()}`);
        }

        // ── Step 7: Start worker processes ───────────────────────────────────
        log('7', 'Start 4 worker processes (ports 9000-9003)');
        for (let i = 0; i < NUM_WORKERS; i++) {
            const proc = spawnWorker(workerKeys[i], WORKER_BASE_PORT + i, adminAddr);
            workers.push(proc);
        }

        log('7b', 'Wait for workers to become healthy');
        for (let i = 0; i < NUM_WORKERS; i++) {
            await waitWorkerHealthy(WORKER_BASE_PORT + i);
        }
        // Give extra time for registration transactions to land
        await sleep(3000);

        // ── Step 8: Admin sets epoch 1 committee ─────────────────────────────
        log('8', `Admin calls start_epoch_change with ${NUM_WORKERS} workers, threshold=${THRESHOLD}`);
        const workerAddrs = workerAccounts.map(a => a.accountAddress.toStringLong());
        await submitTxn(aptos, adminAccount, adminAddr, 'ace_network', 'start_epoch_change', [
            workerAddrs, THRESHOLD,
        ]);
        const [epochNum] = await callView(aptos, adminAddr, 'ace_network', 'get_current_epoch', []);
        assert(Number(epochNum) === 1, `Expected epoch 1, got ${epochNum}`);
        console.log(`  Epoch is now ${epochNum}, committee set`);

        // ── Step 9: Admin starts DKG ──────────────────────────────────────────
        log('9', 'Admin calls start_dkg');
        await submitTxn(aptos, adminAccount, adminAddr, 'ace_network', 'start_dkg', []);
        console.log('  DKG record created (InProgress)');

        // ── Step 10: Wait for DKG completion ─────────────────────────────────
        log('10', 'Wait for workers to complete DKG and store shares');
        await waitFor('DKG done (secret_count >= 1)', async () => {
            const [count] = await callView(aptos, adminAddr, 'ace_network', 'get_secret_count', []);
            return Number(count) >= 1;
        }, 60_000);
        console.log('  DKG complete, secret_id=0 created');

        // Give workers time to derive their shares
        await sleep(5000);
        console.log('  Workers should have derived shares by now');

        // ── Step 11: Register blob (Alice as owner, Bob in allowlist) ─────────
        log('11', 'Alice registers a blob with Bob in the allowlist');
        const blobNameSuffix = 'test-blob-001';

        // BCS-serialize a vector<RegistrationInfo>:
        //   outer: ULEB128(count=1)
        //   per registration: serializeStr(suffix) + u8(scheme) + ULEB128(addr_count) + addresses...
        const regSerializer = new Serializer();
        regSerializer.serializeStr(blobNameSuffix);
        regSerializer.serializeU8(0); // SCHEME_ALLOWLIST
        regSerializer.serializeU32AsUleb128(1); // 1 address
        regSerializer.serialize(bob.accountAddress);
        const regBytes = regSerializer.toUint8Array();

        const outerSerializer = new Serializer();
        outerSerializer.serializeU32AsUleb128(1); // 1 registration
        outerSerializer.serializeFixedBytes(regBytes);
        const regsBytes = outerSerializer.toUint8Array();

        const registerTxn = await aptos.transaction.build.simple({
            sender: alice.accountAddress,
            data: {
                function: `${adminAddr}::access_control::register_blobs` as `${string}::${string}::${string}`,
                typeArguments: [],
                functionArguments: [Array.from(regsBytes)],
            },
        });
        const registerPending = await aptos.signAndSubmitTransaction({ signer: alice, transaction: registerTxn });
        await aptos.waitForTransaction({ transactionHash: registerPending.hash });
        console.log(`  Blob '${blobNameSuffix}' registered (owner=Alice, allowlist=[Bob])`);

        // Compute full blob name: "@<canonical_alice_addr>/<blobNameSuffix>"
        // Note: to_string_with_canonical_addresses produces "@<64hexchars>" with NO "0x" prefix.
        const fullBlobName = `@${alice.accountAddress.toStringLong().slice(2)}/${blobNameSuffix}`;
        const blobDomain = new TextEncoder().encode(fullBlobName);

        // DIAGNOSTIC: verify check_permission works directly from the test
        {
            const registerTxResult = await aptos.waitForTransaction({ transactionHash: registerPending.hash });
            console.log(`  [DIAG] register tx success=${registerTxResult.success} vm_status=${registerTxResult.vm_status}`);
            const diagAlice = await aptos.view({
                payload: {
                    function: `${adminAddr}::access_control::check_permission` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [alice.accountAddress, Array.from(blobDomain)],
                },
            });
            console.log(`  [DIAG] check_permission(alice=owner, Array.from(blobDomain)) = ${diagAlice[0]}`);
            const diagResult = await aptos.view({
                payload: {
                    function: `${adminAddr}::access_control::check_permission` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [bob.accountAddress, Array.from(blobDomain)],
                },
            });
            console.log(`  [DIAG] check_permission(bob, Array.from(blobDomain)) = ${diagResult[0]}`);
            console.log(`  [DIAG] fullBlobName = ${fullBlobName}`);
            console.log(`  [DIAG] blobDomain hex = 0x${Buffer.from(blobDomain).toString('hex')}`);
        }

        // ── Step 12: Alice encrypts plaintext ────────────────────────────────
        log('12', 'Alice encrypts plaintext using committee MPK');
        const plaintext = new TextEncoder().encode('Hello threshold IBE world!');

        const network: ace_threshold.AceNetwork = {
            contractAddress: adminAddr,
            chainId: CHAIN_ID,
            rpcConfig: { aptos: { localnet: { endpoint: LOCALNET_URL } } },
        };

        const encKeyResult = await ace_threshold.ThresholdEncryptionKey.fetch(network);
        assert(encKeyResult.isOk, `Failed to fetch encryption key: ${encKeyResult.errValue}`);
        const encKey = encKeyResult.okValue!;

        const contractId = ace.ContractID.newAptos({
            chainId: CHAIN_ID,
            moduleAddr: AccountAddress.fromString(adminAddr),
            moduleName: 'access_control',
            functionName: 'check_permission',
        });

        const encResult = ace_threshold.encryptThreshold({
            encryptionKey: encKey,
            contractId,
            domain: blobDomain,
            plaintext,
        });
        assert(encResult.isOk, `Encryption failed: ${encResult.errValue}`);
        const { fullDecryptionDomain, ciphertext } = encResult.okValue!;
        console.log(`  Encrypted (ciphertext hex length: ${ciphertext.toHex().length})`);

        // ── Step 13: Bob fetches partial keys and decrypts ───────────────────
        log('13', 'Bob requests partial keys (using threshold=3 workers) and decrypts');

        // Bob signs the pretty-printed decryption domain to prove his identity.
        // The signature and fullMessage must be consistent with what verifyPermission checks.
        const msgToSign = fullDecryptionDomain.toPrettyMessage();
        const proof = ace.ProofOfPermission.createAptos({
            userAddr: bob.accountAddress,
            publicKey: bob.publicKey,
            signature: bob.sign(msgToSign),
            fullMessage: msgToSign,
        });

        const decKeyResult = await ace_threshold.ThresholdDecryptionKey.fetch(
            network, contractId, blobDomain, proof
        );
        assert(decKeyResult.isOk, `Failed to fetch decryption key: ${JSON.stringify(decKeyResult.errValue)}`);

        const decResult = ace_threshold.decryptThreshold({ decryptionKey: decKeyResult.okValue!, ciphertext });
        assert(decResult.isOk, `Decryption failed: ${decResult.errValue}`);
        const decryptedText = new TextDecoder().decode(decResult.okValue!);
        assert(decryptedText === 'Hello threshold IBE world!', `Decrypted text mismatch: ${decryptedText}`);
        console.log(`  Bob decrypted: "${decryptedText}" ✓`);

        // ── Step 14: Epoch change (DKR) ──────────────────────────────────────
        log('14', 'Admin triggers epoch change (DKR for all secrets)');
        await submitTxn(aptos, adminAccount, adminAddr, 'ace_network', 'start_epoch_change', [
            workerAddrs, THRESHOLD,
        ]);
        console.log('  EpochChangeRecord created (InProgress)');

        // ── Step 15: Wait for epoch change to complete ───────────────────────
        log('15', 'Wait for epoch change to complete');
        await waitFor('epoch 2', async () => {
            const [ep] = await callView(aptos, adminAddr, 'ace_network', 'get_current_epoch', []);
            return Number(ep) === 2;
        }, 60_000);
        console.log('  Epoch advanced to 2');

        // Wait for workers to re-derive shares at epoch 2
        await sleep(6000);

        // ── Step 16: Bob decrypts again after DKR ────────────────────────────
        log('16', 'Bob decrypts again after DKR (same MPK, refreshed shares)');

        const decKey2Result = await ace_threshold.ThresholdDecryptionKey.fetch(
            network, contractId, blobDomain, proof
        );
        assert(decKey2Result.isOk, `Post-DKR decryption key fetch failed: ${JSON.stringify(decKey2Result.errValue)}`);
        const decResult2 = ace_threshold.decryptThreshold({
            decryptionKey: decKey2Result.okValue!,
            ciphertext,
        });
        assert(decResult2.isOk, `Post-DKR decryption failed: ${decResult2.errValue}`);
        const decrypted2 = new TextDecoder().decode(decResult2.okValue!);
        assert(decrypted2 === 'Hello threshold IBE world!', `Post-DKR text mismatch: ${decrypted2}`);
        console.log(`  Bob decrypted after DKR: "${decrypted2}" ✓`);

        // ── All steps passed ─────────────────────────────────────────────────
        console.log('\n✅ All tests passed!\n');

    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        console.log('\nCleaning up worker processes...');
        for (const proc of workers) {
            proc.kill('SIGTERM');
        }
        // Clean up share files
        for (let i = 0; i < NUM_WORKERS; i++) {
            const jsonPath = path.join(process.cwd(), `worker_shares_${WORKER_BASE_PORT + i}.json`);
            if (existsSync(jsonPath)) rmSync(jsonPath);
        }
        process.exit(exitCode);
    }
}

main();
