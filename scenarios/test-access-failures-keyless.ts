// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test: decrypt failure cases, with a KEYLESS signer.
 *
 * Identical structure to test-access-failures.ts, except Bob (the legitimate
 * data consumer) signs proof-of-permissions with a `KeylessAccount` instead of
 * a raw Ed25519 key. The on-chain auth-key for Bob is derived from his
 * `KeylessPublicKey` (SHA3-256(BCS(AnyPublicKey::Keyless(pk)) || 0x02)), and
 * the worker must:
 *   1. Parse pk_scheme=4 / sig_scheme=4 on the wire.
 *   2. Verify the ephemeral Ed25519 signature over the pretty message.
 *   3. Verify the Groth16 proof against the on-chain VK using the public-input
 *      hash derived from (iss, idc, epk, exp_date_secs, exp_horizon_secs, ...).
 *   4. Verify the JWT signature (via the proof's commitment to jwt_header.kid)
 *      against the on-chain RSA JWK installed for `iss="test.oidc.provider"`.
 *   5. Compare derived auth_key against on-chain authentication_key.
 *
 * Until those land in worker-components/network-node/src/verify.rs, this
 * scenario fails at Step A/C/D (the worker rejects pk_scheme=4). Step B still
 * passes because Charlie remains Ed25519.
 *
 * Charlie stays Ed25519 because aptos-core ships exactly one valid sample
 * Groth16 proof (devnet-groth16-keys @ 02e5675) — minting a second keyless
 * identity would require running the prover service. Coverage:
 *   A. Bob (keyless) + nonexistent keypair → worker keypair-lookup 404.
 *   B. Charlie (ed25519, not allowlisted) → worker permission-view 403.
 *   C. Bob (keyless) + wrong domain        → worker permission-view 403.
 *   D. Bob (keyless) + correct inputs      → success.
 *
 * Steps A, C, D, E, F exercise the keyless verification path end-to-end.
 *
 * Mauling cases:
 *   E. Bob (keyless) + bit-flipped ephemeral Ed25519 signature → must fail.
 *      Exercises the worker's ephemeral-signature verification step.
 *   F. Bob (keyless) + bit-flipped Groth16 proof.a → must fail.
 *      Exercises the worker's Groth16 verifier, ensuring the proof field is
 *      actually checked (not blindly trusted because the rest of the
 *      KeylessSignature looks correct).
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-keyless
 */

import {
    Account,
    AccountAddress,
    Ed25519PrivateKey,
    Ed25519Signature,
    EphemeralCertificate,
    EphemeralCertificateVariant,
    EphemeralKeyPair,
    EphemeralSignature,
    Groth16Zkp,
    KeylessAccount,
    KeylessSignature,
    Serializer,
    ZeroKnowledgeSig,
    ZkProof,
    ZkpVariant,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { pke } from '@aptos-labs/ace-sdk';
import { ChildProcess } from 'child_process';

import { execFile } from 'child_process';
import { existsSync } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { promisify } from 'util';

import {
    ACCESS_CONTROL_CONTRACT_DIR,
    CHAIN_ID,
    LOCALNET_URL,
    REPO_ROOT,
    WORKER_BASE_PORT,
} from './common/config';

const execFileAsync = promisify(execFile);
import {
    assertTxnSuccess,
    assert,
    sleep,
    waitFor,
    createAptos,
    fundAccount,
    submitTxn,
    deployContracts,
    startLocalnet,
    getNetworkState,
    proposeAndApprove,
    serializeNewSecretProposal,
} from './common/helpers';
import {
    deployContract,
} from './common/infra';
import {
    buildRustWorkspace,
    spawnNetworkNodeMaybeSplit,
} from './common/network-clients';
import {
    SAMPLE_AUD,
    SAMPLE_EPHEMERAL_SK_HEX,
    SAMPLE_EPK_BLINDER_HEX,
    SAMPLE_EXP_DATE_SECS,
    SAMPLE_EXP_HORIZON_SECS,
    SAMPLE_ISS,
    SAMPLE_JWT,
    SAMPLE_PEPPER_HEX,
    SAMPLE_PROOF_A_HEX,
    SAMPLE_PROOF_B_HEX,
    SAMPLE_PROOF_C_HEX,
    SAMPLE_UID_KEY,
} from './common/keyless-fixtures';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;

function step(n: string | number, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

/**
 * Localnet must have:
 *   1. An RSA JWK installed under iss="test.oidc.provider" / kid="test-rsa"
 *      matching aptos-core's insecure_test_jwk.json.
 *   2. A Groth16 verifying key installed in 0x1::keyless_account matching
 *      SAMPLE_PROOF (devnet-groth16-keys @ 02e5675).
 *   3. `max_exp_horizon_secs` ≥ SAMPLE_EXP_HORIZON_SECS, training-wheels off.
 *
 * Both are framework-signer-only operations. We bounce through
 * `aptos_governance::get_signer_testnet_only` from the localnet's root mint
 * account (`0xA550C18`) — its private key is written to
 * `~/.aptos/testnet/mint.key` by `aptos node run-local-testnet`. The script
 * itself is `scenarios/keyless-bootstrap.move`.
 */
async function setupLocalnetForKeyless(_adminAccount: Account): Promise<void> {
    await runKeylessBootstrapScript();
}

/**
 * Runs `aptos move run-script` against `scenarios/keyless-bootstrap.move`
 * using the localnet's `0xA550C18` root key. The script installs the test
 * JWK, Groth16 VK, and a relaxed `max_exp_horizon_secs`; see the file for
 * the full body.
 */
/**
 * Returns the path to the localnet's `mint.key`. The `aptos` CLI resolves
 * its test-dir from the nearest `.aptos` folder walking from the current
 * working directory upward (see `get_derived_test_dir` in aptos-core); it
 * only falls back to `~/.aptos` if none is found. We mirror that resolution
 * so stale `~/.aptos/testnet/mint.key` files from a different localnet
 * never get picked up.
 */
function resolveLocalnetMintKeyPath(): string {
    let dir = process.cwd();
    while (true) {
        const candidate = path.join(dir, '.aptos', 'testnet', 'mint.key');
        if (existsSync(candidate)) return candidate;
        const parent = path.dirname(dir);
        if (parent === dir) break;
        dir = parent;
    }
    const fallback = path.join(os.homedir(), '.aptos', 'testnet', 'mint.key');
    if (existsSync(fallback)) return fallback;
    throw new Error(
        `Localnet mint key not found (searched cwd→root for .aptos/testnet/mint.key, ` +
        `and ${fallback}). Did startLocalnet() run?`
    );
}

async function runKeylessBootstrapScript(): Promise<void> {
    const mintKeyPath = resolveLocalnetMintKeyPath();
    const scriptPath = path.join(REPO_ROOT, 'scenarios', 'keyless-bootstrap.move');

    console.log('  Running keyless bootstrap script (installs JWK + Groth16 VK + config patch)...');
    const { stdout, stderr } = await execFileAsync(
        'aptos',
        [
            'move',
            'run-script',
            '--script-path',
            scriptPath,
            // mint.key is the BCS-encoded `Ed25519PrivateKey` (33 bytes:
            // uleb128(32) || 32 raw bytes) — use --encoding bcs so the CLI
            // unwraps the newtype-struct correctly.
            '--private-key-file',
            mintKeyPath,
            '--encoding',
            'bcs',
            '--sender-account',
            '0xA550C18',
            '--url',
            LOCALNET_URL,
            '--assume-yes',
            '--skip-fetch-latest-git-deps',
        ],
        { maxBuffer: 16 * 1024 * 1024 },
    );
    if (stdout) process.stdout.write(`  [keyless-bootstrap] ${stdout}`);
    if (stderr) process.stderr.write(`  [keyless-bootstrap] ${stderr}`);
    console.log('  Keyless bootstrap script: OK');
}

/**
 * Build Bob's KeylessAccount from the hard-coded sample fixtures. All inputs
 * are tied to SAMPLE_PROOF; do not vary them independently or the Groth16
 * proof will not verify.
 */
function buildBobKeylessAccount(): KeylessAccount {
    const sk = new Ed25519PrivateKey(hexToBytes(SAMPLE_EPHEMERAL_SK_HEX));
    const ephemeralKeyPair = new EphemeralKeyPair({
        privateKey: sk,
        expiryDateSecs: Number(SAMPLE_EXP_DATE_SECS),
        blinder: hexToBytes(SAMPLE_EPK_BLINDER_HEX),
    });

    const groth16Zkp = new Groth16Zkp({
        a: SAMPLE_PROOF_A_HEX,
        b: SAMPLE_PROOF_B_HEX,
        c: SAMPLE_PROOF_C_HEX,
    });
    // SAMPLE_PROOF_NO_EXTRA_FIELD: extraField is intentionally omitted —
    // the proof was generated without revealing any extra JWT claim.
    const proof = new ZeroKnowledgeSig({
        proof: new ZkProof(groth16Zkp, ZkpVariant.Groth16),
        expHorizonSecs: Number(SAMPLE_EXP_HORIZON_SECS),
    });

    return KeylessAccount.create({
        proof,
        jwt: SAMPLE_JWT,
        ephemeralKeyPair,
        pepper: hexToBytes(SAMPLE_PEPPER_HEX),
        uidKey: SAMPLE_UID_KEY,
    });
}

async function main() {
    const workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;

    let exitCode = 0;
    try {
        const aptos = createAptos();

        step(0, 'Start fresh localnet');
        localnetProc = await startLocalnet();
        console.log('  Localnet is up');

        step(1, 'Fund admin, Alice, Bob (keyless), Charlie');
        const adminKey = new Ed25519PrivateKey('0x1111111111111111111111111111111111111111111111111111111111111111');
        const adminAccount = Account.fromPrivateKey({ privateKey: adminKey });
        await fundAccount(adminAccount.accountAddress);
        const adminAddr = adminAccount.accountAddress.toStringLong();
        const adminKeyHex = Buffer.from(adminAccount.privateKey.toUint8Array()).toString('hex');
        console.log(`  Admin: ${adminAddr}`);

        const aliceKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 100)));
        // Charlie: NOT on any allowlist — used for the access-denied test
        const charlieKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 50)));
        const alice = Account.fromPrivateKey({ privateKey: aliceKey });
        const charlie = Account.fromPrivateKey({ privateKey: charlieKey });

        const bob = buildBobKeylessAccount();
        console.log(`  Alice:           ${alice.accountAddress.toStringLong()}`);
        console.log(`  Bob   (keyless): ${bob.accountAddress.toStringLong()} (iss="${SAMPLE_ISS}", aud="${SAMPLE_AUD}")`);
        console.log(`  Charlie:         ${charlie.accountAddress.toStringLong()} (NOT on allowlist)`);

        await Promise.all([
            fundAccount(alice.accountAddress),
            fundAccount(bob.accountAddress),
            fundAccount(charlie.accountAddress),
        ]);

        step(2, 'Deploy ACE network contracts');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);
        console.log('  Contracts deployed');

        step('2a', 'Bootstrap localnet keyless config (JWK + Groth16 VK)');
        await setupLocalnetForKeyless(adminAccount);

        step(3, `Fund ${TOTAL_WORKERS} worker accounts`);
        const workerKeys: Ed25519PrivateKey[] = [];
        const workerAccounts: Account[] = [];
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const key = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, j) => j + 10 + i)));
            const acc = Account.fromPrivateKey({ privateKey: key });
            await fundAccount(acc.accountAddress);
            workerKeys.push(key);
            workerAccounts.push(acc);
        }

        step(4, 'Register worker PKE keys and endpoints on-chain');
        const encKeypairs = await Promise.all(Array.from({ length: TOTAL_WORKERS }, () => pke.keygen()));
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const endpoint = `http://localhost:${WORKER_BASE_PORT + i}`;
            assertTxnSuccess(
                await submitTxn({
                    signer: workerAccounts[i],
                    entryFunction: `${adminAddr}::worker_config::register_pke_enc_key`,
                    args: [Array.from(encKeypairs[i].encryptionKey.toBytes())],
                }),
                `register_pke_enc_key worker ${i}`,
            );
            assertTxnSuccess(
                await submitTxn({
                    signer: workerAccounts[i],
                    entryFunction: `${adminAddr}::worker_config::register_endpoint`,
                    args: [endpoint],
                }),
                `register_endpoint worker ${i}`,
            );
        }

        step(5, `Admin: start_initial_epoch (workers ${EPOCH0_WORKER_INDICES}, threshold=${EPOCH0_THRESHOLD})`);
        const epoch0Addrs = EPOCH0_WORKER_INDICES.map(i => workerAccounts[i].accountAddress.toStringLong());
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::network::start_initial_epoch`,
                args: [epoch0Addrs, EPOCH0_THRESHOLD, 600],
            }),
            'network::start_initial_epoch',
        );

        step(6, 'Build and spawn worker processes');
        await buildRustWorkspace();
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const pkeDkHex = `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`;
            workers.push(...spawnNetworkNodeMaybeSplit({
                index: i,
                total: TOTAL_WORKERS,
                runAs: workerAccounts[i],
                pkeDkHex,
                aceDeploymentAddr: adminAddr,
                aceDeploymentApi: LOCALNET_URL,
                workerBasePort: WORKER_BASE_PORT,
            }));
        }
        await sleep(2000);

        step(7, 'Admin proposes keypair-0; workers 0,1 approve');
        const epoch0WorkerAccounts = EPOCH0_WORKER_INDICES.map(i => workerAccounts[i]);
        {
            const approvers = epoch0WorkerAccounts.slice(0, EPOCH0_THRESHOLD);
            await proposeAndApprove(approvers[0]!, approvers, adminAddr, serializeNewSecretProposal(1));
        }
        const adminAccountAddress = AccountAddress.fromString(adminAddr);
        await waitFor('keypair-0 DKG done', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.secrets.length >= 1;
        }, 90_000);
        const state0 = (await getNetworkState(adminAccountAddress)).unwrapOrThrow('state read failed after keypair-0 DKG');
        const keypair0Id = state0.secrets[0]!.keypairId;
        console.log(`  Keypair-0 ID: ${keypair0Id.toStringLong()}`);
        await sleep(10000);

        step(8, 'Deploy and initialize access_control');
        await deployContract(ACCESS_CONTROL_CONTRACT_DIR, adminAddr, adminKeyHex);
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::access_control::initialize`,
                args: [],
            }),
            'access_control::initialize',
        );

        step(9, 'Alice registers "ping-blob" (allowlist: [Bob only])');
        {
            const regSer = new Serializer();
            regSer.serializeStr('ping-blob');
            regSer.serializeU8(0); // SCHEME_ALLOWLIST = 0
            regSer.serializeU32AsUleb128(1);
            regSer.serialize(bob.accountAddress);

            const outerSer = new Serializer();
            outerSer.serializeU32AsUleb128(1);
            outerSer.serializeFixedBytes(regSer.toUint8Array());

            const txn = await aptos.transaction.build.simple({
                sender: alice.accountAddress,
                data: {
                    function: `${adminAddr}::access_control::register_blobs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [Array.from(outerSer.toUint8Array())],
                },
            });
            const pending = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
            await aptos.waitForTransaction({ transactionHash: pending.hash });
            console.log('  ping-blob registered (owner=Alice, allowlist=[Bob-keyless])');
        }

        step(10, 'Alice encrypts "PING" with keypair-0, domain=@alice/ping-blob');
        const correctDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/ping-blob`);
        const aceDeployment = new ACE.AceDeployment({
            apiEndpoint: LOCALNET_URL,
            contractAddr: adminAccountAddress,
        });
        const pingEncResult = await ACE.AptosBasicFlow.encrypt({
            aceDeployment,
            keypairId: keypair0Id,
            chainId: CHAIN_ID,
            moduleAddr: adminAccountAddress,
            moduleName: 'access_control',
            functionName: 'check_permission',
            domain: correctDomain,
            plaintext: new TextEncoder().encode('PING'),
        });
        assert(pingEncResult.isOk, `encrypt PING failed: ${pingEncResult.errValue}`);
        const pingCiph = pingEncResult.okValue!;
        console.log('  Encrypted PING');

        // ── Negative A: nonexistent keypair ID (Bob keyless) ────────────────────
        step('A', 'Negative: Bob (keyless) decrypt with nonexistent keypair ID → must fail (404)');
        {
            const fakeKeypairId = AccountAddress.fromString('0x' + 'ab'.repeat(32));
            const session = await ACE.AptosBasicFlow.DecryptionSession.create({
                aceDeployment,
                keypairId: fakeKeypairId,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: correctDomain,
                ciphertext: pingCiph,
            });
            const msg = await session.getRequestToSign();
            const result = await session.decryptWithProof({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: bob.sign(msg),
            });
            assert(!result.isOk, `Expected decrypt to fail with nonexistent keypairId, but it succeeded`);
            console.log(`  ✓ decrypt with nonexistent keypairId correctly rejected (${result.errValue})`);
        }

        // ── Negative B: non-allowlisted Ed25519 user ────────────────────────────
        // Charlie stays Ed25519 (one keyless proof to share between Bob's tests).
        step('B', 'Negative: decrypt by Charlie (Ed25519, not allowlisted) → must fail (403)');
        {
            const session = await ACE.AptosBasicFlow.DecryptionSession.create({
                aceDeployment,
                keypairId: keypair0Id,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: correctDomain,
                ciphertext: pingCiph,
            });
            const msg = await session.getRequestToSign();
            const result = await session.decryptWithProof({
                userAddr: charlie.accountAddress,
                publicKey: charlie.publicKey,
                signature: charlie.sign(msg),
            });
            assert(!result.isOk, `Expected decrypt to fail for non-allowlisted Charlie, but it succeeded`);
            console.log(`  ✓ decrypt by non-allowlisted Charlie correctly rejected (${result.errValue})`);
        }

        // ── Negative C: wrong domain (Bob keyless) ──────────────────────────────
        step('C', 'Negative: Bob (keyless) decrypt with wrong domain → must fail (403)');
        {
            const wrongDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/other-blob`);
            const session = await ACE.AptosBasicFlow.DecryptionSession.create({
                aceDeployment,
                keypairId: keypair0Id,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: wrongDomain,
                ciphertext: pingCiph,
            });
            const msg = await session.getRequestToSign();
            const result = await session.decryptWithProof({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: bob.sign(msg),
            });
            assert(!result.isOk, `Expected decrypt to fail with wrong domain, but it succeeded`);
            console.log(`  ✓ decrypt with wrong domain correctly rejected (${result.errValue})`);
        }

        // ── Positive control D: Bob (keyless) happy path ─────────────────────────
        step('D', 'Positive: Bob (keyless, allowlisted) decrypts with correct inputs → must succeed');
        {
            const session = await ACE.AptosBasicFlow.DecryptionSession.create({
                aceDeployment,
                keypairId: keypair0Id,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: correctDomain,
                ciphertext: pingCiph,
            });
            const msg = await session.getRequestToSign();
            const result = await session.decryptWithProof({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: bob.sign(msg),
            });
            assert(result.isOk, `decrypt with correct inputs failed: ${result.errValue}`);
            assert(new TextDecoder().decode(result.okValue!) === 'PING', 'PING plaintext mismatch');
            console.log('  ✓ Bob (keyless) decrypted successfully with correct inputs');
        }

        // ── Negative E: mauled ephemeral signature ──────────────────────────────
        // Everything else in the KeylessSignature is valid; only the inner
        // Ed25519 bytes over the pretty message are bit-flipped. Worker must
        // reject in its ephemeral-sig verification step.
        step('E', 'Negative: Bob (keyless) with mauled ephemeral Ed25519 signature → must fail');
        {
            const session = await ACE.AptosBasicFlow.DecryptionSession.create({
                aceDeployment,
                keypairId: keypair0Id,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: correctDomain,
                ciphertext: pingCiph,
            });
            const msg = await session.getRequestToSign();
            const goodSig = bob.sign(msg);
            const innerEd = goodSig.ephemeralSignature.signature as Ed25519Signature;
            const mauledBytes = new Uint8Array(innerEd.toUint8Array());
            mauledBytes[0] ^= 0x01;
            const mauledSig = new KeylessSignature({
                jwtHeader: goodSig.jwtHeader,
                ephemeralCertificate: goodSig.ephemeralCertificate,
                expiryDateSecs: goodSig.expiryDateSecs,
                ephemeralPublicKey: goodSig.ephemeralPublicKey,
                ephemeralSignature: new EphemeralSignature(new Ed25519Signature(mauledBytes)),
            });
            const result = await session.decryptWithProof({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: mauledSig,
            });
            assert(!result.isOk, `Expected decrypt to fail with mauled ephemeral signature, but it succeeded`);
            console.log(`  ✓ decrypt with mauled ephemeral signature correctly rejected (${result.errValue})`);
        }

        // ── Negative F: mauled Groth16 proof ────────────────────────────────────
        // The ephemeral signature still verifies (it's over msg + ephemeral_pk),
        // but proof.a is corrupted so Groth16 verification must fail. Catches a
        // worker bug where the proof field is parsed but never verified.
        step('F', 'Negative: Bob (keyless) with mauled Groth16 proof.a → must fail');
        {
            const session = await ACE.AptosBasicFlow.DecryptionSession.create({
                aceDeployment,
                keypairId: keypair0Id,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: correctDomain,
                ciphertext: pingCiph,
            });
            const msg = await session.getRequestToSign();
            const goodSig = bob.sign(msg);

            // Flip the first byte of proof.a (still 32 bytes; not necessarily a
            // valid curve point but the worker should fail closed regardless).
            const firstByte = parseInt(SAMPLE_PROOF_A_HEX.slice(0, 2), 16);
            const mauledFirstByte = (firstByte ^ 0x01).toString(16).padStart(2, '0');
            const mauledAHex = mauledFirstByte + SAMPLE_PROOF_A_HEX.slice(2);
            const mauledProof = new Groth16Zkp({
                a: mauledAHex,
                b: SAMPLE_PROOF_B_HEX,
                c: SAMPLE_PROOF_C_HEX,
            });
            const goodZk = goodSig.ephemeralCertificate.signature as ZeroKnowledgeSig;
            const mauledCert = new EphemeralCertificate(
                new ZeroKnowledgeSig({
                    proof: new ZkProof(mauledProof, ZkpVariant.Groth16),
                    expHorizonSecs: goodZk.expHorizonSecs,
                    extraField: goodZk.extraField,
                    overrideAudVal: goodZk.overrideAudVal,
                    trainingWheelsSignature: goodZk.trainingWheelsSignature,
                }),
                EphemeralCertificateVariant.ZkProof,
            );
            const mauledSig = new KeylessSignature({
                jwtHeader: goodSig.jwtHeader,
                ephemeralCertificate: mauledCert,
                expiryDateSecs: goodSig.expiryDateSecs,
                ephemeralPublicKey: goodSig.ephemeralPublicKey,
                ephemeralSignature: goodSig.ephemeralSignature,
            });
            const result = await session.decryptWithProof({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: mauledSig,
            });
            assert(!result.isOk, `Expected decrypt to fail with mauled Groth16 proof, but it succeeded`);
            console.log(`  ✓ decrypt with mauled Groth16 proof correctly rejected (${result.errValue})`);
        }

        console.log('\n✅ All keyless access-control enforcement tests passed!\n');

    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        console.log('\nCleaning up worker processes...');
        for (const proc of workers) {
            proc.kill('SIGTERM');
        }
        if (localnetProc) {
            console.log('Stopping localnet...');
            localnetProc.kill('SIGTERM');
        }
        process.exit(exitCode);
    }
}

main();
