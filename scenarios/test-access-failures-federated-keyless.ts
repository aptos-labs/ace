// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test: decrypt failure cases, with a FEDERATED-KEYLESS signer.
 *
 * Sibling of `test-access-failures-keyless.ts`. Same six steps (A–F), same
 * sample Groth16 proof, same JWT — but Bob is a `FederatedKeylessAccount`
 * whose RSA JWK is published at a dapp-controlled `jwk_addr` rather than at
 * `0x1::jwks::PatchedJWKs`. Exercises:
 *   1. pk_scheme=5 / sig_scheme=4 wire parsing in the worker.
 *   2. Federated auth-key derivation:
 *      `SHA3-256(0x04 || BCS(FederatedKeylessPublicKey) || 0x02)`.
 *   3. JWK lookup against `0x1::jwks::FederatedJWKs` at `jwk_addr` after the
 *      system list misses. The bootstrap script deliberately clears
 *      `PatchedJWKs` so the test fails closed if the worker only consults the
 *      system list.
 *   4. The remaining keyless invariants (Groth16, EPK expiry, JWT/header kid
 *      binding, ephemeral signature) shared with the regular keyless path.
 *
 * `jwk_addr` here is the admin account — convenient because admin is already
 * signing a bunch of other setup txns. In a real dapp it would be a dedicated
 * issuer-management account.
 *
 * Coverage mirrors the regular keyless scenario:
 *   A. Bob (federated keyless) + nonexistent keypair → keypair-lookup 404.
 *   B. Charlie (ed25519, not allowlisted)            → permission-view 403.
 *   C. Bob (federated keyless) + wrong domain        → permission-view 403.
 *   D. Bob (federated keyless) + correct inputs      → success.
 *   E. Bob (federated keyless) + mauled ephemeral signature → must fail.
 *   F. Bob (federated keyless) + mauled Groth16 proof.a      → must fail.
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-federated-keyless
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
    FederatedKeylessAccount,
    Groth16Zkp,
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
    SAMPLE_JWK_ALG,
    SAMPLE_JWK_E,
    SAMPLE_JWK_KID,
    SAMPLE_JWK_N,
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
 * Returns the path to the localnet's `mint.key`. Same resolution logic as the
 * regular keyless scenario — see test-access-failures-keyless.ts for the
 * rationale.
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

/**
 * Runs the framework-side bootstrap: clears `PatchedJWKs`, installs the
 * Groth16 VK + Configuration. The federated JWK itself is published by the
 * admin in a separate step (no framework signer needed).
 */
async function runFederatedKeylessBootstrapScript(): Promise<void> {
    const mintKeyPath = resolveLocalnetMintKeyPath();
    const scriptPath = path.join(REPO_ROOT, 'scenarios', 'federated-keyless-bootstrap.move');

    console.log('  Running federated-keyless bootstrap script (clears system JWKs, installs Groth16 VK + config)...');
    const { stdout, stderr } = await execFileAsync(
        'aptos',
        [
            'move',
            'run-script',
            '--script-path', scriptPath,
            '--private-key-file', mintKeyPath,
            '--encoding', 'bcs',
            '--sender-account', '0xA550C18',
            '--url', LOCALNET_URL,
            '--assume-yes',
            '--skip-fetch-latest-git-deps',
        ],
        { maxBuffer: 16 * 1024 * 1024 },
    );
    if (stdout) process.stdout.write(`  [federated-keyless-bootstrap] ${stdout}`);
    if (stderr) process.stderr.write(`  [federated-keyless-bootstrap] ${stderr}`);
    console.log('  Federated-keyless bootstrap script: OK');
}

/**
 * Publishes the test RSA JWK at `jwk_owner::0x1::jwks::FederatedJWKs`. Plain
 * `public entry fun` — no governance needed. Mirrors the install step in
 * `aptos-core/testsuite/smoke-test/src/keyless.rs::federated_keyless_scenario`.
 */
async function installFederatedJwk(jwk_owner: Account): Promise<void> {
    assertTxnSuccess(
        await submitTxn({
            signer: jwk_owner,
            entryFunction: '0x1::jwks::update_federated_jwk_set',
            args: [
                Array.from(new TextEncoder().encode(SAMPLE_ISS)),
                [SAMPLE_JWK_KID],
                [SAMPLE_JWK_ALG],
                [SAMPLE_JWK_E],
                [SAMPLE_JWK_N],
            ],
        }),
        '0x1::jwks::update_federated_jwk_set',
    );
}

/**
 * Build Bob's FederatedKeylessAccount from the hard-coded sample fixtures.
 * All inputs are tied to SAMPLE_PROOF; do not vary them independently or the
 * Groth16 proof will not verify.
 *
 * `jwkAddress` is the on-chain account where `FederatedJWKs` lives. The
 * worker (and the chain VM) hashes it into the auth-key, so this MUST match
 * the account we called `update_federated_jwk_set` on.
 */
function buildBobFederatedKeylessAccount(jwkAddress: AccountAddress): FederatedKeylessAccount {
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
    const proof = new ZeroKnowledgeSig({
        proof: new ZkProof(groth16Zkp, ZkpVariant.Groth16),
        expHorizonSecs: Number(SAMPLE_EXP_HORIZON_SECS),
    });

    return FederatedKeylessAccount.create({
        proof,
        jwt: SAMPLE_JWT,
        ephemeralKeyPair,
        pepper: hexToBytes(SAMPLE_PEPPER_HEX),
        uidKey: SAMPLE_UID_KEY,
        jwkAddress,
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

        step(1, 'Fund admin, Alice, Bob (federated keyless), Charlie');
        const adminKey = new Ed25519PrivateKey('0x1111111111111111111111111111111111111111111111111111111111111111');
        const adminAccount = Account.fromPrivateKey({ privateKey: adminKey });
        await fundAccount(adminAccount.accountAddress);
        const adminAddr = adminAccount.accountAddress.toStringLong();
        const adminKeyHex = Buffer.from(adminAccount.privateKey.toUint8Array()).toString('hex');
        console.log(`  Admin (also jwk_addr): ${adminAddr}`);

        const aliceKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 100)));
        const charlieKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 50)));
        const alice = Account.fromPrivateKey({ privateKey: aliceKey });
        const charlie = Account.fromPrivateKey({ privateKey: charlieKey });

        const bob = buildBobFederatedKeylessAccount(adminAccount.accountAddress);
        console.log(`  Alice:                      ${alice.accountAddress.toStringLong()}`);
        console.log(`  Bob   (federated keyless):  ${bob.accountAddress.toStringLong()} (iss="${SAMPLE_ISS}", aud="${SAMPLE_AUD}", jwk_addr=${bob.publicKey.jwkAddress.toStringLong()})`);
        console.log(`  Charlie:                    ${charlie.accountAddress.toStringLong()} (NOT on allowlist)`);

        await Promise.all([
            fundAccount(alice.accountAddress),
            fundAccount(bob.accountAddress),
            fundAccount(charlie.accountAddress),
        ]);

        step(2, 'Deploy ACE network contracts');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);
        console.log('  Contracts deployed');

        step('2a', 'Bootstrap framework keyless config (clear PatchedJWKs, install VK + Configuration)');
        await runFederatedKeylessBootstrapScript();

        step('2b', `Publish FederatedJWKs at jwk_addr=${adminAddr}`);
        await installFederatedJwk(adminAccount);
        console.log('  Federated JWK installed (iss=test.oidc.provider, kid=test-rsa)');

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
            console.log('  ping-blob registered (owner=Alice, allowlist=[Bob-federated-keyless])');
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

        // ── Negative A: nonexistent keypair ID (Bob federated keyless) ──────────
        step('A', 'Negative: Bob (federated keyless) decrypt with nonexistent keypair ID → must fail (404)');
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

        // ── Negative C: wrong domain (Bob federated keyless) ────────────────────
        step('C', 'Negative: Bob (federated keyless) decrypt with wrong domain → must fail (403)');
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

        // ── Positive control D: Bob (federated keyless) happy path ──────────────
        step('D', 'Positive: Bob (federated keyless, allowlisted) decrypts with correct inputs → must succeed');
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
            console.log('  ✓ Bob (federated keyless) decrypted successfully with correct inputs');
        }

        // ── Negative E: mauled ephemeral signature ──────────────────────────────
        step('E', 'Negative: Bob (federated keyless) with mauled ephemeral Ed25519 signature → must fail');
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
        step('F', 'Negative: Bob (federated keyless) with mauled Groth16 proof.a → must fail');
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

        console.log('\n✅ All federated-keyless access-control enforcement tests passed!\n');

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
