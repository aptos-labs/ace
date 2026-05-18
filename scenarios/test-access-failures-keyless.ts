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
 * Steps A, C, and D exercise the keyless verification path end-to-end.
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-keyless
 */

import {
    Account,
    AccountAddress,
    EphemeralKeyPair,
    Ed25519PrivateKey,
    KeylessAccount,
    ZeroKnowledgeSig,
    ZkProof,
    ZkpVariant,
    Groth16Zkp,
    Serializer,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { pke } from '@aptos-labs/ace-sdk';
import { ChildProcess } from 'child_process';

import {
    ACCESS_CONTROL_CONTRACT_DIR,
    CHAIN_ID,
    LOCALNET_URL,
    WORKER_BASE_PORT,
} from './common/config';
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
    SAMPLE_EPHEMERAL_SK_HEX_PLACEHOLDER,
    SAMPLE_EPK_BLINDER_HEX,
    SAMPLE_EXP_DATE_SECS,
    SAMPLE_EXP_HORIZON_SECS,
    SAMPLE_EXTRA_FIELD_KEY,
    SAMPLE_ISS,
    SAMPLE_JWT_PLACEHOLDER,
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
 *
 * Both are installed via governance entries in the keyless framework. On a
 * vanilla `aptos node run-localnet` neither is present, so this helper exists
 * as the bootstrap hook for the worker PR's e2e test. Implementation deferred
 * to the same PR that adds keyless verification to verify.rs.
 *
 * TODO(keyless-bootstrap): wire this up. For now it is a no-op so the scenario
 * can be reviewed end-to-end; the assertions below will fail at the worker
 * dispatch step until both the bootstrap and the worker support land.
 */
async function setupLocalnetForKeyless(_adminAccount: Account): Promise<void> {
    console.log('  setupLocalnetForKeyless: NOT YET IMPLEMENTED (see TODO in source)');
}

/**
 * Build Bob's KeylessAccount from the hard-coded sample fixtures. All inputs
 * are tied to SAMPLE_PROOF; do not vary them independently or the Groth16
 * proof will not verify.
 */
function buildBobKeylessAccount(): KeylessAccount {
    const sk = new Ed25519PrivateKey(hexToBytes(SAMPLE_EPHEMERAL_SK_HEX_PLACEHOLDER));
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
        extraField: `"${SAMPLE_EXTRA_FIELD_KEY}":"Straka"`,
    });

    return KeylessAccount.create({
        proof,
        jwt: SAMPLE_JWT_PLACEHOLDER,
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
