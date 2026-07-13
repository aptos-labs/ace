// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Full happy-path E2E test: covers SDK, network, DKG/DKR, epoch transitions, and threshold VRF.
 *
 * Epoch layout (epoch_duration = 90 s so epoch 1 times out before any manual proposal):
 *   Epoch 0: committee {0,1,2}    threshold=2  (initial)
 *     ↓ new_secret proposal → keypair-0 DKG
 *   Epoch 1: committee {0,1,2}    threshold=2
 *     ↓ timeout (no proposal; epoch 1 expires after 90 s)
 *   Epoch 2: committee {0,1,2}    threshold=2
 *     ↓ CommitteeChange: add workers 3&4, drop worker 0
 *   Epoch 3: committee {1,2,3,4}  threshold=3
 *     ↓ new_secret proposal → keypair-1 DKG
 *   Epoch 4: committee {1,2,3,4}  threshold=3
 *     ↓ CommitteeChange: drop worker 1
 *   Epoch 5: committee {2,3,4}    threshold=3
 *
 * Flow:
 *   - Worker 0 proposes keypair-0 (epoch 0→1 DKG; workers 0,1 approve)
 *   - Epoch 1→2 auto-reshare (same committee, epoch duration expires)
 *   - Bob derives "ping-blob" VRF bytes from keypair-0 (allowlist: Bob)
 *   - Epoch 2→3 CommitteeChange to {1,2,3,4} (workers 0,1 approve from epoch-2 committee)
 *   - Bob derives "ping-blob" again after DKR; output is unchanged
 *   - Worker 1 proposes keypair-1 (epoch 3→4 DKG; workers 1,2 approve)
 *   - Bob registers "pong-blob" and derives VRF bytes as owner
 *   - Epoch 4→5 CommitteeChange to {2,3,4}
 *   - Alice purchases pong-blob and derives the same VRF bytes after DKR
 *
 * Run:
 *   cd scenarios && pnpm full-happy-path
 */

import {
    Account,
    AccountAddress,
    Ed25519PrivateKey,
    Serializer,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { pke, sig } from '@aptos-labs/ace-sdk';
import { ChildProcess } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import * as path from 'path';

import {
    ACCESS_CONTROL_CONTRACT_DIR,
    CHAIN_ID,
    LOCALNET_URL,
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
    serializeCommitteeChangeProposal,
} from './common/helpers';
import {
    deployContract,
} from './common/infra';
import {
    buildRustWorkspace,
    killStaleNetworkNodes,
    shouldSpawnSplitNetworkNode,
    spawnNetworkNodeMaybeSplit,
} from './common/network-clients';
import { buildAptosWalletFullMessage } from './common/aptos-wallet-message';
import { makeNodeMsgEndpoints } from './common/vss-protocol-setup';

const TOTAL_WORKERS = 5;
// Three overlapping committees referenced by worker indices (not epoch numbers).
const COMMITTEE_A_INDICES = [0, 1, 2];   // epochs 0, 1, 2
const COMMITTEE_A_THRESHOLD = 2;
const COMMITTEE_B_INDICES = [1, 2, 3, 4]; // epochs 3, 4
const COMMITTEE_B_THRESHOLD = 3;
const COMMITTEE_C_INDICES = [2, 3, 4];   // epoch 5
const COMMITTEE_C_THRESHOLD = 3;

// Short enough for epoch 1 to time out before the CommitteeChange proposal in step 12.
// Long enough for workers to complete the keypair-0 DKG (~30 s at n=3) before timeout.
const EPOCH_DURATION_SECS = 90;

function step(n: string | number, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

function assertBytesEqual(label: string, actual: Uint8Array, expected: Uint8Array): void {
    const actualHex = Buffer.from(actual).toString('hex');
    const expectedHex = Buffer.from(expected).toString('hex');
    assert(actualHex === expectedHex, `${label} mismatch: expected 0x${expectedHex}, got 0x${actualHex}`);
}

async function deriveVrfBytes(args: {
    aceDeployment: ACE.AceDeployment;
    keypairId: AccountAddress;
    contractId: ACE.ContractID;
    label: Uint8Array;
    account: Account;
    nonce: string;
}): Promise<Uint8Array> {
    const session = await ACE.VRF_Aptos.DerivationSession.create({
        aceDeployment: args.aceDeployment,
        keypairId: args.keypairId,
        contractId: args.contractId,
        label: args.label,
        accountAddress: args.account.accountAddress,
    });
    const msgToSign = await session.getRequestToSign();
    const fullMessage = buildAptosWalletFullMessage({
        accountAddress: args.account.accountAddress,
        chainId: CHAIN_ID,
        message: msgToSign,
        nonce: args.nonce,
    });
    const derived = (await session.deriveWithSignature({
        pubKey: args.account.publicKey,
        signature: args.account.sign(fullMessage),
        fullMessage,
    })).unwrapOrThrow('VRF derive failed');
    assert(derived.length === 32, `VRF output should be 32 bytes, got ${derived.length}`);
    return derived;
}

async function main() {
    const workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let tmpRoot: string | null = null;

    let exitCode = 0;
    try {
        const aptos = createAptos();

        // ── Step 0: Start a fresh localnet ──────────────────────────────────
        step(0, 'Start fresh localnet');
        localnetProc = await startLocalnet();
        console.log('  Localnet is up');

        // ── Step 1: Fund admin, Alice, Bob ───────────────────────────────────
        step(1, 'Fund admin, Alice, Bob');
        const adminKey = new Ed25519PrivateKey('0x1111111111111111111111111111111111111111111111111111111111111111');
        const adminAccount = Account.fromPrivateKey({ privateKey: adminKey });
        await fundAccount(adminAccount.accountAddress);
        const adminAddr = adminAccount.accountAddress.toStringLong();
        const adminKeyHex = Buffer.from(adminAccount.privateKey.toUint8Array()).toString('hex');
        console.log(`  Admin: ${adminAddr}`);

        const aliceKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 100)));
        const bobKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 200)));
        const alice = Account.fromPrivateKey({ privateKey: aliceKey });
        const bob = Account.fromPrivateKey({ privateKey: bobKey });
        await Promise.all([fundAccount(alice.accountAddress), fundAccount(bob.accountAddress)]);
        console.log(`  Alice: ${alice.accountAddress.toStringLong()}`);
        console.log(`  Bob:   ${bob.accountAddress.toStringLong()}`);

        // ── Step 2: Deploy ACE network contracts ─────────────────────────────
        step(2, 'Deploy ACE network contracts');
        await deployContracts(adminAccount, ['pke', 'sig', 'worker_config', 'group', 'secret-usage', 'fiat-shamir-transform', 'sigma-dlog-linear', 'pedersen-polynomial-commitment', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);
        console.log('  Contracts deployed');

        // ── Step 3: Fund 5 worker accounts ───────────────────────────────────
        step(3, `Fund ${TOTAL_WORKERS} worker accounts`);
        const workerKeys: Ed25519PrivateKey[] = [];
        const workerAccounts: Account[] = [];
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const key = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, j) => j + 10 + i)));
            const acc = Account.fromPrivateKey({ privateKey: key });
            await fundAccount(acc.accountAddress);
            workerKeys.push(key);
            workerAccounts.push(acc);
            console.log(`  Worker ${i}: ${acc.accountAddress.toStringLong()}`);
        }

        // ── Step 4: Register all workers on-chain ────────────────────────────
        step(4, 'Register all worker PKE keys, signature keys, and endpoints on-chain (before start_initial_epoch)');
        const encKeypairs = await Promise.all(Array.from({ length: TOTAL_WORKERS }, () => pke.keygen()));
        const sigKeypairs = await Promise.all(Array.from({ length: TOTAL_WORKERS }, () => sig.keygen()));
        tmpRoot = mkdtempSync(path.join(tmpdir(), 'ace-full-happy-'));
        const storeUrls = workerAccounts.map((_, i) => `sqlite://${path.join(tmpRoot!, `node-${i}.db`)}`);
        const nodeMsgEndpoints = makeNodeMsgEndpoints(TOTAL_WORKERS);
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const endpoint = nodeMsgEndpoints.clientUrls[i]!;
            const nodeMsgEndpoint = shouldSpawnSplitNetworkNode(i, TOTAL_WORKERS)
                ? nodeMsgEndpoints.nodeMsgUrls[i]
                : endpoint;
            console.log(`  Registering worker ${i}: node-msg=${nodeMsgEndpoint}, client=${endpoint}`);
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
                    entryFunction: `${adminAddr}::worker_config::register_sig_verification_key`,
                    args: [sigKeypairs[i].publicKey.toBytes()],
                }),
                `register_sig_verification_key worker ${i}`,
            );
            assertTxnSuccess(
                await submitTxn({
                    signer: workerAccounts[i],
                    entryFunction: `${adminAddr}::worker_config::register_client_endpoint`,
                    args: [endpoint],
                }),
                `register_client_endpoint worker ${i}`,
            );
            assertTxnSuccess(
                await submitTxn({
                    signer: workerAccounts[i],
                    entryFunction: `${adminAddr}::worker_config::register_node_msg_endpoint`,
                    args: [nodeMsgEndpoint],
                }),
                `register_node_msg_endpoint worker ${i}`,
            );
        }

        // ── Step 5: Admin calls start_initial_epoch (epoch 0) ────────────────
        step(5, `Admin: start_initial_epoch (committee A = workers ${COMMITTEE_A_INDICES}, threshold=${COMMITTEE_A_THRESHOLD})`);
        const committeeAAddrs = COMMITTEE_A_INDICES.map(i => workerAccounts[i].accountAddress.toStringLong());
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::network::start_initial_epoch`,
                args: [committeeAAddrs, COMMITTEE_A_THRESHOLD, EPOCH_DURATION_SECS],
            }),
            'network::start_initial_epoch',
        );
        console.log(`  Epoch 0 started (committee A = workers ${COMMITTEE_A_INDICES}, threshold=${COMMITTEE_A_THRESHOLD}, duration=${EPOCH_DURATION_SECS}s)`);

        // ── Step 6: Build worker binary ───────────────────────────────────────
        step(6, 'Build network-node binary');
        await buildRustWorkspace();

        // ── Step 6b: Spawn all worker processes ───────────────────────────────
        // Front half runs split (maintainer + handler), back half runs monolith.
        // For TOTAL_WORKERS=5: workers 0,1,2 split; workers 3,4 monolith.
        step('6b', `Spawn ${TOTAL_WORKERS} workers — front ${Math.ceil(TOTAL_WORKERS / 2)} split (maintainer+handler), rest monolith`);
        killStaleNetworkNodes();
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const pkeDkHex = `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`;
            workers.push(...spawnNetworkNodeMaybeSplit({
                index: i,
                total: TOTAL_WORKERS,
                runAs: workerAccounts[i],
                pkeDkHex,
                sigSkHex: sigKeypairs[i].signingKey.toHex(),
                vssStoreUrl: storeUrls[i],
                nodeMsgListen: nodeMsgEndpoints.nodeMsgListens[i],
                aceDeploymentAddr: adminAddr,
                aceDeploymentApi: LOCALNET_URL,
                workerBasePort: nodeMsgEndpoints.basePort,
            }));
        }

        step('6c', 'Wait for workers to initialize');
        await sleep(2000);

        // ── Step 7: Worker 0 proposes keypair-0 (new_secret, epoch 0→1) ──────
        // Proposer and approvers are all from committee A (workers 0,1,2; threshold=2).
        step(7, 'Worker 0 proposes keypair-0 (threshold VRF/G2); workers 0,1 approve');
        const committeeAApprovers = COMMITTEE_A_INDICES.slice(0, COMMITTEE_A_THRESHOLD).map(i => workerAccounts[i]);
        await proposeAndApprove(
            committeeAApprovers[0]!,
            committeeAApprovers,
            adminAddr,
            serializeNewSecretProposal(ACE.network.PRIMITIVE_BLS12381_THRESHOLD_VRF),
        );
        const adminAccountAddress = AccountAddress.fromString(adminAddr);
        await waitFor('keypair-0 DKG done (epoch advances to 1)', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 1;
        }, 90_000);
        const state0 = (await getNetworkState(adminAccountAddress)).unwrapOrThrow('state read failed after keypair-0 DKG');
        const keypair0Id = state0.secrets[0]!.keypairId;
        console.log(`  Keypair-0 ID: ${keypair0Id.toStringLong()}`);
        await sleep(30000); // workers derive shares for keypair-0

        // ── Step 8: Wait for epoch 1→2 auto-reshare (timeout-triggered) ──────
        // Epoch 1 has the same ${EPOCH_DURATION_SECS}s duration. Once it expires,
        // network::touch triggers a same-committee reshare with no manual proposal needed.
        step(8, `Wait for epoch 1→2 auto-reshare (epoch ${EPOCH_DURATION_SECS}s timer expires; same committee A)`);
        await waitFor('auto-reshare done (epoch advances to 2)', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 2;
        }, 300_000);
        console.log('  Epoch advanced to 2 (timeout-triggered reshare)');
        await sleep(10000); // workers derive shares for epoch-2 committee

        // ── Step 9: Deploy access_control contract ────────────────────────────
        step(9, 'Deploy and initialize access_control contract');
        await deployContract(ACCESS_CONTROL_CONTRACT_DIR, adminAddr, adminKeyHex);
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::access_control::initialize`,
                args: [],
            }),
            'access_control::initialize',
        );
        console.log('  access_control deployed and initialized');

        // ── Step 10: Alice registers "ping-blob" (allowlist: [Bob]) ──────────
        step(10, 'Alice registers "ping-blob" (allowlist: [Bob])');
        {
            const regSer = new Serializer();
            regSer.serializeStr('ping-blob');
            regSer.serializeU8(0); // SCHEME_ALLOWLIST = 0
            regSer.serializeU32AsUleb128(1); // 1 address in allowlist
            regSer.serialize(bob.accountAddress);
            const regBytes = regSer.toUint8Array();

            const outerSer = new Serializer();
            outerSer.serializeU32AsUleb128(1); // 1 registration entry
            outerSer.serializeFixedBytes(regBytes);
            const regsBytes = outerSer.toUint8Array();

            const txn = await aptos.transaction.build.simple({
                sender: alice.accountAddress,
                data: {
                    function: `${adminAddr}::access_control::register_blobs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [Array.from(regsBytes)],
                },
            });
            const pending = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
            await aptos.waitForTransaction({ transactionHash: pending.hash });
            console.log('  ping-blob registered (owner=Alice, allowlist=[Bob])');
        }

        // ── Step 11: Bob derives "ping-blob" VRF bytes with keypair-0 ────────
        step(11, 'Bob derives "ping-blob" VRF bytes with keypair-0');
        const pingDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/ping-blob`);
        const aceDeployment = new ACE.AceDeployment({
            apiEndpoint: LOCALNET_URL,
            contractAddr: adminAccountAddress,
        });
        const accessContractId = ACE.ContractID.newAptos({
            chainId: CHAIN_ID,
            moduleAddr: adminAccountAddress,
            moduleName: 'access_control',
        });

        const pingEpoch2Vrf = await deriveVrfBytes({
            aceDeployment,
            keypairId: keypair0Id,
            contractId: accessContractId,
            label: pingDomain,
            account: bob,
            nonce: 'full-happy-path-ping-epoch-2',
        });
        console.log(`  Bob derived ping VRF: 0x${Buffer.from(pingEpoch2Vrf).toString('hex')}`);

        // ── Step 12: CommitteeChange epoch 2→3 (committee B = workers 1,2,3,4) ─
        // Still in epoch 2 (committee A = {0,1,2}, threshold=2); propose and approve
        // before the epoch-2 ${EPOCH_DURATION_SECS}s timer expires.
        step(12, `Epoch 2→3 CommitteeChange to committee B = workers ${COMMITTEE_B_INDICES}, threshold=${COMMITTEE_B_THRESHOLD}`);
        await proposeAndApprove(
            committeeAApprovers[0]!,
            committeeAApprovers,
            adminAddr,
            serializeCommitteeChangeProposal(
                COMMITTEE_B_INDICES.map(i => workerAccounts[i].accountAddress),
                COMMITTEE_B_THRESHOLD,
            ),
        );
        await waitFor('epoch 3', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 3;
        }, 120_000);
        console.log('  Epoch advanced to 3 (committee B active)');
        await sleep(30000); // workers re-derive shares for epoch-3 committee

        // ── Step 13: Bob derives "ping-blob" again after DKR ─────────────────
        step(13, 'Bob derives "ping-blob" again after DKR (keypair-0, epoch-3 committee)');
        const pingEpoch3Vrf = await deriveVrfBytes({
            aceDeployment,
            keypairId: keypair0Id,
            contractId: accessContractId,
            label: pingDomain,
            account: bob,
            nonce: 'full-happy-path-ping-epoch-3',
        });
        assertBytesEqual('ping VRF output across DKR', pingEpoch3Vrf, pingEpoch2Vrf);
        console.log('  Bob derived the same ping VRF bytes after DKR');

        // ── Step 14: Worker 1 proposes keypair-1 (epoch 3→4) ─────────────────
        // Proposer and approvers are from committee B (workers 1,2,3,4; threshold=3).
        step(14, 'Worker 1 proposes keypair-1 (threshold VRF/G2) in epoch 3; workers 1,2,3 approve');
        const committeeBApprovers = COMMITTEE_B_INDICES.slice(0, COMMITTEE_B_THRESHOLD).map(i => workerAccounts[i]);
        await proposeAndApprove(
            committeeBApprovers[0]!,
            committeeBApprovers,
            adminAddr,
            serializeNewSecretProposal(ACE.network.PRIMITIVE_BLS12381_THRESHOLD_VRF),
        );
        await waitFor('keypair-1 DKG done (epoch advances to 4)', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 4;
        }, 90_000);
        const state1 = (await getNetworkState(adminAccountAddress)).unwrapOrThrow('state read failed after keypair-1 DKG');
        const keypair1Id = state1.secrets[1]!.keypairId;
        console.log(`  Keypair-1 ID: ${keypair1Id.toStringLong()}`);
        await sleep(30000); // workers derive shares for keypair-1

        // ── Step 15: Bob registers "pong-blob" (pay-to-download) and derives VRF bytes ──
        step(15, 'Bob registers "pong-blob" (pay-to-download, price=1) and derives VRF bytes as owner');
        const pongDomain = new TextEncoder().encode(`@${bob.accountAddress.toStringLong().slice(2)}/pong-blob`);
        {
            const regSer = new Serializer();
            regSer.serializeStr('pong-blob');
            regSer.serializeU8(2); // SCHEME_PAY_TO_DOWNLOAD = 2
            regSer.serializeU64(1); // price = 1 octa
            const regBytes = regSer.toUint8Array();

            const outerSer = new Serializer();
            outerSer.serializeU32AsUleb128(1); // 1 registration entry
            outerSer.serializeFixedBytes(regBytes);
            const regsBytes = outerSer.toUint8Array();

            const txn = await aptos.transaction.build.simple({
                sender: bob.accountAddress,
                data: {
                    function: `${adminAddr}::access_control::register_blobs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [Array.from(regsBytes)],
                },
            });
            const pending = await aptos.signAndSubmitTransaction({ signer: bob, transaction: txn });
            await aptos.waitForTransaction({ transactionHash: pending.hash });
            console.log('  pong-blob registered (owner=Bob, pay-to-download price=1)');
        }

        const pongEpoch4Vrf = await deriveVrfBytes({
            aceDeployment,
            keypairId: keypair1Id,
            contractId: accessContractId,
            label: pongDomain,
            account: bob,
            nonce: 'full-happy-path-pong-epoch-4-owner',
        });
        console.log(`  Bob derived pong VRF: 0x${Buffer.from(pongEpoch4Vrf).toString('hex')}`);

        // ── Step 16: CommitteeChange epoch 4→5 (committee C = workers 2,3,4) ──
        step(16, `Epoch 4→5 CommitteeChange to committee C = workers ${COMMITTEE_C_INDICES}, threshold=${COMMITTEE_C_THRESHOLD}`);
        await proposeAndApprove(
            committeeBApprovers[0]!,
            committeeBApprovers,
            adminAddr,
            serializeCommitteeChangeProposal(
                COMMITTEE_C_INDICES.map(i => workerAccounts[i].accountAddress),
                COMMITTEE_C_THRESHOLD,
            ),
        );
        await waitFor('epoch 5', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 5;
        }, 120_000);
        console.log('  Epoch advanced to 5 (committee C active)');
        await sleep(30000); // workers re-derive shares for epoch-5 committee

        // ── Step 17: Alice purchases pong-blob and derives the same VRF bytes ─
        step(17, 'Alice purchases pong-blob and derives the same VRF bytes');
        assertTxnSuccess(
            await submitTxn({
                signer: alice,
                entryFunction: `${adminAddr}::access_control::init_new_buyer`,
                args: [],
            }),
            'access_control::init_new_buyer',
        );
        assertTxnSuccess(
            await submitTxn({
                signer: alice,
                entryFunction: `${adminAddr}::access_control::purchase`,
                args: [new TextDecoder().decode(pongDomain)],
            }),
            'access_control::purchase',
        );
        console.log('  Alice purchased pong-blob');

        const pongEpoch5Vrf = await deriveVrfBytes({
            aceDeployment,
            keypairId: keypair1Id,
            contractId: accessContractId,
            label: pongDomain,
            account: alice,
            nonce: 'full-happy-path-pong-epoch-5-buyer',
        });
        assertBytesEqual('pong VRF output across DKR and caller accounts', pongEpoch5Vrf, pongEpoch4Vrf);
        console.log('  Alice derived the same pong VRF bytes after purchase and DKR');

        console.log('\n✅ All tests passed!\n');

    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        console.log('\nCleaning up worker processes...');
        for (const proc of workers) {
            proc.kill('SIGKILL');
        }
        if (localnetProc) {
            console.log('Stopping localnet...');
            localnetProc.kill('SIGTERM');
        }
        if (tmpRoot) {
            rmSync(tmpRoot, { recursive: true, force: true });
        }
        process.exit(exitCode);
    }
}

main();
