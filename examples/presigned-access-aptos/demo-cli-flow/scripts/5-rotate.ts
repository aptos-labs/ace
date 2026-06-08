// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 5 — Alice rotates the `accessPublicKey` on-chain.
 *
 * Re-registering under the same `blob_suffix` overwrites the previous
 * entry; the old `accessPrivateKey` no longer signs anything that verifies
 * under the new `accessPublicKey`. This is the demo's "revoke" knob.
 *
 * The rotation does NOT have to go through tVRF — the contract only
 * checks that `accessPublicKey` is a well-formed G1 point. Alice could re-derive
 * via tVRF (under a different keypair_id, say), pick a random scalar
 * locally, or use any other process. Here we just derive a fresh
 * deterministic-but-different scalar so the demo stays self-contained.
 */

import {
    Account, Aptos, AptosConfig, Ed25519PrivateKey, Network,
} from '@aptos-labs/ts-sdk';
import { bytesToHex } from '@noble/hashes/utils';

import {
    ALICE_FILE, AccountFile, CONFIG_FILE, ConfigFile,
    log, readJson, readLocalnetConfig, vrfOutputToAccessKeypair,
} from './common.js';

const BLOB_SUFFIX = 'song-1.mp3';

async function main() {
    const cfg = readLocalnetConfig();
    const conf = readJson<ConfigFile>(CONFIG_FILE);
    const aliceFile = readJson<AccountFile>(ALICE_FILE);
    const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(aliceFile.privateKeyHex) });

    const aptos = new Aptos(new AptosConfig({ network: Network.LOCAL, fullnode: cfg.apiEndpoint }));

    // Any 32 bytes work; using deterministic-but-different bytes so the
    // demo doesn't depend on system randomness.
    const rotationBytes = new Uint8Array(32).map((_, i) => i + 100);
    const { accessPublicKey: accessPublicKeyPrime } = vrfOutputToAccessKeypair(rotationBytes);
    log(`Rotating accessPublicKey -> 0x${bytesToHex(accessPublicKeyPrime)}`);

    const txn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: `${conf.appContractAddr}::presigned_access::register` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [BLOB_SUFFIX, accessPublicKeyPrime],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log('Rotation done. The accessPrivateKey in data/grant.json is now stale.');
    log('');
    log('Next: pnpm 6-decrypt-after-rotate — the old grant should now be rejected.');
}

main().catch(err => { console.error(err); process.exit(1); });
