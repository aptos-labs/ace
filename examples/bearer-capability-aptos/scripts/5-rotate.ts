// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 5 — Alice rotates the `accessPublicKey` on-chain.
 *
 * Re-registering under the same `blob_suffix` overwrites the previous
 * entry; the old `accessPrivateKey` no longer signs anything that verifies
 * under the new `accessPublicKey`. This is the demo's "revoke" knob.
 *
 * The contract only checks that `accessPublicKey` is a well-formed G1 point.
 * Here Alice derives a replacement keypair from ACE threshold VRF under a
 * versioned label, so rotation is deterministic for Alice but not derivable
 * without her Aptos signature.
 */

import { Account, AccountAddress, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { bytesToHex } from '@noble/hashes/utils';

import {
    ALICE_FILE, AccountFile, CONFIG_FILE, ConfigFile,
    APP_ORIGIN, aceDeploymentFromConfig, aptosFromConfig, log, readAceConfig, readJson,
    vrfOutputToAccessKeypair,
} from './common.js';

const BLOB_SUFFIX = 'song-1.mp3';

async function main() {
    const cfg = readAceConfig();
    const conf = readJson<ConfigFile>(CONFIG_FILE);
    const aliceFile = readJson<AccountFile>(ALICE_FILE);
    const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(aliceFile.privateKeyHex) });

    const aptos = aptosFromConfig(cfg);
    const aceDeployment = aceDeploymentFromConfig(cfg);
    const vrfKeypairId = AccountAddress.fromString(cfg.vrfKeypairId);
    const moduleAddr = AccountAddress.fromString(conf.appContractAddr);
    const moduleName = 'capability_access';
    const chainId = await aptos.getChainId();

    const blobId = `@${alice.accountAddress.toStringLong().slice(2)}/${BLOB_SUFFIX}`;
    const rotationLabel = `${blobId}#rotation-1`;
    const rotationLabelBytes = new TextEncoder().encode(rotationLabel);

    log(`Deriving replacement access key via ACE threshold VRF label "${rotationLabel}"...`);
    const vrfBytes = (await ACE.VRF_Aptos.derive({
        aceDeployment,
        keypairId: vrfKeypairId,
        chainId,
        moduleAddr,
        moduleName,
        label: rotationLabelBytes,
        accountAddress: alice.accountAddress,
        sign: async message => {
            const fullMessage = ACE.VRF_Aptos.buildAptosWalletFullMessage({
                accountAddress: alice.accountAddress,
                application: APP_ORIGIN,
                chainId,
                message,
                nonce: `bearer-capability-rotate-${BLOB_SUFFIX}`,
            });
            return {
                pubKey: alice.publicKey,
                signature: alice.sign(fullMessage),
                fullMessage,
            };
        },
    })).unwrapOrThrow('threshold VRF derive failed');
    const { accessPublicKey: accessPublicKeyPrime } = vrfOutputToAccessKeypair(vrfBytes);
    log(`Rotating accessPublicKey -> 0x${bytesToHex(accessPublicKeyPrime)}`);

    const txn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: `${conf.appContractAddr}::capability_access::register` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [BLOB_SUFFIX, accessPublicKeyPrime],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log('Rotation done. The accessPrivateKey in data/capability.json is now stale.');
    log('');
    log('Next: pnpm 6-decrypt-after-rotate — the old capability should now be rejected.');
}

main().catch(err => { console.error(err); process.exit(1); });
