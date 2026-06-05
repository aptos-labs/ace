// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Helpers for the `access_control` dapp used across the access-failure
 * scenarios. Owns the deploy + initialize sequence, the allowlist-blob
 * registration, the domain-bytes convention `@<owner-addr>/<blob-name>`, and
 * a thin wrapper around `ACE.AptosBasicFlow.encrypt` for the PING fixture.
 */

import { Account, AccountAddress, Aptos, Serializer } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import { ACCESS_CONTROL_CONTRACT_DIR, CHAIN_ID } from './config';
import { BaseAceActors, assert, assertTxnSuccess, createAptos, submitTxn } from './helpers';
import { deployContract } from './infra';

/** Deploys the `access_control` Move package at `adminAddr` and calls its
 *  `initialize` entry function. Caller is responsible for funding `admin`
 *  beforehand. */
export async function deployAndInitAccessControl(
    admin: Account,
    adminAddr: string,
    adminKeyHex: string,
): Promise<void> {
    await deployContract(ACCESS_CONTROL_CONTRACT_DIR, adminAddr, adminKeyHex);
    assertTxnSuccess(
        await submitTxn({
            signer: admin,
            entryFunction: `${adminAddr}::access_control::initialize`,
            args: [],
        }),
        'access_control::initialize',
    );
}

/** Submits `access_control::register_blobs` from `owner` registering a single
 *  allowlist-scheme blob `blobName` whose sole authorised reader is
 *  `allowedReader`. Matches the on-wire encoding `register_blobs` expects:
 *  a length-prefixed Vec<RegisterBlobArg> where each arg is
 *  `(name: String, scheme: u8, allowlist: Vec<AccountAddress>)`. */
export async function registerAllowlistBlob(
    aptos: Aptos,
    owner: Account,
    allowedReader: AccountAddress,
    adminAddr: string,
    blobName: string,
): Promise<void> {
    const regSer = new Serializer();
    regSer.serializeStr(blobName);
    regSer.serializeU8(0); // SCHEME_ALLOWLIST = 0
    regSer.serializeU32AsUleb128(1);
    regSer.serialize(allowedReader);

    const outerSer = new Serializer();
    outerSer.serializeU32AsUleb128(1);
    outerSer.serializeFixedBytes(regSer.toUint8Array());

    const txn = await aptos.transaction.build.simple({
        sender: owner.accountAddress,
        data: {
            function: `${adminAddr}::access_control::register_blobs` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [Array.from(outerSer.toUint8Array())],
        },
    });
    const pending = await aptos.signAndSubmitTransaction({ signer: owner, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: pending.hash });
}

/** Domain-bytes convention used by `access_control`: `@<owner-long-addr>/<blob-name>`,
 *  UTF-8 encoded. Strips the `0x` prefix from the owner address. */
export function domainForBlob(owner: Account, blobName: string): Uint8Array {
    return new TextEncoder().encode(`@${owner.accountAddress.toStringLong().slice(2)}/${blobName}`);
}

/** Encrypts `plaintext` for `(keypairId, domain)` against the `access_control`
 *  permission view. Returns the ciphertext bytes. Asserts on encryption failure. */
export async function encryptForAccessControl(
    aceDeployment: ACE.AceDeployment,
    adminAccountAddress: AccountAddress,
    keypairId: AccountAddress,
    domain: Uint8Array,
    plaintext: Uint8Array,
): Promise<Uint8Array> {
    const result = await ACE.AptosBasicFlow.encrypt({
        aceDeployment,
        keypairId,
        chainId: CHAIN_ID,
        moduleAddr: adminAccountAddress,
        moduleName: 'access_control',
        domain,
        plaintext,
    });
    assert(result.isOk, `encrypt failed: ${result.errValue}`);
    return result.okValue!;
}

/** End-to-end setup for an access-failure scenario, parameterised on
 *  whichever Bob the scenario constructed (Bob's address is all the helper
 *  needs — it doesn't care about the signature scheme). Performs:
 *    1. deploy + initialize `access_control` at `actors.adminAddr`,
 *    2. register Alice's `ping-blob` with `bobAddr` as the sole allowlistee,
 *    3. encrypt plaintext "PING" under `(keypair0Id, @alice/ping-blob)`.
 *  Returns the encrypted ciphertext + the domain it was encrypted under,
 *  ready for the access-failure step bodies to consume. */
export async function setupAccessControlAppAndEncryptPing(
    actors: BaseAceActors,
    bobAddr: AccountAddress,
    aceDeployment: ACE.AceDeployment,
    adminAccountAddress: AccountAddress,
    keypair0Id: AccountAddress,
): Promise<{ correctDomain: Uint8Array; pingCiph: Uint8Array }> {
    await deployAndInitAccessControl(actors.admin, actors.adminAddr, actors.adminKeyHex);
    await registerAllowlistBlob(createAptos(), actors.alice, bobAddr, actors.adminAddr, 'ping-blob');
    const correctDomain = domainForBlob(actors.alice, 'ping-blob');
    const pingCiph = await encryptForAccessControl(
        aceDeployment, adminAccountAddress, keypair0Id, correctDomain,
        new TextEncoder().encode('PING'),
    );
    return { correctDomain, pingCiph };
}
