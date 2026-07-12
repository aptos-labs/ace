// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Helpers for the `access_control` dapp used across IBE scenarios. Owns the
 * deploy + initialize sequence, the allowlist-blob registration, and the
 * domain-bytes convention `@<owner-addr>/<blob-name>`.
 */

import { Account, AccountAddress, Aptos, Serializer } from '@aptos-labs/ts-sdk';

import { ACCESS_CONTROL_CONTRACT_DIR } from './config';
import { assertTxnSuccess, submitTxn } from './helpers';
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
