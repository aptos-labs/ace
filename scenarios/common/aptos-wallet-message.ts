// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from '@aptos-labs/ts-sdk';

export const ACE_SCENARIO_APP_ORIGIN = 'https://shelby.example';

/**
 * Builds the `fullMessage` an AIP-62 wallet would return from `aptos:signMessage`
 * for `{ message, nonce, address: true, application: true, chainId: true }`.
 *
 * Wire layout: literal prefix `APTOS`, then `<field>: <value>` lines joined by
 * `\n`, one per included field. This is the labeled multi-line encoding the
 * Aptos wallet-adapter implements; the canonical encoder/decoder pair lives at
 * https://github.com/aptos-labs/aptos-wallet-adapter/blob/294f5a49af55549a75e549ca0d303e45d70809bf/packages/derived-wallet-base/src/StructuredMessage.ts
 * (see `encodeStructuredMessage` / `decodeStructuredMessage`). The
 * `signMessage` API and `fullMessage` field are specified in AIP-62:
 * https://github.com/aptos-foundation/AIPs/blob/bb5b7ebcdb01b29622e968f785b03cd71cfb6c17/aips/aip-062-wallet-standard.md
 *
 * Worker-side parsing only requires the `APTOS` prefix and an `application:`
 * line (origin extraction); field ordering past that is not load-bearing.
 */
export function buildAptosWalletFullMessage(args: {
    accountAddress: AccountAddress | string;
    chainId: number;
    message: string;
    nonce: string;
    application?: string;
}): string {
    const address = typeof args.accountAddress === 'string'
        ? args.accountAddress
        : args.accountAddress.toStringLong();
    return [
        'APTOS',
        `address: ${address}`,
        `application: ${args.application ?? ACE_SCENARIO_APP_ORIGIN}`,
        `chainId: ${args.chainId}`,
        `message: ${args.message}`,
        `nonce: ${args.nonce}`,
    ].join('\n');
}
