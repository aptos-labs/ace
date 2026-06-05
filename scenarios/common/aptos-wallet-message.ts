// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from '@aptos-labs/ts-sdk';

export const ACE_SCENARIO_APP_ORIGIN = 'https://shelby.example';

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
