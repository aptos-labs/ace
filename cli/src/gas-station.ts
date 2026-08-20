// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { GasStationTransactionSubmitter } from '@aptos-labs/gas-station-client';
import type { Network, TransactionSubmitter } from '@aptos-labs/ts-sdk';

/**
 * `@aptos-labs/gas-station-client@2.0.3` depends on `@aptos-labs/ts-sdk@^5`.
 * The plugin talks BCS bytes and ignores `aptosConfig`; wrap `submitTransaction`
 * so the v7 `TransactionSubmitter` shape is checked without asserting the v5
 * class. Drop this helper when gas-station-client supports ts-sdk `^7`.
 */
export function gasStationTransactionSubmitter(args: {
    network: Network;
    apiKey: string;
}): TransactionSubmitter {
    const gs = new GasStationTransactionSubmitter({
        apiKey: args.apiKey,
        baseUrl: `https://api.${args.network}.aptoslabs.com/gs/v1`,
    });
    return {
        submitTransaction: (submitArgs) => gs.submitTransaction(submitArgs as never),
    };
}
