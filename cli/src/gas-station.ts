// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { GasStationTransactionSubmitter } from '@aptos-labs/gas-station-client';
import type { Network, TransactionSubmitter } from '@aptos-labs/ts-sdk';

/**
 * `@aptos-labs/gas-station-client@2.0.3` depends on `@aptos-labs/ts-sdk@^5`
 * and is typed against that copy. The plugin interface is compatible with
 * ts-sdk v7 at runtime, so we bridge the duplicate `AptosConfig` types here.
 */
export function gasStationTransactionSubmitter(args: {
    network: Network;
    apiKey: string;
}): TransactionSubmitter {
    return new GasStationTransactionSubmitter(args) as unknown as TransactionSubmitter;
}
