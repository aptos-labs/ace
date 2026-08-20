// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { GasStationTransactionSubmitter } from '@aptos-labs/gas-station-client';
import { Network } from '@aptos-labs/ts-sdk';
import type { TransactionSubmitter } from '@aptos-labs/ts-sdk';

export interface GasStationOptions {
    network: Network;
    apiKey: string;
    baseUrl?: string;
}

export function gasStationOptions(rpcUrl: string, network: Network, apiKey: string): GasStationOptions {
    return {
        network,
        apiKey,
        ...gasStationBaseUrlForRpcUrl(rpcUrl),
    };
}

function gasStationBaseUrlForRpcUrl(rpcUrl: string): { baseUrl: string } | {} {
    let host: string;
    let origin: string;
    try {
        const url = new URL(rpcUrl);
        host = url.hostname.toLowerCase();
        origin = url.origin;
    } catch {
        return {};
    }

    if (host === 'api.shelbynet.shelby.xyz' || host === 'api.shelbynet.aptoslabs.com') {
        return { baseUrl: `${origin}/gs/v1` };
    }
    return {};
}

/**
 * `@aptos-labs/gas-station-client@2.0.3` depends on `@aptos-labs/ts-sdk@^5`
 * and is typed against that copy. The plugin talks BCS bytes and ignores
 * `aptosConfig`, so it is compatible with ts-sdk v7 at runtime; wrap
 * `submitTransaction` so the v7 `TransactionSubmitter` shape is checked
 * without asserting the v5 class. Preserves the per-host `baseUrl` selection
 * from `gasStationOptions` (e.g. shelbynet). Drop this helper when
 * gas-station-client supports ts-sdk `^7`.
 */
export function gasStationTransactionSubmitter(
    rpcUrl: string,
    network: Network,
    apiKey: string,
): TransactionSubmitter {
    const gs = new GasStationTransactionSubmitter(gasStationOptions(rpcUrl, network, apiKey));
    return {
        submitTransaction: (submitArgs) => gs.submitTransaction(submitArgs as never),
    };
}
