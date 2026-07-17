// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Network } from '@aptos-labs/ts-sdk';

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
