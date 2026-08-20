// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Network } from '@aptos-labs/ts-sdk';

/** Map an RPC URL to the ts-sdk `Network` used for AptosConfig / gas-station hosts. */
export function inferNetwork(rpcUrl: string): Network {
    const url = rpcUrl.toLowerCase();
    if (url.includes('mainnet')) return Network.MAINNET;
    if (url.includes('testnet')) return Network.TESTNET;
    if (url.includes('devnet')) return Network.DEVNET;
    if (url.includes('localhost') || url.includes('127.0.0.1')) return Network.LOCAL;
    // ACE's private Shelby deployment is not public shelbynet (and contains "shelby").
    if (url.includes('shelby-private-beta')) return Network.CUSTOM;
    if (url.includes('shelbynet') || url.includes('shelby')) return Network.SHELBYNET;
    if (url.includes('netna')) return Network.NETNA;
    return Network.CUSTOM;
}
