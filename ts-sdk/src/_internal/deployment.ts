// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, ClientConfig } from "@aptos-labs/ts-sdk";

export class AceDeployment {
    apiEndpoint: string;
    contractAddr: AccountAddress;
    apiKey?: string;
    /**
     * Extra configuration for the underlying Aptos client, forwarded verbatim to
     * `AptosConfig.clientConfig`. Use this to reach the fullnode through a proxy,
     * add headers, or opt out of HTTP/2 on runtimes that do not support it.
     *
     * `apiKey` still owns the `Authorization` header; anything set here is merged
     * underneath it.
     *
     * Applies to the FULLNODE path only. It is not consulted when discovery mode is
     * active (`discoveryUrl` set and no `apiKey`) — that path never builds an Aptos
     * client, so proxy/header/HTTP-2 settings here have no effect there. See
     * `discoveryUrl` for the two-path model.
     */
    clientConfig?: ClientConfig;
    /**
     * Optional ACE discovery service base URL (lets the client read config without a node API key).
     * Normally baked into the `knownDeployments`
     * entry so a client gets rate-limit immunity just by upgrading the SDK — no code change.
     *
     * When set AND no `apiKey` is provided, the on-chain reads behind enc/dec/VRF operations
     * resolve from this service (one GET of an aggregated snapshot) instead of the fullnode REST
     * API — so no node API key and no backend proxy are needed. If `apiKey` is set, the fullnode
     * path takes priority and behavior is unchanged.
     *
     * This path uses the platform `fetch` (HTTP/1.1 by default) and never constructs an Aptos
     * client, so it is unaffected by `clientConfig` — and it naturally sidesteps the fullnode
     * client's default HTTP/2 attempt (see `clientConfig`). Worker share requests are direct
     * `fetch` POSTs regardless of path.
     */
    discoveryUrl?: string;

    constructor({apiEndpoint, contractAddr, apiKey, clientConfig, discoveryUrl}: {apiEndpoint: string, contractAddr: AccountAddress, apiKey?: string, clientConfig?: ClientConfig, discoveryUrl?: string}) {
        this.apiEndpoint = apiEndpoint;
        this.contractAddr = contractAddr;
        this.apiKey = apiKey;
        this.clientConfig = clientConfig;
        this.discoveryUrl = discoveryUrl;
    }

    withApiKey(apiKey?: string): AceDeployment {
        return new AceDeployment({
            apiEndpoint: this.apiEndpoint,
            contractAddr: this.contractAddr,
            apiKey,
            clientConfig: this.clientConfig,
            discoveryUrl: this.discoveryUrl,
        });
    }

    withClientConfig(clientConfig?: ClientConfig): AceDeployment {
        return new AceDeployment({
            apiEndpoint: this.apiEndpoint,
            contractAddr: this.contractAddr,
            apiKey: this.apiKey,
            clientConfig,
            discoveryUrl: this.discoveryUrl,
        });
    }
}
