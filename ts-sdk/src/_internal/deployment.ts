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
     */
    clientConfig?: ClientConfig;
    /**
     * Optional keyless ACE discovery service base URL. Normally baked into the `knownDeployments`
     * entry so a client gets rate-limit immunity just by upgrading the SDK — no code change. When
     * set AND no `apiKey` is provided, the on-chain reads behind enc/dec/VRF operations resolve
     * from this service (one GET of an aggregated snapshot) instead of the fullnode REST API. If
     * `apiKey` is set, the fullnode path takes priority and behavior is unchanged.
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
