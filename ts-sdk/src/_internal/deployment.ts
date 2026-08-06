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

    constructor({apiEndpoint, contractAddr, apiKey, clientConfig}: {apiEndpoint: string, contractAddr: AccountAddress, apiKey?: string, clientConfig?: ClientConfig}) {
        this.apiEndpoint = apiEndpoint;
        this.contractAddr = contractAddr;
        this.apiKey = apiKey;
        this.clientConfig = clientConfig;
    }

    withApiKey(apiKey?: string): AceDeployment {
        return new AceDeployment({
            apiEndpoint: this.apiEndpoint,
            contractAddr: this.contractAddr,
            apiKey,
            clientConfig: this.clientConfig,
        });
    }

    withClientConfig(clientConfig?: ClientConfig): AceDeployment {
        return new AceDeployment({
            apiEndpoint: this.apiEndpoint,
            contractAddr: this.contractAddr,
            apiKey: this.apiKey,
            clientConfig,
        });
    }
}
