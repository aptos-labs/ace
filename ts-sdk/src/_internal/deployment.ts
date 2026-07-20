// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";

export class AceDeployment {
    apiEndpoint: string;
    contractAddr: AccountAddress;
    apiKey?: string;

    constructor({apiEndpoint, contractAddr, apiKey}: {apiEndpoint: string, contractAddr: AccountAddress, apiKey?: string}) {
        this.apiEndpoint = apiEndpoint;
        this.contractAddr = contractAddr;
        this.apiKey = apiKey;
    }

    withApiKey(apiKey?: string): AceDeployment {
        return new AceDeployment({
            apiEndpoint: this.apiEndpoint,
            contractAddr: this.contractAddr,
            apiKey,
        });
    }
}
