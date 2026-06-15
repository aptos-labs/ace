// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { AceDeployment } from "./_internal/common";

function knownDeployment<const T extends { aceDeployment: AceDeployment }>(
    deployment: T,
): T & { withApiKey(apiKey?: string): T } {
    return {
        ...deployment,
        withApiKey(apiKey?: string): T {
            return {
                ...deployment,
                aceDeployment: deployment.aceDeployment.withApiKey(apiKey),
            };
        },
    };
}

export const knownDeployments = {
    preview20260610: knownDeployment({
        chainId: 2,
        aceDeployment: new AceDeployment({
            apiEndpoint: 'https://api.testnet.aptoslabs.com/v1',
            contractAddr: AccountAddress.fromString('0x19ca96aabae3230c67f35b64b004c0f7480f51d81648f416a39c960de119b251'),
        }),
        ibeKeypairId: AccountAddress.fromString('0xbb83c1eb79580d9e23639fa28373047f64d2c8bd3526590d2d886cf91fb5a307'),
        vrfKeypairId: AccountAddress.fromString('0x3ca79722e34031f87ef5be65890d2c12d742390a641d9b1f0333155eda67dd9d'),
    }),
} as const;
