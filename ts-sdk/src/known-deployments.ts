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
    preview20260714: knownDeployment({
        chainId: 2,
        aceDeployment: new AceDeployment({
            apiEndpoint: 'https://api.testnet.aptoslabs.com/v1',
            contractAddr: AccountAddress.fromString('0x8fbdf62c41ec553cf5519da36eafb1a27edf0184db7295d7ef2b921eb5775094'),
        }),
        ibeKeypairId: AccountAddress.fromString('0xf82778e10e7d442be0f6fad8f3fc2a40607afb6e08e54fa85159ec578fe4373b'),
        vrfKeypairId: AccountAddress.fromString('0x4764be8a1b379ac7507f3e29956b5037c88b4706ced12d8378d90fec69896bf2'),
    }),
} as const;
