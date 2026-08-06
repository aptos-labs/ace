// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, ClientConfig } from "@aptos-labs/ts-sdk";
import { AceDeployment } from "./_internal/deployment";

/** A known deployment plus the builders that override its connection settings. */
type KnownDeployment<T> = T & {
    withApiKey(apiKey?: string): KnownDeployment<T>;
    withClientConfig(clientConfig?: ClientConfig): KnownDeployment<T>;
};

/**
 * Wraps a deployment so its connection settings can be overridden. The builders
 * return wrapped deployments too, so they can be chained — a caller that needs
 * both an API key and custom client settings applies them in either order.
 */
function knownDeployment<const T extends { aceDeployment: AceDeployment }>(
    deployment: T,
): KnownDeployment<T> {
    return {
        ...deployment,
        withApiKey(apiKey?: string): KnownDeployment<T> {
            return knownDeployment({
                ...deployment,
                aceDeployment: deployment.aceDeployment.withApiKey(apiKey),
            });
        },
        withClientConfig(clientConfig?: ClientConfig): KnownDeployment<T> {
            return knownDeployment({
                ...deployment,
                aceDeployment: deployment.aceDeployment.withClientConfig(clientConfig),
            });
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
    'shelby-beta-usce1': knownDeployment({
        chainId: 125,
        aceDeployment: new AceDeployment({
            apiEndpoint: 'https://api.beta.shelby.xyz/v1',
            contractAddr: AccountAddress.fromString('0x086f9a291d3d28140413505f6224d10e07cb6d6d08ab5933f62ff1b685830408'),
        }),
        ibeKeypairId: AccountAddress.fromString('0x50ca2eb86412416256522777770b9846ced2b0185db1d301f233d5f47215f4c3'),
        vrfKeypairId: AccountAddress.fromString('0xf47b51b8c648a3dd53a1c0ec5d38e2b861f0b6d4c3181f0b84b0d535e274a98d'),
    }),
    'shelbynet-20260731': knownDeployment({
        chainId: 118,
        aceDeployment: new AceDeployment({
            apiEndpoint: 'https://api.shelbynet.shelby.xyz/v1',
            contractAddr: AccountAddress.fromString('0x2a800d06b231476e045e874b5319409f80aa4449d7cabcdc68d2e0b5a66ee43d'),
        }),
        ibeKeypairId: AccountAddress.fromString('0xa36e6db16b015c6c2c9a376afe3075b11031ee0df393c226e7d599f615759a17'),
        vrfKeypairId: AccountAddress.fromString('0xa36e6db16b015c6c2c9a376afe3075b11031ee0df393c226e7d599f615759a17'),
    }),
} as const;
