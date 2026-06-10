// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { AceDeployment } from "./_internal/common";

export const knownDeployments = {
    preview20260430: {
        chainId: 2,
        aceDeployment: new AceDeployment({
            apiEndpoint: 'https://api.testnet.aptoslabs.com/v1',
            contractAddr: AccountAddress.fromString('0xa8901d400cb74ad6309ebfc6ef48761ae5e5a307e3f3d727412d67fc1bc4c629'),
        }),
        keypairId: AccountAddress.fromString('0xa3dbce2724e053ce9cb00384255efaed27f1c920d0b4cf82d9fdecbaa27ca5af'),
    },
    preview20260501: {
        chainId: 2,
        aceDeployment: new AceDeployment({
            apiEndpoint: 'https://api.testnet.aptoslabs.com/v1',
            contractAddr: AccountAddress.fromString('0xf45a5462b922731be6732f68099b9990a6e69e1072d971a2dde5bfe9539b2750'),
        }),
        keypairId: AccountAddress.fromString('0x3d9a818deeb290e8cf79589ef57e0afa9b241cbaecc1b23682fb6e9b3a54c77c'),
    },
    preview20260504: {
        chainId: 2,
        aceDeployment: new AceDeployment({
            apiEndpoint: 'https://api.testnet.aptoslabs.com/v1',
            contractAddr: AccountAddress.fromString('0x97c41a8ea25534a469ba079ed9007b9d08610e981c4d1962948247fa8595354c'),
        }),
        keypairId: AccountAddress.fromString('0xdcf7992d1458683ac63420cfa8ff3726639b9c467e5eb0104253f2541fcfdc96'),
    },
    preview20260506: {
        chainId: 2,
        aceDeployment: new AceDeployment({
            apiEndpoint: 'https://api.testnet.aptoslabs.com/v1',
            contractAddr: AccountAddress.fromString('0x8413bde991653f1b486cfba2aa2d05c8f179ada9f6174188387cf35a95caaa76'),
        }),
        keypairId: AccountAddress.fromString('0x0e3da06e527b86eb2d43010fe5b39133b883ac84537a45c82d4ccc95922bc08b'),
    },
    preview20260610: {
        chainId: 2,
        aceDeployment: new AceDeployment({
            apiEndpoint: 'https://api.testnet.aptoslabs.com/v1',
            contractAddr: AccountAddress.fromString('0x19ca96aabae3230c67f35b64b004c0f7480f51d81648f416a39c960de119b251'),
        }),
        ibeKeypairId: AccountAddress.fromString('0xbb83c1eb79580d9e23639fa28373047f64d2c8bd3526590d2d886cf91fb5a307'),
        vrfKeypairId: AccountAddress.fromString('0x3ca79722e34031f87ef5be65890d2c12d742390a641d9b1f0333155eda67dd9d'),
    },
} as const;
