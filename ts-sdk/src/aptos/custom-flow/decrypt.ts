// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { AceDeployment } from "../../_internal/common";

// Node protocol for custom-flow decryption is not yet defined.
export async function decrypt(
    _ciphertext: Uint8Array,
    _label: Uint8Array,
    _encPk: Uint8Array,
    _encSk: Uint8Array,
    _payload: Uint8Array,
    _aceDeployment: AceDeployment,
    _keypairId: AccountAddress,
    _chainId: number,
    _moduleAddr: AccountAddress,
    _moduleName: string,
    _functionName: string,
): Promise<Uint8Array> {
    throw new Error('AptosCustomFlow.decrypt: not yet implemented');
}
