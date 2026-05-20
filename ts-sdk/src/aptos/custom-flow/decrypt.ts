// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import * as pke from "../../pke";
import {
    AceDeployment,
    ContractID,
    CustomFlowProof,
    CustomFlowRequest,
    fetchNetworkState,
    decryptCoreCustom,
} from "../../_internal/common";

export async function decrypt({
    ciphertext, label, encPk, encSk, payload,
    aceDeployment, keypairId, chainId, moduleAddr, moduleName, functionName,
}: {
    ciphertext: Uint8Array,
    label: Uint8Array,
    encPk: Uint8Array,
    encSk: Uint8Array,
    payload: Uint8Array,
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    chainId: number,
    moduleAddr: AccountAddress,
    moduleName: string,
    functionName: string,
}): Promise<Uint8Array> {
    const callerEncPk = pke.EncryptionKey.fromBytes(encPk)
        .unwrapOrThrow('AptosCustomFlow.decrypt: parse encPk');
    const callerDecSk = pke.DecryptionKey.fromBytes(encSk)
        .unwrapOrThrow('AptosCustomFlow.decrypt: parse encSk');

    const networkState = await fetchNetworkState(aceDeployment);
    const contractId = ContractID.newAptos({chainId, moduleAddr, moduleName, functionName});
    const proof = CustomFlowProof.createAptos(payload);
    const customRequest = new CustomFlowRequest({
        keypairId,
        epoch: networkState.epoch,
        contractId,
        label,
        encPk: callerEncPk,
        proof,
    });

    return (await decryptCoreCustom({
        aceDeployment,
        networkState,
        customRequest,
        callerDecryptionKey: callerDecSk,
        ciphertext,
    })).unwrapOrThrow('AptosCustomFlow.decrypt failed');
}
