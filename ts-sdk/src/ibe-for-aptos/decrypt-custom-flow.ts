// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import * as pke from "../pke";
import * as tibe from "../t-ibe";
import {
    AceDeployment,
    ContractID,
    CustomFlowProof,
    CustomFlowRequest,
    fetchNetworkState,
    decryptWithIdentityKeyShares,
    fetchIdentityKeySharesCoreCustom,
} from "../_internal/common";

export async function fetchIdentityKeySharesCustomFlow({
    label, encPk, encSk, payload,
    aceDeployment, keypairId, chainId, moduleAddr, moduleName, tibeScheme,
}: {
    label: Uint8Array,
    encPk: Uint8Array,
    encSk: Uint8Array,
    payload: Uint8Array,
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    chainId: number,
    moduleAddr: AccountAddress,
    moduleName: string,
    tibeScheme?: number,
}): Promise<Result<tibe.IdentityDecryptionKeyShare[]>> {
    return Result.captureAsync({
        recordsExecutionTimeMs: true,
        task: async () => {
            const callerEncPk = pke.EncryptionKey.fromBytes(encPk)
                .unwrapOrThrow('AptosCustomFlow.fetchIdentityKeyShares: parse encPk');
            const callerDecSk = pke.DecryptionKey.fromBytes(encSk)
                .unwrapOrThrow('AptosCustomFlow.fetchIdentityKeyShares: parse encSk');

            const networkState = await fetchNetworkState(aceDeployment);
            const contractId = ContractID.newAptos({chainId, moduleAddr, moduleName});
            const proof = CustomFlowProof.createAptos(payload);
            const customRequest = new CustomFlowRequest({
                keypairId,
                epoch: networkState.epoch,
                contractId,
                label,
                encPk: callerEncPk,
                proof,
            });

            return (await fetchIdentityKeySharesCoreCustom({
                aceDeployment,
                networkState,
                customRequest,
                callerDecryptionKey: callerDecSk,
                tibeScheme: tibeScheme ?? tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
            })).unwrapOrThrow('AptosCustomFlow.fetchIdentityKeyShares failed');
        },
    });
}

export async function decryptCustomFlow(args: {
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
}): Promise<Result<Uint8Array>> {
    return Result.captureAsync({
        recordsExecutionTimeMs: true,
        task: async () => {
            const tibeScheme = tibe.Ciphertext.fromBytes(args.ciphertext)
                .unwrapOrThrow('AptosCustomFlow.decrypt failed')
                .scheme;
            const identityKeySharesResult = await fetchIdentityKeySharesCustomFlow({
                label: args.label,
                encPk: args.encPk,
                encSk: args.encSk,
                payload: args.payload,
                aceDeployment: args.aceDeployment,
                keypairId: args.keypairId,
                chainId: args.chainId,
                moduleAddr: args.moduleAddr,
                moduleName: args.moduleName,
                tibeScheme,
            });
            return decryptWithIdentityKeyShares({
                ciphertext: args.ciphertext,
                identityKeyShares: identityKeySharesResult.unwrapOrThrow('AptosCustomFlow.decrypt failed'),
            }).unwrapOrThrow('AptosCustomFlow.decrypt failed');
        },
    });
}
