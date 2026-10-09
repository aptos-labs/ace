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
    getChainReader,
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
    const callerEncPk = pke.EncryptionKey.fromBytes(encPk)
        .unwrapOrThrow('AptosCustomFlow.fetchIdentityKeyShares: parse encPk');
    const callerDecSk = pke.DecryptionKey.fromBytes(encSk)
        .unwrapOrThrow('AptosCustomFlow.fetchIdentityKeyShares: parse encSk');

    const reader = getChainReader(aceDeployment);
    const networkState = await reader.networkState();
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

    return fetchIdentityKeySharesCoreCustom({
        reader,
        networkState,
        customRequest,
        callerDecryptionKey: callerDecSk,
        primitive: tibeScheme ?? tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
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
}): Promise<Uint8Array> {
    const ciphertext = tibe.Ciphertext.fromBytes(args.ciphertext);
    if (!ciphertext.isOk) {
        throw new Error('AptosCustomFlow.decrypt failed (parse ciphertext)', {cause: ciphertext.errValue});
    }

    let identityKeySharesResult: Result<tibe.IdentityDecryptionKeyShare[]>;
    try {
        identityKeySharesResult = await fetchIdentityKeySharesCustomFlow({
            label: args.label,
            encPk: args.encPk,
            encSk: args.encSk,
            payload: args.payload,
            aceDeployment: args.aceDeployment,
            keypairId: args.keypairId,
            chainId: args.chainId,
            moduleAddr: args.moduleAddr,
            moduleName: args.moduleName,
            tibeScheme: ciphertext.okValue!.scheme,
        });
    } catch (cause) {
        throw new Error('AptosCustomFlow.decrypt failed (fetch identity key shares)', {cause});
    }
    if (!identityKeySharesResult.isOk) {
        throw new Error('AptosCustomFlow.decrypt failed (fetch identity key shares)', {cause: identityKeySharesResult.errValue});
    }

    const decrypted = decryptWithIdentityKeyShares({
        ciphertext: args.ciphertext,
        identityKeyShares: identityKeySharesResult.okValue!,
    });
    if (!decrypted.isOk) {
        throw new Error('AptosCustomFlow.decrypt failed (local decrypt)', {cause: decrypted.errValue});
    }
    return decrypted.okValue!;
}
