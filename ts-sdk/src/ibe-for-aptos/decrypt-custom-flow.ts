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
    aceDeployment, keypairId, chainId, moduleAddr, moduleName, tibeScheme, detailedErrors = false,
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
    detailedErrors?: boolean,
}): Promise<Result<tibe.IdentityDecryptionKeyShare[]>> {
    const callerEncPk = pke.EncryptionKey.fromBytes(encPk)
        .unwrapOrThrow('AptosCustomFlow.fetchIdentityKeyShares: parse encPk', detailedErrors);
    const callerDecSk = pke.DecryptionKey.fromBytes(encSk)
        .unwrapOrThrow('AptosCustomFlow.fetchIdentityKeyShares: parse encSk', detailedErrors);

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
    /** Opt in to Error.cause chains on failure; default thrown values remain unchanged. */
    detailedErrors?: boolean,
}): Promise<Uint8Array> {
    const detailedErrors = args.detailedErrors ?? false;
    const errorMessage = (stage: string) => detailedErrors
        ? `AptosCustomFlow.decrypt failed (${stage})`
        : 'AptosCustomFlow.decrypt failed';
    const tibeScheme = tibe.Ciphertext.fromBytes(args.ciphertext)
        .unwrapOrThrow(errorMessage('parse ciphertext'), detailedErrors)
        .scheme;

    const sharesPromise = fetchIdentityKeySharesCustomFlow({
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
        detailedErrors,
    });
    const identityKeySharesResult = detailedErrors
        ? await sharesPromise.catch(cause => { throw new Error(errorMessage('fetch identity key shares'), {cause}); })
        : await sharesPromise;
    return decryptWithIdentityKeyShares({
        ciphertext: args.ciphertext,
        identityKeyShares: identityKeySharesResult.unwrapOrThrow(errorMessage('fetch identity key shares'), detailedErrors),
        detailedErrors,
    }).unwrapOrThrow(errorMessage('local decrypt'), detailedErrors);
}
