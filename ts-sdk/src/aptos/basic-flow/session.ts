// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, PublicKey, Signature } from "@aptos-labs/ts-sdk";
import { Result } from "../../result";
import * as pke from "../../pke";
import { State as NetworkState } from "../../network";
import {
    AceDeployment,
    ContractID,
    FullDecryptionDomain,
    ProofOfPermission,
    DecryptionRequestPayload,
    fetchNetworkStateAndBuildRequest,
    decryptCore,
} from "../../_internal/common";

export class DecryptionSession {
    aceDeployment: AceDeployment;
    fullDecryptionDomain: FullDecryptionDomain;
    ciphertext: Uint8Array;
    ephemeralDecryptionKey: pke.DecryptionKey;
    ephemeralEncryptionKey: pke.EncryptionKey;
    request: DecryptionRequestPayload | undefined;
    networkState: NetworkState | undefined;

    private constructor({
        aceDeployment, keypairId, chainId, moduleAddr, moduleName, functionName, domain, ciphertext,
        ephemeralEncryptionKey, ephemeralDecryptionKey,
    }: {
        aceDeployment: AceDeployment,
        keypairId: AccountAddress,
        chainId: number,
        moduleAddr: AccountAddress,
        moduleName: string,
        functionName?: string,
        domain: Uint8Array,
        ciphertext: Uint8Array,
        ephemeralEncryptionKey: pke.EncryptionKey,
        ephemeralDecryptionKey: pke.DecryptionKey,
    }) {
        this.aceDeployment = aceDeployment;
        if (functionName === undefined) functionName = 'check_permission';
        const contractId = ContractID.newAptos({chainId, moduleAddr, moduleName, functionName});
        this.fullDecryptionDomain = new FullDecryptionDomain({keypairId, contractId, domain});
        this.ciphertext = ciphertext;
        this.ephemeralEncryptionKey = ephemeralEncryptionKey;
        this.ephemeralDecryptionKey = ephemeralDecryptionKey;
    }

    static async create(params: {
        aceDeployment: AceDeployment,
        keypairId: AccountAddress,
        chainId: number,
        moduleAddr: AccountAddress,
        moduleName: string,
        functionName?: string,
        domain: Uint8Array,
        ciphertext: Uint8Array,
    }): Promise<DecryptionSession> {
        const {encryptionKey, decryptionKey} = await pke.keygen();
        return new DecryptionSession({
            ...params,
            ephemeralEncryptionKey: encryptionKey,
            ephemeralDecryptionKey: decryptionKey,
        });
    }

    async getRequestToSign(): Promise<string> {
        const {networkState, request} = await fetchNetworkStateAndBuildRequest(
            this.aceDeployment, this.fullDecryptionDomain, this.ephemeralEncryptionKey);
        this.networkState = networkState;
        this.request = request;
        return request.toPrettyMessage();
    }

    async decryptWithProof({userAddr, publicKey, signature, fullMessage}: {
        userAddr: AccountAddress,
        publicKey: PublicKey,
        signature: Signature,
        fullMessage?: string,
    }): Promise<Result<Uint8Array>> {
        if (fullMessage === undefined) fullMessage = this.request!.toPrettyMessage();
        const proof = ProofOfPermission.createAptos({userAddr, publicKey, signature, fullMessage});
        return decryptCore({
            aceDeployment: this.aceDeployment,
            networkState: this.networkState!,
            request: this.request!,
            proof,
            ephemeralDecryptionKey: this.ephemeralDecryptionKey,
            ciphertext: this.ciphertext,
        });
    }
}
