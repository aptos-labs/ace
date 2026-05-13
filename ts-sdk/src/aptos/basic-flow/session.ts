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
    /** If set, send the V2 wire variant so workers don't have to derive
     *  the t-IBE scheme from the share's group. Defaults to undefined (V1). */
    tibeScheme: number | undefined;
    request: DecryptionRequestPayload | undefined;
    networkState: NetworkState | undefined;

    private constructor({
        aceDeployment, keypairId, chainId, moduleAddr, moduleName, functionName, domain, ciphertext,
        ephemeralEncryptionKey, ephemeralDecryptionKey, tibeScheme,
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
        tibeScheme?: number,
    }) {
        this.aceDeployment = aceDeployment;
        if (functionName === undefined) functionName = 'check_permission';
        const contractId = ContractID.newAptos({chainId, moduleAddr, moduleName, functionName});
        this.fullDecryptionDomain = new FullDecryptionDomain({keypairId, contractId, domain});
        this.ciphertext = ciphertext;
        this.ephemeralEncryptionKey = ephemeralEncryptionKey;
        this.ephemeralDecryptionKey = ephemeralDecryptionKey;
        this.tibeScheme = tibeScheme;
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
        /** Opt into V2 wire format. The value should match the t-IBE scheme
         *  the ciphertext was produced with; the worker validates it against
         *  the share's group. If omitted, V1 is sent and the worker guesses. */
        tibeScheme?: number,
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
            tibeScheme: this.tibeScheme,
        });
    }
}
