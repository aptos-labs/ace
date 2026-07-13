// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { AceDeployment } from "../_internal/common";
import { Result } from "../result";
import * as pke from "../pke";
import * as tibe from "../t-ibe";
import {
    decryptCustomFlow,
    fetchIdentityKeySharesCustomFlow,
} from "./decrypt-custom-flow";

export type CustomDecryptionSessionArgs = {
    aceDeployment: AceDeployment;
    keypairId: AccountAddress;
    chainId: number;
    moduleAddr: AccountAddress;
    moduleName: string;
    label: Uint8Array;
};

/**
 * Holds the one-time response encryption keypair for a custom-flow request.
 * This prevents callers from accidentally proving possession for one encPk
 * while passing an unrelated encSk to the worker response path.
 */
export class CustomDecryptionSession {
    private readonly args: CustomDecryptionSessionArgs;
    private readonly encryptionKey: pke.EncryptionKey;
    private readonly decryptionKey: pke.DecryptionKey;

    private constructor(
        args: CustomDecryptionSessionArgs,
        encryptionKey: pke.EncryptionKey,
        decryptionKey: pke.DecryptionKey,
    ) {
        this.args = args;
        this.encryptionKey = encryptionKey;
        this.decryptionKey = decryptionKey;
    }

    static async create(args: CustomDecryptionSessionArgs): Promise<CustomDecryptionSession> {
        const { encryptionKey, decryptionKey } = await pke.keygen();
        return new CustomDecryptionSession(args, encryptionKey, decryptionKey);
    }

    /** Public key bytes that the app-defined proof must bind as `enc_pk`. */
    getEncryptionKeyBytes(): Uint8Array {
        return this.encryptionKey.toBytes();
    }

    async fetchIdentityKeyShares({
        payload,
        tibeScheme,
    }: {
        payload: Uint8Array;
        tibeScheme?: number;
    }): Promise<Result<tibe.IdentityDecryptionKeyShare[]>> {
        return fetchIdentityKeySharesCustomFlow({
            ...this.args,
            encPk: this.encryptionKey.toBytes(),
            encSk: this.decryptionKey.toBytes(),
            payload,
            tibeScheme,
        });
    }

    async decrypt({
        ciphertext,
        payload,
    }: {
        ciphertext: Uint8Array;
        payload: Uint8Array;
    }): Promise<Result<Uint8Array>> {
        return decryptCustomFlow({
            ...this.args,
            ciphertext,
            encPk: this.encryptionKey.toBytes(),
            encSk: this.decryptionKey.toBytes(),
            payload,
        });
    }
}
