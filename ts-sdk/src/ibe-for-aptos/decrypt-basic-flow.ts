// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, PublicKey, Signature } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import { AceDeployment } from "../_internal/common";
import { BasicDecryptionSession } from "./basic-decryption-session";

/**
 * One-shot wrapper around `BasicDecryptionSession.create →
 * getRequestToSign → decryptWithProof`. For CLIs / scripts /
 * server-side jobs that already know how to sign and don't need to
 * keep the session object around between phases.
 *
 * Use the two-phase `BasicDecryptionSession` API directly when a wallet
 * UI needs to render the canonical request message to the user before
 * the signature happens.
 */
export async function decryptBasicFlow(args: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    chainId: number,
    moduleAddr: AccountAddress,
    moduleName: string,
    label: Uint8Array,
    ciphertext: Uint8Array,
    accountAddress: AccountAddress,
    sign: (msgToSign: string) => Promise<{
        pubKey: PublicKey;
        signature: Signature;
        fullMessage: string;
    }>;
}): Promise<Result<Uint8Array>> {
    const session = await BasicDecryptionSession.create({
        aceDeployment: args.aceDeployment,
        keypairId: args.keypairId,
        chainId: args.chainId,
        moduleAddr: args.moduleAddr,
        moduleName: args.moduleName,
        label: args.label,
        ciphertext: args.ciphertext,
    });
    const message = await session.getRequestToSign();
    const { pubKey, signature, fullMessage } = await args.sign(message);
    return session.decryptWithProof({
        userAddr: args.accountAddress,
        publicKey: pubKey,
        signature,
        fullMessage,
    });
}
