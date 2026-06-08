// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import { AceDeployment } from "../_internal/common";
import { BasicDecryptionSession } from "./basic-decryption-session";

/**
 * One-shot wrapper around `BasicDecryptionSession.create →
 * getRequestToSign → decryptWithProof`. The Solana auth proof is a
 * signed Solana transaction whose instruction data commits to the
 * canonical request bytes the session emits.
 *
 * Use the two-phase `BasicDecryptionSession` API directly when a wallet
 * UI needs to render the request to the user before signing.
 */
export async function decryptBasicFlow(args: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    knownChainName: string,
    programId: string,
    label: Uint8Array,
    ciphertext: Uint8Array,
    signTxn: (fullRequestBytes: Uint8Array) => Promise<Uint8Array>,
}): Promise<Result<Uint8Array>> {
    const session = await BasicDecryptionSession.create({
        aceDeployment: args.aceDeployment,
        keypairId: args.keypairId,
        knownChainName: args.knownChainName,
        programId: args.programId,
        label: args.label,
        ciphertext: args.ciphertext,
    });
    const fullRequestBytes = await session.getRequestToSign();
    const signedTxn = await args.signTxn(fullRequestBytes);
    return session.decryptWithProof({ txn: signedTxn });
}
