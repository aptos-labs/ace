// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import * as tibe from "../t-ibe";
import * as tibeStream from "../t-ibe-stream";
import { AceDeployment } from "../_internal/common";
import { PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM } from "../network";
import { BasicDecryptionSession } from "../ibe-for-solana/basic-decryption-session";
import { fetchIdentityKeySharesCustomFlow } from "../ibe-for-solana/decrypt-custom-flow";

type ByteChunks = AsyncIterable<Uint8Array> | Iterable<Uint8Array>;

/** Solana streaming decryptor bound to already-fetched IDK shares — see the Aptos equivalent. */
export interface StreamDecryptor {
    idkShares: tibe.IdentityDecryptionKeyShare[];
    decryptStream(ciphertextChunks: ByteChunks): AsyncGenerator<Uint8Array>;
    createSeekableDecryptor(ciphertextSource: tibeStream.CiphertextSource): Promise<tibeStream.SeekableDecryptor>;
}

function makeDecryptor(idkShares: tibe.IdentityDecryptionKeyShare[], chunkSize?: number): StreamDecryptor {
    return {
        idkShares,
        decryptStream: (ciphertextChunks) => tibeStream.decryptStream({ idkShares, ciphertextChunks, chunkSize }),
        createSeekableDecryptor: (ciphertextSource) =>
            tibeStream.createSeekableDecryptor({ idkShares, ciphertextSource, chunkSize }),
    };
}

/**
 * Basic-flow streaming decrypt on Solana: sign the canonical request transaction once, fetch the
 * streaming-primitive (`3`) IDK shares, and return a `StreamDecryptor` over them.
 */
export async function createStreamDecryptorBasicFlow(args: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    knownChainName: string,
    programId: string,
    label: Uint8Array,
    signTxn: (fullRequestBytes: Uint8Array) => Promise<Uint8Array>,
    chunkSize?: number,
}): Promise<StreamDecryptor> {
    const session = await BasicDecryptionSession.create({
        aceDeployment: args.aceDeployment,
        keypairId: args.keypairId,
        knownChainName: args.knownChainName,
        programId: args.programId,
        label: args.label,
        primitive: PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM,
    });
    const fullRequestBytes = await session.getRequestToSign();
    const signedTxn = await args.signTxn(fullRequestBytes);
    const idkShares = (await session.fetchIdentityKeySharesWithProof({ txn: signedTxn }))
        .unwrapOrThrow('StreamIBE_Solana.basicFlow: fetchIdentityKeyShares failed');
    return makeDecryptor(idkShares, args.chunkSize);
}

/** Custom-flow streaming decrypt on Solana. */
export async function createStreamDecryptorCustomFlow(args: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    knownChainName: string,
    programId: string,
    label: Uint8Array,
    encPk: Uint8Array,
    encSk: Uint8Array,
    epoch: number,
    txn: Uint8Array,
    chunkSize?: number,
}): Promise<StreamDecryptor> {
    const idkShares = (await fetchIdentityKeySharesCustomFlow({
        label: args.label,
        encPk: args.encPk,
        encSk: args.encSk,
        epoch: args.epoch,
        txn: args.txn,
        aceDeployment: args.aceDeployment,
        keypairId: args.keypairId,
        knownChainName: args.knownChainName,
        programId: args.programId,
        // Forwarded into the request's `primitive` field.
        tibeScheme: PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM,
    })).unwrapOrThrow('StreamIBE_Solana.customFlow: fetchIdentityKeyShares failed');
    return makeDecryptor(idkShares, args.chunkSize);
}
