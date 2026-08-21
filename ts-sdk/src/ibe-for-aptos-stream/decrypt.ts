// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, PublicKey, Signature } from "@aptos-labs/ts-sdk";
import * as tibe from "../t-ibe";
import * as tibeStream from "../t-ibe-stream";
import { AceDeployment } from "../_internal/common";
import { PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM } from "../network";
import { BasicDecryptionSession } from "../ibe-for-aptos/basic-decryption-session";
import { fetchIdentityKeySharesCustomFlow } from "../ibe-for-aptos/decrypt-custom-flow";

type ByteChunks = AsyncIterable<Uint8Array> | Iterable<Uint8Array>;

/**
 * A streaming decryptor bound to an already-fetched set of t-of-n IDK shares. Authenticate once to
 * obtain the shares (tiny, payload-independent), then stream-decrypt or seek arbitrarily many times
 * over the same shares — the network round-trip is not repeated per read.
 */
export interface StreamDecryptor {
    idkShares: tibe.IdentityDecryptionKeyShare[];
    /** Forward-decrypt an (async) iterable of ciphertext chunks → plaintext byte chunks. */
    decryptStream(ciphertextChunks: ByteChunks): AsyncGenerator<Uint8Array>;
    /** Random-access decrypt over stored ciphertext chunks (web-video seek). */
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
 * Basic-flow streaming decrypt: sign the canonical decryption request once, fetch the IDK shares
 * for the streaming primitive (`3`), and return a `StreamDecryptor` over them. No ciphertext is
 * needed to fetch shares (streaming is fixed by the scope), so the decryptor can be obtained before
 * the ciphertext stream/source is available.
 */
export async function createStreamDecryptorBasicFlow(args: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    chainId: number,
    moduleAddr: AccountAddress,
    moduleName: string,
    label: Uint8Array,
    accountAddress: AccountAddress,
    sign: (msgToSign: string) => Promise<{ pubKey: PublicKey; signature: Signature; fullMessage: string }>,
    chunkSize?: number,
}): Promise<StreamDecryptor> {
    const session = await BasicDecryptionSession.create({
        aceDeployment: args.aceDeployment,
        keypairId: args.keypairId,
        chainId: args.chainId,
        moduleAddr: args.moduleAddr,
        moduleName: args.moduleName,
        label: args.label,
        primitive: PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM,
    });
    const message = await session.getRequestToSign();
    const { pubKey, signature, fullMessage } = await args.sign(message);
    const idkShares = (await session.fetchIdentityKeySharesWithProof({
        userAddr: args.accountAddress, publicKey: pubKey, signature, fullMessage,
    })).unwrapOrThrow('StreamIBE_Aptos.basicFlow: fetchIdentityKeyShares failed');
    return makeDecryptor(idkShares, args.chunkSize);
}

/**
 * Custom-flow (app-supplied proof, e.g. ZK) streaming decrypt: fetch the streaming-primitive IDK
 * shares and return a `StreamDecryptor` over them.
 */
export async function createStreamDecryptorCustomFlow(args: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    chainId: number,
    moduleAddr: AccountAddress,
    moduleName: string,
    label: Uint8Array,
    encPk: Uint8Array,
    encSk: Uint8Array,
    payload: Uint8Array,
    chunkSize?: number,
}): Promise<StreamDecryptor> {
    const idkShares = (await fetchIdentityKeySharesCustomFlow({
        label: args.label,
        encPk: args.encPk,
        encSk: args.encSk,
        payload: args.payload,
        aceDeployment: args.aceDeployment,
        keypairId: args.keypairId,
        chainId: args.chainId,
        moduleAddr: args.moduleAddr,
        moduleName: args.moduleName,
        // The custom-flow helper forwards this into the request's `primitive` field.
        tibeScheme: PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM,
    })).unwrapOrThrow('StreamIBE_Aptos.customFlow: fetchIdentityKeyShares failed');
    return makeDecryptor(idkShares, args.chunkSize);
}
