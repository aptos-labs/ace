// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Generic streaming + seekable t-IBE API — the chunk-oriented sibling of the object-oriented
 * `t-ibe` API, wrapped by the chain-specific `StreamIBE_*` scopes.
 *
 * Streaming reuses the **shortsig-aead (block) key/share objects verbatim** — the crypto is
 * identical; only the DEM differs. So this module takes ordinary `tibe.MasterPublicKey` /
 * `tibe.IdentityDecryptionKeyShare` (scheme `shortsig-aead`) and applies the segmented DEM from
 * `../t-ibe/bfibe-bls12381-shortsig-aead-stream`.
 *
 * There is no `Ciphertext` type here: the output is a stream of **ciphertext chunks** (header
 * chunk, then segment chunks). The `primitive = 3` that distinguishes stream from block on the
 * ACE-node wire lives in the `StreamIBE_*` scopes / request layer, never in this API.
 */

import * as tibe from "../t-ibe";
import * as ShortSigAead from "../t-ibe/bfibe-bls12381-shortsig-aead";
import * as Stream from "../t-ibe/bfibe-bls12381-shortsig-aead-stream";

export const DEFAULT_CHUNK_SIZE = Stream.DEFAULT_CHUNK_SIZE;
/** 1-byte marker at the head of the first ciphertext chunk (the on-chain primitive). */
export const STREAM_MARKER = Stream.STREAM_MARKER;

export type CiphertextSource = Stream.CiphertextSource;
export type SeekableDecryptor = Stream.SeekableDecryptor;

type ByteChunks = AsyncIterable<Uint8Array> | Iterable<Uint8Array>;

function requireShortsigMpk(mpk: tibe.MasterPublicKey): ShortSigAead.MasterPublicKey {
    if (mpk.scheme !== tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD) {
        throw `t-ibe-stream: expected a shortsig-aead master public key (scheme ${tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD}), got ${mpk.scheme}`;
    }
    return mpk.inner as ShortSigAead.MasterPublicKey;
}

function requireShortsigShares(idkShares: tibe.IdentityDecryptionKeyShare[]): ShortSigAead.IdentityDecryptionKeyShare[] {
    return idkShares.map(s => {
        if (s.scheme !== tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD) {
            throw `t-ibe-stream: expected shortsig-aead IDK shares (scheme ${tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD}), got ${s.scheme}`;
        }
        return s.inner as ShortSigAead.IdentityDecryptionKeyShare;
    });
}

// The segment size is a fixed part of the wire format — it is NOT stored in the ciphertext, so the
// decryptor derives layout from the total length assuming a constant. It is therefore deliberately
// not a public parameter: encrypt and decrypt would have to agree with nothing enforcing it, and
// the caller's input chunking is already re-segmented internally. It stays a constant here and a
// knob only on the low-level DEM (below) that the tests / cross-impl vectors need.

/** Encrypt plaintext byte chunks into ciphertext byte chunks (header chunk, then segments). */
export function encryptStream({ mpk, id, plaintext, randomness }: {
    mpk: tibe.MasterPublicKey;
    id: Uint8Array;
    plaintext: ByteChunks;
    randomness?: Uint8Array;
}): AsyncGenerator<Uint8Array> {
    return Stream.encryptChunks(requireShortsigMpk(mpk), id, plaintext, { randomness });
}

/** Decrypt ciphertext byte chunks (any re-chunking) into plaintext byte chunks. Fails closed. */
export function decryptStream({ idkShares, ciphertextChunks }: {
    idkShares: tibe.IdentityDecryptionKeyShare[];
    ciphertextChunks: ByteChunks;
}): AsyncGenerator<Uint8Array> {
    return Stream.decryptChunks(requireShortsigShares(idkShares), ciphertextChunks);
}

/** Build a seekable decryptor over a random-access ciphertext source (see `CiphertextSource`). */
export function createSeekableDecryptor({ idkShares, ciphertextSource }: {
    idkShares: tibe.IdentityDecryptionKeyShare[];
    ciphertextSource: CiphertextSource;
}): Promise<SeekableDecryptor> {
    return Stream.createSeekableDecryptor({ idkShares: requireShortsigShares(idkShares), ciphertextSource });
}

// ── Byte-exact whole-buffer helpers (concatenated ciphertext chunks, for cross-impl vectors) ──
// These keep an explicit `chunkSize` because the fixtures pin multi-segment vectors with a tiny
// size to stay compact; they are not part of the streaming/seekable production surface.

export function encryptToConcatChunksWithRandomness({ mpk, id, plaintext, randomness, chunkSize }: {
    mpk: tibe.MasterPublicKey;
    id: Uint8Array;
    plaintext: Uint8Array;
    randomness: Uint8Array;
    chunkSize?: number;
}): Uint8Array {
    return Stream.encryptToConcatChunksWithRandomness(requireShortsigMpk(mpk), id, plaintext, randomness, chunkSize);
}

export function decryptFromConcatChunks({ idkShares, chunks, chunkSize }: {
    idkShares: tibe.IdentityDecryptionKeyShare[];
    chunks: Uint8Array;
    chunkSize?: number;
}): Uint8Array {
    return Stream.decryptFromConcatChunks(requireShortsigShares(idkShares), chunks, chunkSize);
}
