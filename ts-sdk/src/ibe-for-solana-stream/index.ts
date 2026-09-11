// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// StreamIBE_Solana — streaming + seekable IBE for Solana. Chunk-in / chunk-out; no scheme param,
// no ciphertext object. Internally the streaming primitive (3) is set on the ACE-node request.

export { encryptStream, fetchPk } from "./encrypt";
export type { StreamDecryptor } from "./decrypt";
export { createStreamDecryptorBasicFlow, createStreamDecryptorCustomFlow } from "./decrypt";
