// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

use super::{aptos_any as any, aptos_multi_ed25519 as multi_ed25519, aptos_multi_key as multi_key};

#[derive(Serialize, Deserialize)]
pub struct AptosContractId {
    pub chain_id: u8,
    pub module_addr: [u8; 32],
    pub module_name: String,
}

/// Proof of permission for a basic-flow Aptos request.
///
/// `pk_scheme` / `sig_scheme` already disambiguate which inner type lives in
/// `public_key` / `signature` on the wire; we use those tags to deserialize
/// directly into a typed enum, no `Vec<u8>` framing. The custom serde impls
/// below match the inline encoding the TS SDK writes — see
/// `ts-sdk/src/_internal/aptos.ts`.
pub struct AptosProofOfPermission {
    pub user_addr: [u8; 32],
    pub pk_scheme: u8,
    pub public_key: AptosPublicKeyMaterial,
    pub sig_scheme: u8,
    pub signature: AptosSignatureMaterial,
    pub full_message: String,
}

/// Inner public-key payload for [`AptosProofOfPermission`].
#[derive(Clone, Debug)]
pub enum AptosPublicKeyMaterial {
    /// pk_scheme=0. BCS wire is `Vec<u8>(32 bytes)` — the natural BCS of
    /// `aptos_crypto::Ed25519PublicKey` (whose serde derive emits
    /// `serialize_bytes(&self.0)`).
    Ed25519([u8; 32]),
    /// pk_scheme=1. BCS wire is `ULEB128(any_variant) || BCS(inner)`. See
    /// [`any::AnyPublicKeyInner`] for the inner variant layout; the same
    /// account model also covers Secp256k1Ecdsa, Secp256r1Ecdsa, Keyless,
    /// and FederatedKeyless under a single SingleKey auth-key derivation.
    Any(any::AnyPublicKeyInner),
    /// pk_scheme=2. BCS wire is `serialize_bytes(pk_1 || ... || pk_N || threshold)`
    /// — the flat-concat layout from aptos-core's
    /// `MultiEd25519PublicKey::to_bytes`. Legacy K-of-N over raw Ed25519
    /// keys; auth-key derivation uses `Scheme::MultiEd25519 = 0x01`.
    MultiEd25519(multi_ed25519::MultiEd25519PublicKeyInner),
    /// pk_scheme=3. BCS wire is the inline `MultiKey` struct
    /// (`{ public_keys: Vec<AnyPublicKey>, signatures_required: u8 }`).
    /// K-of-N over the AnyPublicKey variants; auth-key derivation uses
    /// `Scheme::MultiKey = 0x03` (vs. `0x02` for SingleKey).
    MultiKey(multi_key::MultiKeyInner),
    /// pk_scheme=4. BCS wire is the inline `KeylessPublicKey` struct
    /// (`{ iss_val: String, idc: Vec<u8> }`).
    Keyless(aptos_keyless_common::KeylessPublicKey),
    /// pk_scheme=5. BCS wire is the inline `FederatedKeylessPublicKey` struct
    /// (`{ jwk_addr: [u8;32], pk: KeylessPublicKey }`). The signature carried
    /// alongside is still a `KeylessSignature` (sig_scheme=4).
    FederatedKeyless(aptos_keyless_common::FederatedKeylessPublicKey),
}

/// Inner signature payload for [`AptosProofOfPermission`].
#[derive(Clone, Debug)]
pub enum AptosSignatureMaterial {
    /// sig_scheme=0. BCS wire is `Vec<u8>(64 bytes)`.
    Ed25519([u8; 64]),
    /// sig_scheme=1. BCS wire is `ULEB128(any_variant) || BCS(inner)`. See
    /// [`any::AnySignatureInner`] — pairs with pk_scheme=1 / `AnyPublicKey`.
    Any(any::AnySignatureInner),
    /// sig_scheme=2. BCS wire is `serialize_bytes(sig_1 || ... || sig_K || bitmap[4])`
    /// — the flat-concat layout from aptos-core's
    /// `MultiEd25519Signature::to_bytes`. Pairs with pk_scheme=2 /
    /// `MultiEd25519`.
    MultiEd25519(multi_ed25519::MultiEd25519SignatureInner),
    /// sig_scheme=3. BCS wire is the inline `MultiKeyAuthenticator`
    /// signature struct (`{ signatures: Vec<AnySignature>, bitmap: Vec<u8> }`)
    /// — pairs with pk_scheme=3 / `MultiKey`. Bitmap is MSB-first per byte;
    /// position bits select which N of M positions signed.
    MultiKey(multi_key::MultiKeySigInner),
    /// sig_scheme=4. BCS wire is the inline `KeylessSignature` struct.
    Keyless(aptos_keyless_common::KeylessSignature),
}

impl AptosPublicKeyMaterial {
    pub(super) fn tag_name(&self) -> &'static str {
        match self {
            AptosPublicKeyMaterial::Ed25519(_) => "ed25519",
            AptosPublicKeyMaterial::Any(_) => "any",
            AptosPublicKeyMaterial::MultiEd25519(_) => "multi_ed25519",
            AptosPublicKeyMaterial::MultiKey(_) => "multi_key",
            AptosPublicKeyMaterial::Keyless(_) => "keyless",
            AptosPublicKeyMaterial::FederatedKeyless(_) => "federated_keyless",
        }
    }
}

impl AptosSignatureMaterial {
    pub(super) fn tag_name(&self) -> &'static str {
        match self {
            AptosSignatureMaterial::Ed25519(_) => "ed25519",
            AptosSignatureMaterial::Any(_) => "any",
            AptosSignatureMaterial::MultiEd25519(_) => "multi_ed25519",
            AptosSignatureMaterial::MultiKey(_) => "multi_key",
            AptosSignatureMaterial::Keyless(_) => "keyless",
        }
    }
}
