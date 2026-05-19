// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0
//
// Vendored from aptos-core's `aptos-keyless-verify` crate (which itself
// vendors from `aptos-types::keyless::*` at rev 8ec3fb76). BCS wire format is
// the contract; field types and serde impls match upstream so signatures
// produced by the TS SDK / aptos-types round-trip into these types.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_big_array::BigArray;

// ── Public key ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct IdCommitment(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl IdCommitment {
    pub const NUM_BYTES: usize = 32;
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct KeylessPublicKey {
    /// `iss` claim from the JWT (e.g. "https://accounts.google.com" or
    /// "test.oidc.provider" on the local test fixture).
    pub iss_val: String,
    /// 32-byte hiding commitment to (aud, uid_key, uid_val, pepper).
    pub idc: IdCommitment,
}

/// BCS-compatible with `aptos_types::keyless::FederatedKeylessPublicKey`. Field
/// order matters: `jwk_addr` first, then the inner `KeylessPublicKey`.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct FederatedKeylessPublicKey {
    pub jwk_addr: [u8; 32],
    pub pk: KeylessPublicKey,
}

// ── Ephemeral key / signature ────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum EphemeralPublicKey {
    Ed25519 {
        #[serde(with = "serde_bytes")]
        public_key: Vec<u8>,
    },
    Secp256r1Ecdsa {
        #[serde(with = "serde_bytes")]
        public_key: Vec<u8>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum EphemeralSignature {
    Ed25519 {
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
    WebAuthn {
        #[serde(with = "serde_bytes")]
        signature: Vec<u8>,
    },
}

// ── Groth16 proof types ──────────────────────────────────────────────────────

pub const G1_COMPRESSED_BYTES: usize = 32;
pub const G2_COMPRESSED_BYTES: usize = 64;

/// 32-byte compressed BN254 G1 point in Circom encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct G1Bytes(pub [u8; G1_COMPRESSED_BYTES]);

impl<'de> Deserialize<'de> for G1Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = <String>::deserialize(d)?;
            let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
            let arr: [u8; G1_COMPRESSED_BYTES] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("G1Bytes: expected 32 bytes"))?;
            Ok(G1Bytes(arr))
        } else {
            #[derive(Deserialize)]
            #[serde(rename = "G1Bytes")]
            struct Value([u8; G1_COMPRESSED_BYTES]);
            Ok(G1Bytes(Value::deserialize(d)?.0))
        }
    }
}

impl Serialize for G1Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            hex::encode(self.0).serialize(s)
        } else {
            s.serialize_newtype_struct("G1Bytes", &self.0)
        }
    }
}

/// 64-byte compressed BN254 G2 point in Circom encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct G2Bytes(pub [u8; G2_COMPRESSED_BYTES]);

impl<'de> Deserialize<'de> for G2Bytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = <String>::deserialize(d)?;
            let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
            let arr: [u8; G2_COMPRESSED_BYTES] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("G2Bytes: expected 64 bytes"))?;
            Ok(G2Bytes(arr))
        } else {
            #[derive(Deserialize)]
            #[serde(rename = "G2Bytes")]
            struct Value(#[serde(with = "BigArray")] [u8; G2_COMPRESSED_BYTES]);
            Ok(G2Bytes(Value::deserialize(d)?.0))
        }
    }
}

impl Serialize for G2Bytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            hex::encode(self.0).serialize(s)
        } else {
            #[derive(Serialize)]
            #[serde(rename = "G2Bytes")]
            struct Value(#[serde(with = "BigArray")] [u8; G2_COMPRESSED_BYTES]);
            Value(self.0).serialize(s)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Groth16Proof {
    pub a: G1Bytes,
    pub b: G2Bytes,
    pub c: G1Bytes,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ZkpVariant {
    Groth16 = 0,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ZkProof {
    Groth16Zkp(Groth16Proof),
}

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ZeroKnowledgeSig {
    pub proof: ZkProof,
    pub exp_horizon_secs: u64,
    pub extra_field: Option<String>,
    pub override_aud_val: Option<String>,
    pub training_wheels_signature: Option<EphemeralSignature>,
}

// `OpenIdSig` (non-ZK certificate) is not modelled — production keyless flows
// always use the ZK variant. If the wire carries one, the BCS deserializer
// will fail loudly at the enum-tag stage rather than silently accept it.

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum EphemeralCertificate {
    ZeroKnowledgeSig(ZeroKnowledgeSig),
    /// Present in the BCS layout for compatibility; treated as unsupported by
    /// [`crate::verify_signature`].
    OpenIdSig(serde_bytes::ByteBuf),
}

// ── Signature ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct KeylessSignature {
    pub cert: EphemeralCertificate,
    pub jwt_header_json: String,
    pub exp_date_secs: u64,
    pub ephemeral_pubkey: EphemeralPublicKey,
    pub ephemeral_signature: EphemeralSignature,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JwtHeader {
    pub kid: String,
    pub alg: String,
}

// ── Configuration ────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Configuration {
    pub override_aud_vals: Vec<String>,
    pub max_signatures_per_txn: u16,
    pub max_exp_horizon_secs: u64,
    pub training_wheels_pubkey: Option<Vec<u8>>,
    pub max_commited_epk_bytes: u16,
    pub max_iss_val_bytes: u16,
    pub max_extra_field_bytes: u16,
    pub max_jwt_header_b64_bytes: u32,
}
