// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Wire types shared by every ACE request flow (TS: `_internal/common.ts` lines 1-608 and
//! `_internal/aptos.ts`). Every layout here is hand-written BCS that must match the worker-side
//! Rust structs in `worker-components/network-node/src/verify/mod.rs` byte for byte.
//!
//! This crate has no Aptos SDK, so the Aptos account key / signature types that
//! `ProofOfPermission` carries are modelled as (`scheme`, raw BCS bytes) pairs — see
//! [`AptosPublicKey`] / [`AptosSignature`].

use crate::address::AccountAddress;
use crate::error::{AceError, Result};
use crate::group::wire_via_serialize;
use crate::pke;
use crate::utils::sha3_256;
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

// ── ContractID ────────────────────────────────────────────────────────────────────────────

/// Aptos contract identifier (TS: `aptos.ts::ContractID`).
///
/// Layout: `u8(chain_id) ++ fixed32(module_addr) ++ str(module_name)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptosContractID {
    pub chain_id: u8,
    pub module_addr: AccountAddress,
    pub module_name: String,
}

impl AptosContractID {
    pub fn new(chain_id: u8, module_addr: AccountAddress, module_name: impl Into<String>) -> Self {
        Self {
            chain_id,
            module_addr,
            module_name: module_name.into(),
        }
    }

    /// TS `ContractID.dummy()`: `(0, 0x1, "module3")`.
    pub fn dummy() -> Self {
        Self::new(0, AccountAddress::ONE, "module3")
    }

    pub fn serialize(&self, s: &mut Serializer) {
        s.u8(self.chain_id);
        self.module_addr.serialize(s);
        s.str(&self.module_name);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let chain_id = d.u8()?;
        let module_addr = AccountAddress::deserialize(d)?;
        let module_name = d.str()?;
        Ok(Self {
            chain_id,
            module_addr,
            module_name,
        })
    }
}
wire_via_serialize!(AptosContractID);

/// Solana contract identifier (TS: `solana.ts::ContractID`), kept only so that Solana ids
/// round-trip through [`ContractID`]; this crate does no Solana-specific processing.
///
/// Layout: `str(known_chain_name) ++ bytes(program_id)` (program id is a 32-byte pubkey).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SolanaContractID {
    pub known_chain_name: String,
    pub program_id: Vec<u8>,
}

impl SolanaContractID {
    pub fn serialize(&self, s: &mut Serializer) {
        s.str(&self.known_chain_name);
        s.bytes(&self.program_id);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let known_chain_name = d.str()?;
        let program_id = d.bytes()?;
        Ok(Self {
            known_chain_name,
            program_id,
        })
    }
}
wire_via_serialize!(SolanaContractID);

pub const CONTRACT_ID_SCHEME_APTOS: u8 = 0;
pub const CONTRACT_ID_SCHEME_SOLANA: u8 = 1;

/// Chain-tagged contract identifier (TS: `common.ts::ContractID`).
///
/// Layout: `u8(scheme) ++ inner` where scheme `0` = [`AptosContractID`], `1` =
/// [`SolanaContractID`]. An Aptos id is therefore `1 + 1 + 32 + uleb(len) + len` bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ContractID {
    Aptos(AptosContractID),
    Solana(SolanaContractID),
}

impl ContractID {
    pub fn new_aptos(
        chain_id: u8,
        module_addr: AccountAddress,
        module_name: impl Into<String>,
    ) -> Self {
        Self::Aptos(AptosContractID::new(chain_id, module_addr, module_name))
    }

    /// `program_id` is the raw 32-byte Solana program pubkey (base58-decoded).
    pub fn new_solana(known_chain_name: impl Into<String>, program_id: &[u8]) -> Self {
        Self::Solana(SolanaContractID {
            known_chain_name: known_chain_name.into(),
            program_id: program_id.to_vec(),
        })
    }

    pub fn dummy() -> Self {
        Self::Aptos(AptosContractID::dummy())
    }

    pub fn scheme(&self) -> u8 {
        match self {
            Self::Aptos(_) => CONTRACT_ID_SCHEME_APTOS,
            Self::Solana(_) => CONTRACT_ID_SCHEME_SOLANA,
        }
    }

    pub fn as_aptos(&self) -> Result<&AptosContractID> {
        match self {
            Self::Aptos(x) => Ok(x),
            _ => Err(AceError::Other("ContractID is not an Aptos id".into())),
        }
    }

    pub fn as_solana(&self) -> Result<&SolanaContractID> {
        match self {
            Self::Solana(x) => Ok(x),
            _ => Err(AceError::Other("ContractID is not a Solana id".into())),
        }
    }

    pub fn serialize(&self, s: &mut Serializer) {
        s.u8(self.scheme());
        match self {
            Self::Aptos(x) => x.serialize(s),
            Self::Solana(x) => x.serialize(s),
        }
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        match d.u8()? {
            CONTRACT_ID_SCHEME_APTOS => Ok(Self::Aptos(AptosContractID::deserialize(d)?)),
            CONTRACT_ID_SCHEME_SOLANA => Ok(Self::Solana(SolanaContractID::deserialize(d)?)),
            other => Err(AceError::UnsupportedScheme(other)),
        }
    }
}
wire_via_serialize!(ContractID);

// ── Aptos account public keys / signatures ────────────────────────────────────────────────

pub const PK_SCHEME_ED25519: u8 = 0;
pub const PK_SCHEME_ANY: u8 = 1;
pub const PK_SCHEME_MULTI_ED25519: u8 = 2;
pub const PK_SCHEME_MULTI_KEY: u8 = 3;
pub const PK_SCHEME_KEYLESS: u8 = 4;
pub const PK_SCHEME_FEDERATED_KEYLESS: u8 = 5;

pub const SIG_SCHEME_ED25519: u8 = 0;
pub const SIG_SCHEME_ANY: u8 = 1;
pub const SIG_SCHEME_MULTI_ED25519: u8 = 2;
pub const SIG_SCHEME_MULTI_KEY: u8 = 3;
pub const SIG_SCHEME_KEYLESS: u8 = 4;

/// `AnyPublicKey` / `AnySignature` variant indices from `@aptos-labs/ts-sdk` (uleb128-encoded).
pub const ANY_PK_VARIANT_ED25519: u32 = 0;
pub const ANY_PK_VARIANT_SECP256K1: u32 = 1;
pub const ANY_PK_VARIANT_SECP256R1: u32 = 2;
pub const ANY_PK_VARIANT_KEYLESS: u32 = 3;
pub const ANY_PK_VARIANT_FEDERATED_KEYLESS: u32 = 4;
pub const ANY_SIG_VARIANT_ED25519: u32 = 0;
pub const ANY_SIG_VARIANT_SECP256K1: u32 = 1;
pub const ANY_SIG_VARIANT_WEBAUTHN: u32 = 2;
pub const ANY_SIG_VARIANT_KEYLESS: u32 = 3;

/// An Aptos account public key as carried by [`AptosProofOfPermission`] (TS: an Aptos-SDK
/// `PublicKey` plus `getPublicKeyScheme`).
///
/// `bcs` is the Aptos-SDK BCS encoding of the inner key **without** the scheme byte:
/// - `PK_SCHEME_ED25519`: `bytes(32)` = `uleb(32) ++ 32B` (33 bytes);
/// - `PK_SCHEME_ANY`: `uleb(variant) ++ inner` (Ed25519 → `uleb(0) ++ bytes(32)`, 34 bytes).
///
/// On the wire the parent writes `u8(scheme) ++ bcs`. Deserialization parses `ED25519` and
/// `ANY::Ed25519` exactly; other schemes/variants yield [`AceError::UnsupportedScheme`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptosPublicKey {
    pub scheme: u8,
    pub bcs: Vec<u8>,
}

impl AptosPublicKey {
    pub fn ed25519(pk: &[u8; 32]) -> Self {
        let mut s = Serializer::new();
        s.bytes(pk);
        Self {
            scheme: PK_SCHEME_ED25519,
            bcs: s.into_bytes(),
        }
    }

    /// `AnyPublicKey::Ed25519`.
    pub fn any_ed25519(pk: &[u8; 32]) -> Self {
        let mut s = Serializer::new();
        s.uleb128(ANY_PK_VARIANT_ED25519).bytes(pk);
        Self {
            scheme: PK_SCHEME_ANY,
            bcs: s.into_bytes(),
        }
    }

    /// Writes `bcs` only (the scheme byte is written by the parent).
    pub fn serialize(&self, s: &mut Serializer) {
        s.fixed(&self.bcs);
    }

    /// Reads the inner key for an already-consumed `scheme` byte.
    pub fn deserialize(scheme: u8, d: &mut Deserializer<'_>) -> Result<Self> {
        match scheme {
            PK_SCHEME_ED25519 => {
                let pk = d.bytes()?;
                let pk: [u8; 32] = pk
                    .try_into()
                    .map_err(|_| AceError::wire("ed25519 public key must be 32 bytes"))?;
                Ok(Self::ed25519(&pk))
            }
            PK_SCHEME_ANY => {
                let variant = d.uleb128()?;
                if variant != ANY_PK_VARIANT_ED25519 {
                    return Err(AceError::UnsupportedScheme(scheme));
                }
                let pk = d.bytes()?;
                let pk: [u8; 32] = pk
                    .try_into()
                    .map_err(|_| AceError::wire("ed25519 public key must be 32 bytes"))?;
                Ok(Self::any_ed25519(&pk))
            }
            other => Err(AceError::UnsupportedScheme(other)),
        }
    }
}

/// An Aptos account signature as carried by [`AptosProofOfPermission`] (TS: an Aptos-SDK
/// `Signature` plus `getSignatureScheme`).
///
/// `bcs` is the Aptos-SDK BCS encoding of the inner signature **without** the scheme byte:
/// - `SIG_SCHEME_ED25519`: `bytes(64)` = `uleb(64) ++ 64B` (65 bytes);
/// - `SIG_SCHEME_ANY`: `uleb(variant) ++ inner` (Ed25519 → `uleb(0) ++ bytes(64)`, 66 bytes).
///
/// Deserialization parses `ED25519` and `ANY::Ed25519` exactly; other schemes/variants yield
/// [`AceError::UnsupportedScheme`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptosSignature {
    pub scheme: u8,
    pub bcs: Vec<u8>,
}

impl AptosSignature {
    pub fn ed25519(sig: &[u8; 64]) -> Self {
        let mut s = Serializer::new();
        s.bytes(sig);
        Self {
            scheme: SIG_SCHEME_ED25519,
            bcs: s.into_bytes(),
        }
    }

    /// `AnySignature::Ed25519`.
    pub fn any_ed25519(sig: &[u8; 64]) -> Self {
        let mut s = Serializer::new();
        s.uleb128(ANY_SIG_VARIANT_ED25519).bytes(sig);
        Self {
            scheme: SIG_SCHEME_ANY,
            bcs: s.into_bytes(),
        }
    }

    /// Writes `bcs` only (the scheme byte is written by the parent).
    pub fn serialize(&self, s: &mut Serializer) {
        s.fixed(&self.bcs);
    }

    /// Reads the inner signature for an already-consumed `scheme` byte.
    pub fn deserialize(scheme: u8, d: &mut Deserializer<'_>) -> Result<Self> {
        match scheme {
            SIG_SCHEME_ED25519 => {
                let sig = d.bytes()?;
                let sig: [u8; 64] = sig
                    .try_into()
                    .map_err(|_| AceError::wire("ed25519 signature must be 64 bytes"))?;
                Ok(Self::ed25519(&sig))
            }
            SIG_SCHEME_ANY => {
                let variant = d.uleb128()?;
                if variant != ANY_SIG_VARIANT_ED25519 {
                    return Err(AceError::UnsupportedScheme(scheme));
                }
                let sig = d.bytes()?;
                let sig: [u8; 64] = sig
                    .try_into()
                    .map_err(|_| AceError::wire("ed25519 signature must be 64 bytes"))?;
                Ok(Self::any_ed25519(&sig))
            }
            other => Err(AceError::UnsupportedScheme(other)),
        }
    }
}

// ── ProofOfPermission ─────────────────────────────────────────────────────────────────────

/// Aptos proof of permission (TS: `aptos.ts::ProofOfPermission`): the user's account key and
/// its signature over `full_message` (the wallet's `signMessage` full message).
///
/// Layout: `fixed32(user_addr) ++ u8(pk_scheme) ++ pk.bcs ++ u8(sig_scheme) ++ sig.bcs ++
/// str(full_message)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AptosProofOfPermission {
    pub user_addr: AccountAddress,
    pub public_key: AptosPublicKey,
    pub signature: AptosSignature,
    pub full_message: String,
}

impl AptosProofOfPermission {
    pub fn serialize(&self, s: &mut Serializer) {
        self.user_addr.serialize(s);
        s.u8(self.public_key.scheme);
        self.public_key.serialize(s);
        s.u8(self.signature.scheme);
        self.signature.serialize(s);
        s.str(&self.full_message);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let user_addr = AccountAddress::deserialize(d)?;
        let pk_scheme = d.u8()?;
        let public_key = AptosPublicKey::deserialize(pk_scheme, d)?;
        let sig_scheme = d.u8()?;
        let signature = AptosSignature::deserialize(sig_scheme, d)?;
        let full_message = d.str()?;
        Ok(Self {
            user_addr,
            public_key,
            signature,
            full_message,
        })
    }
}
wire_via_serialize!(AptosProofOfPermission);

pub const SOLANA_POP_SCHEME_UNVERSIONED: u8 = 0;
pub const SOLANA_POP_SCHEME_VERSIONED: u8 = 1;

/// Solana proof of permission (TS: `solana.ts::ProofOfPermission`): an opaque signed
/// transaction. Kept for round-tripping only.
///
/// Layout: `u8(scheme) ++ bytes(txn)` with scheme `0` = unversioned, `1` = versioned.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SolanaProofOfPermission {
    pub scheme: u8,
    pub txn_bytes: Vec<u8>,
}

impl SolanaProofOfPermission {
    pub fn serialize(&self, s: &mut Serializer) {
        s.u8(self.scheme);
        s.bytes(&self.txn_bytes);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let scheme = d.u8()?;
        let txn_bytes = d.bytes()?;
        if scheme != SOLANA_POP_SCHEME_UNVERSIONED && scheme != SOLANA_POP_SCHEME_VERSIONED {
            return Err(AceError::UnsupportedScheme(scheme));
        }
        Ok(Self { scheme, txn_bytes })
    }
}
wire_via_serialize!(SolanaProofOfPermission);

pub const POP_SCHEME_APTOS: u8 = 0;
pub const POP_SCHEME_SOLANA: u8 = 1;

/// Chain-tagged proof of permission (TS: `common.ts::ProofOfPermission`).
///
/// Layout: `u8(scheme) ++ inner` where scheme `0` = [`AptosProofOfPermission`], `1` =
/// [`SolanaProofOfPermission`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ProofOfPermission {
    Aptos(AptosProofOfPermission),
    Solana(SolanaProofOfPermission),
}

impl ProofOfPermission {
    pub fn create_aptos(
        user_addr: AccountAddress,
        public_key: AptosPublicKey,
        signature: AptosSignature,
        full_message: impl Into<String>,
    ) -> Self {
        Self::Aptos(AptosProofOfPermission {
            user_addr,
            public_key,
            signature,
            full_message: full_message.into(),
        })
    }

    /// TS `createSolana` infers versioned/unversioned from the txn bytes; here the caller
    /// passes the scheme explicitly (`SOLANA_POP_SCHEME_*`).
    pub fn create_solana(scheme: u8, txn: &[u8]) -> Result<Self> {
        if scheme != SOLANA_POP_SCHEME_UNVERSIONED && scheme != SOLANA_POP_SCHEME_VERSIONED {
            return Err(AceError::UnsupportedScheme(scheme));
        }
        Ok(Self::Solana(SolanaProofOfPermission {
            scheme,
            txn_bytes: txn.to_vec(),
        }))
    }

    pub fn scheme(&self) -> u8 {
        match self {
            Self::Aptos(_) => POP_SCHEME_APTOS,
            Self::Solana(_) => POP_SCHEME_SOLANA,
        }
    }

    pub fn as_aptos(&self) -> Result<&AptosProofOfPermission> {
        match self {
            Self::Aptos(x) => Ok(x),
            _ => Err(AceError::Other(
                "ProofOfPermission is not an Aptos proof".into(),
            )),
        }
    }

    pub fn serialize(&self, s: &mut Serializer) {
        s.u8(self.scheme());
        match self {
            Self::Aptos(x) => x.serialize(s),
            Self::Solana(x) => x.serialize(s),
        }
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        match d.u8()? {
            POP_SCHEME_APTOS => Ok(Self::Aptos(AptosProofOfPermission::deserialize(d)?)),
            POP_SCHEME_SOLANA => Ok(Self::Solana(SolanaProofOfPermission::deserialize(d)?)),
            other => Err(AceError::UnsupportedScheme(other)),
        }
    }
}
wire_via_serialize!(ProofOfPermission);

// ── FullDecryptionDomain ──────────────────────────────────────────────────────────────────

/// Fully-qualified decryption domain (TS: `FullDecryptionDomain`): the IBE identity is derived
/// from these bytes.
///
/// Layout: `fixed32(keypair_id) ++ ContractID ++ bytes(label)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FullDecryptionDomain {
    pub keypair_id: AccountAddress,
    pub contract_id: ContractID,
    pub label: Vec<u8>,
}

impl FullDecryptionDomain {
    pub fn new(keypair_id: AccountAddress, contract_id: ContractID, label: &[u8]) -> Self {
        Self {
            keypair_id,
            contract_id,
            label: label.to_vec(),
        }
    }

    /// TS `dummy()`: zero keypair id, `ContractID::dummy()`, empty label.
    pub fn dummy() -> Self {
        Self::new(AccountAddress([0u8; 32]), ContractID::dummy(), &[])
    }

    pub fn as_aptos_contract_id(&self) -> Result<&AptosContractID> {
        self.contract_id.as_aptos()
    }

    pub fn serialize(&self, s: &mut Serializer) {
        self.keypair_id.serialize(s);
        self.contract_id.serialize(s);
        s.bytes(&self.label);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let keypair_id = AccountAddress::deserialize(d)?;
        let contract_id = ContractID::deserialize(d)?;
        let label = d.bytes()?;
        Ok(Self {
            keypair_id,
            contract_id,
            label,
        })
    }
}
wire_via_serialize!(FullDecryptionDomain);

// ── DecryptionRequestPayload ──────────────────────────────────────────────────────────────

/// The bytes a wallet signs in the basic flow (TS: `DecryptionRequestPayload`).
///
/// Layout: `fixed32(keypair_id) ++ u64(epoch) ++ ContractID ++ bytes(domain) ++
/// pke::EncryptionKey`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DecryptionRequestPayload {
    pub keypair_id: AccountAddress,
    pub epoch: u64,
    pub contract_id: ContractID,
    pub domain: Vec<u8>,
    pub ephemeral_enc_key: pke::EncryptionKey,
}

impl DecryptionRequestPayload {
    pub fn serialize(&self, s: &mut Serializer) {
        self.keypair_id.serialize(s);
        s.u64(self.epoch);
        self.contract_id.serialize(s);
        s.bytes(&self.domain);
        self.ephemeral_enc_key.serialize(s);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let keypair_id = AccountAddress::deserialize(d)?;
        let epoch = d.u64()?;
        let contract_id = ContractID::deserialize(d)?;
        let domain = d.bytes()?;
        let ephemeral_enc_key = pke::EncryptionKey::deserialize(d)?;
        Ok(Self {
            keypair_id,
            epoch,
            contract_id,
            domain,
            ephemeral_enc_key,
        })
    }

    /// 32-byte WebAuthn challenge for this payload:
    /// `SHA3-256( SHA3-256(b"ACE::DecryptionRequestPayload") || BCS(payload) )`
    /// (aptos-core `CryptoHasher` pattern). Only used by the passkey
    /// (`AnyPublicKey<Secp256r1Ecdsa>` + `AnySignature<WebAuthn>`) path.
    pub fn to_webauthn_challenge(&self) -> [u8; 32] {
        let seed = sha3_256(b"ACE::DecryptionRequestPayload");
        let mut preimage = seed.to_vec();
        preimage.extend_from_slice(&self.to_bytes());
        sha3_256(&preimage)
    }
}
wire_via_serialize!(DecryptionRequestPayload);

// ── Custom-flow proof ─────────────────────────────────────────────────────────────────────

pub const CUSTOM_FLOW_PROOF_SCHEME_APTOS: u8 = 0;
pub const CUSTOM_FLOW_PROOF_SCHEME_SOLANA: u8 = 1;

/// Opaque custom-flow proof (TS: `CustomFlowProof`), typically a Groth16 proof the dapp's
/// `on_ace_decryption_request_custom_flow` view validates.
///
/// Layout: `u8(scheme) ++ body` where `Aptos(payload)` (scheme 0) writes `bytes(payload)` and
/// `Solana{inner_scheme, txn}` (scheme 1) writes `u8(inner_scheme) ++ bytes(txn)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CustomFlowProof {
    Aptos(Vec<u8>),
    Solana {
        inner_scheme: u8,
        txn_bytes: Vec<u8>,
    },
}

impl CustomFlowProof {
    pub fn create_aptos(payload: &[u8]) -> Self {
        Self::Aptos(payload.to_vec())
    }

    /// TS infers `inner_scheme` from the txn bytes; here it is passed explicitly
    /// (`SOLANA_POP_SCHEME_*`).
    pub fn create_solana(inner_scheme: u8, txn: &[u8]) -> Self {
        Self::Solana {
            inner_scheme,
            txn_bytes: txn.to_vec(),
        }
    }

    pub fn scheme(&self) -> u8 {
        match self {
            Self::Aptos(_) => CUSTOM_FLOW_PROOF_SCHEME_APTOS,
            Self::Solana { .. } => CUSTOM_FLOW_PROOF_SCHEME_SOLANA,
        }
    }

    pub fn serialize(&self, s: &mut Serializer) {
        s.u8(self.scheme());
        match self {
            Self::Aptos(payload) => {
                s.bytes(payload);
            }
            Self::Solana {
                inner_scheme,
                txn_bytes,
            } => {
                s.u8(*inner_scheme).bytes(txn_bytes);
            }
        }
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        match d.u8()? {
            CUSTOM_FLOW_PROOF_SCHEME_APTOS => Ok(Self::Aptos(d.bytes()?)),
            CUSTOM_FLOW_PROOF_SCHEME_SOLANA => {
                let inner_scheme = d.u8()?;
                let txn_bytes = d.bytes()?;
                Ok(Self::Solana {
                    inner_scheme,
                    txn_bytes,
                })
            }
            other => Err(AceError::UnsupportedScheme(other)),
        }
    }
}
wire_via_serialize!(CustomFlowProof);

// ── Custom-flow request ───────────────────────────────────────────────────────────────────

/// Custom-flow request body without the primitive id (TS: `CustomFlowRequest`).
///
/// Layout: `fixed32(keypair_id) ++ u64(epoch) ++ ContractID ++ bytes(label) ++
/// pke::EncryptionKey ++ CustomFlowProof`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CustomFlowRequest {
    pub keypair_id: AccountAddress,
    pub epoch: u64,
    pub contract_id: ContractID,
    pub label: Vec<u8>,
    pub enc_pk: pke::EncryptionKey,
    pub proof: CustomFlowProof,
}

impl CustomFlowRequest {
    pub fn serialize(&self, s: &mut Serializer) {
        self.keypair_id.serialize(s);
        s.u64(self.epoch);
        self.contract_id.serialize(s);
        s.bytes(&self.label);
        self.enc_pk.serialize(s);
        self.proof.serialize(s);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let keypair_id = AccountAddress::deserialize(d)?;
        let epoch = d.u64()?;
        let contract_id = ContractID::deserialize(d)?;
        let label = d.bytes()?;
        let enc_pk = pke::EncryptionKey::deserialize(d)?;
        let proof = CustomFlowProof::deserialize(d)?;
        Ok(Self {
            keypair_id,
            epoch,
            contract_id,
            label,
            enc_pk,
            proof,
        })
    }
}
wire_via_serialize!(CustomFlowRequest);

/// Worker envelope body for the custom flow (TS: `DecryptionCustomFlowRequest`).
///
/// Layout: `CustomFlowRequest ++ u8(primitive)`. `primitive` is the on-chain secret primitive
/// id the share should be formatted for (0 = shortpk, 1 = shortsig, 3 = shortsig-stream).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DecryptionCustomFlowRequest {
    pub request: CustomFlowRequest,
    pub primitive: u8,
}

impl DecryptionCustomFlowRequest {
    pub fn serialize(&self, s: &mut Serializer) {
        self.request.serialize(s);
        s.u8(self.primitive);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let request = CustomFlowRequest::deserialize(d)?;
        let primitive = d.u8()?;
        Ok(Self { request, primitive })
    }
}
wire_via_serialize!(DecryptionCustomFlowRequest);

/// Worker envelope body for the basic flow (TS: `DecryptionBasicFlowRequest`).
///
/// Layout: `DecryptionRequestPayload ++ ProofOfPermission ++ u8(primitive)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DecryptionBasicFlowRequest {
    pub request: DecryptionRequestPayload,
    pub proof: ProofOfPermission,
    pub primitive: u8,
}

impl DecryptionBasicFlowRequest {
    pub fn serialize(&self, s: &mut Serializer) {
        self.request.serialize(s);
        self.proof.serialize(s);
        s.u8(self.primitive);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let request = DecryptionRequestPayload::deserialize(d)?;
        let proof = ProofOfPermission::deserialize(d)?;
        let primitive = d.u8()?;
        Ok(Self {
            request,
            proof,
            primitive,
        })
    }
}
wire_via_serialize!(DecryptionBasicFlowRequest);

// ── WorkerRequest ─────────────────────────────────────────────────────────────────────────

pub const WORKER_REQUEST_SCHEME_DECRYPTION_BASIC_FLOW: u8 = 0;
pub const WORKER_REQUEST_SCHEME_DECRYPTION_CUSTOM_FLOW: u8 = 1;
pub const WORKER_REQUEST_SCHEME_THRESHOLD_VRF: u8 = 2;
pub const WORKER_REQUEST_SCHEME_RECONSTRUCTION: u8 = 3;

/// Outer request envelope sent to a worker (TS: `WorkerRequest`).
///
/// Layout: `u8(scheme) ++ body`, discriminants matching the worker-side Rust enum:
/// 0 = [`DecryptionBasicFlowRequest`], 1 = [`DecryptionCustomFlowRequest`], 2 = threshold VRF
/// request, 3 = reconstruction (disaster-recovery) request.
///
/// The VRF (`vrf-for-aptos`) and reconstruction (`admin-recovery`) bodies are not ported yet, so
/// those variants carry the **already-serialized** body bytes verbatim; on deserialization they
/// swallow all remaining bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum WorkerRequest {
    DecryptionBasicFlow(DecryptionBasicFlowRequest),
    DecryptionCustomFlow(DecryptionCustomFlowRequest),
    ThresholdVrf(Vec<u8>),
    Reconstruction(Vec<u8>),
}

impl WorkerRequest {
    pub fn new_decryption_basic_flow(
        request: DecryptionRequestPayload,
        proof: ProofOfPermission,
        primitive: u8,
    ) -> Self {
        Self::DecryptionBasicFlow(DecryptionBasicFlowRequest {
            request,
            proof,
            primitive,
        })
    }

    pub fn new_decryption_custom_flow(request: CustomFlowRequest, primitive: u8) -> Self {
        Self::DecryptionCustomFlow(DecryptionCustomFlowRequest { request, primitive })
    }

    /// `body` must be the BCS bytes of the threshold-VRF request body.
    pub fn new_threshold_vrf(body: &[u8]) -> Self {
        Self::ThresholdVrf(body.to_vec())
    }

    /// `body` must be the BCS bytes of the reconstruction request body.
    pub fn new_reconstruction(body: &[u8]) -> Self {
        Self::Reconstruction(body.to_vec())
    }

    pub fn scheme(&self) -> u8 {
        match self {
            Self::DecryptionBasicFlow(_) => WORKER_REQUEST_SCHEME_DECRYPTION_BASIC_FLOW,
            Self::DecryptionCustomFlow(_) => WORKER_REQUEST_SCHEME_DECRYPTION_CUSTOM_FLOW,
            Self::ThresholdVrf(_) => WORKER_REQUEST_SCHEME_THRESHOLD_VRF,
            Self::Reconstruction(_) => WORKER_REQUEST_SCHEME_RECONSTRUCTION,
        }
    }

    pub fn serialize(&self, s: &mut Serializer) {
        s.u8(self.scheme());
        match self {
            Self::DecryptionBasicFlow(x) => x.serialize(s),
            Self::DecryptionCustomFlow(x) => x.serialize(s),
            Self::ThresholdVrf(b) | Self::Reconstruction(b) => {
                s.fixed(b);
            }
        }
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        match d.u8()? {
            WORKER_REQUEST_SCHEME_DECRYPTION_BASIC_FLOW => Ok(Self::DecryptionBasicFlow(
                DecryptionBasicFlowRequest::deserialize(d)?,
            )),
            WORKER_REQUEST_SCHEME_DECRYPTION_CUSTOM_FLOW => Ok(Self::DecryptionCustomFlow(
                DecryptionCustomFlowRequest::deserialize(d)?,
            )),
            WORKER_REQUEST_SCHEME_THRESHOLD_VRF => Ok(Self::ThresholdVrf(d.fixed(d.remaining())?)),
            WORKER_REQUEST_SCHEME_RECONSTRUCTION => {
                Ok(Self::Reconstruction(d.fixed(d.remaining())?))
            }
            other => Err(AceError::UnsupportedScheme(other)),
        }
    }
}
wire_via_serialize!(WorkerRequest);

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> AccountAddress {
        AccountAddress([b; 32])
    }

    fn enc_key() -> pke::EncryptionKey {
        pke::derive_encryption_key(&pke::keygen(pke::DEFAULT_SCHEME).unwrap())
    }

    fn aptos_pop() -> ProofOfPermission {
        let (pk, sk) = crate::sig::keygen();
        let msg = "APTOS\nmessage: hello\nnonce: 1";
        let sig = sk.sign(msg.as_bytes());
        ProofOfPermission::create_aptos(
            addr(7),
            AptosPublicKey::ed25519(&pk.bytes),
            AptosSignature::ed25519(&sig.bytes),
            msg,
        )
    }

    fn rt<T: Wire + PartialEq + std::fmt::Debug>(v: &T) -> Vec<u8> {
        let bytes = v.to_bytes();
        assert_eq!(&T::from_bytes(&bytes).unwrap(), v);
        assert_eq!(&T::from_hex(&v.to_hex()).unwrap(), v);
        bytes
    }

    #[test]
    fn contract_id_aptos_layout() {
        let id = ContractID::new_aptos(4, AccountAddress::ONE, "module3");
        let bytes = rt(&id);
        assert_eq!(bytes.len(), 1 + 1 + 32 + 1 + 7);
        assert_eq!(bytes[0], CONTRACT_ID_SCHEME_APTOS);
        assert_eq!(bytes[1], 4);
        assert_eq!(bytes[33], 1);
        assert_eq!(bytes[34], 7);
        assert_eq!(&bytes[35..], b"module3");
        assert_eq!(id.as_aptos().unwrap().module_name, "module3");
        assert!(ContractID::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let dummy_inner = rt(&AptosContractID::dummy());
        assert_eq!(
            dummy_inner,
            bytes[1..]
                .iter()
                .cloned()
                .map(|b| if b == 4 { 0 } else { b })
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn contract_id_solana_roundtrip() {
        let id = ContractID::new_solana("mainnet", &[9u8; 32]);
        let bytes = rt(&id);
        assert_eq!(bytes.len(), 1 + 1 + 7 + 1 + 32);
        assert_eq!(bytes[0], CONTRACT_ID_SCHEME_SOLANA);
        assert!(matches!(
            ContractID::from_bytes(&[9]),
            Err(AceError::UnsupportedScheme(9))
        ));
    }

    #[test]
    fn aptos_keys_layout() {
        let pk = AptosPublicKey::ed25519(&[1u8; 32]);
        assert_eq!(pk.bcs.len(), 33);
        assert_eq!(pk.bcs[0], 32);
        let any = AptosPublicKey::any_ed25519(&[1u8; 32]);
        assert_eq!(any.bcs.len(), 34);
        assert_eq!(&any.bcs[..2], &[0, 32]);
        let sig = AptosSignature::ed25519(&[2u8; 64]);
        assert_eq!(sig.bcs.len(), 65);
        let any_sig = AptosSignature::any_ed25519(&[2u8; 64]);
        assert_eq!(any_sig.bcs.len(), 66);
        assert_eq!(&any_sig.bcs[..2], &[0, 64]);
        for k in [&pk, &any] {
            let mut d = Deserializer::new(&k.bcs);
            assert_eq!(&AptosPublicKey::deserialize(k.scheme, &mut d).unwrap(), k);
            d.finish().unwrap();
        }
        for k in [&sig, &any_sig] {
            let mut d = Deserializer::new(&k.bcs);
            assert_eq!(&AptosSignature::deserialize(k.scheme, &mut d).unwrap(), k);
            d.finish().unwrap();
        }
    }

    #[test]
    fn proof_of_permission_layout_and_unknown_scheme() {
        let pop = aptos_pop();
        let bytes = rt(&pop);
        let msg_len = pop.as_aptos().unwrap().full_message.len();
        assert_eq!(bytes.len(), 1 + 32 + 1 + 33 + 1 + 65 + 1 + msg_len);
        assert_eq!(bytes[0], POP_SCHEME_APTOS);
        assert_eq!(bytes[33], PK_SCHEME_ED25519);
        assert_eq!(bytes[67], SIG_SCHEME_ED25519);
        let mut bad = bytes.clone();
        bad[33] = PK_SCHEME_MULTI_KEY;
        assert!(matches!(
            ProofOfPermission::from_bytes(&bad),
            Err(AceError::UnsupportedScheme(PK_SCHEME_MULTI_KEY))
        ));
        let sol =
            ProofOfPermission::create_solana(SOLANA_POP_SCHEME_VERSIONED, &[1, 2, 3]).unwrap();
        assert_eq!(rt(&sol), vec![1, 1, 3, 1, 2, 3]);
    }

    #[test]
    fn domain_payload_and_requests_roundtrip() {
        let dom = FullDecryptionDomain::new(addr(1), ContractID::dummy(), b"lbl");
        assert_eq!(rt(&dom).len(), 32 + 42 + 1 + 3);
        rt(&FullDecryptionDomain::dummy());
        let payload = DecryptionRequestPayload {
            keypair_id: addr(2),
            epoch: 5,
            contract_id: ContractID::dummy(),
            domain: b"dom".to_vec(),
            ephemeral_enc_key: enc_key(),
        };
        rt(&payload);
        let c1 = payload.to_webauthn_challenge();
        assert_eq!(c1, payload.to_webauthn_challenge());
        let proof = CustomFlowProof::create_aptos(&[0xaa; 5]);
        assert_eq!(rt(&proof), [vec![0, 5], vec![0xaa; 5]].concat());
        rt(&CustomFlowProof::create_solana(1, &[1, 2]));
        let cfr = CustomFlowRequest {
            keypair_id: addr(3),
            epoch: 9,
            contract_id: ContractID::dummy(),
            label: vec![],
            enc_pk: enc_key(),
            proof,
        };
        rt(&cfr);
        let basic = WorkerRequest::new_decryption_basic_flow(payload.clone(), aptos_pop(), 1);
        let b = rt(&basic);
        assert_eq!(b[0], 0);
        assert_eq!(*b.last().unwrap(), 1);
        let custom = WorkerRequest::new_decryption_custom_flow(cfr.clone(), 0);
        let c = rt(&custom);
        assert_eq!(c[0], 1);
        assert_eq!(
            &c[1..],
            &rt(&DecryptionCustomFlowRequest {
                request: cfr,
                primitive: 0
            })[..]
        );
        assert_eq!(
            rt(&WorkerRequest::new_threshold_vrf(&[7, 8])),
            vec![2, 7, 8]
        );
        assert_eq!(rt(&WorkerRequest::new_reconstruction(&[])), vec![3]);
        assert!(matches!(
            WorkerRequest::from_bytes(&[4]),
            Err(AceError::UnsupportedScheme(4))
        ));
    }
}
