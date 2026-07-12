// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Application-layer cryptography served by the network node.

use anyhow::{anyhow, Result};
use ark_bls12_381::{Fr, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    AffineRepr, CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use vss_common::crypto::{fr_from_le_bytes, fr_to_le_bytes};
use vss_common::group::{BcsElement, BcsPublicPoint, BcsScalar, SCHEME_BLS12381G2};
use vss_common::session::BcsPcsPublicParams;

use crate::verify::ContractId;

pub const SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC: u8 = 0;
pub const SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD: u8 = 1;

const DST_HASH_TO_G2_SHORTPK: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORT_PK/HASH_ID_TO_CURVE";
const DST_HASH_TO_G1_SHORTSIG: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE";
const DST_THRESHOLD_VRF_G1: &[u8] = b"ACE_THRESHOLD_VRF_BLS12381G1/HASH_TO_CURVE/v1";

type G2Hasher = MapToCurveBasedHasher<
    G2Projective,
    DefaultFieldHasher<Sha256, 128>,
    WBMap<ark_bls12_381::g2::Config>,
>;
type G1Hasher = MapToCurveBasedHasher<
    G1Projective,
    DefaultFieldHasher<Sha256, 128>,
    WBMap<ark_bls12_381::g1::Config>,
>;

pub fn group_scheme_for_tibe(tibe_scheme: u8) -> Result<u8> {
    use vss_common::group::{SCHEME_BLS12381G1, SCHEME_BLS12381G2};
    match tibe_scheme {
        SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC => Ok(SCHEME_BLS12381G1),
        SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD => Ok(SCHEME_BLS12381G2),
        scheme => Err(anyhow!("unsupported t-IBE scheme {}", scheme)),
    }
}

/// Return the BCS encoding of the TS SDK's `IdentityDecryptionKeyShare`.
pub fn partial_extract_idk_share(
    tibe_scheme: u8,
    id_bytes: &[u8],
    scalar_le32: &[u8; 32],
    eval_point: u64,
) -> Result<Vec<u8>> {
    let scalar = Fr::from_le_bytes_mod_order(scalar_le32);
    let (share_bytes, share_len_tag) = match tibe_scheme {
        SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC => {
            let hasher = G2Hasher::new(DST_HASH_TO_G2_SHORTPK)
                .map_err(|e| anyhow!("G2Hasher::new: {:?}", e))?;
            let id_point: G2Projective = hasher
                .hash(id_bytes)
                .map_err(|e| anyhow!("hash identity to G2: {:?}", e))?
                .into();
            let mut bytes = Vec::with_capacity(96);
            (id_point * scalar)
                .into_affine()
                .serialize_compressed(&mut bytes)
                .map_err(|e| anyhow!("serialize G2 IDK share: {:?}", e))?;
            (bytes, 0x60)
        }
        SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD => {
            let hasher = G1Hasher::new(DST_HASH_TO_G1_SHORTSIG)
                .map_err(|e| anyhow!("G1Hasher::new: {:?}", e))?;
            let id_point: G1Projective = hasher
                .hash(id_bytes)
                .map_err(|e| anyhow!("hash identity to G1: {:?}", e))?
                .into();
            let mut bytes = Vec::with_capacity(48);
            (id_point * scalar)
                .into_affine()
                .serialize_compressed(&mut bytes)
                .map_err(|e| anyhow!("serialize G1 IDK share: {:?}", e))?;
            (bytes, 0x30)
        }
        scheme => return Err(anyhow!("unsupported t-IBE scheme {}", scheme)),
    };

    let eval_bytes = Fr::from(eval_point).into_bigint().to_bytes_le();
    let mut eval_le32 = [0u8; 32];
    eval_le32[..eval_bytes.len()].copy_from_slice(&eval_bytes);

    let mut out = Vec::with_capacity(36 + share_bytes.len());
    out.push(tibe_scheme);
    out.push(0x20); // BCS vector length for the 32-byte evaluation point.
    out.extend_from_slice(&eval_le32);
    out.push(share_len_tag);
    out.extend_from_slice(&share_bytes);
    out.push(0x00); // No separate proof; the public sub-PK verifies this share.
    Ok(out)
}

#[derive(serde::Serialize)]
struct ThresholdVrfInput<'a> {
    purpose: &'static str,
    keypair_id: &'a [u8; 32],
    contract_id: &'a ContractId,
    label: &'a [u8],
}

const THRESHOLD_VRF_INPUT_PURPOSE: &str = "ace.threshold-vrf.input.v1";

#[derive(serde::Serialize, serde::Deserialize)]
struct ThresholdVrfShareWire {
    eval_point: u64,
    share: BcsElement,
    proof: ThresholdVrfShareProofWire,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ThresholdVrfShareProofWire {
    commitment_nonce: BcsElement,
    vrf_nonce: BcsElement,
    z_secret: BcsScalar,
    z_blinding: BcsScalar,
}

/// Compute this worker's threshold-VRF share and return the BCS bytes consumed
/// by `ts-sdk/src/vrf-for-aptos/index.ts::ThresholdVrfShare`.
///
/// The DKG public commitments live in G2; the VRF share itself is in G1 so the
/// client can verify `e(share_i, G2) == e(H_to_G1(input), P_i)`.
pub fn partial_derive_threshold_vrf_share(
    keypair_id: &[u8; 32],
    contract_id: &ContractId,
    label: &[u8],
    scalar_le32: &[u8; 32],
    blinding_le32: &[u8; 32],
    eval_point: u64,
    group_scheme: u8,
    pcs_context: &BcsPcsPublicParams,
    share_commitment: &BcsElement,
) -> Result<Vec<u8>> {
    if group_scheme != SCHEME_BLS12381G2 {
        return Err(anyhow!(
            "partial_derive_threshold_vrf_share: threshold VRF requires BLS12-381 G2 DKG shares, got group scheme {}",
            group_scheme
        ));
    }

    let input = ThresholdVrfInput {
        purpose: THRESHOLD_VRF_INPUT_PURPOSE,
        keypair_id,
        contract_id,
        label,
    };
    let input_bytes = bcs::to_bytes(&input)
        .map_err(|e| anyhow!("partial_derive_threshold_vrf_share: encode input: {}", e))?;
    if pcs_context.generator_g.scheme() != SCHEME_BLS12381G2
        || pcs_context.generator_h.scheme() != SCHEME_BLS12381G2
        || share_commitment.scheme() != SCHEME_BLS12381G2
    {
        return Err(anyhow!(
            "partial_derive_threshold_vrf_share: threshold VRF proof requires G2 Pedersen context and share commitment"
        ));
    }

    let scalar_fr = fr_from_le_bytes(*scalar_le32);
    let blinding_fr = fr_from_le_bytes(*blinding_le32);
    let h2c = G1Hasher::new(DST_THRESHOLD_VRF_G1)
        .map_err(|e| anyhow!("threshold VRF G1Hasher::new: {:?}", e))?;
    let id_proj: G1Projective = h2c
        .hash(&input_bytes)
        .map_err(|e| anyhow!("threshold VRF hash input to G1: {:?}", e))?
        .into();
    let share_point = id_proj * scalar_fr;
    let share_elem = g1_to_bcs(share_point)?;
    let input_elem = g1_to_bcs(id_proj)?;
    let proof = prove_threshold_vrf_share(
        keypair_id,
        contract_id,
        label,
        eval_point,
        pcs_context,
        share_commitment,
        &input_elem,
        &share_elem,
        id_proj,
        scalar_fr,
        blinding_fr,
    )?;

    let share = ThresholdVrfShareWire {
        eval_point,
        share: share_elem,
        proof,
    };
    bcs::to_bytes(&share)
        .map_err(|e| anyhow!("partial_derive_threshold_vrf_share: encode share: {}", e))
}

fn prove_threshold_vrf_share(
    keypair_id: &[u8; 32],
    contract_id: &ContractId,
    label: &[u8],
    eval_point: u64,
    pcs_context: &BcsPcsPublicParams,
    share_commitment: &BcsElement,
    input_elem: &BcsElement,
    share_elem: &BcsElement,
    input_point: G1Projective,
    scalar: Fr,
    blinding: Fr,
) -> Result<ThresholdVrfShareProofWire> {
    let generator_g = bcs_g2_projective(&pcs_context.generator_g)?;
    let generator_h = bcs_g2_projective(&pcs_context.generator_h)?;

    let a = random_fr();
    let b = random_fr();
    let commitment_nonce = g2_to_bcs(generator_g * a + generator_h * b)?;
    let vrf_nonce = g1_to_bcs(input_point * a)?;

    let challenge = threshold_vrf_share_challenge(
        keypair_id,
        contract_id,
        label,
        eval_point,
        pcs_context,
        share_commitment,
        input_elem,
        share_elem,
        &commitment_nonce,
        &vrf_nonce,
    )?;

    Ok(ThresholdVrfShareProofWire {
        commitment_nonce,
        vrf_nonce,
        z_secret: BcsScalar::from_scheme_and_bytes(
            SCHEME_BLS12381G2,
            fr_to_le_bytes(a + challenge * scalar).to_vec(),
        )?,
        z_blinding: BcsScalar::from_scheme_and_bytes(
            SCHEME_BLS12381G2,
            fr_to_le_bytes(b + challenge * blinding).to_vec(),
        )?,
    })
}

fn threshold_vrf_share_challenge(
    keypair_id: &[u8; 32],
    contract_id: &ContractId,
    label: &[u8],
    eval_point: u64,
    pcs_context: &BcsPcsPublicParams,
    share_commitment: &BcsElement,
    input_elem: &BcsElement,
    share_elem: &BcsElement,
    commitment_nonce: &BcsElement,
    vrf_nonce: &BcsElement,
) -> Result<Fr> {
    const PROOF_PURPOSE: &str = "ace.threshold-vrf.share-proof.v1";
    let mut transcript = Vec::new();
    transcript.extend(
        bcs::to_bytes(&PROOF_PURPOSE.to_string())
            .map_err(|e| anyhow!("bcs proof purpose: {}", e))?,
    );
    transcript.extend(bcs::to_bytes(keypair_id).map_err(|e| anyhow!("bcs keypair_id: {}", e))?);
    transcript.extend(bcs::to_bytes(contract_id).map_err(|e| anyhow!("bcs contract_id: {}", e))?);
    transcript.extend(bcs::to_bytes(&label.to_vec()).map_err(|e| anyhow!("bcs label: {}", e))?);
    transcript.extend(bcs::to_bytes(&eval_point).map_err(|e| anyhow!("bcs eval_point: {}", e))?);
    transcript.extend(
        bcs::to_bytes(&pcs_context.generator_g).map_err(|e| anyhow!("bcs generator_g: {}", e))?,
    );
    transcript.extend(
        bcs::to_bytes(&pcs_context.generator_h).map_err(|e| anyhow!("bcs generator_h: {}", e))?,
    );
    transcript.extend(
        bcs::to_bytes(share_commitment).map_err(|e| anyhow!("bcs share_commitment: {}", e))?,
    );
    transcript.extend(bcs::to_bytes(input_elem).map_err(|e| anyhow!("bcs input_elem: {}", e))?);
    transcript.extend(bcs::to_bytes(share_elem).map_err(|e| anyhow!("bcs share_elem: {}", e))?);
    transcript.extend(
        bcs::to_bytes(commitment_nonce).map_err(|e| anyhow!("bcs commitment_nonce: {}", e))?,
    );
    transcript.extend(bcs::to_bytes(vrf_nonce).map_err(|e| anyhow!("bcs vrf_nonce: {}", e))?);

    let hash = Sha512::digest(&transcript);
    Ok(Fr::from_be_bytes_mod_order(hash.as_slice()))
}

fn random_fr() -> Fr {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    Fr::from_le_bytes_mod_order(&bytes)
}

fn g1_to_bcs(point: G1Projective) -> Result<BcsElement> {
    let mut bytes = Vec::with_capacity(48);
    point
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|e| anyhow!("threshold VRF G1 serialize_compressed: {:?}", e))?;
    if bytes.len() != 48 {
        return Err(anyhow!(
            "threshold VRF G1 compressed must be 48 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(BcsElement::Bls12381G1(BcsPublicPoint { point: bytes }))
}

fn g2_to_bcs(point: G2Projective) -> Result<BcsElement> {
    let mut bytes = Vec::with_capacity(96);
    point
        .into_affine()
        .serialize_compressed(&mut bytes)
        .map_err(|e| anyhow!("threshold VRF G2 serialize_compressed: {:?}", e))?;
    if bytes.len() != 96 {
        return Err(anyhow!(
            "threshold VRF G2 compressed must be 96 bytes, got {}",
            bytes.len()
        ));
    }
    Ok(BcsElement::Bls12381G2(BcsPublicPoint { point: bytes }))
}

fn bcs_g2_projective(elem: &BcsElement) -> Result<G2Projective> {
    match elem {
        BcsElement::Bls12381G2(p) => Ok(G2Affine::deserialize_compressed(p.point.as_slice())
            .map_err(|e| anyhow!("threshold VRF G2 deserialize_compressed: {:?}", e))?
            .into_group()),
        _ => Err(anyhow!("threshold VRF expected G2 element")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tibe_share_wire_formats_cover_both_groups() {
        let scalar = fr_to_le_bytes(Fr::from(7u64));
        let short_pk = partial_extract_idk_share(
            SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
            b"identity",
            &scalar,
            2,
        )
        .unwrap();
        assert_eq!(short_pk.len(), 132);
        assert_eq!(short_pk[0], SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC);
        assert_eq!(short_pk[1], 32);
        assert_eq!(short_pk[34], 96);
        assert_eq!(short_pk[131], 0);

        let short_sig = partial_extract_idk_share(
            SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
            b"identity",
            &scalar,
            2,
        )
        .unwrap();
        assert_eq!(short_sig.len(), 84);
        assert_eq!(short_sig[0], SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD);
        assert_eq!(short_sig[1], 32);
        assert_eq!(short_sig[34], 48);
        assert_eq!(short_sig[83], 0);
    }

    #[test]
    fn threshold_vrf_share_is_eval_point_plus_g1_element() {
        let contract_id = ContractId::Aptos(crate::verify::AptosContractId {
            chain_id: 4,
            module_addr: [0xef; 32],
            module_name: "presigned_access".to_string(),
        });
        let scalar = Fr::from(7u64);
        let blinding = Fr::from(11u64);
        let g = G2Affine::generator().into_group();
        let h = g * Fr::from(5u64);
        let commitment = g2_to_bcs(g * scalar + h * blinding).unwrap();
        let pcs_context = BcsPcsPublicParams {
            generator_g: g2_to_bcs(g).unwrap(),
            generator_h: g2_to_bcs(h).unwrap(),
        };
        let share = partial_derive_threshold_vrf_share(
            &[0xab; 32],
            &contract_id,
            b"label-1",
            &fr_to_le_bytes(scalar),
            &fr_to_le_bytes(blinding),
            42,
            SCHEME_BLS12381G2,
            &pcs_context,
            &commitment,
        )
        .unwrap();
        let decoded: ThresholdVrfShareWire = bcs::from_bytes(&share).unwrap();
        assert_eq!(decoded.eval_point, 42);
        assert_eq!(decoded.share.scheme(), vss_common::group::SCHEME_BLS12381G1);
        assert_eq!(decoded.share.point_bytes().len(), 48);
        assert_eq!(decoded.proof.commitment_nonce.scheme(), SCHEME_BLS12381G2);
        assert_eq!(
            decoded.proof.vrf_nonce.scheme(),
            vss_common::group::SCHEME_BLS12381G1
        );
        assert_eq!(decoded.proof.z_secret.scheme(), SCHEME_BLS12381G2);
        assert_eq!(decoded.proof.z_blinding.scheme(), SCHEME_BLS12381G2);
    }
}
