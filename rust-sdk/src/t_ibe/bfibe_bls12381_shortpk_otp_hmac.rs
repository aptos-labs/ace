// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/t-ibe/bfibe-bls12381-shortpk-otp-hmac.ts`.
//!
//! A threshold IBE based on Boneh-Franklin IBE, where...
//! - The underlying curve is BLS12-381.
//! - The public key is in G1 (identity keys / shares are in G2).
//! - The symmetric cipher inside is a one-time pad.
//! - HMAC-SHA3-256 is used for authentication.
//! - In decryption, decryption key shares are Lagrange-combined in the exponent and then it is
//!   a normal Boneh-Franklin IBE decryption.

use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::CurveGroup;
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::{Field, One, Zero};
use ark_serialize::CanonicalSerialize;
use sha2::Sha256;

use crate::error::{AceError, Result};
use crate::group::bls12381fr::{
    fr_from_le_bytes, fr_from_le_bytes_mod_order, fr_from_u64, fr_to_le_bytes, Fr,
};
use crate::group::{bls12381g1, bls12381g2, wire_via_serialize};
use crate::utils::{hmac_sha3_256, kdf, rand_bytes, xor_bytes};
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

pub const DST_OTP: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORT_PK/OTP";
pub const DST_ID_HASH: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORT_PK/HASH_ID_TO_CURVE";
pub const DST_MAC: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORT_PK/MAC";

/// noble's default DST for `bls12_381.G1.hashToCurve` (only used by [`keygen_for_testing`]).
const DST_NOBLE_G1_DEFAULT: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

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

/// `bls12_381.G2.hashToCurve(id, { DST: DST_ID_HASH })` (RFC 9380 BLS12381G2_XMD:SHA-256_SSWU_RO_).
pub fn hash_id_to_g2(id: &[u8]) -> Result<bls12381g2::PublicPoint> {
    let h2c = G2Hasher::new(DST_ID_HASH)
        .map_err(|e| AceError::crypto(format!("G2Hasher::new: {e:?}")))?;
    let affine: G2Affine = h2c
        .hash(id)
        .map_err(|e| AceError::crypto(format!("hash_id_to_g2: {e:?}")))?;
    Ok(bls12381g2::PublicPoint { pt: affine.into() })
}

/// Aptos/arkworks Gt encoding: 576 bytes, the 12 Fq coefficients in tower order
/// (c0.c0.c0, c0.c0.c1, c0.c1.c0, ..., c1.c2.c1), each 48-byte little-endian.
/// This equals the TS `bls12381GtReprNobleToAptos(Fp12.toBytes(gt))` (noble emits the same
/// coefficient order but big-endian per coefficient; TS reverses each 48-byte chunk).
fn gt_to_bytes(gt: &PairingOutput<Bls12_381>) -> Vec<u8> {
    let mut out = Vec::with_capacity(576);
    gt.0.serialize_uncompressed(&mut out)
        .expect("Fp12 serialize");
    debug_assert_eq!(out.len(), 576);
    out
}

fn pairing(g1: &G1Projective, g2: &G2Projective) -> PairingOutput<Bls12_381> {
    let a: G1Affine = g1.into_affine();
    let b: G2Affine = g2.into_affine();
    Bls12_381::pairing(a, b)
}

/// BCS: `bytes(basePoint G1) ++ bytes(pk G1)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MasterPublicKey {
    pub base_point: bls12381g1::PublicPoint,
    pub pk: bls12381g1::PublicPoint,
}

impl MasterPublicKey {
    pub fn serialize(&self, s: &mut Serializer) {
        self.base_point.serialize(s);
        self.pk.serialize(s);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let base_point = bls12381g1::PublicPoint::deserialize(d)?;
        let pk = bls12381g1::PublicPoint::deserialize(d)?;
        Ok(Self { base_point, pk })
    }
}
wire_via_serialize!(MasterPublicKey);

/// BCS: `bytes(base G1) ++ bytes(32-byte LE scalar)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MasterPrivateKey {
    pub base: bls12381g1::PublicPoint,
    pub scalar: Fr,
}

impl MasterPrivateKey {
    pub fn serialize(&self, s: &mut Serializer) {
        self.base.serialize(s);
        s.bytes(&fr_to_le_bytes(&self.scalar));
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let base = bls12381g1::PublicPoint::deserialize(d)?;
        let scalar = fr_from_le_bytes(&d.bytes()?)?;
        Ok(Self { base, scalar })
    }
}
wire_via_serialize!(MasterPrivateKey);

/// BCS: `bytes(32-byte LE evalPoint) ++ bytes(idkShare G2) ++ u8(hasProof) [++ bytes(proof)]`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentityDecryptionKeyShare {
    pub eval_point: u64,
    pub idk_share: bls12381g2::PublicPoint,
    pub proof: Option<Vec<u8>>,
}

impl IdentityDecryptionKeyShare {
    pub fn serialize(&self, s: &mut Serializer) {
        let mut ep = [0u8; 32];
        ep[..8].copy_from_slice(&self.eval_point.to_le_bytes());
        s.bytes(&ep);
        self.idk_share.serialize(s);
        s.u8(if self.proof.is_some() { 1 } else { 0 });
        if let Some(p) = &self.proof {
            s.bytes(p);
        }
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let ep = d.bytes()?;
        if ep.len() != 32 {
            return Err(AceError::wire(
                "IdentityDecryptionKeyShare: expected 32-byte evalPoint",
            ));
        }
        if ep[8..].iter().any(|&b| b != 0) {
            return Err(AceError::wire(
                "IdentityDecryptionKeyShare: evalPoint does not fit in u64",
            ));
        }
        let eval_point = u64::from_le_bytes(ep[..8].try_into().unwrap());
        let idk_share = bls12381g2::PublicPoint::deserialize(d)?;
        let has_proof = d.u8()? != 0;
        let proof = if has_proof { Some(d.bytes()?) } else { None };
        Ok(Self {
            eval_point,
            idk_share,
            proof,
        })
    }
}
wire_via_serialize!(IdentityDecryptionKeyShare);

/// BCS: `bytes(c0 G1) ++ bytes(symmetricCiph) ++ bytes(mac)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ciphertext {
    pub c0: bls12381g1::PublicPoint,
    pub symmetric_ciph: Vec<u8>,
    pub mac: Vec<u8>,
}

impl Ciphertext {
    pub fn serialize(&self, s: &mut Serializer) {
        self.c0.serialize(s);
        s.bytes(&self.symmetric_ciph);
        s.bytes(&self.mac);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let c0 = bls12381g1::PublicPoint::deserialize(d)?;
        let symmetric_ciph = d.bytes()?;
        let mac = d.bytes()?;
        Ok(Self {
            c0,
            symmetric_ciph,
            mac,
        })
    }
}
wire_via_serialize!(Ciphertext);

/// `keygenForTesting`: random base point (hash-to-G1 of 32 random bytes) + random scalar.
pub fn keygen_for_testing() -> MasterPrivateKey {
    let h2c = G1Hasher::new(DST_NOBLE_G1_DEFAULT).expect("G1Hasher::new");
    let affine: G1Affine = h2c.hash(&rand_bytes(32)).expect("hash to G1");
    let base = bls12381g1::PublicPoint { pt: affine.into() };
    let scalar = bls12381g1::sample().scalar;
    MasterPrivateKey { base, scalar }
}

pub fn derive_public_key(msk: &MasterPrivateKey) -> MasterPublicKey {
    let pk = msk
        .base
        .scale(&bls12381g1::PrivateScalar::from_fr(msk.scalar));
    MasterPublicKey {
        base_point: msk.base,
        pk,
    }
}

fn dem_encrypt(seed: &[u8], plaintext: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let otp = kdf(seed, DST_OTP, plaintext.len());
    let mac_key = kdf(seed, DST_MAC, 32);
    let symmetric_ciph = xor_bytes(&otp, plaintext);
    let mac = hmac_sha3_256(&mac_key, &symmetric_ciph).to_vec();
    (symmetric_ciph, mac)
}

/// `encryptWithRandomness`: `r = bytesToNumberLE(randomness)` (reduced mod r; TS relies on
/// noble reducing it inside `multiply`), `c0 = base^r`, `seed = e(pk^r, H_G2(id))`.
pub fn encrypt_with_randomness(
    mpk: &MasterPublicKey,
    id: &[u8],
    plaintext: &[u8],
    randomness: &[u8],
) -> Result<Ciphertext> {
    let r = fr_from_le_bytes_mod_order(randomness);
    if r.is_zero() {
        return Err(AceError::crypto("encryptWithRandomness: zero randomness"));
    }
    let id_point = hash_id_to_g2(id)?;
    let seed_element = pairing(&(mpk.pk.pt * r), &id_point.pt);
    let seed = gt_to_bytes(&seed_element);
    let (symmetric_ciph, mac) = dem_encrypt(&seed, plaintext);
    let c0 = bls12381g1::PublicPoint {
        pt: mpk.base_point.pt * r,
    };
    Ok(Ciphertext {
        c0,
        symmetric_ciph,
        mac,
    })
}

pub fn encrypt(mpk: &MasterPublicKey, id: &[u8], plaintext: &[u8]) -> Result<Ciphertext> {
    let r = bls12381g1::sample().scalar;
    encrypt_with_randomness(mpk, id, plaintext, &fr_to_le_bytes(&r))
}

/// Identity-key (share) extraction: `H_G2(id)^{scalar}`. For a share-holder, `scalar` is the
/// Shamir share `f(eval_point)`; for a full key use the master scalar. Not in the TS file
/// (the worker does this), but provided for tests and local use. `proof` is left `None`.
pub fn extract(scalar: &Fr, eval_point: u64, id: &[u8]) -> Result<IdentityDecryptionKeyShare> {
    let id_point = hash_id_to_g2(id)?;
    Ok(IdentityDecryptionKeyShare {
        eval_point,
        idk_share: bls12381g2::PublicPoint {
            pt: id_point.pt * scalar,
        },
        proof: None,
    })
}

/// Verify that `share.idk_share = H_G2(id)^{f(x)}` where `share_pk = base_point^{f(x)}`:
/// `e(base_point, idk_share) == e(share_pk, H_G2(id))`.
///
/// Caller is responsible for binding `share_pk` to the right index.
pub fn verify_share(
    base_point: &bls12381g1::PublicPoint,
    share_pk: &bls12381g1::PublicPoint,
    id: &[u8],
    share: &IdentityDecryptionKeyShare,
) -> bool {
    let Ok(id_point) = hash_id_to_g2(id) else {
        return false;
    };
    let lhs = pairing(&base_point.pt, &share.idk_share.pt);
    let rhs = pairing(&share_pk.pt, &id_point.pt);
    lhs == rhs
}

/// Lagrange-combine the shares at x = 0 in the exponent, then standard BF-IBE decryption.
pub fn decrypt(
    idk_shares: &[IdentityDecryptionKeyShare],
    ciphertext: &Ciphertext,
) -> Result<Vec<u8>> {
    if idk_shares.is_empty() {
        return Err(AceError::crypto("decrypt: no IDK shares provided"));
    }
    let xs: Vec<Fr> = idk_shares
        .iter()
        .map(|s| fr_from_u64(s.eval_point))
        .collect();
    for i in 0..xs.len() {
        for j in (i + 1)..xs.len() {
            if xs[i] == xs[j] {
                return Err(AceError::crypto("decrypt: duplicate evalPoint"));
            }
        }
    }
    let mut idk_full: Option<G2Projective> = None;
    for (i, xi) in xs.iter().enumerate() {
        let mut lambda = Fr::one();
        for (j, xj) in xs.iter().enumerate() {
            if i == j {
                continue;
            }
            // λ_i = Π_{j≠i} (0 - x_j) / (x_i - x_j)  in Fr
            let denom = (*xi - xj)
                .inverse()
                .ok_or_else(|| AceError::crypto("decrypt: duplicate evalPoint"))?;
            lambda *= -*xj * denom;
        }
        if lambda.is_zero() {
            continue;
        }
        let scaled = idk_shares[i].idk_share.pt * lambda;
        idk_full = Some(match idk_full {
            None => scaled,
            Some(acc) => acc + scaled,
        });
    }
    let idk_full =
        idk_full.ok_or_else(|| AceError::crypto("decrypt: all Lagrange coefficients were zero"))?;

    // pair(c0, idkFull) = pair(base^r, H(id)^s) = pair(base, H(id))^{rs} = pair(pk^r, H(id))
    let seed = gt_to_bytes(&pairing(&ciphertext.c0.pt, &idk_full));
    let mac_key = kdf(&seed, DST_MAC, 32);
    let mac_another = hmac_sha3_256(&mac_key, &ciphertext.symmetric_ciph);
    if ciphertext.mac.as_slice() != mac_another.as_slice() {
        return Err(AceError::Verify("decrypt: MAC verification failed".into()));
    }
    let otp = kdf(&seed, DST_OTP, ciphertext.symmetric_ciph.len());
    Ok(xor_bytes(&otp, &ciphertext.symmetric_ciph))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::bls12381fr::eval_poly;

    const ID: &[u8] = b"alice@example.com";
    const MSG: &[u8] = b"hello threshold boneh-franklin";

    /// Shamir-split `msk.scalar` with threshold `t` over eval points `1..=n`.
    fn split(msk: &MasterPrivateKey, t: usize, n: usize) -> Vec<(u64, Fr)> {
        let mut coeffs = vec![msk.scalar];
        for _ in 1..t {
            coeffs.push(bls12381g1::sample().scalar);
        }
        (1..=n as u64)
            .map(|x| (x, eval_poly(&coeffs, fr_from_u64(x))))
            .collect()
    }

    fn is_verify(r: &Result<Vec<u8>>) -> bool {
        matches!(r, Err(AceError::Verify(_)))
    }

    #[test]
    fn shortpk_threshold_roundtrip() {
        let msk = keygen_for_testing();
        let mpk = derive_public_key(&msk);
        let shares = split(&msk, 2, 3);
        let idk_shares: Vec<IdentityDecryptionKeyShare> = shares
            .iter()
            .map(|(x, s)| extract(s, *x, ID).unwrap())
            .collect();

        // verify_share: true with the matching share pk, false otherwise.
        for ((_, s), share) in shares.iter().zip(&idk_shares) {
            let share_pk = msk.base.scale(&bls12381g1::PrivateScalar::from_fr(*s));
            assert!(verify_share(&mpk.base_point, &share_pk, ID, share));
            assert!(!verify_share(&mpk.base_point, &mpk.pk, ID, share));
            assert!(!verify_share(&mpk.base_point, &share_pk, b"bob", share));
        }
        let other = keygen_for_testing();
        let bad = extract(&other.scalar, 1, ID).unwrap();
        let share_pk1 = msk
            .base
            .scale(&bls12381g1::PrivateScalar::from_fr(shares[0].1));
        assert!(!verify_share(&mpk.base_point, &share_pk1, ID, &bad));

        let ct = encrypt(&mpk, ID, MSG).unwrap();
        assert_eq!(ct.symmetric_ciph.len(), MSG.len());
        assert_eq!(ct.mac.len(), 32);

        // Any 2 of 3 decrypt; order-independent.
        for pair in [[0, 1], [0, 2], [1, 2], [2, 0]] {
            let subset = vec![idk_shares[pair[0]].clone(), idk_shares[pair[1]].clone()];
            assert_eq!(decrypt(&subset, &ct).unwrap(), MSG);
        }
        assert_eq!(decrypt(&idk_shares, &ct).unwrap(), MSG);
        // A single share holding the full master scalar also works (any eval point).
        let full = extract(&msk.scalar, 7, ID).unwrap();
        assert_eq!(decrypt(&[full], &ct).unwrap(), MSG);

        // Below threshold / empty / duplicate.
        assert!(is_verify(&decrypt(&idk_shares[..1], &ct)));
        assert!(decrypt(&[], &ct).is_err());
        let dup = vec![idk_shares[0].clone(), idk_shares[0].clone()];
        assert!(decrypt(&dup, &ct).is_err());

        // Wrong identity -> MAC failure.
        let wrong_id: Vec<_> = shares
            .iter()
            .take(2)
            .map(|(x, s)| extract(s, *x, b"bob").unwrap())
            .collect();
        assert!(is_verify(&decrypt(&wrong_id, &ct)));

        // Tampering.
        let mut t1 = ct.clone();
        t1.symmetric_ciph[0] ^= 1;
        assert!(is_verify(&decrypt(&idk_shares[..2], &t1)));
        let mut t2 = ct.clone();
        t2.mac[5] ^= 1;
        assert!(is_verify(&decrypt(&idk_shares[..2], &t2)));
    }

    #[test]
    fn shortpk_encrypt_with_randomness_is_deterministic() {
        let msk = keygen_for_testing();
        let mpk = derive_public_key(&msk);
        let rnd = fr_to_le_bytes(&bls12381g1::sample().scalar);
        let a = encrypt_with_randomness(&mpk, ID, MSG, &rnd).unwrap();
        let b = encrypt_with_randomness(&mpk, ID, MSG, &rnd).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.to_bytes(), b.to_bytes());
        let c = encrypt_with_randomness(&mpk, ID, MSG, &[9u8; 32]).unwrap();
        assert_ne!(a, c);
        assert!(encrypt_with_randomness(&mpk, ID, MSG, &[0u8; 32]).is_err());
        let full = extract(&msk.scalar, 1, ID).unwrap();
        assert_eq!(decrypt(&[full.clone()], &c).unwrap(), MSG);
        let e = encrypt_with_randomness(&mpk, ID, b"", &rnd).unwrap();
        assert_eq!(decrypt(&[full], &e).unwrap(), b"");
    }

    #[test]
    fn shortpk_wire_roundtrips() {
        let msk = keygen_for_testing();
        let mpk = derive_public_key(&msk);
        let b = mpk.to_bytes();
        assert_eq!(b.len(), 2 * 49);
        assert_eq!(b[0], 48);
        // compressed flag set, infinity flag clear (the y-sign bit depends on the point)
        assert_eq!(b[1] & 0xc0, 0x80);
        assert_eq!(b[49], 48);
        assert_eq!(MasterPublicKey::from_bytes(&b).unwrap(), mpk);
        assert_eq!(MasterPublicKey::from_hex(&mpk.to_hex()).unwrap(), mpk);
        let mut trailing = b.clone();
        trailing.push(0);
        assert!(MasterPublicKey::from_bytes(&trailing).is_err());

        let b = msk.to_bytes();
        assert_eq!(b.len(), 49 + 33);
        assert_eq!(b[49], 32);
        assert_eq!(&b[50..], &fr_to_le_bytes(&msk.scalar));
        assert_eq!(MasterPrivateKey::from_bytes(&b).unwrap(), msk);

        let share = extract(&msk.scalar, 3, ID).unwrap();
        let b = share.to_bytes();
        assert_eq!(b.len(), 33 + 97 + 1);
        assert_eq!(b[0], 32);
        assert_eq!(b[1], 3);
        assert!(b[2..33].iter().all(|&x| x == 0));
        assert_eq!(b[33], 96);
        assert_eq!(b[34] & 0xc0, 0x80);
        assert_eq!(b[130], 0);
        assert_eq!(IdentityDecryptionKeyShare::from_bytes(&b).unwrap(), share);
        let with_proof = IdentityDecryptionKeyShare {
            proof: Some(vec![1, 2, 3, 4, 5]),
            ..share.clone()
        };
        let b = with_proof.to_bytes();
        assert_eq!(b.len(), 33 + 97 + 1 + 1 + 5);
        assert_eq!(b[130], 1);
        assert_eq!(b[131], 5);
        assert_eq!(
            IdentityDecryptionKeyShare::from_bytes(&b).unwrap(),
            with_proof
        );

        let ct = encrypt(&mpk, ID, MSG).unwrap();
        let b = ct.to_bytes();
        assert_eq!(b.len(), 49 + 1 + MSG.len() + 33);
        assert_eq!(b[0], 48);
        assert_eq!(b[49] as usize, MSG.len());
        assert_eq!(b[50 + MSG.len()], 32);
        assert_eq!(Ciphertext::from_bytes(&b).unwrap(), ct);
        assert_eq!(Ciphertext::from_hex(&ct.to_hex()).unwrap(), ct);
    }

    #[test]
    fn shortpk_gt_bytes_are_576_le_limbs() {
        let gt = pairing(&bls12381g1::generator().pt, &bls12381g2::generator().pt);
        let bytes = gt_to_bytes(&gt);
        assert_eq!(bytes.len(), 576);
        for limb in bytes.chunks(48) {
            assert!(limb[47] <= 0x1a, "limb is not little-endian Fq");
        }
        let ob = gt_to_bytes(&PairingOutput::<Bls12_381>::zero());
        assert_eq!(ob[0], 1);
        assert!(ob[1..].iter().all(|&x| x == 0));
    }
}
