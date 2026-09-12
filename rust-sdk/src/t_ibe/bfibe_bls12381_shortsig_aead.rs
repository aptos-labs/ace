// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Port of `ts-sdk/src/t-ibe/bfibe-bls12381-shortsig-aead.ts`.
//!
//! Boneh-Franklin IBE over BLS12-381, "shortsig" variant:
//! - Master public key / `c0` in G2 (96 bytes compressed).
//! - Identity hashed to G1 (RFC 9380 `BLS12381G1_XMD:SHA-256_SSWU_RO_` with the DST below).
//! - Identity decryption key shares in G1 (48 bytes compressed).
//! - DEM: HKDF-SHA256 → ChaCha20-Poly1305.
//!
//! Gt seed canonicalization: TS takes noble's `Fp12.toBytes()` (12 big-endian 48-byte Fp limbs,
//! order c0.c0.c0, c0.c0.c1, c0.c1.c0, …, c1.c2.c1) and reverses every limb to little-endian —
//! the "Aptos layout". That is exactly arkworks' `Fq12::serialize_uncompressed` (same tower
//! order, LE limbs), so we use it directly. Verified byte-for-byte against the TS/Python fixture
//! ciphertexts in the tests below.

use ark_bls12_381::{g1, Bls12_381, Fr, G1Projective};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::CurveGroup;
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::{One, Zero};
use ark_serialize::CanonicalSerialize;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{AceError, Result};
use crate::group::bls12381fr::{fr_from_le_bytes, fr_to_le_bytes};
use crate::group::bls12381g1::PublicPoint as G1Point;
use crate::group::bls12381g2::PublicPoint as G2Point;
use crate::group::wire_via_serialize;
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

pub const DST_HASH_ID_TO_CURVE: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE";
pub const DST_KDF: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/KDF";

const AEAD_KEY_BYTES: usize = 32;
const AEAD_NONCE_BYTES: usize = 12;
const AEAD_TAG_BYTES: usize = 16;

type G1Hasher =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>;

// ── MasterPublicKey ─────────────────────────────────────────────────────────

/// BCS: `bytes(basePoint G2) ++ bytes(pk G2)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MasterPublicKey {
    pub base_point: G2Point,
    pub pk: G2Point,
}

impl MasterPublicKey {
    pub fn new(base_point: G2Point, pk: G2Point) -> Self {
        Self { base_point, pk }
    }
    pub fn serialize(&self, s: &mut Serializer) {
        self.base_point.serialize(s);
        self.pk.serialize(s);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let base_point = G2Point::deserialize(d)?;
        let pk = G2Point::deserialize(d)?;
        Ok(Self { base_point, pk })
    }
}
wire_via_serialize!(MasterPublicKey);

// ── MasterPrivateKey ────────────────────────────────────────────────────────

/// BCS: `bytes(base G2) ++ bytes(32-byte LE scalar)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MasterPrivateKey {
    pub base: G2Point,
    pub scalar: Fr,
}

impl MasterPrivateKey {
    pub fn new(base: G2Point, scalar: Fr) -> Self {
        Self { base, scalar }
    }
    pub fn serialize(&self, s: &mut Serializer) {
        self.base.serialize(s);
        s.bytes(&fr_to_le_bytes(&self.scalar));
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let base = G2Point::deserialize(d)?;
        let scalar = fr_from_le_bytes(&d.bytes()?)?;
        Ok(Self { base, scalar })
    }
}
wire_via_serialize!(MasterPrivateKey);

// ── IdentityDecryptionKeyShare ──────────────────────────────────────────────

/// BCS: `bytes(32-byte LE evalPoint) ++ bytes(idkShare G1) ++ u8(hasProof) [++ bytes(proof)]`.
///
/// TS holds `evalPoint` as a bigint; we hold a `u64` and require the upper 24 bytes to be zero.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct IdentityDecryptionKeyShare {
    pub eval_point: u64,
    pub idk_share: G1Point,
    pub proof: Option<Vec<u8>>,
}

impl IdentityDecryptionKeyShare {
    pub fn new(eval_point: u64, idk_share: G1Point, proof: Option<Vec<u8>>) -> Self {
        Self {
            eval_point,
            idk_share,
            proof,
        }
    }
    pub fn serialize(&self, s: &mut Serializer) {
        let mut ep = [0u8; 32];
        ep[..8].copy_from_slice(&self.eval_point.to_le_bytes());
        s.bytes(&ep);
        self.idk_share.serialize(s);
        match &self.proof {
            Some(p) => {
                s.u8(1);
                s.bytes(p);
            }
            None => {
                s.u8(0);
            }
        }
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let ep = d.bytes()?;
        if ep.len() != 32 {
            return Err(AceError::wire(
                "IdentityDecryptionKeyShare: expected 32-byte evalPoint",
            ));
        }
        if ep[8..].iter().any(|b| *b != 0) {
            return Err(AceError::wire(
                "IdentityDecryptionKeyShare: evalPoint does not fit in u64",
            ));
        }
        let eval_point = u64::from_le_bytes(ep[..8].try_into().unwrap());
        let idk_share = G1Point::deserialize(d)?;
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

// ── Ciphertext ──────────────────────────────────────────────────────────────

/// BCS: `bytes(c0 G2) ++ bytes(aeadCt)` where `aeadCt = ChaCha20-Poly1305 ct || 16-byte tag`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ciphertext {
    pub c0: G2Point,
    pub aead_ct: Vec<u8>,
}

impl Ciphertext {
    pub fn new(c0: G2Point, aead_ct: Vec<u8>) -> Result<Self> {
        if aead_ct.len() < AEAD_TAG_BYTES {
            return Err(AceError::wire(format!(
                "Ciphertext: aeadCt must be >= {AEAD_TAG_BYTES} bytes (Poly1305 tag), got {}",
                aead_ct.len()
            )));
        }
        Ok(Self { c0, aead_ct })
    }
    pub fn serialize(&self, s: &mut Serializer) {
        self.c0.serialize(s);
        s.bytes(&self.aead_ct);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let c0 = G2Point::deserialize(d)?;
        let aead_ct = d.bytes()?;
        Self::new(c0, aead_ct)
    }
}
wire_via_serialize!(Ciphertext);

// ── Helpers ─────────────────────────────────────────────────────────────────

/// `H_G1(id)` — RFC 9380 BLS12381G1_XMD:SHA-256_SSWU_RO_ with [`DST_HASH_ID_TO_CURVE`].
pub fn hash_id_to_g1(id: &[u8]) -> Result<G1Point> {
    let hasher = G1Hasher::new(DST_HASH_ID_TO_CURVE)
        .map_err(|e| AceError::crypto(format!("hash-to-G1 init: {e:?}")))?;
    let affine = hasher
        .hash(id)
        .map_err(|e| AceError::crypto(format!("hash-to-G1: {e:?}")))?;
    Ok(G1Point {
        pt: G1Projective::from(affine),
    })
}

/// Gt → 576 seed bytes (12 × 48-byte LE Fp limbs; see module docs).
fn gt_to_seed_bytes(gt: &PairingOutput<Bls12_381>) -> Vec<u8> {
    let mut out = Vec::with_capacity(576);
    gt.0.serialize_uncompressed(&mut out)
        .expect("Fq12 serialization cannot fail");
    debug_assert_eq!(out.len(), 576);
    out
}

/// HKDF-SHA256(IKM=seed, salt=∅, info=DST_KDF, L=44) → (32-byte key, 12-byte nonce).
fn derive_aead_key_and_nonce(seed: &[u8]) -> ([u8; AEAD_KEY_BYTES], [u8; AEAD_NONCE_BYTES]) {
    let hk = Hkdf::<Sha256>::new(None, seed);
    let mut okm = [0u8; AEAD_KEY_BYTES + AEAD_NONCE_BYTES];
    hk.expand(DST_KDF, &mut okm)
        .expect("44 bytes is a valid HKDF length");
    let mut key = [0u8; AEAD_KEY_BYTES];
    let mut nonce = [0u8; AEAD_NONCE_BYTES];
    key.copy_from_slice(&okm[..AEAD_KEY_BYTES]);
    nonce.copy_from_slice(&okm[AEAD_KEY_BYTES..]);
    (key, nonce)
}

fn pairing(p: &G1Point, q: &G2Point) -> PairingOutput<Bls12_381> {
    Bls12_381::pairing(p.pt.into_affine(), q.pt.into_affine())
}

// ── Key generation + derivation ─────────────────────────────────────────────

/// Random master private key with a random G2 base point. Tests only — in production the base
/// point comes from the on-chain DKG session.
pub fn keygen_for_testing() -> MasterPrivateKey {
    let base = crate::group::bls12381g2::generator().scale(&crate::group::bls12381g2::sample());
    let scalar = crate::group::bls12381g2::sample().scalar;
    MasterPrivateKey::new(base, scalar)
}

pub fn derive_public_key(msk: &MasterPrivateKey) -> MasterPublicKey {
    let pk = G2Point {
        pt: msk.base.pt * msk.scalar,
    };
    MasterPublicKey::new(msk.base, pk)
}

/// Full identity decryption key `msk · H_G1(id)`, wrapped as a single share at eval point 1
/// (a one-element share set interpolates to itself), so it can be fed straight to [`decrypt`].
pub fn extract(msk_scalar: &Fr, id: &[u8]) -> Result<IdentityDecryptionKeyShare> {
    let id_point = hash_id_to_g1(id)?;
    Ok(IdentityDecryptionKeyShare::new(
        1,
        G1Point {
            pt: id_point.pt * *msk_scalar,
        },
        None,
    ))
}

// ── Encrypt / Decrypt ───────────────────────────────────────────────────────

/// IBE half of encryption: `(seed = e(H_G1(id), pk^r), c0 = r · basePoint)`.
/// `randomness` is interpreted as a little-endian integer (TS `bytesToNumberLE`), reduced mod r.
pub fn ibe_encrypt_seed_and_c0(
    mpk: &MasterPublicKey,
    id: &[u8],
    randomness: &[u8],
) -> Result<(Vec<u8>, G2Point)> {
    let r = crate::group::bls12381fr::fr_from_le_bytes_mod_order(randomness);
    let id_point = hash_id_to_g1(id)?;
    let pk_r = G2Point { pt: mpk.pk.pt * r };
    let seed = gt_to_seed_bytes(&pairing(&id_point, &pk_r));
    let c0 = G2Point {
        pt: mpk.base_point.pt * r,
    };
    Ok((seed, c0))
}

pub fn encrypt_with_randomness(
    mpk: &MasterPublicKey,
    id: &[u8],
    plaintext: &[u8],
    randomness: &[u8],
) -> Result<Ciphertext> {
    let (seed, c0) = ibe_encrypt_seed_and_c0(mpk, id, randomness)?;
    let (key, nonce) = derive_aead_key_and_nonce(&seed);
    let cipher = ChaCha20Poly1305::new((&key).into());
    let aead_ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| AceError::crypto("ChaCha20-Poly1305 encrypt failed"))?;
    Ciphertext::new(c0, aead_ct)
}

/// Encrypt with fresh randomness.
pub fn encrypt(mpk: &MasterPublicKey, id: &[u8], plaintext: &[u8]) -> Result<Ciphertext> {
    let r = crate::group::bls12381g2::sample().scalar;
    encrypt_with_randomness(mpk, id, plaintext, &fr_to_le_bytes(&r))
}

/// Pairing check `e(idkShare, basePoint) == e(H_G1(id), sharePk)`; the caller binds `share_pk`
/// to the share's evaluation point.
pub fn verify_share(
    base_point: &G2Point,
    share_pk: &G2Point,
    id: &[u8],
    share: &IdentityDecryptionKeyShare,
) -> bool {
    let Ok(id_point) = hash_id_to_g1(id) else {
        return false;
    };
    pairing(&share.idk_share, base_point) == pairing(&id_point, share_pk)
}

/// IBE half of decryption: Lagrange-interpolate the shares in G1 at x=0 to recover the full
/// identity key, then `seed = e(idkFull, c0)`.
pub fn ibe_reconstruct_seed(
    idk_shares: &[IdentityDecryptionKeyShare],
    c0: &G2Point,
) -> Result<Vec<u8>> {
    if idk_shares.is_empty() {
        return Err(AceError::crypto("decrypt: no IDK shares provided"));
    }
    let xs: Vec<Fr> = idk_shares.iter().map(|s| Fr::from(s.eval_point)).collect();
    for i in 0..xs.len() {
        for j in i + 1..xs.len() {
            if xs[i] == xs[j] {
                return Err(AceError::crypto("decrypt: duplicate evalPoint"));
            }
        }
    }
    let mut idk_full = G1Projective::zero();
    let mut any = false;
    for (i, xi) in xs.iter().enumerate() {
        let mut lambda = Fr::one();
        for (j, xj) in xs.iter().enumerate() {
            if i == j {
                continue;
            }
            let denom = *xi - *xj;
            let inv = ark_ff::Field::inverse(&denom)
                .ok_or_else(|| AceError::crypto("decrypt: zero Lagrange denominator"))?;
            lambda *= -*xj * inv;
        }
        if lambda.is_zero() {
            continue;
        }
        any = true;
        idk_full += idk_shares[i].idk_share.pt * lambda;
    }
    if !any {
        return Err(AceError::crypto(
            "decrypt: all Lagrange coefficients were zero",
        ));
    }
    Ok(gt_to_seed_bytes(&pairing(&G1Point { pt: idk_full }, c0)))
}

/// Decrypt with a set of IDK shares at distinct eval points. Tag mismatch → [`AceError::Verify`].
pub fn decrypt(
    idk_shares: &[IdentityDecryptionKeyShare],
    ciphertext: &Ciphertext,
) -> Result<Vec<u8>> {
    let seed = ibe_reconstruct_seed(idk_shares, &ciphertext.c0)?;
    let (key, nonce) = derive_aead_key_and_nonce(&seed);
    let cipher = ChaCha20Poly1305::new((&key).into());
    cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.aead_ct.as_slice())
        .map_err(|_| AceError::Verify("decrypt: ChaCha20-Poly1305 tag verification failed".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::bls12381fr::eval_poly;
    use crate::wire::decode_hex;

    fn fixture() -> serde_json::Value {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-fixtures/python-sdk-cross-impl.json"
        ))
        .unwrap();
        v["t_ibe_shortsig_aead"].clone()
    }

    /// The fixture hex strings are the TAGGED layouts from `ts-sdk/src/t-ibe/index.ts`: a leading
    /// `u8` scheme byte (`01` = shortsig-aead) followed by the scheme-1 struct. Strip it.
    fn untagged(hex: &str) -> Vec<u8> {
        let b = decode_hex(hex).unwrap();
        assert_eq!(b[0], 1, "expected scheme tag 01");
        b[1..].to_vec()
    }

    #[test]
    fn cross_impl_fixture_matches_ts_and_python() {
        let fx = fixture();
        let id = fx["identity_utf8"].as_str().unwrap().as_bytes();
        let pt = fx["plaintext_utf8"].as_str().unwrap().as_bytes();
        let msk =
            MasterPrivateKey::from_bytes(&untagged(fx["master_private_key_hex"].as_str().unwrap()))
                .unwrap();
        let mpk =
            MasterPublicKey::from_bytes(&untagged(fx["master_public_key_hex"].as_str().unwrap()))
                .unwrap();
        assert_eq!(derive_public_key(&msk), mpk);

        let randomness = decode_hex(fx["randomness_hex"].as_str().unwrap()).unwrap();
        let ct = encrypt_with_randomness(&mpk, id, pt, &randomness).unwrap();
        let ts_ct = untagged(fx["typescript_ciphertext_hex"].as_str().unwrap());
        let py_ct = untagged(fx["python_ciphertext_hex"].as_str().unwrap());
        assert_eq!(
            ct.to_bytes(),
            ts_ct,
            "ciphertext must match TS byte-for-byte"
        );
        assert_eq!(
            ct.to_bytes(),
            py_ct,
            "ciphertext must match Python byte-for-byte"
        );

        let idk = IdentityDecryptionKeyShare::from_bytes(&untagged(
            fx["identity_decryption_key_hex"].as_str().unwrap(),
        ))
        .unwrap();
        assert_eq!(idk.eval_point, 1);
        assert_eq!(extract(&msk.scalar, id).unwrap(), idk);
        assert!(verify_share(&mpk.base_point, &mpk.pk, id, &idk));

        let parsed = Ciphertext::from_bytes(&ts_ct).unwrap();
        assert_eq!(decrypt(&[idk.clone()], &parsed).unwrap(), pt);
        assert_eq!(decrypt(&[idk], &ct).unwrap(), pt);
    }

    #[test]
    fn threshold_roundtrip() {
        let msk = keygen_for_testing();
        let mpk = derive_public_key(&msk);
        let id = b"some identity";
        let pt = b"hello threshold ibe";

        // Shamir split scalar: f(0) = s, degree 1 (threshold 2 of 3).
        let a1 = crate::group::bls12381g2::sample().scalar;
        let coeffs = [msk.scalar, a1];
        let shares: Vec<IdentityDecryptionKeyShare> = (1u64..=3)
            .map(|i| {
                let si = eval_poly(&coeffs, Fr::from(i));
                let mut sh = extract(&si, id).unwrap();
                sh.eval_point = i;
                sh
            })
            .collect();
        for (i, sh) in shares.iter().enumerate() {
            let si = eval_poly(&coeffs, Fr::from(i as u64 + 1));
            let share_pk = G2Point {
                pt: msk.base.pt * si,
            };
            assert!(verify_share(&msk.base, &share_pk, id, sh));
            assert!(!verify_share(&msk.base, &mpk.pk, id, sh));
            assert!(!verify_share(&msk.base, &share_pk, b"other id", sh));
        }

        let ct = encrypt(&mpk, id, pt).unwrap();
        assert_eq!(
            decrypt(&[shares[0].clone(), shares[1].clone()], &ct).unwrap(),
            pt
        );
        assert_eq!(
            decrypt(&[shares[2].clone(), shares[0].clone()], &ct).unwrap(),
            pt
        );
        assert_eq!(decrypt(&shares, &ct).unwrap(), pt);
        // Full key alone at eval point 1.
        assert_eq!(
            decrypt(&[extract(&msk.scalar, id).unwrap()], &ct).unwrap(),
            pt
        );

        // Insufficient shares → wrong key → tag failure.
        assert!(matches!(
            decrypt(&[shares[0].clone()], &ct),
            Err(AceError::Verify(_))
        ));
        assert!(decrypt(&[], &ct).is_err());
        assert!(decrypt(&[shares[0].clone(), shares[0].clone()], &ct).is_err());

        // Tampered ciphertext.
        let mut bad = ct.clone();
        bad.aead_ct[0] ^= 1;
        assert!(matches!(decrypt(&shares, &bad), Err(AceError::Verify(_))));
        // Wrong identity.
        let other = extract(&msk.scalar, b"other").unwrap();
        assert!(matches!(decrypt(&[other], &ct), Err(AceError::Verify(_))));
    }

    #[test]
    fn wire_roundtrips() {
        let msk = keygen_for_testing();
        let mpk = derive_public_key(&msk);
        assert_eq!(MasterPrivateKey::from_hex(&msk.to_hex()).unwrap(), msk);
        assert_eq!(MasterPublicKey::from_hex(&mpk.to_hex()).unwrap(), mpk);
        let mut sh = extract(&msk.scalar, b"id").unwrap();
        assert_eq!(
            IdentityDecryptionKeyShare::from_hex(&sh.to_hex()).unwrap(),
            sh
        );
        sh.eval_point = 7;
        sh.proof = Some(vec![1, 2, 3]);
        let b = sh.to_bytes();
        assert_eq!(b.len(), 1 + 32 + 1 + 48 + 1 + 1 + 3);
        assert_eq!(IdentityDecryptionKeyShare::from_bytes(&b).unwrap(), sh);
        let ct = encrypt(&mpk, b"id", b"msg").unwrap();
        assert_eq!(Ciphertext::from_hex(&ct.to_hex()).unwrap(), ct);
        assert!(Ciphertext::from_bytes(&[ct.to_bytes(), vec![0]].concat()).is_err());
    }
}
