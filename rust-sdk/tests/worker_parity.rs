// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Golden-constant / wire parity between `ace-sdk` and the worker components. These tests are the
//! contract that lets `worker-components/*` adopt `ace-sdk` (phase 4) without changing a single
//! byte on the wire: every primitive both sides implement must agree on identical inputs, and
//! every artifact the worker produces must verify/decrypt in the SDK.

use ace_sdk::group::bls12381fr::{eval_poly, fr_from_le_bytes, fr_to_le_bytes, Fr};
use ace_sdk::group::{bls12381g1, bls12381g2, Element};
use ace_sdk::wire::Wire;
use ace_sdk::{network, pke, t_ibe, utils};
use ark_ff::UniformRand;

fn rand_fr() -> Fr {
    Fr::rand(&mut rand::thread_rng())
}

#[test]
fn fr_encoding_and_poly_eval_agree() {
    for _ in 0..8 {
        let f = rand_fr();
        assert_eq!(vss_common::crypto::fr_to_le_bytes(f), fr_to_le_bytes(&f));
        let b = fr_to_le_bytes(&f);
        assert_eq!(
            vss_common::crypto::fr_from_le_bytes(b),
            fr_from_le_bytes(&b).unwrap()
        );
    }
    let coefs = [rand_fr(), rand_fr(), rand_fr()];
    for x in 1..=5u64 {
        assert_eq!(
            vss_common::crypto::poly_eval(&coefs, Fr::from(x)),
            eval_poly(&coefs, Fr::from(x))
        );
    }
}

#[test]
fn group_point_encodings_agree() {
    for _ in 0..4 {
        let s = rand_fr();
        // generator-based
        let sdk_g1 = bls12381g1::generator().scale(&bls12381g1::PrivateScalar::from_fr(s));
        assert_eq!(
            vss_common::crypto::g1_compressed(s).to_vec(),
            sdk_g1.raw_bytes()
        );
        // arbitrary base
        let base1 = bls12381g1::generator().scale(&bls12381g1::PrivateScalar::from_fr(rand_fr()));
        let w1 = vss_common::crypto::g1_compressed_with_base(s, &base1.raw_bytes()).unwrap();
        assert_eq!(
            w1.to_vec(),
            base1
                .scale(&bls12381g1::PrivateScalar::from_fr(s))
                .raw_bytes()
        );
        let base2 = bls12381g2::generator().scale(&bls12381g2::PrivateScalar::from_fr(rand_fr()));
        let w2 = vss_common::crypto::g2_compressed_with_base(s, &base2.raw_bytes()).unwrap();
        assert_eq!(
            w2.to_vec(),
            base2
                .scale(&bls12381g2::PrivateScalar::from_fr(s))
                .raw_bytes()
        );
    }
    // tagged Element BCS == worker BcsElement BCS
    let p = bls12381g2::generator();
    let worker = vss_common::group::BcsElement::Bls12381G2(vss_common::group::BcsPublicPoint {
        point: p.raw_bytes(),
    });
    assert_eq!(
        bcs::to_bytes(&worker).unwrap(),
        Element::Bls12381G2(p).to_bytes()
    );
    assert_eq!(
        vss_common::crypto::group_identity_compressed(
            network::PRIMITIVE_BFIBE_BLS12381_SHORTPK_OTP_HMAC
        )
        .unwrap(),
        bls12381g1::PublicPoint {
            pt: Default::default()
        }
        .raw_bytes()
    );
}

#[test]
fn kdf_and_hmac_agree() {
    let seed = [3u8; 40];
    for len in [1usize, 31, 32, 33, 100] {
        assert_eq!(
            vss_common::crypto::kdf(&seed, b"dst", len),
            utils::kdf(&seed, b"dst", len)
        );
    }
    let key = [9u8; 32];
    assert_eq!(
        vss_common::crypto::hmac_sha3_256(&key, b"msg"),
        utils::hmac_sha3_256(&key, b"msg")
    );
}

#[test]
fn pke_interop_both_directions() {
    // SDK key, worker encrypts, SDK decrypts -- and the reverse -- for both PKE schemes.
    for scheme in [
        pke::SCHEME_ELGAMAL_OTP_RISTRETTO255,
        pke::SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305,
    ] {
        let dk = pke::keygen(scheme).unwrap();
        let ek = pke::derive_encryption_key(&dk);
        let worker_ek: vss_common::pke::EncryptionKey = bcs::from_bytes(&ek.to_bytes()).unwrap();
        // key encodings agree
        assert_eq!(bcs::to_bytes(&worker_ek).unwrap(), ek.to_bytes());
        // worker -> SDK
        let ct_w = vss_common::crypto::pke_encrypt(&worker_ek, b"from worker");
        let ct_sdk = pke::Ciphertext::from_bytes(&bcs::to_bytes(&ct_w).unwrap()).unwrap();
        assert_eq!(pke::decrypt(&dk, &ct_sdk).unwrap(), b"from worker");
        // SDK -> worker
        let ct = pke::encrypt(&ek, b"from sdk").unwrap();
        assert_eq!(
            vss_common::pke::pke_decrypt_bytes(&dk.to_bytes(), &ct.to_bytes()).unwrap(),
            b"from sdk"
        );
    }
}

/// Split `secret` into a 2-of-3 sharing; returns (shares as Fr, coefficient list).
fn split_2_of_3(secret: Fr) -> Vec<Fr> {
    let coefs = [secret, rand_fr()];
    (1..=3u64).map(|i| eval_poly(&coefs, Fr::from(i))).collect()
}

#[test]
fn worker_extracted_ibe_shares_verify_and_decrypt_in_sdk() {
    // primitive -> (scheme the SDK expects, how to build the tagged base / share-pk elements)
    for primitive in [
        network::PRIMITIVE_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
        network::PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD,
        network::PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM,
    ] {
        let scheme = if primitive == network::PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM {
            1
        } else {
            primitive
        };
        let msk = t_ibe::keygen_for_testing(scheme).unwrap();
        let mpk = t_ibe::derive_public_key(&msk);
        let (secret, base): (Fr, Element) = match scheme {
            0 => {
                let m = msk.as_shortpk_otp_hmac().unwrap();
                (m.scalar, Element::Bls12381G1(m.base))
            }
            _ => {
                let m = msk.as_shortsig_aead().unwrap();
                (m.scalar, Element::Bls12381G2(m.base))
            }
        };
        let id = b"worker-parity/identity";
        let ct = t_ibe::encrypt(&mpk, id, b"plaintext for parity").unwrap();

        let shares_fr = split_2_of_3(secret);
        let mut sdk_shares = vec![];
        for (i, s) in shares_fr.iter().enumerate() {
            let eval_point = i as u64 + 1;
            // the worker's exact extraction routine -> hex of the tagged share
            let hex = network_node::crypto::partial_extract_idk_share(
                primitive,
                id,
                &fr_to_le_bytes(s),
                eval_point,
            )
            .unwrap();
            let share = t_ibe::IdentityDecryptionKeyShare::from_hex(&hex).unwrap();
            assert_eq!(
                share.scheme(),
                scheme,
                "stream shares are tagged as shortsig"
            );
            let share_pk = match &base {
                Element::Bls12381G1(b) => {
                    Element::Bls12381G1(b.scale(&bls12381g1::PrivateScalar::from_fr(*s)))
                }
                Element::Bls12381G2(b) => {
                    Element::Bls12381G2(b.scale(&bls12381g2::PrivateScalar::from_fr(*s)))
                }
            };
            assert!(
                t_ibe::verify_share(&base, &share_pk, id, &share).unwrap(),
                "primitive {primitive} share {eval_point}"
            );
            assert!(!t_ibe::verify_share(&base, &share_pk, b"wrong id", &share).unwrap());
            sdk_shares.push(share);
        }
        assert_eq!(
            t_ibe::decrypt(&sdk_shares[..2], &ct).unwrap(),
            b"plaintext for parity"
        );
        assert_eq!(
            t_ibe::decrypt(&sdk_shares[1..], &ct).unwrap(),
            b"plaintext for parity"
        );
        assert!(t_ibe::decrypt(&sdk_shares[..1], &ct).is_err());
    }
}

#[test]
fn worker_vrf_shares_verify_and_reconstruct_in_sdk() {
    use ace_sdk::aptos::common::ContractID;
    use ace_sdk::aptos::flows::CurrentSessionPks;
    use ace_sdk::aptos::vrf::{
        reconstruct_threshold_vrf, verify_threshold_vrf_share, ThresholdVrfRequestPayload,
        ThresholdVrfShare,
    };
    use ace_sdk::AccountAddress;

    let keypair_id = AccountAddress([0x11; 32]);
    let account = AccountAddress([0x22; 32]);
    let module_addr = AccountAddress([0x33; 32]);
    let label = b"vrf/label".to_vec();
    let chain_id = 118u8;

    // The SDK's VRF input bytes must equal the worker's `ThresholdVrfInput` BCS -- proven
    // indirectly: the worker hashes its own input, and the SDK verifies the share against its own.
    let payload = ThresholdVrfRequestPayload {
        keypair_id,
        epoch: 5,
        contract_id: ContractID::new_aptos(chain_id, module_addr, "acl"),
        label: label.clone(),
        account_address: account,
        response_enc_key: pke::derive_encryption_key(&pke::keygen(pke::DEFAULT_SCHEME).unwrap()),
    };
    let input = payload.to_vrf_input_bytes();

    let worker_cid =
        network_node::verify::ContractId::Aptos(network_node::verify::AptosContractId {
            chain_id,
            module_addr: module_addr.0,
            module_name: "acl".into(),
        });
    // ContractID encodings agree too.
    assert_eq!(
        bcs::to_bytes(&worker_cid).unwrap(),
        payload.contract_id.to_bytes()
    );

    let secret = rand_fr();
    let shares_fr = split_2_of_3(secret);
    let g2 = bls12381g2::generator();
    let pks = CurrentSessionPks {
        base_point: Element::Bls12381G2(g2),
        share_pks: shares_fr
            .iter()
            .map(|s| Element::Bls12381G2(g2.scale(&bls12381g2::PrivateScalar::from_fr(*s))))
            .collect(),
    };
    let mut shares = vec![];
    for (i, s) in shares_fr.iter().enumerate() {
        let bytes = network_node::crypto::partial_derive_threshold_vrf_share(
            &keypair_id.0,
            &worker_cid,
            &account.0,
            &label,
            &fr_to_le_bytes(s),
            i as u64 + 1,
            ace_sdk::group::SCHEME_BLS12381G2,
        )
        .unwrap();
        let share = ThresholdVrfShare::from_bytes(&bytes).unwrap();
        assert!(
            verify_threshold_vrf_share(&share, i, &pks, &input),
            "vrf share {}",
            i + 1
        );
        assert!(!verify_threshold_vrf_share(&share, i, &pks, b"other input"));
        shares.push(share);
    }
    let out = reconstruct_threshold_vrf(&shares[..2]).unwrap();
    assert_eq!(reconstruct_threshold_vrf(&shares[1..]).unwrap(), out);
    assert_eq!(out.len(), 32);
}

#[test]
fn signature_encodings_agree() {
    use ace_sdk::sig;
    let (pk, sk) = sig::keygen();
    let dalek = ed25519_dalek::SigningKey::from_bytes(&sk.bytes);
    // worker-signed -> SDK-verified, and both encodings identical
    let worker_sig = vss_common::sig::sign_ed25519(&dalek, b"msg");
    let sdk_sig = sig::Signature::from_bytes(&worker_sig.to_bytes()).unwrap();
    assert!(sig::verify(b"msg", &sdk_sig, &pk));
    assert_eq!(
        sk.sign(b"msg").to_bytes(),
        worker_sig.to_bytes(),
        "ed25519 is deterministic"
    );
    // SDK public key bytes parse and verify on the worker side
    let worker_pk = vss_common::sig::PublicKey::from_bytes(&pk.to_bytes()).unwrap();
    assert!(worker_pk.verify(b"msg", &worker_sig).unwrap());
    assert_eq!(worker_pk.to_bytes(), pk.to_bytes());
}
