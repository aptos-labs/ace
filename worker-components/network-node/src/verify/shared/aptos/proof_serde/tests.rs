// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use serde::Serialize;

use super::super::constants::{PK_SCHEME_ED25519_WIRE, SIG_SCHEME_ED25519_WIRE};
use super::super::{AptosProofOfPermission, AptosPublicKeyMaterial, AptosSignatureMaterial};

#[derive(Serialize)]
struct LegacyEd25519Proof {
    user_addr: [u8; 32],
    pk_scheme: u8,
    #[serde(with = "serde_bytes")]
    public_key: Vec<u8>,
    sig_scheme: u8,
    #[serde(with = "serde_bytes")]
    signature: Vec<u8>,
    full_message: String,
}

#[test]
fn proof_material_serde_keeps_legacy_wire_shape() {
    let user_addr = [0x11; 32];
    let public_key = [0x22; 32];
    let signature = [0x33; 64];
    let full_message = "APTOS\nmessage: 0xabc".to_string();
    let legacy = LegacyEd25519Proof {
        user_addr,
        pk_scheme: PK_SCHEME_ED25519_WIRE,
        public_key: public_key.to_vec(),
        sig_scheme: SIG_SCHEME_ED25519_WIRE,
        signature: signature.to_vec(),
        full_message: full_message.clone(),
    };
    let typed = AptosProofOfPermission {
        user_addr,
        public_key: AptosPublicKeyMaterial::Ed25519(public_key),
        signature: AptosSignatureMaterial::Ed25519(signature),
        full_message,
    };
    let legacy_bytes = bcs::to_bytes(&legacy).unwrap();
    assert_eq!(bcs::to_bytes(&typed).unwrap(), legacy_bytes);

    let decoded: AptosProofOfPermission = bcs::from_bytes(&legacy_bytes).unwrap();
    assert!(matches!(
        decoded.public_key,
        AptosPublicKeyMaterial::Ed25519(_)
    ));
    assert!(matches!(
        decoded.signature,
        AptosSignatureMaterial::Ed25519(_)
    ));
}
