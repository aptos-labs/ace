// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use vss_common::group::{BcsElement, BcsPublicPoint};
use vss_common::session::BcsPcsPublicParams;

pub(crate) fn dummy_pcs_context() -> BcsPcsPublicParams {
    BcsPcsPublicParams {
        generator_g: BcsElement::Bls12381G2(BcsPublicPoint {
            point: vec![1u8; 96],
        }),
        generator_h: BcsElement::Bls12381G2(BcsPublicPoint {
            point: vec![2u8; 96],
        }),
    }
}

pub(crate) fn dummy_share_commitment() -> BcsElement {
    BcsElement::Bls12381G2(BcsPublicPoint {
        point: vec![3u8; 96],
    })
}
