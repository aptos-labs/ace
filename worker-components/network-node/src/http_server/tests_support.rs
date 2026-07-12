// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc};

use vss_common::group::{BcsElement, BcsPublicPoint};
use vss_common::session::BcsPcsPublicParams;

use crate::secrets::{ShareEntry, Snapshot};

pub(crate) fn snapshot_with_share(keypair_id: &str, epoch: u64, entry: ShareEntry) -> Snapshot {
    let mut entries = HashMap::new();
    entries.insert((keypair_id.to_string(), epoch), entry);
    Snapshot {
        entries: Arc::new(entries),
    }
}

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
