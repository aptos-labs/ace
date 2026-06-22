// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc};

use vss_common::pke::EncryptionKey;
use vss_common::pke_hpke_x25519_chacha20poly1305 as hpke;

use crate::secrets::{ShareEntry, Snapshot};

pub(crate) fn dummy_response_enc_key() -> EncryptionKey {
    EncryptionKey::HpkeX25519ChaCha20Poly1305(hpke::EncryptionKey { pk: vec![0u8; 32] })
}

pub(crate) fn snapshot_with_share(keypair_id: &str, epoch: u64, entry: ShareEntry) -> Snapshot {
    let mut entries = HashMap::new();
    entries.insert((keypair_id.to_string(), epoch), entry);
    Snapshot {
        entries: Arc::new(entries),
    }
}
