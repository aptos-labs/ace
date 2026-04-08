// JSON file key share store

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    pub scalar_share_hex: String,   // LE 32 bytes hex
    pub base_hex: String,           // 48 bytes G1 compressed hex
    pub acquired_at_epoch: u64,
}

#[derive(Debug, Clone, Default)]
pub struct ShareStore {
    path: String,
    data: HashMap<String, KeyShare>,
}

impl ShareStore {
    pub fn load(path: &str) -> Self {
        let data = if std::path::Path::new(path).exists() {
            let contents = std::fs::read_to_string(path).unwrap_or_default();
            serde_json::from_str(&contents).unwrap_or_default()
        } else {
            HashMap::new()
        };
        Self { path: path.to_string(), data }
    }

    pub fn get(&self, secret_id: u64) -> Option<&KeyShare> {
        self.data.get(&secret_id.to_string())
    }

    pub fn insert(&mut self, secret_id: u64, share: KeyShare) {
        self.data.insert(secret_id.to_string(), share);
        let contents = serde_json::to_string_pretty(&self.data).unwrap_or_default();
        let _ = std::fs::write(&self.path, contents);
    }
}
