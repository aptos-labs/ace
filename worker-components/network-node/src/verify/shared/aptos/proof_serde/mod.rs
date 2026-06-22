// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

pub(super) mod bytes;
pub(super) mod multi_ed25519;

// `AptosPublicKeyMaterial` and `AptosSignatureMaterial` use normal serde enum
// tags for `pk_scheme` / `sig_scheme`. Helpers here only adapt payloads whose
// Aptos wire shape is `serialize_bytes(...)`.
#[cfg(test)]
mod tests;
