// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

mod bytes;
mod public_key;
mod signature;

// BCS is not self-describing and does not support `deserialize_any`, so
// `#[serde(untagged)]` cannot pick a material variant for us. The small
// visitors only read the explicit scheme byte; each payload still uses its
// normal serde implementation after that.
#[cfg(test)]
mod tests;
