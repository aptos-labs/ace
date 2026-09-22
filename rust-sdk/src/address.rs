// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Aptos `AccountAddress`: 32 bytes, BCS = raw fixed bytes (no length prefix). Stands in for
//! `@aptos-labs/ts-sdk`'s `AccountAddress` so the crate needs no Aptos SDK dependency.

use std::fmt;

use crate::error::{AceError, Result};
use crate::wire::{Deserializer, Serializer, Wire};

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AccountAddress(pub [u8; 32]);

impl AccountAddress {
    pub const ZERO: AccountAddress = AccountAddress([0u8; 32]);
    pub const ONE: AccountAddress = {
        let mut b = [0u8; 32];
        b[31] = 1;
        AccountAddress(b)
    };

    /// Parse `0x`-prefixed or bare hex up to 64 nibbles (left-padded) -- what
    /// `AccountAddress.from(...)` accepts in TS.
    pub fn from_str_relaxed(s: &str) -> Result<Self> {
        let h = s.strip_prefix("0x").unwrap_or(s);
        if h.is_empty() || h.len() > 64 || !h.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(AceError::wire(format!("invalid account address: {s}")));
        }
        let bytes = hex::decode(format!("{:0>64}", h))?;
        Ok(AccountAddress(bytes.try_into().unwrap()))
    }

    /// `toStringLong()`: `0x` + 64 lowercase hex digits.
    pub fn to_string_long(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    pub fn serialize(&self, s: &mut Serializer) {
        s.fixed(&self.0);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(AccountAddress(d.fixed_array::<32>()?))
    }
}

impl Wire for AccountAddress {
    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| {
            AceError::wire(format!(
                "account address must be 32 bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(AccountAddress(arr))
    }
}

impl fmt::Debug for AccountAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_long())
    }
}
impl fmt::Display for AccountAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_long())
    }
}
impl std::str::FromStr for AccountAddress {
    type Err = AceError;
    fn from_str(s: &str) -> Result<Self> {
        Self::from_str_relaxed(s)
    }
}
impl From<[u8; 32]> for AccountAddress {
    fn from(b: [u8; 32]) -> Self {
        AccountAddress(b)
    }
}

impl serde::Serialize for AccountAddress {
    fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.to_string_long())
        } else {
            serde::Serialize::serialize(&self.0, s) // BCS: fixed 32 bytes
        }
    }
}

impl<'de> serde::Deserialize<'de> for AccountAddress {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> core::result::Result<Self, D::Error> {
        if d.is_human_readable() {
            let s = <String as serde::Deserialize>::deserialize(d)?;
            AccountAddress::from_str_relaxed(&s).map_err(serde::de::Error::custom)
        } else {
            let b = <[u8; 32] as serde::Deserialize>::deserialize(d)?;
            Ok(AccountAddress(b))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_format() {
        let a = AccountAddress::from_str_relaxed("0x1").unwrap();
        assert_eq!(a, AccountAddress::ONE);
        assert_eq!(a.to_string_long(), format!("0x{}1", "0".repeat(63)));
        assert_eq!(AccountAddress::from_str_relaxed("1").unwrap(), a);
        assert!(AccountAddress::from_str_relaxed("0xzz").is_err());
        assert!(AccountAddress::from_str_relaxed(&"1".repeat(65)).is_err());
        assert_eq!(bcs::to_bytes(&a).unwrap(), a.to_bytes());
        assert_eq!(bcs::from_bytes::<AccountAddress>(&a.to_bytes()).unwrap(), a);
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            format!("\"{}\"", a.to_string_long())
        );
    }
}
