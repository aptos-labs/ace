// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Minimal BCS stream reader for parsing variable-length values from buffers that have
//! trailing data after them. Mirrors the streaming semantics of TS's
//! `@aptos-labs/ts-sdk` `Deserializer` and Move's `aptos_std::bcs_stream::BCSStream`.
//!
//! The Aptos `bcs` crate exposes only whole-buffer or whole-reader parsers
//! (`bcs::from_bytes` / `bcs::from_reader`), both of which assert end-of-input
//! and reject trailing data. That forces every caller that has trailing data
//! to know the exact on-wire size of the value they're reading, which scales
//! poorly when adding new variants. This module gives types a way to parse a
//! prefix and report how many bytes they consumed, so callers can keep walking
//! the buffer.

use anyhow::{anyhow, Result};

/// Cursor over a borrowed byte slice that supports the BCS primitives used in
/// this crate's wire formats: `u8`, ULEB128 lengths, and length-prefixed byte
/// fields (`Vec<u8>`).
pub struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.pos)
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.bytes.len() {
            return Err(anyhow!("bcs_stream::read_u8: end of input"));
        }
        let b = self.bytes[self.pos];
        self.pos += 1;
        Ok(b)
    }

    /// Read a ULEB128-encoded unsigned integer (little-endian, 7 bits/byte, MSB = continuation).
    /// Caps at 9 bytes since we never serialize more than `u64`.
    pub fn read_uleb128(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        for byte_idx in 0..10 {
            let b = self.read_u8()?;
            result |= ((b & 0x7f) as u64) << shift;
            if b & 0x80 == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 && byte_idx > 0 {
                return Err(anyhow!("bcs_stream::read_uleb128: value overflows u64"));
            }
        }
        Err(anyhow!("bcs_stream::read_uleb128: ULEB128 too long"))
    }

    /// Read a BCS `Vec<u8>` field (`[ULEB128 length][length bytes]`) and return the bytes.
    pub fn read_bytes_field(&mut self) -> Result<Vec<u8>> {
        let len = self.read_uleb128()? as usize;
        if self.pos + len > self.bytes.len() {
            return Err(anyhow!(
                "bcs_stream::read_bytes_field: need {} bytes, have {}",
                len,
                self.bytes.len() - self.pos
            ));
        }
        let out = self.bytes[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_uleb128_single_byte() {
        let buf = [0x05u8, 0xff];
        let mut cur = Cursor::new(&buf);
        assert_eq!(cur.read_uleb128().unwrap(), 5);
        assert_eq!(cur.position(), 1);
    }

    #[test]
    fn read_uleb128_multi_byte() {
        // 300 = 0xAC 0x02 in ULEB128
        let buf = [0xacu8, 0x02];
        let mut cur = Cursor::new(&buf);
        assert_eq!(cur.read_uleb128().unwrap(), 300);
        assert_eq!(cur.position(), 2);
    }

    #[test]
    fn read_bytes_field_basic() {
        // [ULEB(3)=0x03][a, b, c][trailing]
        let buf = [0x03u8, b'a', b'b', b'c', 0xff];
        let mut cur = Cursor::new(&buf);
        let v = cur.read_bytes_field().unwrap();
        assert_eq!(v, b"abc");
        assert_eq!(cur.position(), 4);
        assert_eq!(cur.remaining(), 1);
    }

    #[test]
    fn read_bytes_field_short_input_errs() {
        let buf = [0x05u8, b'a', b'b']; // claims 5 bytes but only 2 follow
        let mut cur = Cursor::new(&buf);
        assert!(cur.read_bytes_field().is_err());
    }

    #[test]
    fn end_of_input_errs() {
        let buf: [u8; 0] = [];
        let mut cur = Cursor::new(&buf);
        assert!(cur.read_u8().is_err());
    }
}
