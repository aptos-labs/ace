// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! The "BCS quartet" every TS wire type has (`serialize/deserialize/toBytes/fromBytes` +
//! `toHex/fromHex`), plus a tiny BCS cursor pair for hand-written layouts. Layouts derived with
//! serde use [`impl_bcs_wire!`]; layouts TS writes by hand use [`Serializer`]/[`Deserializer`].

use crate::error::{AceError, Result};

pub trait Wire: Sized {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
    fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_bytes()))
    }
    fn from_hex(s: &str) -> Result<Self> {
        Self::from_bytes(&decode_hex(s)?)
    }
}

/// Accepts with or without a `0x` prefix.
pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(hex::decode(s)?)
}

pub fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// Implement [`Wire`] for a serde type whose derived BCS layout matches the TS layout.
#[macro_export]
macro_rules! impl_bcs_wire {
    ($t:ty) => {
        impl $crate::wire::Wire for $t {
            fn to_bytes(&self) -> Vec<u8> {
                bcs::to_bytes(self).expect("bcs serialization cannot fail for in-memory values")
            }
            fn from_bytes(bytes: &[u8]) -> $crate::error::Result<Self> {
                let v: Self = bcs::from_bytes(bytes)?;
                Ok(v)
            }
        }
    };
}

/// BCS writer mirroring the `Serializer` methods the TS SDK uses.
#[derive(Default)]
pub struct Serializer {
    buf: Vec<u8>,
}

impl Serializer {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u128(&mut self, v: u128) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn uleb128(&mut self, mut v: u32) -> &mut Self {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.buf.push(byte);
                return self;
            }
            self.buf.push(byte | 0x80);
        }
    }
    /// `serializeBytes`: ULEB128 length prefix + bytes.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.uleb128(b.len() as u32);
        self.buf.extend_from_slice(b);
        self
    }
    /// `serializeFixedBytes`: raw bytes, no prefix.
    pub fn fixed(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }
    pub fn vec_of<T: Wire>(&mut self, items: &[T]) -> &mut Self {
        self.uleb128(items.len() as u32);
        for it in items {
            self.buf.extend_from_slice(&it.to_bytes());
        }
        self
    }
    pub fn option<T: Wire>(&mut self, v: Option<&T>) -> &mut Self {
        match v {
            None => self.u8(0),
            Some(x) => {
                self.u8(1);
                self.buf.extend_from_slice(&x.to_bytes());
                self
            }
        }
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// BCS reader mirroring the `Deserializer` methods the TS SDK uses.
pub struct Deserializer<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Deserializer<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    pub fn finish(self) -> Result<()> {
        if self.remaining() != 0 {
            return Err(AceError::wire(format!("{} trailing bytes", self.remaining())));
        }
        Ok(())
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(AceError::wire(format!(
                "unexpected end of input: need {n} bytes, have {}",
                self.remaining()
            )));
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            b => Err(AceError::wire(format!("invalid bool byte {b}"))),
        }
    }
    pub fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_le_bytes(self.take(16)?.try_into().unwrap()))
    }
    pub fn uleb128(&mut self) -> Result<u32> {
        let mut value: u64 = 0;
        let mut shift = 0;
        loop {
            let byte = self.u8()?;
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift > 28 {
                return Err(AceError::wire("uleb128 too long"));
            }
        }
        u32::try_from(value).map_err(|_| AceError::wire("uleb128 overflow"))
    }
    pub fn bytes(&mut self) -> Result<Vec<u8>> {
        let n = self.uleb128()? as usize;
        Ok(self.take(n)?.to_vec())
    }
    pub fn fixed(&mut self, n: usize) -> Result<Vec<u8>> {
        Ok(self.take(n)?.to_vec())
    }
    pub fn fixed_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.take(N)?.try_into().unwrap())
    }
    pub fn str(&mut self) -> Result<String> {
        String::from_utf8(self.bytes()?).map_err(|e| AceError::wire(format!("utf8: {e}")))
    }
    pub fn vec_len(&mut self) -> Result<usize> {
        Ok(self.uleb128()? as usize)
    }
    pub fn option_tag(&mut self) -> Result<bool> {
        self.bool()
    }
}

/// Run `f` over `bytes` and require that nothing is left over.
pub fn from_bytes_exact<T>(
    bytes: &[u8],
    f: impl FnOnce(&mut Deserializer<'_>) -> Result<T>,
) -> Result<T> {
    let mut d = Deserializer::new(bytes);
    let v = f(&mut d)?;
    d.finish()?;
    Ok(v)
}
