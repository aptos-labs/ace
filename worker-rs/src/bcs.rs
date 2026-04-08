// BCS (Binary Canonical Serialization) reader

use anyhow::{anyhow, Result};

pub struct BcsReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> BcsReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(anyhow!("BCS: unexpected end of data reading u8"));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    pub fn read_fixed_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        if self.pos + n > self.data.len() {
            return Err(anyhow!("BCS: unexpected end of data reading {} fixed bytes", n));
        }
        let bytes = self.data[self.pos..self.pos + n].to_vec();
        self.pos += n;
        Ok(bytes)
    }

    pub fn read_uleb128(&mut self) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        loop {
            let byte = self.read_u8()?;
            result |= ((byte & 0x7f) as u64) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
            if shift >= 64 {
                return Err(anyhow!("BCS: ULEB128 overflow"));
            }
        }
        Ok(result)
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>> {
        let len = self.read_uleb128()? as usize;
        self.read_fixed_bytes(len)
    }

    pub fn read_str(&mut self) -> Result<String> {
        let bytes = self.read_bytes()?;
        String::from_utf8(bytes).map_err(|e| anyhow!("BCS: invalid UTF-8 string: {}", e))
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
}
