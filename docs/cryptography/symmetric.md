# Symmetric primitives

## 1. KDF

A SHA3-256-based deterministic KDF that mirrors `ts-sdk/src/utils.ts::kdf`.

```
kdf(seed, dst, target_len) → Vec<u8> of length target_len

block_idx := 0
output    := []
while target_len > 0:
    block := SHA3-256( BCS(seed) || BCS(dst) || LE64(target_len_total) || LE64(block_idx) )
    take  := min(32, target_len)
    output ||= block[0..take]
    target_len -= take
    block_idx  += 1
return output
```
where `BCS(bytes) = ULEB128(bytes.len()) || bytes` and `target_len_total` is the **original** requested length (not the decreasing remaining).

Source: `worker-components/vss-common/src/crypto.rs:26-48` (Rust), `ts-sdk/src/utils.ts` (TS).

**Audit notes.**
- Domain separation is provided by `dst`. `seed.len()` is also covered (via the BCS length prefix), so colliding `(seed, dst)` requires colliding the entire SHA3-256 input.
- `target_len` is included in the per-block hash, so the same `(seed, dst, block_idx)` produces a different block for a different `target_len`. This is non-standard relative to HKDF and serves no obvious security purpose — but it's harmless and matches the TS / on-chain Move spec.
- SHA3-256 is used (Keccak), not SHA-256. Sponge construction → no length-extension risk.

## 2. HMAC-SHA3-256

Standard HMAC ([RFC 2104](https://www.rfc-editor.org/rfc/rfc2104)) with SHA3-256 and a fixed 32-byte key.

```
hmac_sha3_256(key[32], msg) → [32]
  pad := key || 0x00·32      # 64 bytes
  ipad := pad XOR (0x36·64)
  opad := pad XOR (0x5c·64)
  inner := SHA3-256(ipad || msg)
  outer := SHA3-256(opad || inner)
  return outer
```
Source: `worker-components/vss-common/src/crypto.rs:76-96` (Rust), `ts-sdk/src/utils.ts` (TS).

**Audit notes.**
- HMAC is overkill on a sponge primitive (SHA3-256 is not vulnerable to length-extension), but the construction is well-understood and the cost is one extra hash.
- The 64-byte block size is the SHA3-256 *capacity-block* convention used in this repo for HMAC; it is not the SHA3-256 rate (which is 136 bytes). Result: this is **not** the FIPS 198-1 HMAC-SHA3-256 (which uses a 136-byte block). It is an HMAC-like construction with a fixed 64-byte block, identical across TS, Rust, and (transitively) Move-side roundtrips. **External tooling that expects FIPS HMAC-SHA3-256 will compute different MACs.**
- This is intentional and load-bearing; it is the contract between `ts-sdk` and the workers. Auditors should verify (a) it's used consistently and (b) the implication is documented.
