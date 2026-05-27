# Out of scope (not yet implemented)

The following were called out in earlier discussions and are **not** in the current codebase. Auditors should not flag their absence; they're tracked as future work.

- **Post-quantum PKE.** No PQ-hybrid or PQ-only scheme is currently shipped. (Future: HPKE-X-Wing or Kyber-hybrid; tracked separately.)
- **256-bit security level PKE.** Both PKE schemes are ~128-bit. (Future: HPKE-X448-HKDF-SHA512-ChaCha20Poly1305 or similar.)
- **t-IBE share proof.** The `IdentityDecryptionKeyShare` wire format reserves a 1-byte "proof" flag for a future per-share Schnorr proof; today it is always `0x00` (no proof). The verification check in [`t-ibe.md`](./t-ibe.md) §1 uses on-chain `share_pks` instead, which is sufficient for honest-majority assumptions but not for accountability under accusatory failure.
- **Move-side HPKE / shortsig-aead encrypt-decrypt.** Move only decodes these formats; the on-chain side never holds a private key for either, so no on-chain encrypt or decrypt is needed.
- **DKG bias-avoidance round (GJKR'99 commit-then-open).** Not implemented. The current DKG admits up to `t` bits of bias on the master public key distribution under a rushing adversary; see [`dkg.md`](./dkg.md) §2. Acceptable under standard threshold-decryption / threshold-signing applications, where the master key is consumed only as `g^{MSK}` and bias on a few bits of `MSK` is not exploitable.
- **Formal DKG / DKR / t-IBE secrecy arguments.** Only the VSS sharing-phase secrecy argument ([`vss.md`](./vss.md) §2) is currently spelled out. DKG, DKR, and t-IBE adaptive-decryption security are sketched conceptually in their respective files but not yet written as formal game-based reductions.
