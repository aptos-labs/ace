# Threshold Identity-Based Encryption (`t-ibe::*`)

t-IBE is the layer the **end-user** sees: encryption is to a "keypair-id" (an on-chain DKG session address) and an "identity" (the BCS bytes of `(keypair_id, contract_id, label)`, where `label` is the app-specific scoping bytes); decryption requires t-of-n workers to each release a partial extraction of the IBE identity decryption key (IDK). Each worker holds a Shamir share of the master secret $s$; the master public key $\mathsf{mpk}$ is the joint DKG output (constant-term commitment of the joint polynomial over $\mathbb{F}_r$). See [`dkg.md`](./dkg.md) for how $\mathsf{mpk}$ and the shares are produced.

| Scheme | Tag | Status | Defined |
|--------|-----|--------|---------|
| BFIBE-BLS12381-ShortPK-OTP-HMAC | `0x00` | **test-only** (see below) | `ts-sdk/src/t-ibe/bfibe-bls12381-shortpk-otp-hmac.ts`, `worker-components/network-node/src/crypto.rs:34` |
| BFIBE-BLS12381-ShortSig-AEAD | `0x01` | **production, default** | `ts-sdk/src/t-ibe/bfibe-bls12381-shortsig-aead.ts`, `worker-components/network-node/src/crypto.rs:35` |

> **Audit scope.** Only **scheme `0x01`** is audited. Scheme `0x00` is **test-only** — Boneh–Franklin in G1 with the same hand-rolled OTP + custom-HMAC-SHA3-256 DEM as PKE scheme `0x00` ([`pke.md`](./pke.md)). It is selected only when the underlying DKG uses a G1 basepoint, which today happens only in the regression scenario `scenarios/test-network-protocol-shortpk.ts` and an internal SDK test. Production deployments use a G2 basepoint and therefore scheme `0x01`. A follow-up PR may delete scheme `0x00` from the codebase. The remainder of this file describes scheme `0x01` only.

The runtime choice between schemes is a static dispatch on the underlying DKG basepoint group, in `worker-components/network-node/src/crypto.rs::tibe_scheme_for_group`: G1 → scheme `0x00` (test-only), G2 → scheme `0x01` (production).

## 1. BFIBE-BLS12381-ShortSig-AEAD (scheme `0x01`, default)

A Boneh–Franklin t-IBE (BasicIdent extended to threshold via Shamir over $\mathbb{F}_r$) with a [Fujisaki–Okamoto](https://link.springer.com/chapter/10.1007/3-540-48405-1_34)-style DEM on top.

- **Master public key** lives in **G2** (96-byte compressed).
- **Identity hash** maps to **G1** via RFC 9380 hash-to-curve.
- **IDK share** lives in **G1** (48-byte compressed) — hence "short sig". This matches `draft-irtf-cfrg-bls-signature` "minimal-signature-size", and the share is computationally a [BLS](https://www.iacr.org/archive/asiacrypt2001/22480516.pdf) signature on the identity.
- **DEM** is `HKDF-SHA256` keying `ChaCha20-Poly1305` — the same primitive set as the HPKE-X25519 PKE, with a single derived (key, nonce) pair.

**DSTs** (`ts-sdk/src/t-ibe/bfibe-bls12381-shortsig-aead.ts:38-42`):
```
DST_HASH_ID_TO_CURVE = "BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE"
DST_KDF              = "BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/KDF"
```

**Hash-to-curve suite.** `BLS12381G1_XMD:SHA-256_SSWU_RO_` (RFC 9380 §8.8.1) with the DST above.

**Master keypair.**
```
basePoint ← G2                                 # 96B compressed
s         ← Fr (committee-jointly via DKG)
pk        := s · basePoint                      ∈ G2
MasterPublicKey  = (basePoint ∈ G2, pk ∈ G2)
```

**Encrypt** `(MasterPublicKey, identity_bytes, plaintext)`:
```
r       ← Fr
c0      := r · basePoint                       ∈ G2                          # 96B compressed
Q_id    := hash_to_curve_G1(identity_bytes, DST_HASH_ID_TO_CURVE)             ∈ G1
seed_gt := pairing(Q_id, r · pk)               ∈ Gt
seed    := bls12381_gt_repr_to_bytes(seed_gt)                                 # 576 bytes; canonical Aptos LE-per-limb form (§2)
okm     := HKDF-SHA256(IKM=seed, salt=∅, info=DST_KDF, L=32+12)               # = 44 bytes
key     := okm[0..32]                                                         # ChaCha20 key
nonce   := okm[32..44]                                                        # 12B nonce
aead_ct := ChaCha20-Poly1305(key, nonce, AAD=∅).encrypt(plaintext)
                                                                              # ciphertext || 16B Poly1305 tag
Ciphertext = (c0, aead_ct)                     # 96 + |plaintext| + 16 bytes (excluding wire ULEBs)
```

**Decrypt** with t-of-n IDK shares:
```
For each share i:
  share_i = (eval_point_i, idk_share_i)  where idk_share_i = s_i · Q_id  ∈ G1
  s_i     = Shamir share of master secret at x = eval_point_i

Verify share i (enforced by SDK):
  pairing(idk_share_i, basePoint) == pairing(Q_id, share_pk_i)              # share_pk_i is on-chain
  where share_pk_i = s_i · basePoint                       (read from VSS::share_pks)

Reconstruct full IDK:
  λ_i := ∏_{j ≠ i} (0 - x_j) / (x_i - x_j)   in Fr        (Lagrange basis at x=0)
  idk := Σ_i λ_i · idk_share_i                ∈ G1         # = s · Q_id

Recover seed and decrypt:
  seed_gt := pairing(idk, c0)                 ∈ Gt         # = e(Q_id, basePoint)^{r·s}, identical to encrypt
  seed    := bls12381_gt_repr_to_bytes(seed_gt)
  okm     := HKDF-SHA256(IKM=seed, salt=∅, info=DST_KDF, L=44)
  key     := okm[0..32]
  nonce   := okm[32..44]
  return ChaCha20-Poly1305(key, nonce, AAD=∅).decrypt(aead_ct)              # throws on tag mismatch
```

**Output sizes** (excluding wire ULEBs):
- Ciphertext: **112 + |plaintext|** bytes.
- IDK share: **81 bytes** = 32B `eval_point` LE || 48B G1 || 1B share-proof flag.

**Security.** CCA-secure under [Boneh–Franklin 2001 / FullIdent](https://crypto.stanford.edu/~dabo/papers/bfibe.pdf) on BLS12-381 (BDH assumption), threshold-extended via Shamir over $\mathbb{F}_r$, in the random-oracle model. The AEAD provides authenticated encryption with a single-use derived (key, nonce) — no nonce reuse risk because each fresh $r$ derives a fresh seed and therefore a fresh $(\text{key}, \text{nonce})$. ~128-bit security level.

**Audit notes.**
- Share verification is `pairing(idk_share_i, basePoint) == pairing(Q_id, share_pk_i)` (`ts-sdk/src/t-ibe/bfibe-bls12381-shortsig-aead.ts:374-380`).
- The HKDF `info` parameter is the DST literal — there is no per-ciphertext context beyond the seed itself. Because the seed already binds `Q_id`, the basePoint, and the random `r`, this is sound; but if you ever add a second use of HKDF with the same seed, you must change `info`.
- HKDF L=44 is exactly key+nonce; the AEAD's internal IV expansion is per the AEAD spec.

## 2. Gt → bytes canonicalization

The t-IBE scheme feeds a Gt element into HKDF as IKM. Gt is $\mathbb{F}_{p^{12}}$ (576 bytes uncompressed). The canonical byte representation is the noble/`hpke-js` *big-endian per limb* output of `bls12_381.fields.Fp12.toBytes`, then reversed limb-by-limb to **little-endian per 48-byte Fp limb** to match the on-chain Move convention.

Implementation: `ts-sdk/src/t-ibe/bfibe-bls12381-shortpk-otp-hmac.ts::bls12381GtReprNobleToAptos` and the Rust mirror in `worker-components/network-node/src/crypto.rs`.

Audit hook: any change to this canonicalization breaks cross-implementation interop silently. Round-trip tests in `ts-sdk/tests/bfibe-bls12381-*.test.ts` are the regression gate.
