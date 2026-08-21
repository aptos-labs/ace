# Threshold Identity-Based Encryption (`t-ibe::*`)

t-IBE is the layer the **end-user** sees: encryption is to a "keypair-id" (an on-chain DKG session address) and an "identity" (the BCS bytes of `(keypair_id, contract_id, label)`, where `label` is the app-specific scoping bytes); decryption requires t-of-n workers to each release a partial extraction of the IBE identity decryption key (IDK). Each worker holds a Shamir share of the master secret $s$; the master public key $\mathsf{mpk}$ is the joint DKG output (constant-term commitment of the joint polynomial over $\mathbb{F}_r$). See [`dkg.md`](./dkg.md) for how $\mathsf{mpk}$ and the shares are produced.

| Scheme (t-IBE object tag) | Tag | Status | Defined |
|--------|-----|--------|---------|
| BFIBE-BLS12381-ShortPK-OTP-HMAC | `0x00` | **test-only** (see below) | `ts-sdk/src/t-ibe/bfibe-bls12381-shortpk-otp-hmac.ts`, `worker-components/network-node/src/crypto.rs` |
| BFIBE-BLS12381-ShortSig-AEAD | `0x01` | **production, default** | `ts-sdk/src/t-ibe/bfibe-bls12381-shortsig-aead.ts`, `worker-components/network-node/src/crypto.rs` |

The streaming + seekable variant (**StreamIBE**, §3) is a sibling **primitive** (`3`), not a new
t-IBE object scheme: it reuses the `0x01` key/share objects verbatim. See §3.

> **Audit scope.** Only **scheme `0x01`** is audited. Scheme `0x00` is **test-only** — Boneh–Franklin in G1 with the same hand-rolled OTP + custom-HMAC-SHA3-256 DEM as PKE scheme `0x00` ([`pke.md`](./pke.md)). It is selected only when the underlying DKG uses a G1 basepoint, which today happens only in the regression scenario `scenarios/test-network-protocol-shortpk.ts` and an internal SDK test. Production deployments use a G2 basepoint and therefore scheme `0x01`. A follow-up PR may delete scheme `0x00` from the codebase. The remainder of this file describes scheme `0x01` only.

The decryption request carries an on-chain **`primitive`** id (`worker-components/network-node/src/verify/mod.rs`; `0`=shortpk, `1`=shortsig, `3`=shortsig-stream — VRF's `2` uses its own request variant). For the two block primitives this equals the ciphertext's t-IBE object tag (`0`/`1`), so the wire is unchanged from the legacy `tibe_scheme` field it replaces. The worker validates it against the underlying DKG basepoint group via `crypto::group_scheme_for_primitive` (primitive `0` requires G1; primitives `1` and `3` require G2) and against the on-chain usage mask via `secret_usage::usage_for_primitive`.

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
- Share verification is the pairing equation

  $$e(\sigma_i,g)=e(Q_\text{id},P_i)$$

  where $\sigma_i$ is the IDK share, $g$ the basePoint, $P_i$ the share-PK (`ts-sdk/src/t-ibe/bfibe-bls12381-shortsig-aead.ts:374-380`).
- The HKDF `info` parameter is the DST literal — there is no per-ciphertext context beyond the seed itself. Because the seed already binds `Q_id`, the basePoint, and the random `r`, this is sound; but if you ever add a second use of HKDF with the same seed, you must change `info`.
- HKDF L=44 is exactly key+nonce; the AEAD's internal IV expansion is per the AEAD spec.

## 2. Gt → bytes canonicalization

The t-IBE scheme feeds a Gt element into HKDF as IKM. Gt is $\mathbb{F}_{p^{12}}$ (576 bytes uncompressed). The canonical byte representation is the noble/`hpke-js` *big-endian per limb* output of `bls12_381.fields.Fp12.toBytes`, then reversed limb-by-limb to **little-endian per 48-byte Fp limb** to match the on-chain Move convention.

Implementation: `ts-sdk/src/t-ibe/bfibe-bls12381-shortpk-otp-hmac.ts::bls12381GtReprNobleToAptos` and the Rust mirror in `worker-components/network-node/src/crypto.rs`.

Audit hook: any change to this canonicalization breaks cross-implementation interop silently. Round-trip tests in `ts-sdk/tests/bfibe-bls12381-*.test.ts` are the regression gate.

## 3. StreamIBE — streaming + seekable variant (primitive `3`)

StreamIBE is a **streaming + seekable** variant for large payloads and web-video seek. It is a
sibling **primitive** (on-chain `primitive = 3`, usage bit `8`), **not** a new t-IBE object scheme:
the **IBE half is byte-for-byte identical to `0x01`** — same G2 keys, same `H_G1(id)` DST, same
per-message seed `e(Q_id, pk^r)`, same `c0`, and the **same G1 IDK share**. It reuses the `0x01`
`MasterPublicKey` / `IdentityDecryptionKeyShare` objects verbatim. Only the client-side **DEM**
changes; the worker never runs it.

**Worker impact.** Because the released IDK share is DEM-agnostic, a decryption request carrying
`primitive = 3` is served by the **same** `partial_extract_idk_share` shortsig branch and returns a
share tagged as shortsig (`0x01`), byte-identical to a block-shortsig share. The only worker
differences vs. `primitive = 1` are (a) it maps to usage bit `8` (so on-chain policy can authorize
"encrypt stream" separately from "encrypt block") and (b) group check → G2. Provisioning: a keypair
must carry usage bit `8` (fresh or a combined `bit2|bit8` mask, both G2) to serve streaming.

**DEM (client-side only).** Seekable segmented AEAD (STREAM construction, à la age / Tink):
```
key   := HKDF-SHA256(IKM=seed, salt=∅, info="BONEH_FRANKLIN_BLS12381_SHORTSIG_AEADSTREAM/KDF", L=32)
P     := 65536                                        # plaintext bytes per segment (64 KiB, fixed)
for segment i of k:  nonce_i := BE_11(i) ‖ (0x01 if i==k-1 else 0x00)   # 11B counter ‖ 1B last-flag
                     seg_ct_i := ChaCha20-Poly1305(key, nonce_i, AAD=∅).encrypt(p_i)   # p_i ‖ 16B tag
```

**Wire form — ciphertext *chunks*, not a `Ciphertext` object.** True streaming can't length-prefix
an unknown-size body, and there is no single ciphertext object — only a header chunk plus segment
chunks. On-storage bytes:
```
0x03                       1-byte stream marker (= the primitive), then
c0                         G2 compressed, 96 bytes
seg_ct_0 ‖ … ‖ seg_ct_{k-1}   read to EOF
```
Non-final segments are exactly `P+16` bytes; the final one is the remainder. Segment count +
plaintext length are derivable from the total length (no header field), enabling `readRange` seek:
plaintext `[x, x+len)` → segments `⌊x/P⌋ … ⌊(x+len−1)/P⌋` → their ciphertext bytes, decrypted
independently (each nonce is a pure function of its index) and sliced.

**Security.** Per-segment single-use ChaCha20-Poly1305 (the per-message seed makes `key` unique →
counter nonces never repeat across messages); the counter defeats reordering; the last-flag defeats
truncation in forward streaming. **Seekable tradeoff:** whole-stream truncation is detected only
once the declared end is read (the consumer must know the total length — always true for media via
Content-Length/manifest); every segment remains individually authenticated, so any single-segment
tampering fails closed. ~128-bit.

**Client API / conformance.** Chain-agnostic DEM in `ts-sdk/src/t-ibe/bfibe-bls12381-shortsig-aead-stream.ts`
(+ `t-ibe-stream/`) and `python-sdk/src/ace_sdk/t_ibe/bfibe_bls12381_shortsig_aead_stream.py` (+
`t_ibe_stream.py`); chain scopes `StreamIBE_Aptos` / `StreamIBE_Solana`. Byte-identical TS/Python
chunks are pinned by `test-fixtures/python-sdk-cross-impl.json → t_ibe_shortsig_aead_stream`
(consumed by `ts-sdk/tests/python-cross-impl-fixtures.test.ts` and `python-sdk/tests/test_crypto.py`);
round-trip / seek / fails-closed live in `*-shortsig-aead-stream.test.ts` and `test_tibe_stream.py`.
