# Notation and conventions

- $\mathbb{F}_r$ — scalar field of BLS12-381, prime order $r \approx 2^{252}$.
- $\mathbb{G}_1$, $\mathbb{G}_2$ — the two pairing-friendly subgroups of BLS12-381 (cofactor-cleared).
- $\mathbb{G}_t$ — target group, $\mathbb{F}_{p^{12}}$ in BLS12-381.
- $e(\cdot, \cdot)\colon \mathbb{G}_1 \times \mathbb{G}_2 \to \mathbb{G}_t$ — the BLS12-381 optimal Ate pairing.
- $\mathsf{Ristretto255}$ — prime-order group derived from Ed25519 (RFC 9496 candidate).
- $g$ — generic notation for a group element used as a base point in a particular construction (the session's `public_base_element` for VSS; the master public key's basePoint for t-IBE; etc.). Specific base points are subscripted: $g_{\text{old}}$, $g_{\text{new}}$, $g_1 \in \mathbb{G}_1$, $g_2 \in \mathbb{G}_2$.
- Group operations are written **multiplicatively** in this folder: $g^x$ for scalar exponentiation, $g^x \cdot g^y$ for the group operation. BLS12-381 $\mathbb{G}_1$ and $\mathbb{G}_2$ are elliptic curves where the implementation uses additive notation; the two are mathematically identical and conversion is unambiguous.
- $\|$ denotes byte concatenation. $\mathsf{LE64}(x)$ means 8-byte little-endian. $\mathsf{BCS}(\cdot)$ is Aptos's Binary Canonical Serialization (`Vec<u8>` $\Rightarrow$ $\mathsf{ULEB128}(\mathsf{len}) \,\|\, \mathsf{bytes}$).
- $x \in_R S$ means $x$ is sampled uniformly at random from the set $S$.
- All hash-to-curve uses RFC 9380 ($\mathsf{hash\_to\_curve}$) with the per-suite DST listed in the scheme that uses it.
- Random sampling uses each platform's CSPRNG (`OsRng` in Rust, `crypto.getRandomValues` / Web Crypto in TS). See [`identifiers.md`](./identifiers.md) for the per-component RNG table.

Group/scheme tags used throughout:

- `group::SCHEME_BLS12381G1 = 0x00`
- `group::SCHEME_BLS12381G2 = 0x01`

Defined in `contracts/group/sources/group.move` and mirrored in `worker-components/vss-common/src/session.rs`. Per-scheme element sizes and hash-to-curve suites are tabulated in [`identifiers.md`](./identifiers.md).
