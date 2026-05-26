# Sigma-DLog-Eq Proof

**Statement.** Prover knows a witness $s \in \mathbb{F}_r$ such that

$$P_0 = s \cdot B_0, \qquad P_1 = s \cdot B_1, \qquad \text{both in } G \in \{G_1, G_2\}$$

given the four points $(B_0, P_0, B_1, P_1)$.

**Use.** The VSS resharing dealer ([`dkr.md`](./dkr.md) §2) uses this with $B_0 = B_{\text{old}}$, $P_0 = a_0 \cdot B_{\text{old}}$ (= the first commitment $v_0$), $B_1 = H$, $P_1 = a_0 \cdot H$. Convinces the verifier that the committed $a_0$ equals the original secret share $s_j$.

## 1. Prove (Schnorr + Fiat–Shamir)

```
r ← Fr                                        # CSPRNG, fresh per proof
t0 := r · B0                                  ∈ G
t1 := r · B1                                  ∈ G
P1 := s · B1                                  ∈ G   # also returned
trx := chain_id (1B)                          # Aptos chain id
     || ace_addr (32B)                        # ACE deployment address
     || 0x03 || "vss"                         # BCS-encoded String "vss"
     || for each pt in (B0, P0, B1, P1, t0, t1):
            scheme (1B) || u8(|pt|) || pt     # scheme = 0=G1, 1=G2
c       := Fr::from_le_bytes_mod_order( SHA-512(trx) )
s_proof := r + c·s                            ∈ Fr
return (t0, t1, s_proof, P1)
```

**Transcript shape note.** The element-length byte is a plain `u8` (not a ULEB128) — for G1 it's 48, for G2 it's 96, both fit in one byte. Audit point: if a future group adds a > 255-byte element, the transcript must be widened.

## 2. Verify

The on-chain verifier reconstructs the same Fiat–Shamir transcript from $(B_0, P_0, B_1, P_1, t_0, t_1)$ and the bound (`chain_id`, `ace_addr`, `"vss"`), derives $c$, and checks:

$$s_{\text{proof}} \cdot B_0 = t_0 + c \cdot P_0, \qquad s_{\text{proof}} \cdot B_1 = t_1 + c \cdot P_1$$

**Security.** Standard Schnorr-style argument; soundness holds in the algebraic group model under DLog in $G$; HVZK in the ROM. ~128-bit security level on BLS12-381.

**Audit notes.**
- The (`chain_id`, `ace_addr`, `"vss"`) binding prevents cross-chain / cross-deployment proof replay. If the contract is ever redeployed at a different address, **prior VSS proofs become unverifiable** — by design.
- `from_le_bytes_mod_order` of a SHA-512 digest produces a uniformly-distributed $\mathbb{F}_r$ element with negligible bias ($r > 2^{252}$, hash output is 512 bits).
