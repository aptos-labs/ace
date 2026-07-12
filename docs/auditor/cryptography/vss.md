# Verifiable Secret Sharing (VSS)

ACE's VSS is a single-dealer synchronous VSS built from the protocol skeleton in Das et al. "Verifiable Secret Sharing Simplified" (ePrint 2023/1196), with the paper's Appendix A.2 Pedersen polynomial commitment instantiated over ACE's abstract BLS12-381 group interface. DKG composes one VSS per committee member; DKR composes one resharing VSS per old-committee member.

This document uses additive group notation for the PCS and sigma-proof equations, matching the Move implementation: \(xG\) means scalar multiplication, and \(X + Y\) is group addition.

## 1. Construction

Let the committee size be \(n\) and the reconstruction threshold be \(t\). A dealer samples two degree-\((t-1)\) polynomials over \(\mathbb{F}_r\):

\[
p(X) = p_0 + p_1X + \cdots + p_{t-1}X^{t-1},
\qquad
r(X) = r_0 + r_1X + \cdots + r_{t-1}X^{t-1}.
\]

The secret being shared is \(p(0)\). The blinding polynomial \(r\) is never needed for reconstruction and is revealed only for disputed/unacknowledged openings.

### 1.1 Pedersen PCS

The PCS public parameters are two same-group generators \((G,H)\). A standalone VSS samples them on chain when the VSS session is created. DKG samples one context and passes it to every child VSS; DKR carries forward the original DKG context so commitments remain in one basis across reshares. Security assumes the discrete-log relation between \(G\) and \(H\) is unknown; hiding of individual Pedersen commitments follows from the uniform blinding value \(r(i)\).

ACE commits over the evaluation domain \(\{0,1,\ldots,n\}\):

\[
V_i = p(i)G + r(i)H \qquad \text{for } i=0,\ldots,n.
\]

The original paper's Appendix A.2 only needs commitments for holder positions. ACE additionally includes \(V_0\) because DKG/DKR aggregate a root commitment and DKR must bind a new resharing constant to an already-committed old share opening. The contract therefore stores \(n+1\) commitment points; `commitment_len()` returns \(n\) holder positions.

An opening at position \(i\) is:

\[
(i,\; p(i),\; r(i)).
\]

Verification checks:

\[
p(i)G + r(i)H \stackrel{?}{=} V_i.
\]

### 1.2 Degree Check

The contract receives only group elements \(V_i\), not the polynomials \(p\) and \(r\). To ensure the commitment vector is consistent with some degree-\((t-1)\) pair \((p,r)\), `pedersen_polynomial_commitment` runs a low-degree check over the group codeword.

For \(N=n+1\) commitment points and degree bound \(d=t-1\), the checker samples a random polynomial \(z\) of degree at most \(N-d-2\) and checks:

\[
\sum_{i=0}^{N-1} z(i)\lambda_i V_i = 0,
\qquad
\lambda_i = \left(\prod_{j\neq i}(i-j)\right)^{-1}.
\]

This is the SCRAPE/Pedersen Appendix A.2 check: if \(V_i\) are evaluations of a degree-\(d\) polynomial over the group, the weighted sum vanishes for every such \(z\). If the submitted vector has higher degree, a fresh random \(z\) catches it except with the usual Schwartz-Zippel style probability. ACE derives \(z\) from Aptos on-chain randomness after DC0 is committed and advances the check with `touch()` transactions to stay inside gas limits.

The \(\lambda_i\) values are computed from a factorial-inverse table for the fixed ACE domain \(0,1,\ldots,n\), currently supporting up to 64 workers.

### 1.3 Round Flow

`DealerContribution0` contains:

- the Pedersen commitment vector \(V_0,\ldots,V_n\);
- for resharing sessions only, a sigma proof tying the new constant opening to the previous commitment.

The dealer's polynomials are stored in the off-chain VSS store, not encrypted
onto the chain. After DC0, the chain runs the touch-driven degree check before
recipients may ACK.

A holder requests its opening over the node-message gateway. The request is a
signed node message whose sender must match the requested holder index and
includes a fresh HPKE-X25519 response key. The dealer encrypts the BCS
opening \((i,p(i),r(i))\) under that key with AAD binding the response to the
signed request transcript. The holder decrypts and verifies:

\[
p(i)G+r(i)H \stackrel{?}{=} V_i
\]

and ACKs on chain if the opening is valid. The ACK is a normal Aptos transaction
from the holder account; there is no separate off-chain receipt in the VSS
contract semantics.

After the ACK window, the dealer submits `DealerContribution1`:

- `shares_to_reveal[0]` is always `None`;
- for a holder \(i\geq1\) that did not ACK, `shares_to_reveal[i]` is the full opening \((i,p(i),r(i))\);
- for each holder that did ACK, no opening is revealed.
- `public_keys[i] = p(i)G` for every position `i = 0..n`;
- when an opening remains private, a sigma proof binds `public_keys[i]` to the
  same secret scalar committed in `V_i`.

For non-ACKing holders, the chain verifies the revealed Pedersen opening. For
ACKing holders, the chain relies on the holder's on-chain ACK that it received
and verified the private opening. The chain separately verifies each public key
either from a revealed opening or from its DC1 sigma proof.

### 1.4 Resharing Same-Secret Proof

The proof module is `ace::sigma_dlog_linear`. It is a Fiat-Shamir generalized Schnorr proof for a witness vector satisfying multiple linear representation equations.

For resharing, the witness is the old and new opening scalars. If the previous
commitment is:

\[
C_{\text{old}} = sG_{\text{old}} + \rho H_{\text{old}},
\]

and the new VSS root commitment is:

\[
C_{\text{new}} = p(0)G_{\text{new}} + r(0)H_{\text{new}},
\]

the dealer proves knowledge of \((s,\rho,r(0))\) such that:

\[
sG_{\text{old}} + \rho H_{\text{old}} = C_{\text{old}},
\qquad
sG_{\text{new}} + r(0)H_{\text{new}} = C_{\text{new}}.
\]

The statement proves the new secret scalar equals the old committed share scalar
without revealing either blinding. The transcript domain includes the Aptos
chain id, ACE module address, `"vss"`, purpose string
`"vss::dc0-consistency"`, and the session address.

### 1.5 Resharing Binding

For fresh DKG VSS sessions, `previous_commitment=None`.

For DKR, old holder \(j\) must reshare its existing share opening
\((s_j,\rho_j)\). The parent DKG/DKR session already published the old share
commitment \(C_j=s_jG+\rho_jH\). The child VSS stores this as
`previous_commitment = (G,H,C_j)` and requires the DC0 same-secret proof above.
This replaces the old direct equality check. The binding is now a sigma
proof of knowledge of the same secret scalar in both Pedersen equations.

## 2. Security Properties

The Pedersen vector \(V_i=p(i)G+r(i)H\) is perfectly hiding by itself. VSS also
publishes \(P_i=p(i)G\) for IBE and share verification, so scalar secrecy is
computational with respect to discrete log, plus Shamir secrecy and operational
confidentiality of off-chain share delivery/storage.

**Correctness.** If the dealer follows the protocol, every honest holder verifies its private opening and ACKs. The degree check accepts the commitment vector. Reconstruction from any \(t\) scalar shares recovers \(p(0)\), and the corresponding blinding shares reconstruct \(r(0)\).

**Completeness.** After the ACK window, the dealer can open every non-ACKing holder publicly. The session reaches success if every non-ACKing opening verifies and every ACKed holder keeps its opening private.

**Binding / commitment soundness.** A successful VSS session fixes one degree-\((t-1)\) pair of polynomials \((p,r)\) over the committed domain, except with the degree-check soundness error and DLog binding assumptions for Pedersen. Non-ACKed shares are checked on chain. ACKed shares are checked by the holder before it submits its on-chain ACK.

**Secrecy.** Against fewer than \(t\) corrupted holders, the scalar \(p(0)\) is hidden by Shamir secrecy given their opened shares and by Pedersen hiding for the commitment vector. VSS share delivery is authenticated by node-message signatures but not itself an encryption layer; deployments that need passive-network confidentiality must provide it operationally (for example private networking or TLS).

**Resharing soundness.** In DKR, the DC0 consistency proof forces \(p(0)\) to be the old share scalar inside the previous Pedersen share commitment. A malicious old dealer can refuse to participate, but cannot successfully reshare a different scalar without breaking the sigma proof or Pedersen binding.

## 3. Implementation Map

- Move PCS: `contracts/pedersen-polynomial-commitment/sources/pedersen-polynomial-commitment.move`
- Move VSS state machine: `contracts/vss/sources/vss.move`
- Move sigma proof verifier: `contracts/sigma-dlog-linear/sources/sigma_dlog_linear.move`
- Rust dealer/off-chain prover: `worker-components/vss-dealer/src/lib.rs`
- Rust share verification helpers: `worker-components/vss-common/src/vss_types.rs`
- TypeScript wire builders: `ts-sdk/src/vss/index.ts`, `ts-sdk/src/pedersen-polynomial-commitment/index.ts`, `ts-sdk/src/sigma-dlog-linear/index.ts`
