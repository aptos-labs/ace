# Verifiable Secret Sharing (VSS)

ACE's VSS is a single-dealer synchronous VSS built from the protocol skeleton in Das et al. "Verifiable Secret Sharing Simplified" (ePrint 2023/1196), with the paper's Appendix A.2 Pedersen polynomial commitment instantiated over ACE's abstract BLS12-381 group interface. DKG composes one VSS per committee member; DKR composes one resharing VSS per old-committee member.

This document uses additive group notation for the PCS and public-key-share equations, matching the Move implementation: \(xG\) means scalar multiplication, and \(X + Y\) is group addition.

## 1. Construction

Let the committee size be \(n\) and the reconstruction threshold be \(t\). A dealer samples two degree-\((t-1)\) polynomials over \(\mathbb{F}_r\):

\[
p(X) = p_0 + p_1X + \cdots + p_{t-1}X^{t-1},
\qquad
r(X) = r_0 + r_1X + \cdots + r_{t-1}X^{t-1}.
\]

The secret being shared is \(p(0)\). The blinding polynomial \(r\) is never needed for reconstruction and is revealed only for disputed/unacknowledged openings.

### 1.1 Pedersen PCS

The PCS public parameters are two same-group generators \((G,H)\). ACE samples them on chain when the VSS session is created. Security assumes the discrete-log relation between \(G\) and \(H\) is unknown; hiding of individual Pedersen commitments follows from the uniform blinding value \(r(i)\).

ACE commits over the evaluation domain \(\{0,1,\ldots,n\}\):

\[
V_i = p(i)G + r(i)H \qquad \text{for } i=0,\ldots,n.
\]

The original paper's Appendix A.2 only needs commitments for holder positions. ACE additionally includes \(V_0\) because DKG/DKR need the public key \(p(0)B\), and DKR must bind \(p(0)\) to an already-published old share public key. The contract therefore stores \(n+1\) commitment points; `commitment_len()` returns \(n\) holder positions.

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

- the Pedersen commitment vector \(V_0,\ldots,V_n\),
- one PKE ciphertext per holder, encrypting the holder's opening \((i,p(i),r(i))\),
- dealer recovery state encrypted to the dealer,
- and, for resharing sessions only, a sigma proof tying \(p(0)\) to the previous public key.

After DC0, the chain runs the touch-driven degree check before recipients may ACK. A holder decrypts its PKE ciphertext, verifies \(p(i)G+r(i)H=V_i\), and ACKs on chain if the opening is valid.

After the ACK window, the dealer submits `DealerContribution1`:

- `shares_to_reveal[0]` is always `None`;
- for a holder \(i\geq1\) that did not ACK, `shares_to_reveal[i]` is the full opening \((i,p(i),r(i))\);
- for \(i=0\) and each holder that did ACK, no opening is revealed, but the dealer supplies a sigma proof for the public key \(P_i=p(i)B\);
- `public_keys[i]` stores \(P_i=p(i)B\) for every \(i=0,\ldots,n\).

For non-ACKing holders, the chain verifies the revealed Pedersen opening and then checks \(P_i=p(i)B\) directly. For ACKing holders, the chain verifies the sigma proof instead, so \(r(i)\) stays private.

### 1.4 Sigma Linear-DLog Proofs

The proof module is `ace::sigma_dlog_linear`. It is a Fiat-Shamir generalized Schnorr proof for a witness vector satisfying multiple linear representation equations.

For VSS public-key binding, the witness is \((p(i),r(i))\). The public statement is:

\[
p(i)B + r(i)0 = P_i,
\qquad
p(i)G + r(i)H = V_i.
\]

Equivalently, the verifier uses the row-major matrix:

\[
\begin{bmatrix}
B & 0 \\
G & H
\end{bmatrix}
\begin{bmatrix}
p(i) \\
r(i)
\end{bmatrix}
=
\begin{bmatrix}
P_i \\
V_i
\end{bmatrix}.
\]

The transcript domain includes the Aptos chain id, ACE module address, `"vss"`, a purpose string (`"vss::dc0-consistency"` or `"vss::dc1-public-key"`), the session address, and the evaluation position.

### 1.5 Resharing Binding

For fresh DKG VSS sessions, `previous_public_key=None`.

For DKR, old holder \(j\) must reshare its existing share \(s_j\). The parent DKG/DKR session already published \(P_j=s_jB\). The child VSS stores this as `previous_public_key` and requires the dealer's DC0 consistency proof at position 0:

\[
p(0)B = P_j,
\qquad
p(0)G + r(0)H = V_0.
\]

This replaces the old Feldman-era equality check \(V_0=P_j\). The binding is now a sigma proof of knowledge of the same scalar \(p(0)\) in both equations, without revealing \(r(0)\).

## 2. Security Properties

The Pedersen PCS restores the hiding property that the earlier Feldman instantiation lacked: the commitment vector \(V_i=p(i)G+r(i)H\) does not by itself reveal \(p(i)\). ACE still intentionally publishes public key shares \(P_i=p(i)B\). Thus secrecy of scalar shares and the master secret is computational, under DLog for \(B\), while the PCS no longer adds the extra non-hiding leakage Feldman had.

**Correctness.** If the dealer follows the protocol, every honest holder verifies its private opening and ACKs. The degree check accepts the commitment vector, and DC1 verification populates \(P_0,\ldots,P_n\). Reconstruction from any \(t\) scalar shares recovers \(p(0)\).

**Completeness.** If at least \(t\) holders ACK, the dealer can open every non-ACKing holder publicly and provide sigma proofs for every hidden opening. The session reaches success unless the dealer equivocated.

**Binding / public-key soundness.** A successful VSS session fixes one degree-\((t-1)\) polynomial \(p\) over the committed domain, except with the degree-check soundness error and DLog binding assumptions for Pedersen. For every published public key \(P_i\), the chain has either a revealed opening proving \(P_i=p(i)B\), or a sigma proof of knowledge of \((p(i),r(i))\) tying \(P_i\) to \(V_i\). A dealer therefore cannot make the on-chain share public keys correspond to a different sharing polynomial without breaking the PCS binding or the sigma proof.

**Secrecy.** Against fewer than \(t\) corrupted holders, the scalar \(p(0)\) is hidden by Shamir secrecy given their opened shares, by PKE confidentiality for honest holders' openings, and by DLog for the public group elements \(P_i=p(i)B\). The Pedersen blinding polynomial hides the commitment vector itself, matching the paper's Appendix A.2 intuition.

**Resharing soundness.** In DKR, the DC0 consistency proof forces \(p(0)\) to be the old share whose public key was already on chain. A malicious old dealer can refuse to participate, but cannot successfully reshare a different scalar.

## 3. Implementation Map

- Move PCS: `contracts/pedersen-polynomial-commitment/sources/pedersen-polynomial-commitment.move`
- Move VSS state machine: `contracts/vss/sources/vss.move`
- Move sigma proof verifier: `contracts/sigma-dlog-linear/sources/sigma_dlog_linear.move`
- Rust dealer/off-chain prover: `worker-components/vss-dealer/src/lib.rs`
- Rust share verification helpers: `worker-components/vss-common/src/vss_types.rs`
- TypeScript wire builders: `ts-sdk/src/vss/index.ts`, `ts-sdk/src/pedersen-polynomial-commitment/index.ts`, `ts-sdk/src/sigma-dlog-linear/index.ts`
