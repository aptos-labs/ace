# ACE Trust Model

ACE is currently a permissioned protocol. Operators are admitted by admin/bootstrap action or committee-approved proposals. There is no stake, reward, or slashing mechanism.

## Actors

| Actor | Holds | Trusted for |
|-------|-------|-------------|
| App developer | Aptos app contract | Writing IBE/VRF hooks that approve only intended requests |
| End user | Aptos account key/proof | Signing the intended IBE or VRF request |
| Operator | Worker account key, PKE key, node-message signing key, VSS shares, persistent VSS store | Running VSS/DKG/DKR honestly and serving only hook-approved requests |
| Admin | ACE deployment authority | Bootstrapping and proposing network changes; not reconstructing secrets |
| Aptos RPC/fullnode | Chain state and view results | Returning correct chain state to workers |
| Aptos validators | L1 consensus | Truth of Move state, timestamps, and view functions |

## Core Claims

- **Threshold secrecy**: fewer than `t` workers in an epoch cannot reconstruct the master secret.
- **Contract-approved derivation**: an honest worker returns a threshold VRF share only after the app hook returns `true` for the exact request.
- **Contract-approved decryption**: an honest worker returns an IBE IDK share only after the basic or custom app hook returns `true`.
- **No replay across request fields**: the signed payload binds `keypair_id`, `epoch`, `contract_id`, `label`, `account_address`, and response encryption key.
- **Dealer consistency**: VSS/DKR commitments and proofs prevent a dealer from silently committing one share and serving another.
- **Reshare consistency**: DKR proofs bind resharing sessions to existing share commitments.
- **Authenticated off-chain share delivery**: VSS share requests are accepted only from the expected holder address under that holder's registered node-message signature key.

## Non-Goals and Risks

- **No permissionless Sybil resistance**: admission is operational and governance-driven.
- **No slashing**: wrong or unavailable workers are removed by committee change, not automatic punishment.
- **RPC trust**: a malicious RPC can lie to a worker about view-function results. Production operators should run or strongly trust their fullnode.
- **DoS resistance**: public HTTP endpoints need operational rate limiting.
- **Metadata privacy**: workers see request metadata for requests they serve.
- **Operator storage hygiene**: private VSS shares and dealer state are in persistent storage; pruning is an operational requirement driven by clients at epoch start.
- **Node-message endpoint exposure**: node-message endpoints authenticate requests but are still public network services in many deployments. Operators need rate limiting and monitoring.
- **Post-quantum security**: current PKE/signature/group choices are not post-quantum.

## Cryptographic Assumptions

| Primitive | Assumption | Used by |
|-----------|------------|---------|
| HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305 | RFC 9180 base-mode security | Worker request/response encryption |
| ElGamal-OTP-Ristretto255 | DDH on Ristretto255 + ROM | Test-only legacy PKE path |
| Ed25519 node-message signatures | EUF-CMA of Ed25519 | Worker-to-worker off-chain protocol authentication |
| Pedersen commitments + sigma linear DLog | DLog on BLS12-381, Fiat-Shamir ROM | VSS and DKR consistency |
| BLS12-381 pairing groups | DLog/BDH assumptions | Public keys, t-IBE, VRF share verification, and commitments |
| Aptos account signatures | EUF-CMA of supported Aptos key schemes | Basic IBE and VRF request authorization |
| Aptos chain | BFT honest validator quorum | Orchestration state and app hook truth |
