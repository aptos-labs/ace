# ACE Glossary

Definitions of terms and symbols used across the ACE specification documents.

## Identifiers

- **`keypair_id`** — On-chain Aptos address of the DKG session that established a secret lineage. It remains stable across DKR reshares.
- **`contract_id`** — Aptos application module identifier `(chain_id, module_addr, module_name)`.
- **`label`** — App-chosen bytes that scope a derivation under `(keypair_id, contract_id)`. Apps that need per-account outputs must encode the account into the label.
- **`epoch`** — Network epoch counter. Workers in epoch `e` hold the active shares for that epoch.
- **`account_address`** — Aptos account whose proof signs the request and which the app hook may authorize. It is not part of the VRF input by itself.
- **`origin`** — Wallet/WebAuthn application origin extracted from the signed Aptos full message.

## Roles

- **App developer** — Deploys the Move policy hook and integrates the SDK.
- **End user** — Signs a derivation request for a contract/label tuple plus the account used for authorization.
- **Operator / worker** — Runs worker processes, holds PKE and signing keys, participates in VSS/DKG/DKR, and serves threshold VRF requests.
- **Dealer / recipient** — Per-VSS roles. A dealer creates a committed sharing; recipients verify and ACK their received shares.
- **Admin** — Bootstraps the ACE deployment and proposes network changes; does not hold threshold shares.

## Cryptographic Objects

- **Master secret** ($s$) — Secret jointly held by a committee, never reconstructed by one honest worker.
- **Share** ($s_i$) — Worker `i`'s scalar share of the active secret.
- **Pedersen share commitment** — Point $s_iG + r_iH$ used to verify off-chain share material without publishing it.
- **Aggregate commitment point** — DKG/DKR Pedersen point $F(i)G+R(i)H$ stored on chain for `i = 0..n`.
- **Master / share public key** — Scalar-derived point $F(0)G$ or $F(i)G$ published by DKG/DKR and used by IBE encryption or IDK-share verification.
- **PCS context** — Pedersen generators `G,H` for a VSS/DKG/DKR lineage.
- **Threshold VRF share** — Worker output for a valid request; the SDK verifies its proof and combines at least threshold many shares into 32 derived bytes.
- **Identity decryption key (IDK) share** — Worker output $F(i)H(identity)$; the SDK verifies it against the corresponding share public key before interpolation.
- **Node-message signing key** — Ed25519 key pair used to authenticate off-chain worker-to-worker messages. The verification key is registered on chain.
- **Lagrange coefficient** ($\lambda_i$) — Scalar used to interpolate shares at `x = 0`.

## Protocols

- **VSS** — Verifiable Secret Sharing, the single-dealer primitive.
- **DKG** — Distributed Key Generation, parallel VSS sessions that create a fresh secret.
- **DKR** — Distributed Key Resharing, moving an existing secret to a new committee.
- **PKE** — Public-Key Encryption, used for worker request/response encryption.
- **Node-message gateway** — Per-worker HTTP endpoint for off-chain protocol messages, authenticated by node-message signatures.
- **PCS** — Polynomial Commitment Scheme; ACE uses Pedersen commitments.
- **BCS** — Binary Canonical Serialization.

## Network Terms

- **Aptos L1** — Trust anchor for orchestration state, view-function results, timestamps, and package code.
- **View function** — Read-only Move function called by workers to check app policy.
- **`on_ace_vrf_request`** — Fixed app hook name for threshold VRF approval.
- **`on_ace_decryption_request`** — Fixed Aptos basic-IBE authorization hook.
- **`on_ace_decryption_request_custom_flow`** — Fixed Aptos custom-IBE proof hook.
