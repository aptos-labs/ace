# ACE Protocols

This document summarizes the active ACE protocols and their on-chain/off-chain split. For cryptographic details, see [`cryptography/`](./cryptography/). For byte layouts, see [`wire-formats.md`](./wire-formats.md). For terms, see [`glossary.md`](./glossary.md).

## Overview

ACE runs four orchestration protocols plus two application request flows:

- **VSS**: one dealer creates a Pedersen-committed polynomial sharing and sends each recipient their private `(s_i, r_i)` opening off-chain. Session state, commitments, ACK bits, and timeout transitions live on-chain; private dealer/holder state lives in the VSS store.
- **DKG**: each committee member runs one VSS as dealer. The on-chain result includes both aggregate Pedersen commitments and scalar-derived public keys.
- **DKR**: old committee members reshare their existing shares to a new committee, preserving the underlying secret while changing custody.
- **Epoch change / network**: Move state machines coordinate proposals, auto-rotation, DKG/DKR launch, and epoch advancement.
- **Threshold IBE request flow**: clients encrypt under the DKG master public key; authorized decryption requests collect and verify threshold identity-key shares.
- **Threshold VRF request flow**: clients ask the current committee to derive bytes for `(keypair_id, contract_id, label)` after an Aptos app hook approves the request. The request also binds an `account_address` for authorization, but that account is not part of the VRF input unless the app encodes it into `label`.

## VSS

The chain stores the session phase, public commitments, ACK state, and timeout-driven transitions. The dealer and recipients use the VSS store for private protocol material:

- Dealer private state: the secret and blinding polynomials.
- Holder private state: received and verified `(s_i, r_i)` shares.
- ACKs: holder transactions submitted on-chain through `vss::on_share_holder_ack`.

Share delivery is point-to-point through the node-message gateway. The gateway
serves registered VSS sessions from in-memory dealer state provided by the
dealer client, avoiding chain or DB reads on each share request. Each share
request is a signed node message; the dealer verifies the sender's registered
node-message public key and checks that it matches the requested holder index.

## DKG

DKG composes `n` VSS sessions. A DKG worker client:

1. Ensures the VSS store client exists for `--vss-store-url`.
2. Ensures the node message gateway exists for `--node-msg-listen` when it may deal shares.
3. Follows the DKG session state on-chain.
4. Starts VSS dealer/recipient clients as required for the worker's role.
5. Lets Move aggregate accepted VSS commitment points and public keys into the resulting secret metadata.

The scenario tests assert public aggregation and private share reconstruction from the VSS store. A completed DKG publishes `commitment_points[0..n]` and `public_keys[0..n]`, where `public_keys[i] = F(i)G`.

## DKR

DKR composes resharing VSS sessions. Each old committee dealer proves that the
new VSS constant opening `(g_j(0), h_j(0))` is the same old share opening
committed by the previous DKG/DKR share commitment. New recipients store their
resulting shares in the VSS store. The final aggregate Pedersen commitment is
the Lagrange-weighted combination of accepted resharing commitments.

DKR preserves the original DKG PCS context across reshares. It aggregates both
Pedersen commitments and scalar-derived public keys; the root public key stays
equal to the original DKG result public key.

## Worker Registration

Each worker registers four public pieces of worker configuration on chain:

- client HTTP endpoint, used by SDK clients for worker requests;
- node-message endpoint, used by other workers for off-chain protocol messages;
- PKE encryption key, used by SDK clients to encrypt worker requests;
- node-message signature verification key, used by gateways to authenticate off-chain worker messages.

The private counterparts (`pke_dk`, `sig_sk`) are operator secrets. DKG/DKR
result and per-holder public keys are protocol session state, rather than
worker registration fields.

## Threshold IBE Request Flow

The SDK encrypts to `resultPk = F(0)G` from the original DKG session. For an
authorized basic or custom request, each worker reads its in-memory share
snapshot and returns `F(i)H(identity)` encrypted to the caller's response key.
The SDK fetches the current DKG/DKR `sharePks`, checks each share's evaluation
point and pairing equation, discards invalid shares, and combines at least the
threshold number. See [`cryptography/t-ibe.md`](./cryptography/t-ibe.md).

## Threshold VRF Request Flow

The TypeScript SDK builds a `ThresholdVrfRequest` containing:

- `keypair_id`
- `epoch`
- Aptos `contract_id`
- app `label`
- `account_address`
- response encryption key
- Aptos account signature proof

The SDK encrypts that request to each worker's registered PKE key and POSTs it to the worker HTTP endpoint. A worker:

1. Decrypts the request with its PKE key.
2. Reads its local share snapshot for `(keypair_id, epoch)`.
3. Verifies that the share usage permits threshold VRF.
4. Verifies the Aptos account proof and calls `{module_addr}::{module_name}::on_ace_vrf_request(label, account, origin)`.
5. Derives a VRF share, proves consistency with the aggregate share commitment, encrypts it to the client's response key, and returns it.

The SDK fetches the current DKG/DKR session BCS and verifies returned share
proofs against `pcsContext` and `shareCommitments[i]`. It combines at least
threshold many valid shares into the final 32-byte output. No result public key
or sub public key is fetched or checked for this flow.
