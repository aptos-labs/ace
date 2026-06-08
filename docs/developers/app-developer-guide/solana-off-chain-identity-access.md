# Solana Off-Chain Identity Access: Can off-chain identity X access object Y?

## TLDR

ACE lets your app answer "can off-chain identity X access object Y?" from a Solana program. Use this guide when access is proven by an app-defined payload, such as a code, ZK proof, coupon, signed credential, or custom ACL, inside a signed Solana transaction.

To use it, you will:

- In your Solana program, expose an access-check instruction such as `assert_custom_acl(full_request_bytes)`.
- Decode the request bytes inside that instruction and verify your app-defined payload.
- In your client, encrypt and decrypt objects with the SDK's `ACE.IBE_Solana` custom-flow APIs.

## Example: code-gated custom ACL

In this example, we show how to build a code-gated custom ACL with ACE. The high-level idea is to encrypt content under an object ID, put an app-defined payload in the access request, and make a Solana instruction verify that payload before decrypting.

In this app, we store `CodeEntry` PDAs by label and accept a custom payload only when it matches the stored payload hash. A production app could replace that hash check with a ZK verifier, signed credential check, or richer ACL.

This walkthrough assumes an Anchor hook program and Anchor's TypeScript client. ACE does not require Anchor; it requires a signed Solana transaction that can be checked and that calls your access-check instruction with the custom ACE request bytes. If you use native Solana Rust or another framework, build the equivalent instruction and transaction with your own client code.

### Program changes

In the hook program, we need to decode the custom ACE request, validate the supplied accounts from the decoded label, and verify the payload against our policy.

The hook instruction's input is `full_request_bytes`. We decode it first; the decoded request carries the `label`, the reader's one-time public encryption key `enc_pk`, the app-defined `payload`, and the ACE epoch used by the request:

```rust
let decoded = ace_sdk::decode_custom_request(&full_request_bytes)
    .map_err(|_| ErrorCode::InvalidRequestBytes)?;
```

Then we validate the accounts that the client supplied. In this code-gated example, the label determines the `CodeEntry` PDA:

```rust
let (expected_pda, _) = Pubkey::find_program_address(
    &[b"code", decoded.label.as_ref()],
    &crate::ID,
);
require_keys_eq!(ctx.accounts.code_entry.key(), expected_pda);
```

Finally, we verify the custom payload against the policy. This example compares a hash of the payload to the value stored in a `CodeEntry` account:

```rust
use solana_program::hash::hashv;

#[account]
pub struct CodeEntry {
    pub payload_hash: [u8; 32],
}

let payload_hash = hashv(&[decoded.payload.as_slice()]).to_bytes();
require!(payload_hash == ctx.accounts.code_entry.payload_hash, ErrorCode::AccessDenied);
```

A production app might verify a proof, signature, credential, or issuer statement instead. Design that payload as a canonical statement, not loose bytes: include a version or domain-separation string, the object label, `decoded.enc_pk` if the payload is meant for one request, the program or app audience, and any expiry or nonce your policy needs. The signature, proof, or credential must cover every field the hook relies on.

Putting those pieces together, the hook looks like this:

```rust
use solana_program::hash::hashv;

pub fn assert_custom_acl(
    ctx: Context<AssertCustomAcl>,
    full_request_bytes: Vec<u8>,
) -> Result<()> {
    let decoded = ace_sdk::decode_custom_request(&full_request_bytes)
        .map_err(|_| ErrorCode::InvalidRequestBytes)?;

    let (expected_pda, _) = Pubkey::find_program_address(
        &[b"code", decoded.label.as_ref()],
        &crate::ID,
    );
    require_keys_eq!(ctx.accounts.code_entry.key(), expected_pda);

    let payload_hash = hashv(&[decoded.payload.as_slice()]).to_bytes();
    require!(payload_hash == ctx.accounts.code_entry.payload_hash, ErrorCode::AccessDenied);
    Ok(())
}
```

Deploy the Anchor program and record:

- `knownChainName`: for example `devnet`, `testnet`, or `mainnet-beta`.
- `programId`: the hook program id.
- `aceDeployment` and `keypairId` from the ACE deployment you target, such as a preview value provided by the ACE team or a localnet/example config.
- The label and payload encoding.

### Client changes

In the client, we encrypt under the hook program id, build custom request bytes with `encPk`, `label`, and `payload`, then sign a transaction that passes those bytes to the hook.

Before the SDK calls, fill in the ACE deployment values and the hook program id. The `aceDeployment` values identify the ACE deployment, not your Solana program; `programId` is your hook program:

```typescript
import * as ACE from "@aptos-labs/ace-sdk";
import { AccountAddress } from "@aptos-labs/ts-sdk";

const aceDeployment = new ACE.AceDeployment({
  apiEndpoint: "https://api.testnet.aptoslabs.com/v1",
  contractAddr: AccountAddress.fromString("0x<ace-contract-address>"),
});
const keypairId = AccountAddress.fromString("0x<ace-keypair-id>");
const knownChainName = "testnet";
const programId = customAclProgram.programId.toBase58();
```

First, encrypt under the hook program id:

```typescript
const label = new TextEncoder().encode("<object-id>");
const payload = new TextEncoder().encode("<code-or-proof>");

const ciphertext = (await ACE.IBE_Solana.encrypt({
  aceDeployment,
  keypairId,
  knownChainName,
  programId,
  label,
  plaintext,
})).unwrapOrThrow("ACE encrypt failed");
```

For decryption, we create a fresh one-time encryption keypair, fetch the current ACE epoch, build request bytes, and sign a transaction that calls the hook:

```typescript
const { encryptionKey, decryptionKey } = await ACE.pke.keygen();
const encPk = encryptionKey.toBytes();
const encSk = decryptionKey.toBytes();
const epoch = await ACE.IBE_Solana.fetchCurrentEpoch(aceDeployment);

const requestBytes = ACE.IBE_Solana.buildCustomRequestBytes({
  keypairId,
  epoch,
  encPk,
  label,
  payload,
});

const txn = await customAclProgram.methods
  .assertCustomAcl(Buffer.from(requestBytes))
  .accounts({ codeEntry: deriveCodeEntryPda(label) })
  .transaction();
txn.feePayer = user.publicKey;
txn.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
txn.sign(user);

const plaintext = await ACE.IBE_Solana.decryptCustomFlow({
  ciphertext,
  label,
  encPk,
  encSk,
  epoch,
  txn: txn.serialize(),
  aceDeployment,
  keypairId,
  knownChainName,
  programId,
});
```

ACE checks that the signed transaction matches the request fields and that the access instruction succeeds. If the instruction aborts, decryption fails.

Solana custom flow does not automatically carry a browser origin. If your web app needs origin binding, include an origin or audience field in `payload` or instruction data, sign it as part of the proof, and reject any value except your deployed app's origin. After the client is deployed, update that allowlist or payload issuer configuration.

## Remarks

- Use the same `epoch` in `buildCustomRequestBytes` and `decryptCustomFlow`.
- Bind payloads to `encPk` where possible; otherwise a valid payload may be replayed with a different `encPk`.
- Validate account owners, seeds, and program ids in the hook.
- Keep the hook narrowly focused. A single-purpose hook is easier for developers and auditors to reason about.
- Do not store reusable plaintext secrets on-chain. If the payload is a human-entered code, use a high-entropy value or a signed/one-time credential; a hash alone does not make a weak code hard to guess.
- Treat `label` encoding as part of the wire contract with your clients.

## Ready-To-Run Examples

- [`scenarios/custom-flow-solana`](../../../scenarios/custom-flow-solana): Anchor custom ACL with `buildCustomRequestBytes`.
