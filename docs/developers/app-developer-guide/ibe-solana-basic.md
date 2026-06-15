# Solana Account Access: Can Solana account X access object Y?

## TLDR

ACE lets your app answer "can Solana account X access object Y?" from a Solana program. Use this guide when your users have Solana accounts and your app can prove access with a signed transaction.

To use it, you will:

- In your Solana program, expose an access-check instruction such as `assert_access(full_request_bytes)`.
- Store enough policy state to decide whether the signer can access the requested object.
- In your client, encrypt and decrypt objects with the SDK's `ACE.IBE_Solana` APIs.

## Example: receipt-gated downloads

In this example, we show how to build a receipt-gated download app with ACE. The high-level idea is to encrypt content under an object ID, store receipt or payment policy in Solana PDAs, and make the reader sign a transaction that proves access to that object.

In this app, we store `BlobMetadata` PDAs for listed content and `Receipt` PDAs for users who paid, then ask the reader to sign a transaction that proves the matching receipt exists.

This walkthrough assumes an Anchor hook program and Anchor's TypeScript client. ACE does not require Anchor; it requires a signed Solana transaction that can be checked and that calls your access-check instruction with the ACE request bytes. If you use native Solana Rust or another framework, build the equivalent instruction and transaction with your own client code.

### Program changes

In the hook program, we need to decode the ACE request bytes, use the decoded label to find the policy PDAs, and return `Ok(())` only when the transaction proves access.

The hook instruction should do only the access proof. Its important input is `full_request_bytes`, the exact ACE request bytes that the user signs into a transaction.

First, we decode the label from `full_request_bytes`. That label is the object id the client used when encrypting:

```rust
let label = ace_sdk::decode_blob_name(&full_request_bytes)
    .map_err(|_| ErrorCode::InvalidBlobName)?;
```

Then we verify the Solana policy state for that label. In a receipt-based app, that usually means checking PDA derivation, PDA ownership, receipt validity, and the user signer. `BlobMetadata` and `Receipt` are app-defined accounts; this example uses the following minimal fields:

```rust
#[account]
pub struct BlobMetadata {
    pub label: Vec<u8>,
}

#[account]
pub struct Receipt {
    pub user: Pubkey,
    pub label: Vec<u8>,
    pub paid: bool,
}
```

The access check can then validate the submitted accounts against the decoded label:

```rust
let user = &ctx.accounts.user;
require!(user.is_signer, ErrorCode::MissingSigner);

let (expected_blob_metadata, _) = Pubkey::find_program_address(
    &[b"blob", label.as_ref()],
    &crate::ID,
);
require_keys_eq!(ctx.accounts.blob_metadata.key(), expected_blob_metadata);
let metadata = &ctx.accounts.blob_metadata;
require!(metadata.label.as_slice() == label.as_slice(), ErrorCode::BlobLabelMismatch);

let (expected_receipt, _) = Pubkey::find_program_address(
    &[b"receipt", user.key().as_ref(), label.as_ref()],
    &crate::ID,
);
require_keys_eq!(ctx.accounts.receipt.key(), expected_receipt);

let receipt = &ctx.accounts.receipt;
require_keys_eq!(receipt.user, user.key());
require!(receipt.label.as_slice() == label.as_slice(), ErrorCode::ReceiptLabelMismatch);
require!(receipt.paid, ErrorCode::AccessDenied);
```

Putting those pieces together, the hook looks like this:

```rust
pub fn assert_access(ctx: Context<AssertAccess>, full_request_bytes: Vec<u8>) -> Result<()> {
    let label = ace_sdk::decode_blob_name(&full_request_bytes)
        .map_err(|_| ErrorCode::InvalidBlobName)?;

    let user = &ctx.accounts.user;
    require!(user.is_signer, ErrorCode::MissingSigner);

    let (expected_blob_metadata, _) = Pubkey::find_program_address(
        &[b"blob", label.as_ref()],
        &crate::ID,
    );
    require_keys_eq!(ctx.accounts.blob_metadata.key(), expected_blob_metadata);
    let metadata = &ctx.accounts.blob_metadata;
    require!(metadata.label.as_slice() == label.as_slice(), ErrorCode::BlobLabelMismatch);

    let (expected_receipt, _) = Pubkey::find_program_address(
        &[b"receipt", user.key().as_ref(), label.as_ref()],
        &crate::ID,
    );
    require_keys_eq!(ctx.accounts.receipt.key(), expected_receipt);

    let receipt = &ctx.accounts.receipt;
    require_keys_eq!(receipt.user, user.key());
    require!(receipt.label.as_slice() == label.as_slice(), ErrorCode::ReceiptLabelMismatch);
    require!(receipt.paid, ErrorCode::AccessDenied);
    Ok(())
}
```

Use a dedicated hook program when possible. A single-purpose hook makes it clear which instruction is the access boundary.

Deploy the programs and initialize policy state. Record:

- `knownChainName`: for example `devnet`, `testnet`, or `mainnet-beta`.
- `programId`: the hook program id, not necessarily your main business program id.
- `aceDeployment` and `keypairId`: from the ACE deployment you target, such as a preview value provided by the ACE team or a localnet/example config.
- `label`: the bytes your hook decodes from the ACE request and uses to find policy state.

### Client changes

In the client, we encrypt under the hook program id, then build and sign a transaction that calls the hook with the exact request bytes from the session.

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
const programId = aceHookProgram.programId.toBase58();
```

First, encrypt with the hook program id and label:

```typescript
const label = new TextEncoder().encode("<owner-solana-address>/song.mp3");

const ciphertext = (await ACE.IBE_Solana.encrypt({
  aceDeployment,
  keypairId,
  knownChainName,
  programId,
  label,
  plaintext: songBytes,
})).unwrapOrThrow("ACE encrypt failed");
```

If you encrypt many objects with the same ACE keypair and t-IBE scheme, fetch the public key once and pass it to each encryption call. If you use a non-default `tibeScheme`, pass it to `fetchPk` too.

```typescript
const pk = (await ACE.IBE_Solana.fetchPk({
  aceDeployment,
  keypairId,
})).unwrapOrThrow("ACE public key fetch failed");

const ciphertext = (await ACE.IBE_Solana.encrypt({
  aceDeployment,
  keypairId,
  knownChainName,
  programId,
  label,
  plaintext: songBytes,
  pk,
})).unwrapOrThrow("ACE encrypt failed");
```

For decryption, we use the session API so the user can sign a transaction for the exact object request:

```typescript
const session = await ACE.IBE_Solana.BasicDecryptionSession.create({
  aceDeployment,
  keypairId,
  knownChainName,
  programId,
  label,
  ciphertext,
});

const fullRequestBytes = await session.getRequestToSign();
const txn = await aceHookProgram.methods
  .assertAccess(Buffer.from(fullRequestBytes))
  .accounts({
    blobMetadata: deriveBlobMetadataPda(label),
    receipt: deriveReceiptPda(user.publicKey, label),
    user: user.publicKey,
  })
  .transaction();

txn.feePayer = user.publicKey;
txn.recentBlockhash = (await connection.getLatestBlockhash()).blockhash;
txn.sign(user);

const plaintext = (await session.decryptWithProof({
  txn: txn.serialize(),
})).unwrapOrThrow("ACE decrypt failed");
```

For scripts, `ACE.IBE_Solana.decryptBasicFlow` wraps the same session sequence and asks you for a `signTxn(fullRequestBytes)` callback.

Solana basic proofs do not currently pass a browser `origin` string to the hook. Treat the hook `programId` as the app boundary, and include explicit app context in the instruction data or PDA design if you need stronger origin-style separation. After deploying the web client or CLI, make sure the client only builds transactions for your intended hook program.

## Remarks

- The signed transaction should call the access hook and should not rely on off-chain checks that ACE cannot verify.
- Validate PDA owners and seeds inside the hook. Do not trust accounts just because the client supplied them.
- Bind the hook to `full_request_bytes`; otherwise a user could sign a transaction that proves something other than the ACE request being served.
- Keep ciphertext delivery separate from access proof. ACE encrypts the payload directly; the chain only needs policy state and whatever metadata your app wants on-chain.
- Use a stable label encoding and document it. Changing label encoding changes the object ID and makes old ciphertexts undecryptable under the new label.

## Ready-To-Run Examples

- [`examples/pay-to-download-solana`](../../../examples/pay-to-download-solana): Anchor pay-to-download with a dedicated `ace_hook` program.
