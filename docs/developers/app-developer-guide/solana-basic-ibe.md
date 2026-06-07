# Solana Basic IBE: Transaction-Gated Decryption

## TLDR

Use this flow when a Solana program can prove access by successfully simulating a signed transaction. It is a natural fit for receipt-based pay-to-download, PDA-backed allowlists, and policies where the requestor should sign a Solana transaction that calls a dedicated access-check instruction.

You need to:

- Write the normal Solana business program that stores policy state.
- Write a hook program, usually with a single `assert_access(full_request_bytes)` instruction, that verifies the policy.
- Encrypt with `ACE.IBE_Solana.encrypt`, binding the ciphertext to the hook program id.
- Decrypt with `ACE.IBE_Solana.BasicDecryptionSession`, signing a transaction that embeds the request bytes.

## Walkthrough

This walkthrough assumes an Anchor hook program and Anchor's TypeScript client. The ACE requirement is not Anchor itself; it is a signed Solana transaction that workers can simulate and that calls your access-check instruction with the ACE request bytes. If you use native Solana Rust or another framework, build the equivalent instruction and transaction with your own client code.

Design the policy first. A pay-to-download app might store `BlobMetadata` PDAs for listed content and `Receipt` PDAs for users who paid. The hook instruction should do only the access proof:

```rust
pub fn assert_access(ctx: Context<AssertAccess>, full_request_bytes: Vec<u8>) -> Result<()> {
    let label = ace_sdk::decode_blob_name(&full_request_bytes)
        .map_err(|_| ErrorCode::InvalidBlobName)?;

    // Verify PDA ownership, PDA derivation, receipt freshness, and signer.
    // Return Ok(()) only when the transaction proves access.
    Ok(())
}
```

Use a dedicated hook program when possible. Workers verify and simulate the proof transaction; a single-purpose hook makes it clear which instruction is the access boundary.

Deploy the programs and initialize policy state. Record:

- `knownChainName`: for example `devnet`, `testnet`, or `mainnet-beta`.
- `programId`: the hook program id, not necessarily your main business program id.
- `aceDeployment` and `keypairId`: from your ACE deployment or localnet config.
- `label`: the bytes your hook decodes from the ACE request and uses to find policy state.

Encrypt with the hook program id and label:

```typescript
import * as ACE from "@aptos-labs/ace-sdk";

const label = new TextEncoder().encode("0x<owner-aptos-address>/song.mp3");

const ciphertext = (await ACE.IBE_Solana.encrypt({
  aceDeployment,
  keypairId,
  knownChainName,
  programId: aceHookProgram.programId.toBase58(),
  label,
  plaintext: songBytes,
})).unwrapOrThrow("ACE encrypt failed");
```

For decryption, use the session API so the user can sign the exact request bytes the workers will verify:

```typescript
const session = await ACE.IBE_Solana.BasicDecryptionSession.create({
  aceDeployment,
  keypairId,
  knownChainName,
  programId: aceHookProgram.programId.toBase58(),
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

- The signed transaction should call the access hook and should not rely on off-chain checks that workers cannot simulate.
- Validate PDA owners and seeds inside the hook. Do not trust accounts just because the client supplied them.
- Bind the hook to `full_request_bytes`; otherwise a user could sign a transaction that proves something other than the ACE request being served.
- Keep ciphertext delivery separate from access proof. ACE encrypts the payload directly; the chain only needs policy state and whatever metadata your app wants on-chain.
- Use a stable label encoding and document it. Changing label encoding changes the IBE identity and makes old ciphertexts undecryptable under the new label.

## Ready-To-Run Examples

- [`examples/pay-to-download-solana`](../../../examples/pay-to-download-solana): Anchor pay-to-download with a dedicated `ace_hook` program.
