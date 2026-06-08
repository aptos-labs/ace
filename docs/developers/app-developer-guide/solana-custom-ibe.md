# Solana Custom IBE: Payload-Gated Transactions

## TLDR

Use this flow when a Solana instruction must verify app-defined request bytes and payload before workers release decryption shares. It is useful for custom ACLs, ZK proofs, coupon codes, signed credentials, and policies where the proof naturally belongs in a Solana transaction.

You need to:

- Write an Anchor instruction such as `assert_custom_acl(full_request_bytes)`.
- Decode the ACE custom request bytes inside that instruction.
- Verify the embedded `label`, `enc_pk`, `payload`, and any relevant accounts.
- Encrypt with `ACE.IBE_Solana.encrypt`.
- Build custom request bytes with `ACE.IBE_Solana.buildCustomRequestBytes`, sign a transaction containing those bytes, then call `ACE.IBE_Solana.decryptCustomFlow`.

## Example walkthrough: Code-gated custom ACL

In this example, we show how to build a code-gated custom ACL with ACE Solana custom IBE. The high-level idea is to encrypt content with ACE, encode an app-defined payload in the custom request, and make a Solana instruction verify both the ACE request fields and the app payload during worker simulation.

In this app, we store `CodeEntry` PDAs by label and accept a custom payload only when it matches the stored code. A production app could replace that comparison with a ZK verifier, signed credential check, or richer ACL.

This walkthrough assumes an Anchor hook program and Anchor's TypeScript client. ACE does not require Anchor; it requires a signed Solana transaction that workers can simulate and that calls your access-check instruction with the custom ACE request bytes. If you use native Solana Rust or another framework, build the equivalent instruction and transaction with your own client code.

### 1. Write the Solana Hook Program

In the hook program, we need to decode the custom ACE request, validate the supplied accounts from the decoded label, and verify the payload against our policy.

The hook instruction's input is `full_request_bytes`. We decode it first; the decoded request carries the `label`, the reader's response key `enc_pk`, the app-defined `payload`, and the ACE epoch used by the request:

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

Finally, we verify the custom payload against the policy. The toy example compares the payload to a stored code; a production app might verify a proof, signature, credential, or issuer statement. If your payload authorizes one response key, bind it to `decoded.enc_pk` so it cannot be replayed with another user's response key.

Putting those pieces together, the hook looks like this:

```rust
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

    require!(decoded.payload == stored_payload, ErrorCode::AccessDenied);
    Ok(())
}
```

Deploy the Anchor program and record:

- `knownChainName`: for example `devnet`, `testnet`, or `mainnet-beta`.
- `programId`: the hook program id.
- `aceDeployment` and `keypairId`.
- The label and payload encoding.

### 2. Call the TypeScript SDK

In the client, we encrypt under the hook program id, build custom request bytes with `encPk`, `label`, and `payload`, then sign a transaction that passes those bytes to the hook.

First, encrypt under the hook program id:

```typescript
const ciphertext = (await ACE.IBE_Solana.encrypt({
  aceDeployment,
  keypairId,
  knownChainName,
  programId: customAclProgram.programId.toBase58(),
  label,
  plaintext,
})).unwrapOrThrow("ACE encrypt failed");
```

For decryption, we create a fresh PKE keypair, fetch the current ACE epoch, build request bytes, and sign a transaction that calls the hook:

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
  programId: customAclProgram.programId.toBase58(),
});
```

Workers verify that the signed transaction matches the outer request fields and that simulation succeeds. If the instruction aborts, the worker withholds its share.

Solana custom flow does not automatically carry a browser origin. If your web app needs origin binding, include an origin or audience field in `payload` or instruction data, sign it as part of the proof, and reject any value except your deployed app's origin. After the client is deployed, update that allowlist or payload issuer configuration.

## Remarks

- Use the same `epoch` in `buildCustomRequestBytes` and `decryptCustomFlow`.
- Bind payloads to `encPk` where possible; otherwise a valid payload may be replayed with a different response key.
- Validate account owners, seeds, and program ids in the hook.
- Keep the hook narrowly focused. A single-purpose hook is easier for workers and auditors to reason about.
- Treat `label` encoding as part of the wire contract with your clients.

## Ready-To-Run Examples

- [`scenarios/custom-flow-solana`](../../../scenarios/custom-flow-solana): Anchor custom ACL with `buildCustomRequestBytes`.
