# Solana Custom IBE: Payload-Gated Transactions

## TLDR

Use this flow when a Solana instruction must verify app-defined request bytes and payload before workers release decryption shares. It is useful for custom ACLs, ZK proofs, coupon codes, signed credentials, and policies where the proof naturally belongs in a Solana transaction.

You need to:

- Write an Anchor instruction such as `assert_custom_acl(full_request_bytes)`.
- Decode the ACE custom request bytes inside that instruction.
- Verify the embedded `label`, `enc_pk`, `payload`, and any relevant accounts.
- Encrypt with `ACE.IBE_Solana.encrypt`.
- Build custom request bytes with `ACE.IBE_Solana.buildCustomRequestBytes`, sign a transaction containing those bytes, then call `ACE.IBE_Solana.decryptCustomFlow`.

## Walkthrough

This walkthrough assumes an Anchor hook program and Anchor's TypeScript client. The ACE requirement is not Anchor itself; it is a signed Solana transaction that workers can simulate and that calls your access-check instruction with the custom ACE request bytes. If you use native Solana Rust or another framework, build the equivalent instruction and transaction with your own client code.

Define your policy state and payload. A simple code-gated example stores `CodeEntry` PDAs by label and accepts a payload only when it matches the stored code. A production app would replace that comparison with a ZK verifier, signed credential check, or richer ACL.

The hook instruction should decode the ACE request and validate that supplied accounts match what the request says:

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

Encrypt under the hook program id:

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

For decryption, create a fresh PKE keypair, fetch the current ACE epoch, build request bytes, and sign a transaction that calls your hook:

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
