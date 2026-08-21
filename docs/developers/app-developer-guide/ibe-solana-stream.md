# Solana Streaming Access: encrypt/decrypt large data as chunks (+ web-video seek)

## TLDR

`ACE.StreamIBE_Solana` is the streaming + seekable counterpart of `ACE.IBE_Solana`. Use it when the
payload is too big to hold in memory (files, video, backups) or when a browser `<video>` element
must **seek** into encrypted media.

The access-control model is identical to `IBE_Solana` (same program hook, same `label`, same
basic/custom flows). The differences are entirely client-side: you work in **ciphertext chunks**
(not one blob), and `createSeekableDecryptor` supports random access. There is **no scheme/primitive
parameter**.

See [`ibe-aptos-stream.md`](./ibe-aptos-stream.md) for the full conceptual walkthrough (chunks vs.
objects, the seekable/Service-Worker `<video>` pattern, and the fails-closed guarantees). This page
shows only the Solana-specific inputs (`knownChainName` / `programId`, and a signed-transaction
proof).

## Encrypt

```typescript
import * as ACE from "@aptos-labs/ace-sdk";

const cipherChunks = ACE.StreamIBE_Solana.encryptStream({
  aceDeployment,
  keypairId,
  knownChainName,   // e.g. "solana-devnet"
  programId,
  label,
  plaintext: file.stream(), // any (async) iterable of Uint8Array
});

for await (const chunk of cipherChunks) {
  await upload(chunk);
}
```

## Decrypt (basic flow: signed transaction)

```typescript
const decryptor = await ACE.StreamIBE_Solana.createStreamDecryptorBasicFlow({
  aceDeployment,
  keypairId,
  knownChainName,
  programId,
  label,
  // Same signer contract as ACE.IBE_Solana.decryptBasicFlow: sign the canonical request bytes
  // inside a Solana transaction and return the signed transaction bytes.
  signTxn: async (fullRequestBytes) => signRequestTransaction(fullRequestBytes),
});

for await (const plainChunk of decryptor.decryptStream(downloadCipherChunks())) {
  await sink.write(plainChunk);
}
```

Custom flow (`createStreamDecryptorCustomFlow({ …, encPk, encSk, epoch, txn })`) mirrors
`ACE.IBE_Solana` custom flow and returns the same `decryptor` (with `decryptStream` +
`createSeekableDecryptor`).

## Seekable web video

Identical to the Aptos guide — `decryptor.createSeekableDecryptor({ byteLength, readRange })` decrypts
arbitrary plaintext byte ranges; wire it to a Service-Worker Range handler for native `<video>`
seeking. See [`ibe-aptos-stream.md`](./ibe-aptos-stream.md#seekable-web-video).
