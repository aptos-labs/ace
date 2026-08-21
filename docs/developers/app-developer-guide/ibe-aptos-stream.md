# Aptos Streaming Access: encrypt/decrypt large data as chunks (+ web-video seek)

## TLDR

`ACE.StreamIBE_Aptos` is the streaming + seekable counterpart of `ACE.IBE_Aptos`. Use it when the
payload is too big to hold in memory (files, video, backups) or when you want a browser `<video>`
element to **seek** into encrypted media.

The access-control model is identical to `IBE_Aptos` (same contract hook, same `label`, same
basic/custom flows). The differences are entirely client-side:

- You work in **ciphertext chunks**, not a single ciphertext blob. `encryptStream` yields chunks;
  `decryptStream` consumes chunks and yields plaintext chunks; memory stays ~one chunk.
- For random access, `createSeekableDecryptor` decrypts arbitrary plaintext byte ranges, fetching
  only the ciphertext segments that cover them.
- There is **no scheme/primitive parameter** — you pick the `StreamIBE_Aptos` scope and that's it.

> Streaming reuses the production shortsig-aead IBE keys, but a keypair must be provisioned with the
> streaming usage bit to authorize it. Use the `keypairId` your ACE deployment designates for
> streaming (during preview, the value the ACE team / localnet config provides).

## Encrypt: plaintext chunks → ciphertext chunks

```typescript
import * as ACE from "@aptos-labs/ace-sdk";
import { AccountAddress } from "@aptos-labs/ts-sdk";

const label = new TextEncoder().encode("0x<owner-address>/album/song-001");

// `plaintext` is any (async) iterable of Uint8Array — a File stream, a Node read stream via
// Readable.toWeb, a socket, etc. Nothing is fully buffered.
const cipherChunks = ACE.StreamIBE_Aptos.encryptStream({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName,
  label,
  plaintext: file.stream(), // ReadableStream<Uint8Array>
});

// Store/upload the chunks as they arrive — the concatenation is the stored artifact.
for await (const chunk of cipherChunks) {
  await upload(chunk);
}
```

Encrypting many objects under the same keypair? Fetch the public key once and pass it as `pk`:

```typescript
const pk = (await ACE.StreamIBE_Aptos.fetchPk({ aceDeployment, keypairId }))
  .unwrapOrThrow("ACE stream public key fetch failed");
```

## Decrypt: authenticate once, then stream or seek

Authenticate **once** to fetch the threshold key shares (tiny, independent of payload size), then
decrypt as many times as you like — forward-streaming or random-access.

```typescript
const decryptor = await ACE.StreamIBE_Aptos.createStreamDecryptorBasicFlow({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName,
  label,
  accountAddress: userAddress,
  // Same signer contract as ACE.IBE_Aptos.decryptBasicFlow.
  sign: async (message) => {
    const signed = await wallet.signMessage({ message, nonce: crypto.randomUUID(), application: true, chainId, address: userAddress });
    return { pubKey: signed.publicKey, signature: signed.signature, fullMessage: signed.fullMessage };
  },
});

// Forward streaming: ciphertext chunks in → plaintext chunks out.
for await (const plainChunk of decryptor.decryptStream(downloadCipherChunks())) {
  await sink.write(plainChunk);
}
```

For app-supplied proofs (ZK, coupons, …), use `createStreamDecryptorCustomFlow({ …, encPk, encSk,
payload })` — same shape as `ACE.IBE_Aptos` custom flow, returning the same `decryptor`.

## Seekable web video

A seekable decryptor decrypts arbitrary **plaintext** byte ranges. The caller supplies the
transport that reads **ciphertext** byte ranges (HTTP Range, S3, file); the SDK maps plaintext →
covering segments → ciphertext bytes and decrypts only those.

```typescript
const seek = await decryptor.createSeekableDecryptor({
  byteLength: totalStoredBytes,
  readRange: (offset, length) =>            // CIPHERTEXT bytes
    fetch(url, { headers: { Range: `bytes=${offset}-${offset + length - 1}` } })
      .then((r) => r.arrayBuffer()).then((b) => new Uint8Array(b)),
});

seek.plaintextLength;                        // total video size, for the player
const clip = await seek.readRange(start, length); // PLAINTEXT bytes — only touched segments fetched
```

Wire it to a Service Worker that answers the browser's Range requests, and native `<video>` seeking
"just works" — each scrub becomes a `seek.readRange(...)`:

```typescript
// service-worker.ts
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.pathname !== "/video/decrypted") return;
  const { start, end } = parseRange(e.request.headers.get("Range"), seek.plaintextLength);
  e.respondWith((async () => {
    const bytes = await seek.readRange(start, end - start + 1);
    return new Response(bytes, {
      status: 206,
      headers: {
        "Content-Type": "video/mp4",
        "Accept-Ranges": "bytes",
        "Content-Range": `bytes ${start}-${end}/${seek.plaintextLength}`,
        "Content-Length": String(bytes.length),
      },
    });
  })());
});
```

```html
<video src="/video/decrypted" controls></video>
```

> For seeking to work, the **plaintext** must be a seekable container (fragmented MP4 / CMAF or
> WebM). ACE only delivers decrypted byte ranges; it does not repackage media.

## Python

```python
from ace_sdk import StreamIBE_Aptos

# Encrypt: iterable of plaintext chunks -> iterable of ciphertext chunks
with open("movie.mp4", "rb") as f:
    def plaintext_chunks():
        while b := f.read(65536):
            yield b
    for cipher_chunk in StreamIBE_Aptos.encrypt_stream(
        ace_deployment=ace_deployment, keypair_id=keypair_id, chain_id=chain_id,
        module_addr=module_addr, module_name=module_name, label=label,
        plaintext=plaintext_chunks(),
    ):
        upload(cipher_chunk)

# Decrypt (custom-flow): authenticate once, then stream or seek
decryptor = StreamIBE_Aptos.create_stream_decryptor_custom_flow(
    ace_deployment=ace_deployment, keypair_id=keypair_id, chain_id=chain_id,
    module_addr=module_addr, module_name=module_name, label=label,
    enc_pk=enc_pk, enc_sk=enc_sk, payload=payload,
).unwrap_or_throw(ValueError("decryptor"))

with open("out.mp4", "wb") as out:
    for plain_chunk in decryptor.decrypt_stream(download_cipher_chunks()):
        out.write(plain_chunk)

# Seekable
seek = decryptor.create_seekable_decryptor(source)  # source: .byte_length + .read_range(off, len)
clip = seek.read_range(start_byte, length)          # plaintext bytes
```

## Notes

- **No ciphertext object, no scheme param.** You deal in chunks (or byte ranges for seek). The
  internal wire detail (`primitive = 3`) is set by the SDK; you never pass it.
- **Fails closed.** Any tampered, reordered, dropped, or truncated segment makes decryption throw.
- **Chunk size** is 64 KiB by default and rarely needs changing (tests may override it).
