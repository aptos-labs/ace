# `ace` CLI — calling primitives directly

Status: **design, v1 scope agreed** (2026-09-10). Implementation tracked separately.

The `ace` CLI (`cli/`) today is an operator/admin tool (`deployment`, `node`, offline
`ibe admin-*`). This design adds the *client* path: run the supported primitives against a
real deployment, with real workers and a real signer, from a shell. Goals: scriptable,
pipe/FIFO friendly, one consistent grammar for values, and a wallet-signing option for
humans.

## 1. Command shape

```
ace <primitive> <op> [target] [io] [signer] [--json]
```

| primitive    | ops                  | needs signer | notes                                       |
|--------------|----------------------|--------------|---------------------------------------------|
| `ibe`        | `encrypt`, `decrypt` | decrypt      | block t-IBE (`ibe-for-aptos` basic flow)    |
| `stream-ibe` | `encrypt`, `decrypt` | decrypt      | seekable stream; incremental I/O; `--range` |
| `vrf`        | `derive`             | yes          | `vrf-for-aptos`                             |

Out of scope for v1 (may follow): `custom decrypt` (presigned-access), Solana targets.
The existing offline admin commands stay as `ace ibe admin-extract` / `ace ibe admin-decrypt`.

### Examples

```sh
# encrypt a string, write ciphertext bytes to a file
ace ibe encrypt --deployment shelbynet-20260731 --keypair-id 0xabcd…ef01 \
    --label str:zhoujun/2025/finance --input str:HELLO_WORLD --output file:/tmp/ct.bin

# decrypt with an aptos CLI profile as the signer, print plaintext as utf-8
ace ibe decrypt --deployment shelbynet-20260731 --keypair-id 0xabcd…ef01 \
    --signer profile:alice --input file:/tmp/ct.bin --output stdout:utf8

# long-running stream transformer between two FIFOs
ace stream-ibe decrypt --deployment shelbynet-20260731 --keypair-id 0xabcd…ef01 \
    --signer profile:alice --input file:/tmp/fifo1 --output file:/tmp/fifo2

# seekable: decrypt only plaintext bytes [1000, 2000) of a stored stream
ace stream-ibe decrypt --deployment shelbynet-20260731 --keypair-id 0xabcd…ef01 \
    --signer profile:alice --input file:/data/ct.bin --range 1000-2000 --output -

# derive a VRF output, signing in the browser with a wallet
ace vrf derive --deployment shelbynet-20260731 --keypair-id 0xabcd…ef01 \
    --input str:aaa/bbb/ccc --signer wallet --output stdout:hex
```

## 2. Target: which network, which key

| flag                     | meaning |
|--------------------------|---------|
| `--deployment <id>`      | a `knownDeployments` id (e.g. `shelbynet-20260731`) **or** a local CLI deployment profile alias (`ace deployment ls`). Omitted → the CLI's default profile. |
| `--keypair-id <0x…>`     | on-chain keypair id. Required in v1. |
| `--api-endpoint`, `--contract`, `--discovery-url`, `--api-key` | override individual fields of the resolved deployment (escape hatch; same names as the SDK's `AceDeployment`). |

Resolution order: explicit override flags > `--deployment` > default profile. The
resolved deployment is echoed to stderr (and in `--json`) so scripts can see what was used.

## 3. Values: one grammar for `--input`, `--output`, `--label`, `--seed`, …

Every byte-valued flag takes `<scheme>:<value>`. The scheme *is* the mode.

| scheme                 | in | out | meaning |
|------------------------|----|-----|---------|
| `str:<text>`           | ✔  |     | UTF-8 bytes of `<text>` |
| `hex:<0x…>`            | ✔  |     | hex-decoded bytes (0x prefix optional) |
| `b64:<…>`              | ✔  |     | base64-decoded bytes |
| `file:<path>`          | ✔  | ✔   | read/write raw bytes. Regular files, FIFOs, `/dev/stdin`, `/dev/fd/N`. Streaming ops read and write incrementally. |
| `-`                    | ✔  | ✔   | stdin (input) / stdout as raw bytes (output) |
| `stdout:hex`           |    | ✔   | `0x…` hex + newline on stdout |
| `stdout:b64`           |    | ✔   | base64 + newline on stdout |
| `stdout:utf8`          |    | ✔   | decode as UTF-8, print (fails if not valid UTF-8) |
| `https://…`            | ✔  |     | (stream-ibe decrypt only) HTTP range reads for `--range` |
| *(omitted)*            | ✔  | ✔   | inputs: interactive prompt (TTY only, existing `escInput`); outputs: `stdout:hex` |

Rules:
- A value without a recognised `scheme:` prefix is a usage error (exit 2) — no guessing.
  To pass a literal that starts with `x:`, use `str:x:…`.
- Human-readable logging (`✔ wrote N bytes to …`, resolved deployment, epoch) always goes
  to **stderr**, so `--output -` and `stdout:*` are clean for piping.
- Output `file:` refuses to overwrite an existing regular file unless `--force` (FIFOs and
  character devices are exempt).

## 4. Signers

Ops that talk to workers on behalf of a user (`decrypt`, `derive`) take one flag:

```
--signer <scheme>[:<value>]
```

| signer                          | behaviour |
|---------------------------------|-----------|
| `profile:<name>`                | Ed25519 key from the Aptos CLI config (`~/.aptos/config.yaml`, or `./.aptos/config.yaml` if present). Same lookup rules as `aptos --profile`. |
| `key:hex:<0x…>` / `key:env:<VAR>` / `key:file:<path>` | raw Ed25519 private key (AIP-80 or 32-byte hex). Reuses the §3 grammar after `key:`. |
| `wallet`                        | browser wallet via `@aptos-labs/wallet-adapter` (Petra, Nightly, …). See §4.1. |
| *(omitted)*                     | `profile:default` if that profile exists; otherwise usage error listing the options. |

What is signed: the SDK's `sign(message) → {pubKey, signature, fullMessage}` contract —
an **Aptos wallet message signature** over `buildAptosWalletFullMessage({message, nonce,
application, chainId, address})`, never a transaction. The CLI builds `fullMessage` for key
and profile signers; a wallet builds it itself.

`--application <origin>`: the `application` field in the full message. Defaults to
`ace-cli` for key/profile signers. Some app contracts enforce a client-origin allowlist
(`set_client_origin`); for those, pass the origin the contract expects. For the wallet
signer the origin is whatever the wallet reports (the localhost page), which such contracts
will reject — documented limitation, not something the CLI can spoof.

### 4.1 `--signer wallet`

1. CLI binds `127.0.0.1:<random port>`, prints the URL to stderr, and opens the default
   browser (`--no-open` to just print; `--port` to pin).
2. The page is a single static HTML+JS bundle shipped inside the CLI package, built on
   `@aptos-labs/wallet-adapter-core`. It shows: deployment, keypair id, the op, and the
   exact `message` bytes (hex + utf-8 preview) it is about to request a signature for.
3. User connects a wallet, clicks **Sign**; page calls `signMessage({message, nonce,
   application: true, chainId, address})` and `POST`s `{pubKey, signature, fullMessage,
   address}` back.
4. CLI verifies the signature locally against `pubKey`/`fullMessage` before using it,
   proceeds with the op, responds to the page with success/failure, and shuts the server
   down. Only one signature is accepted per run; the server rejects anything after it.
5. `--wallet-timeout <s>` (default 300) → exit 3 on expiry.

Security: the page is same-origin only (no CORS), the POST carries a one-time token
embedded in the page URL, and the server never returns anything but the static page and
the `ok/fail` result. Nothing about the key leaves the wallet.

For streaming ops the signature is obtained **once** up front; chunk decryption after the
share round-trip is local. The browser tab can be closed after signing.

## 5. Streaming semantics (`stream-ibe`)

- Both ops are pure transformers: read `--input` incrementally, write `--output`
  incrementally, exit 0 on EOF. FIFOs and pipes work with no extra flags; the process
  lives as long as the input does.
- Segment size is internal (64 KiB plaintext); not exposed.
- `decrypt --range <start>[-<end>]` (plaintext byte offsets, end exclusive; `-<end>` or
  `<start>-` allowed) uses the seekable decryptor. Requires a random-access input
  (`file:` regular file or `https://` supporting `Range`); on a FIFO/stdin it is a usage
  error. Without `--range` the whole stream is decrypted sequentially.
- Truncation: sequential decrypt fails closed on a truncated stream (exit 5). With
  `--range`, whole-stream truncation is undetectable by construction — see the
  seekable-mode note in `docs/auditor/cryptography/t-ibe.md`; the CLI says so in
  `--help`.

## 6. Output for scripts

`--json` prints exactly one JSON object on stdout and suppresses `stdout:*` output modes
(the data goes into the object instead, hex-encoded, unless `--output file:`/`-` was given):

```json
{ "ok": true, "op": "ibe.decrypt", "deployment": "shelbynet-20260731",
  "keypairId": "0x…", "epoch": 975, "bytes": 11, "output": "file:/tmp/pt.bin",
  "hex": null, "durationMs": 1234 }
```

On failure: `{ "ok": false, "op": …, "reason": "<code>", "message": "…" }` and a non-zero
exit. Human logs stay on stderr either way.

Exit codes: `0` ok · `2` usage/argument · `3` signer/auth (incl. wallet timeout, profile
not found) · `4` network/workers (fullnode, discovery, insufficient shares) · `5` crypto or
verification failure (bad share, tag mismatch, truncated stream).

## 7. Implementation notes (non-binding)

- Extend `cli/src/index.ts` with `stream-ibe` and `vrf` groups; add `ibe encrypt/decrypt`
  as the client flow while keeping `admin-*`.
- New modules: `cli/src/values.ts` (§3 grammar; one parser used by every byte flag),
  `cli/src/signers/{profile,key,wallet}.ts` exposing a single `Signer` type that matches
  the SDK's `sign` callback, `cli/src/target.ts` (§2 resolution),
  `cli/src/wallet-page/` (static bundle built with the CLI, served from memory).
- Reuse `ibe-for-aptos`, `ibe-for-aptos-stream`, `vrf-for-aptos` from `@aptos-labs/ace-sdk`
  unchanged; the CLI adds no crypto.
- Tests: value-grammar unit tests; signer tests with a generated key and a temp
  `config.yaml`; an end-to-end round-trip against the localnet used by existing CLI tests;
  wallet flow tested with a headless page posting a pre-computed signature.
