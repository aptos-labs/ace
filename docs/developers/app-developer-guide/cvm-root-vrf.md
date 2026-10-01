# Attested c26t CVM root unlock (prototype)

ACE worker request variant `4` adds a separate way for the c26t measured
workload to obtain the existing threshold-VRF output. It does **not** accept
an Aptos user signature. It verifies the worker's registered Ed25519 key and
calls the c26t contract's `on_ace_cvm_root_request` view. A node
serves this variant only when it starts with `--cvm-root-policy-json` (or
`ACE_CVM_ROOT_POLICY_JSON`). Without the policy, the path is disabled.

## Wire contract

BCS `WorkerRequest::CvmRootVrf` is:

```text
ULEB128(4)
ThresholdVrfRequestPayload {
    keypair_id: [u8; 32],
    epoch: u64,                    // little-endian; share lookup only
    contract_id: ContractId::Aptos {
        chain_id: u8,
        module_addr: [u8; 32],
        module_name: String,
    },
    label: Vec<u8>,                // exactly ASCII "c26t/root/v1"
    account_address: [u8; 32],
    response_enc_key: EncryptionKey::HpkeX25519ChaCha20Poly1305 {
        pk: Vec<u8>,               // exactly 32 bytes
    },
}
worker_addr: [u8; 32]            // CVM-generated Aptos account
worker_pk: [u8; 32]              // registered Ed25519 public key
tls_spki_sha256: [u8; 32]        // SHA256 of HTTPS certificate SPKI DER
worker_signature: Vec<u8>        // exactly 64 Ed25519 signature bytes
attestation_jwt: String            // Google Confidential Space OIDC token
```

The guest generates fresh X25519 response and Ed25519 worker key pairs, plus
the HTTPS certificate key, **inside the measured container** at each startup
and retains their private keys in memory. It registers the Ed25519 account in
the c26t contract before asking ACE for the root. It signs exactly:

```text
ASCII("ace/c26t/cvm-root/worker-signature/v1") || 0x00 ||
BCS(ThresholdVrfRequestPayload) || worker_addr || worker_pk || tls_spki_sha256
```

It then asks the Confidential Space launcher for an OIDC attestation token
with the configured custom audience and exactly one nonce:

```text
base64url_no_padding(SHA256(
    ASCII("ace/c26t/cvm-root/attestation/v1") || 0x00 ||
    BCS(ThresholdVrfRequestPayload) || worker_addr || worker_pk ||
    tls_spki_sha256 || worker_signature
))
```

The nonce binds the whole VRF request, including the response public key,
worker identity, and HTTPS certificate public key. The
token can be replayed during its short validity window, but repeated replies
are encrypted to the same guest-only response key. This prototype does not
use a per-node one-time challenge. Before returning a share, each ACE worker
verifies the Ed25519 signature and calls the c26t contract view
`on_ace_cvm_root_request(label, account, worker_addr, worker_pk)` on the
configured Aptos chain. It must return `true` for the exact active registered
key; a missing hook, RPC error, `false`, or malformed response rejects the
request. The label, contract, account, and keypair are fixed by ACE policy,
so attested code cannot request arbitrary tVRF outputs through this path.

The outer request uses ACE's existing PKE-encrypted `POST /` worker transport:
encrypt the BCS request to each worker's registered encryption key and send
the ciphertext as hex. The HTTP response is hex BCS `pke::Ciphertext` encrypted
to `response_enc_key`. After decrypting, parse the existing
`ThresholdVrfShare` (`eval_point: u64` followed by a tagged BLS12-381 G1
element). Verify each share against the current ACE G2 public commitments and
interpolate at zero. The existing `ace_sdk.cvm_root` Python client performs
the request/verification/combination; `ace_sdk.pke` handles HPKE.

The tVRF input remains the existing domain-separated BCS tuple of
`(keypair_id, contract_id, account_address, label)`. Neither epoch, nonce,
JWT, worker account, TLS key, nor response key enters that input. The
`account_address` is the fixed c26t package address (`@c26t`), not the worker
address. An ACE share refresh or epoch change
preserves the root if the underlying keypair secret is retained. A new
keypair changes the root and needs an explicit data migration.

The cross-language request test vector is:

```text
keypair_id       = 0x01 repeated 32 bytes
epoch            = 7
contract_id      = Aptos(119, 0x02 repeated 32 bytes, "confidential_worker")
label            = "c26t/root/v1"
account_address  = 0x03 repeated 32 bytes
response_enc_key = HPKE X25519 public key 0x04 repeated 32 bytes
worker_addr      = 0x05 repeated 32 bytes
worker_pk        = ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c
tls_spki_sha256  = 0x06 repeated 32 bytes
worker_signature = 1df4d2fd976963346d4bb6026803a1f12bcfe908687fbe024701ccfac46769763297b0b04cdc7483d5c0a698a0c45fb2682cb0c722af44ba81ec5f4d9a559e0c
attestation_jwt  = "test.jwt"
nonce            = TUlW5QIbVxjiomgeFYQASwvhk8K6fKoM6Ab-BiEcsaQ
```

The Python, TypeScript, and worker Rust tests assert the same BCS bytes and
nonce. The Rust worker also tests a locally signed RS256 token and rejects
changed response or TLS keys, stale tokens, invalid signatures, and image
digests.

## Worker policy

Each worker's nonsecret policy JSON must pin all of these fields:

```json
{
  "audience": "ace-c26t-cvm-root-v1",
  "image_digest": "sha256:<approved 64 lowercase hex digits>",
  "project_id": "<approved GCP project>",
  "expected_env": {"<nonsecret env name>": "<exact attested value>"},
  "expected_args": ["<exact attested command argument>"],
  "keypair_id": "<ACE threshold-VRF G2 keypair ID, 32-byte hex>",
  "chain_id": 119,
  "module_addr": "<c26t protocol module address, 32-byte hex>",
  "module_name": "confidential_worker",
  "account_address": "<c26t package address, 32-byte hex>"
}
```

The worker validates Google's RS256 signature using the pinned Google
Confidential Space JWKS URL, then checks the issuer, audience, `eat_nonce`,
token times (at most five minutes old), production TDX/secure-boot claims,
disabled memory monitoring, exact image digest, project, environment, and
command. Missing or mismatched claims fail closed. The expected environment
must contain no credentials: attestation claims may be visible to recipients.
The response is always PKE-encrypted; the node checks the keypair's existing
threshold-VRF usage mask and G2 group before deriving a share.

For the current `shelbynet-20260923` ACE deployment, the known VRF keypair ID
is `0xd71f85f53eed44d1d8ea4ac978fc0d2c4c326208097692964d3cdd48d1367114`
on chain 119. This ID in the SDK is a configuration hint, not proof that all
workers have this branch deployed. The c26t module address, measured image
digest, approved environment and command, GCP project, and ACE deployment
approval must be fixed before workers can enable the policy. No production
policy or worker rollout is included in this change.

The immutable disposable c26t smoke-test package does not contain this hook;
ACE must reject root requests for that package. A new package publish with
the hook and real attestation verification is required before any service
using real data can unlock a root.

The Google token flow and nonce support are described in the
[Confidential Space relying-party guide](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources).
