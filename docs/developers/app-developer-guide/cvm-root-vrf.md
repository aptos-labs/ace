# Attested c26t CVM root unlock (prototype)

ACE worker request variant `4` adds a separate way for the c26t measured
workload to obtain the existing threshold-VRF output. It does **not** accept
an Aptos user signature or call the ordinary VRF permission hook. A node
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
attestation_jwt: String            // Google Confidential Space OIDC token
```

The guest generates a fresh X25519 response key pair **inside the measured
container** at each startup and retains its private key in memory. It asks
the Confidential Space launcher for an OIDC attestation token with the
configured custom audience and exactly one nonce:

```text
base64url_no_padding(SHA256(
    ASCII("ace/c26t/cvm-root/attestation/v1") || 0x00 ||
    BCS(ThresholdVrfRequestPayload)
))
```

The nonce binds the whole VRF request, including the response public key. The
token can be replayed during its short validity window, but repeated replies
are encrypted to the same guest-only response key. This prototype does not
use a per-node one-time challenge. The label, contract, account, and keypair
are fixed by ACE policy, so attested code cannot request arbitrary tVRF
outputs through this path.

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
JWT, nor response key enters that input. An ACE share refresh or epoch change
preserves the root if the underlying keypair secret is retained. A new
keypair changes the root and needs an explicit data migration.

The cross-language request test vector is:

```text
keypair_id       = 0x01 repeated 32 bytes
epoch            = 7
contract_id      = Aptos(119, 0x02 repeated 32 bytes, "c26t_vault")
label            = "c26t/root/v1"
account_address  = 0x03 repeated 32 bytes
response_enc_key = HPKE X25519 public key 0x04 repeated 32 bytes
attestation_jwt  = "test.jwt"
nonce            = V5aLE5kkgTxD2AaOrc1IoUbpslJFUPfsnprk0tJUqCU
```

The Python, TypeScript, and worker Rust tests assert the same BCS bytes and
nonce. The Rust worker also tests a locally signed RS256 token and rejects
changed response keys, stale tokens, invalid signatures, and image digests.

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
  "module_name": "<c26t protocol module name>",
  "account_address": "<fixed c26t root-input account, 32-byte hex>"
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

The Google token flow and nonce support are described in the
[Confidential Space relying-party guide](https://docs.cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources).
