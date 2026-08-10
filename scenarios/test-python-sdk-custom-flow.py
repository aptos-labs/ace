# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Python SDK custom-flow smoke scenario.

This is intentionally a small, hermetic scenario: it exercises the public
`ibe_aptos.decrypt_custom_flow` entrypoint against a fake chain reader and a
fake encrypted worker response. That keeps PR gating fast while still covering
the whole Python custom-flow client path: request construction, node PKE,
response PKE, IDK-share parsing, share verification, and final t-IBE decrypt.
"""

from __future__ import annotations

from aptos_sdk.account_address import AccountAddress

from ace_sdk import decryption, group, ibe_aptos, network, pke, t_ibe
from ace_sdk._internal import discovery
from ace_sdk._internal.common import ContractID, FullDecryptionDomain
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk.group import bls12381g2


def main() -> None:
    node = AccountAddress.from_str("0x1")
    keypair_id = AccountAddress.from_str("0x" + "cd" * 32)
    module_addr = AccountAddress.from_str("0x1")
    contract_id = ContractID.new_aptos(42, module_addr, "example")
    label = b"python-custom-flow-smoke"
    fdd = FullDecryptionDomain(keypair_id, contract_id, label)
    plaintext = b"python sdk custom flow works"

    msk = t_ibe.keygen_for_testing(
        t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
    ).unwrap_or_throw("msk")
    mpk = t_ibe.derive_public_key(msk).unwrap_or_throw("mpk")
    ciphertext = t_ibe.encrypt(mpk, fdd.to_bytes(), plaintext).unwrap_or_throw("encrypt")
    idk = t_ibe.extract(msk_scalar=msk.inner.scalar, identity=fdd.to_bytes()).unwrap_or_throw("idk")

    caller_enc_key, caller_dec_key = pke.keygen()
    node_enc_key, node_dec_key = pke.keygen()
    deployment = AceDeployment(
        "https://unused.example/v1",
        AccountAddress.from_str(
            "0x0000000000000000000000000000000000000000000000000000000000000ace"
        ),
    )

    state = network.State(
        epoch=9,
        epoch_start_time_micros=0,
        epoch_duration_micros=0,
        cur_nodes=[node],
        cur_threshold=1,
        secrets=[
            network.SecretInfo(
                current_session=keypair_id,
                keypair_id=keypair_id,
                scheme=network.PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD,
                expected_usage=network.USAGE_BFIBE_BLS12381_SHORTSIG_AEAD,
                note="python custom flow smoke",
            )
        ],
        proposals=[],
        epoch_change_info=None,
    )
    session = discovery.SessionPks(
        base_point=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.base_point)),
        share_pks=[group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk))],
        result_pk=group.Element.from_bls12381_g2(bls12381g2.PublicPoint(mpk.inner.pk)),
    )

    class FakeReader:
        def network_state(self):
            return state

        def session(self, addr: str, is_dkg: bool = True):
            assert addr == "0x" + keypair_id.address.hex()
            assert is_dkg is True
            return session

        def worker_endpoint(self, addr: str) -> str:
            assert addr == "0x" + node.address.hex()
            return "https://node.example/"

        def worker_enc_key(self, addr: str):
            assert addr == "0x" + node.address.hex()
            return node_enc_key

    seen_request_plaintexts: list[bytes] = []

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self):
            return pke.encrypt(caller_enc_key, idk.to_bytes()).to_hex().encode("utf-8")

    def fake_urlopen(request, timeout):
        del timeout
        request_ct = pke.Ciphertext.from_hex(request.data.decode("utf-8")).unwrap_or_throw("ct")
        request_plain = pke.decrypt(node_dec_key, request_ct).unwrap_or_throw("plain")
        seen_request_plaintexts.append(request_plain)
        return Response()

    decryption.get_chain_reader = lambda _deployment: FakeReader()  # type: ignore[assignment]
    ibe_aptos.get_chain_reader = lambda _deployment: FakeReader()  # type: ignore[assignment]
    decryption.urlopen = fake_urlopen  # type: ignore[assignment]

    result = ibe_aptos.decrypt_custom_flow(
        ace_deployment=deployment,
        keypair_id=keypair_id,
        chain_id=42,
        module_addr=module_addr,
        module_name="example",
        label=label,
        enc_pk=caller_enc_key.to_bytes(),
        enc_sk=caller_dec_key.to_bytes(),
        payload=b"custom-proof-payload",
        ciphertext=ciphertext.to_bytes(),
    ).unwrap_or_throw("custom flow decrypt")

    assert result == plaintext
    assert seen_request_plaintexts
    assert seen_request_plaintexts[0][0] == decryption.SCHEME_DECRYPTION_CUSTOM_FLOW
    print("python-sdk custom-flow smoke passed")


if __name__ == "__main__":
    main()
