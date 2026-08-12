# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Python client half of the custom-flow localnet scenario."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from aptos_sdk.account_address import AccountAddress

from ace_sdk import ibe_aptos
from ace_sdk._internal.deployment import AceDeployment


def _hex_to_bytes(value: str) -> bytes:
    text = value[2:] if value.startswith(("0x", "0X")) else value
    return bytes.fromhex(text)


def _read_fixture(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fixture_file:
        return json.load(fixture_file)


def decrypt_fixture(fixture: dict[str, Any]) -> bytes:
    deployment = AceDeployment(
        fixture["api_endpoint"],
        AccountAddress.from_str(fixture["contract_addr"]),
    )
    return ibe_aptos.decrypt_custom_flow(
        ace_deployment=deployment,
        keypair_id=AccountAddress.from_str(fixture["keypair_id"]),
        chain_id=fixture["chain_id"],
        module_addr=AccountAddress.from_str(fixture["module_addr"]),
        module_name=fixture["module_name"],
        label=_hex_to_bytes(fixture["label_hex"]),
        enc_pk=_hex_to_bytes(fixture["enc_pk_hex"]),
        enc_sk=_hex_to_bytes(fixture["enc_sk_hex"]),
        payload=_hex_to_bytes(fixture["payload_hex"]),
        ciphertext=_hex_to_bytes(fixture["ciphertext_hex"]),
    ).unwrap_or_throw("python custom-flow decrypt")


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python-sdk-custom-flow-client.py <fixture.json>", file=sys.stderr)
        return 2

    fixture = _read_fixture(Path(argv[1]))
    plaintext = decrypt_fixture(fixture)
    expected = fixture["expected_plaintext"].encode("utf-8")
    if plaintext != expected:
        raise AssertionError(f"plaintext mismatch: {plaintext!r} != {expected!r}")

    print("python-sdk custom-flow localnet scenario passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
