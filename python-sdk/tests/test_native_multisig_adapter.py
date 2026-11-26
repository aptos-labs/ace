"""Actual SDK unsigned serialization checks; no signer keys or network."""
import unittest
from aptos_sdk.account_address import AccountAddress
from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import RawTransaction, TransactionPayload
from ace_sdk.governance import execution_transaction_payload, execution_transaction_payload_bytes, epoch_config_multisig_payload


def serialized(value):
    serializer = Serializer()
    value.serialize(serializer)
    return serializer.output()


class NativeMultisigAdapterTests(unittest.TestCase):
    def test_stored_payload_uses_sdk_protocol(self):
        address = bytes(31) + b"\x01"
        payload = execution_transaction_payload(address)
        self.assertIsInstance(payload, TransactionPayload)
        self.assertEqual(serialized(payload), b"\x03" + address + b"\x00")

    def test_provided_payload_uses_sdk_protocol(self):
        address = bytes(31) + b"\x01"
        inner = epoch_config_multisig_payload(address, b"\x12\x34")
        self.assertEqual(serialized(execution_transaction_payload(address, inner)),
                         execution_transaction_payload_bytes(address, inner))

    def test_raw_transaction_embeds_native_payload(self):
        sender = bytes(31) + b"\x02"
        address = bytes(31) + b"\x01"
        payload = execution_transaction_payload(address)
        raw = RawTransaction(AccountAddress(sender), 5, payload, 1000, 1, 123, 4)
        expected = (sender + (5).to_bytes(8, "little") + b"\x03" + address + b"\x00"
                    + (1000).to_bytes(8, "little") + (1).to_bytes(8, "little")
                    + (123).to_bytes(8, "little") + b"\x04")
        self.assertEqual(serialized(raw), expected)

    def test_invalid_address_is_not_wrapped(self):
        with self.assertRaises(ValueError):
            execution_transaction_payload(bytes(31))


if __name__ == "__main__":
    unittest.main()
