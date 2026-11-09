"""Dependency-free tests of the actual BCS/payload modules, not package integration."""
import importlib
import sys
import types
import unittest
from pathlib import Path

# Keep optional crypto/HTTP package initialization out of these pure-wire tests.
_PACKAGE = "_ace_governance_wire_tests"
package = types.ModuleType(_PACKAGE)
package.__path__ = [str(Path(__file__).resolve().parents[1] / "src" / "ace_sdk")]
sys.modules[_PACKAGE] = package
encode = importlib.import_module(f"{_PACKAGE}.governance").epoch_config_multisig_payload


bootstrap = importlib.import_module(f"{_PACKAGE}.governance").bootstrap_multisig_payload


class GovernancePayloadTests(unittest.TestCase):
    def test_bootstrap_golden_vector(self):
        nodes = [bytes(31) + b"\x01", bytes(31) + b"\x02"]
        expected = (b"\x00" + bytes(32) + b"\x07network\x13start_initial_epoch"
                    + b"\x00\x03\x41\x02" + b"".join(nodes)
                    + b"\x08" + (2).to_bytes(8, "little")
                    + b"\x08" + (30).to_bytes(8, "little"))
        self.assertEqual(bootstrap(bytes(32), nodes, 2, 30), expected)

    def test_bootstrap_rejects_invalid_node_address(self):
        with self.assertRaises(ValueError):
            bootstrap(bytes(32), [bytes(31), bytes(32)], 2, 30)

    def test_bootstrap_rejects_duplicate_node_addresses(self):
        node = bytes(31) + b"\x01"
        other = bytes(31) + b"\x02"
        for nodes in ([node, node], [node, other, node], [node, node, node]):
            with self.subTest(nodes=nodes), self.assertRaisesRegex(ValueError, "unique"):
                bootstrap(bytes(32), nodes, 2, 30)

    def test_bootstrap_rejects_invalid_secret_threshold(self):
        for threshold in [1, 3, True]:
            with self.subTest(threshold=threshold), self.assertRaises(ValueError):
                bootstrap(bytes(32), [bytes(32), bytes(32)], threshold, 30)

    def test_bootstrap_rejects_invalid_interval(self):
        for interval in [29, -1, 1 << 64, True]:
            with self.subTest(interval=interval), self.assertRaises(ValueError):
                bootstrap(bytes(32), [bytes(32), bytes(32)], 2, interval)

    def test_entry_function_golden_vector(self):
        address = bytes.fromhex("00" * 30 + "cafe")
        expected = (b"\x00" + address + b"\x07network\x14execute_epoch_config"
                    + b"\x00\x01\x03\x02\x12\x34")
        self.assertEqual(encode(address, b"\x12\x34"), expected)

    def test_nested_argument_uleb128_boundary(self):
        payload = encode(bytes(32), bytes(128))
        self.assertTrue(payload.endswith(b"\x82\x01\x80\x01" + bytes(128)))

    def test_rejects_noncanonical_address(self):
        for address in [bytes(31), bytes(33), "0xcafe"]:
            with self.assertRaises(ValueError):
                encode(address, b"")

    def test_rejects_nonbytes_config(self):
        with self.assertRaises(TypeError):
            encode(bytes(32), "00")


if __name__ == "__main__":
    unittest.main()
