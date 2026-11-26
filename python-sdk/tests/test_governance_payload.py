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
governance = importlib.import_module(f"{_PACKAGE}.governance")
encode = governance.epoch_config_multisig_payload
bootstrap = governance.bootstrap_multisig_payload
resource_account_publish = governance.resource_account_create_and_publish_multisig_payload
publisher_bootstrap_publish = governance.publisher_bootstrap_multisig_payload
config_bcs = governance.epoch_config_bcs
publish_upgrade = governance.publish_upgrade_multisig_payload


class GovernancePayloadTests(unittest.TestCase):
    def test_v6_epoch_config_bcs_matches_move_field_order(self):
        a = bytes(31) + b"\x01"
        b = bytes(31) + b"\x02"
        admin = bytes(31) + b"\x03"
        expected = (b"\x02" + a + b
                    + (2).to_bytes(8, "little")
                    + (30_000_000).to_bytes(8, "little")
                    + b"\x01" + a
                    + b"\x01" + (2).to_bytes(8, "little") + b"\x01x"
                    + b"\x04next"
                    + (5).to_bytes(8, "little")
                    + admin
                    + b"\x02" + (0).to_bytes(8, "little") + (63).to_bytes(8, "little"))
        serialized = config_bcs([a, b], 2, 30_000_000, [a], [(2, "x")], "next", 5, admin, [0, 63])
        self.assertEqual(serialized, expected)
        self.assertTrue(governance.epoch_config_multisig_payload(admin, serialized).endswith(serialized))

    def test_v6_epoch_config_rejects_invalid_features(self):
        a = bytes(31) + b"\x01"
        b = bytes(31) + b"\x02"
        for features in ([64], [-1], [1, 1], [True]):
            with self.subTest(features=features), self.assertRaises(ValueError):
                config_bcs([a, b], 2, 30_000_000, [], [], "next", 0, a, features)

    def test_publish_upgrade_payload(self):
        ace = bytes(31) + b"\x01"
        payload = publish_upgrade(ace, b"\x12\x34", [b"\xaa"])
        self.assertTrue(payload.startswith(b"\x00" + ace + b"\x07network\x0fpublish_upgrade"))

    def test_resource_account_create_and_publish_golden_vector(self):
        function = b"create_resource_account_and_publish_package"
        expected = (b"\x00" + bytes(31) + b"\x01"
                    + b"\x10resource_account" + bytes([len(function)]) + function
                    + b"\x00\x03"
                    + b"\x05\x04seed"
                    + b"\x03\x02\x12\x34"
                    + b"\x06\x02\x01\xaa\x02\xbb\xcc")
        self.assertEqual(
            resource_account_publish(b"seed", b"\x12\x34", [b"\xaa", b"\xbb\xcc"]),
            expected,
        )

    def test_publisher_bootstrap_publish_golden_vector(self):
        ace_address = bytes.fromhex("00" * 30 + "cafe")
        expected = (b"\x00" + ace_address + b"\x09publisher\x11bootstrap_publish"
                    + b"\x00\x02"
                    + b"\x03\x02\x12\x34"
                    + b"\x06\x02\x01\xaa\x02\xbb\xcc")
        self.assertEqual(
            publisher_bootstrap_publish(ace_address, b"\x12\x34", [b"\xaa", b"\xbb\xcc"]),
            expected,
        )

    def test_package_builders_reject_malformed_inputs(self):
        with self.assertRaises(TypeError):
            resource_account_publish("seed", b"\x12", [b"\xaa"])
        with self.assertRaises(ValueError):
            publisher_bootstrap_publish(bytes(31), b"\x12", [b"\xaa"])
        for metadata, modules in [(b"", [b"\xaa"]), (b"\x12", []), (b"\x12", [b""]), (b"\x12", ["aa"])]:
            with self.subTest(metadata=metadata, modules=modules), self.assertRaises(ValueError):
                resource_account_publish(b"seed", metadata, modules)
            with self.subTest(metadata=metadata, modules=modules), self.assertRaises(ValueError):
                publisher_bootstrap_publish(bytes(32), metadata, modules)

    def test_bootstrap_golden_vector(self):
        nodes = [bytes(31) + b"\x01", bytes(31) + b"\x02"]
        expected = (b"\x00" + bytes(32) + b"\x07network\x13start_initial_epoch"
                    + b"\x00\x05\x41\x02" + b"".join(nodes)
                    + b"\x08" + (2).to_bytes(8, "little")
                    + b"\x08" + (30).to_bytes(8, "little")
                    + b"\x02\x01\x00"  # vector<u8> containing BCS empty SecretRequest vector.
                    + b"\x01\x00")  # Empty vector<u64>.
        self.assertEqual(bootstrap(bytes(32), nodes, 2, 30), expected)

    def test_bootstrap_encodes_initial_requests_and_features(self):
        nodes = [bytes(31) + b"\x01", bytes(31) + b"\x02"]
        features = [0, 63]
        payload = bootstrap(bytes(32), nodes, 2, 30, b"\x01\x02\x03", features)
        expected_suffix = (b"\x04\x03\x01\x02\x03"
                           + b"\x11\x02" + (0).to_bytes(8, "little")
                           + (63).to_bytes(8, "little"))
        self.assertTrue(payload.endswith(expected_suffix))

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

    def test_bootstrap_rejects_invalid_initial_inputs(self):
        nodes = [bytes(31) + b"\x01", bytes(31) + b"\x02"]
        with self.assertRaises(TypeError):
            bootstrap(bytes(32), nodes, 2, 30, "00")
        with self.assertRaises(ValueError):
            bootstrap(bytes(32), nodes, 2, 30, b"")
        with self.assertRaises(TypeError):
            bootstrap(bytes(32), nodes, 2, 30, b"\x00", (1,))
        for features in ([True], [-1], [64], [1 << 64]):
            with self.subTest(features=features), self.assertRaises(ValueError):
                bootstrap(bytes(32), nodes, 2, 30, b"\x00", features)

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
