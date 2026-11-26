"""Unsigned native proposal/approval object tests; no keys or network."""
import unittest
from ace_sdk.governance import proposal_transaction_payload, approval_transaction_payload


class GovernanceTransactionTests(unittest.TestCase):
    def test_owner_swap_golden_delta_arguments(self):
        from ace_sdk.governance import owner_swap_multisig_payload
        added, removed = bytes(31) + b"\x02", bytes(31) + b"\x03"
        function = b"swap_owners_and_update_signatures_required"
        expected = (b"\x00" + bytes(31) + b"\x01\x10multisig_account"
                    + bytes([len(function)]) + function + b"\x00\x03\x21\x01" + added
                    + b"\x21\x01" + removed + b"\x08" + (2).to_bytes(8, "little"))
        self.assertEqual(owner_swap_multisig_payload([added], [removed], 2), expected)

    def test_owner_swap_empty_deltas(self):
        from ace_sdk.governance import owner_swap_multisig_payload
        self.assertTrue(owner_swap_multisig_payload([], [], 1).endswith(b"\x00\x03\x01\x00\x01\x00\x08" + (1).to_bytes(8, "little")))

    def test_owner_swap_rejects_duplicate_or_invalid_addresses(self):
        from ace_sdk.governance import owner_swap_multisig_payload
        with self.assertRaises(ValueError):
            owner_swap_multisig_payload([bytes(32), bytes(32)], [], 1)
        with self.assertRaises(ValueError):
            owner_swap_multisig_payload([], [bytes(31)], 1)

    def test_owner_swap_rejects_invalid_quorum(self):
        from ace_sdk.governance import owner_swap_multisig_payload
        for quorum in [0, True, 1 << 64]:
            with self.subTest(quorum=quorum), self.assertRaises(ValueError):
                owner_swap_multisig_payload([], [], quorum)

    def test_creation_owner_list_and_quorum_arguments(self):
        from ace_sdk.governance import creation_transaction_payload
        owners = [bytes(31) + b"\x02", bytes(31) + b"\x03"]
        payload = creation_transaction_payload(owners, 2)
        self.assertEqual(payload.variant, 2)
        self.assertEqual(payload.value.function, "create_with_owners")
        self.assertEqual(payload.value.args, [b"\x02" + b"".join(owners), (2).to_bytes(8, "little"), b"\x00", b"\x00"])

    def test_creation_single_implicit_owner(self):
        from ace_sdk.governance import creation_transaction_payload
        self.assertEqual(creation_transaction_payload([], 1).value.args[0], b"\x00")

    def test_creation_rejects_duplicate_or_invalid_owner(self):
        from ace_sdk.governance import creation_transaction_payload
        for owners in [[bytes(32), bytes(32)], [bytes(31)]]:
            with self.subTest(owners=owners), self.assertRaises(ValueError):
                creation_transaction_payload(owners, 1)

    def test_creation_rejects_invalid_quorum(self):
        from ace_sdk.governance import creation_transaction_payload
        for quorum in [0, True, 4]:
            with self.subTest(quorum=quorum), self.assertRaises(ValueError):
                creation_transaction_payload([bytes(31) + b"\x02", bytes(31) + b"\x03"], quorum)

    def test_native_quorum_update_golden(self):
        from ace_sdk.governance import approval_quorum_multisig_payload
        expected = (b"\x00" + bytes(31) + b"\x01\x10multisig_account"
                    + b"\x1aupdate_signatures_required\x00\x01\x08"
                    + (2).to_bytes(8, "little"))
        self.assertEqual(approval_quorum_multisig_payload(2), expected)

    def test_quorum_update_composes_with_native_proposal(self):
        from ace_sdk.governance import approval_quorum_multisig_payload
        from ace_sdk.bcs import Deserializer
        inner = approval_quorum_multisig_payload(2)
        proposal = proposal_transaction_payload(bytes(32), inner)
        self.assertEqual(Deserializer(proposal.value.args[1]).deserialize_bytes(), inner)

    def test_quorum_update_rejects_invalid_u64(self):
        from ace_sdk.governance import approval_quorum_multisig_payload
        for count in [0, -1, True, 1 << 64]:
            with self.subTest(count=count), self.assertRaises(ValueError):
                approval_quorum_multisig_payload(count)

    def test_execution_stored_payload_golden(self):
        from ace_sdk.governance import execution_transaction_payload_bytes
        address = bytes(31) + b"\x01"
        self.assertEqual(execution_transaction_payload_bytes(address), b"\x03" + address + b"\x00")

    def test_execution_provided_payload_has_no_vector_wrapper(self):
        from ace_sdk.governance import execution_transaction_payload_bytes, epoch_config_multisig_payload
        address = bytes(31) + b"\x01"
        inner = epoch_config_multisig_payload(address, b"\x12\x34")
        self.assertEqual(execution_transaction_payload_bytes(address, inner), b"\x03" + address + b"\x01" + inner)

    def test_execution_rejects_invalid_inner_payload(self):
        from ace_sdk.governance import execution_transaction_payload_bytes
        with self.assertRaises(TypeError):
            execution_transaction_payload_bytes(bytes(32), "00")
        with self.assertRaises(ValueError):
            execution_transaction_payload_bytes(bytes(32), b"")

    def test_execution_rejects_invalid_address(self):
        from ace_sdk.governance import execution_transaction_payload_bytes
        with self.assertRaises(ValueError):
            execution_transaction_payload_bytes(bytes(31))

    def test_proposal_targets_native_creation(self):
        address = bytes(31) + b"\x01"
        payload = proposal_transaction_payload(address, b"\x12\x34")
        self.assertEqual(payload.variant, 2)
        self.assertEqual(payload.value.function, "create_transaction")
        self.assertEqual(payload.value.args, [address, b"\x02\x12\x34"])

    def test_approval_targets_native_sequence(self):
        address = bytes(31) + b"\x01"
        payload = approval_transaction_payload(address, 7)
        self.assertEqual(payload.variant, 2)
        self.assertEqual(payload.value.function, "approve_transaction")
        self.assertEqual(payload.value.args, [address, (7).to_bytes(8, "little")])

    def test_rejects_invalid_sequence(self):
        for sequence in [0, -1, True, 1 << 64]:
            with self.subTest(sequence=sequence), self.assertRaises(ValueError):
                approval_transaction_payload(bytes(32), sequence)

    def test_rejects_invalid_proposal_arguments(self):
        with self.assertRaises(ValueError):
            proposal_transaction_payload(bytes(31), b"")
        with self.assertRaises(TypeError):
            proposal_transaction_payload(bytes(32), "00")


if __name__ == "__main__":
    unittest.main()
