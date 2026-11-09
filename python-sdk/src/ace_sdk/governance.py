"""Pure v6 native-multisig payload construction; no signing or submission."""

from typing import TYPE_CHECKING

from .bcs import Serializer

if TYPE_CHECKING:
    from aptos_sdk.transactions import TransactionPayload


def creation_transaction_payload(additional_owners: list[bytes], required_signatures: int) -> "TransactionPayload":
    """Build unsigned create_with_owners payload with empty metadata.

    The creator is the eventual transaction signer and is included implicitly.
    The framework checks that creator is not in additional_owners. No account,
    private key, signer or network request is created by this function.
    """
    from aptos_sdk.bcs import Serializer as AptosSerializer
    from aptos_sdk.transactions import EntryFunction, TransactionArgument, TransactionPayload

    if not isinstance(additional_owners, list):
        raise TypeError("additional_owners must be a list of addresses")
    for owner in additional_owners:
        _validate_address(owner)
    if len(set(additional_owners)) != len(additional_owners):
        raise ValueError("additional_owners must be unique")
    if type(required_signatures) is not int or not (1 <= required_signatures <= len(additional_owners) + 1):
        raise ValueError("required_signatures must be between 1 and the total owner count")
    owners = Serializer()
    owners.serialize_u32_as_uleb128(len(additional_owners))
    for owner in additional_owners:
        owners.serialize_fixed_bytes(owner)
    quorum = Serializer()
    quorum.serialize_u64(required_signatures)
    arguments = [owners.to_bytes(), quorum.to_bytes(), b"\x00", b"\x00"]
    entry = EntryFunction.natural("0x1::multisig_account", "create_with_owners", [], [
        TransactionArgument(argument, AptosSerializer.fixed_bytes) for argument in arguments
    ])
    return TransactionPayload(entry)


def proposal_transaction_payload(multisig_address: bytes, inner_payload: bytes) -> "TransactionPayload":
    """Build unsigned native create_transaction arguments; never sign or submit."""
    from aptos_sdk.account_address import AccountAddress
    from aptos_sdk.bcs import Serializer as AptosSerializer
    from aptos_sdk.transactions import EntryFunction, TransactionArgument, TransactionPayload

    _validate_address(multisig_address)
    if not isinstance(inner_payload, bytes):
        raise TypeError("inner_payload must be bytes")
    entry = EntryFunction.natural("0x1::multisig_account", "create_transaction", [], [
        TransactionArgument(AccountAddress(multisig_address), AptosSerializer.struct),
        TransactionArgument(inner_payload, AptosSerializer.to_bytes),
    ])
    return TransactionPayload(entry)


def approval_transaction_payload(multisig_address: bytes, sequence_number: int) -> "TransactionPayload":
    """Build unsigned native approval arguments; no signer or network is used."""
    from aptos_sdk.account_address import AccountAddress
    from aptos_sdk.bcs import Serializer as AptosSerializer
    from aptos_sdk.transactions import EntryFunction, TransactionArgument, TransactionPayload

    _validate_address(multisig_address)
    if type(sequence_number) is not int or not (1 <= sequence_number < 1 << 64):
        raise ValueError("sequence_number must be a positive u64")
    entry = EntryFunction.natural("0x1::multisig_account", "approve_transaction", [], [
        TransactionArgument(AccountAddress(multisig_address), AptosSerializer.struct),
        TransactionArgument(sequence_number, AptosSerializer.u64),
    ])
    return TransactionPayload(entry)


def execution_transaction_payload(multisig_address: bytes, inner_payload: bytes | None = None) -> "TransactionPayload":
    """Return an unsigned native payload compatible with SDK RawTransaction."""
    from .native_multisig import NativeMultisigTransactionPayload

    return NativeMultisigTransactionPayload(multisig_address, inner_payload)


def execution_transaction_payload_bytes(multisig_address: bytes, inner_payload: bytes | None = None) -> bytes:
    """Serialize native TransactionPayload::Multisig, without signing/submission.

    Omit the inner payload when it was stored with create_transaction. Provide
    its complete MultisigTransactionPayload bytes for hash-only proposals.
    This returns BCS bytes, not an aptos-sdk TransactionPayload object: that
    SDK's built-in object encoder does not support the native multisig variant.
    Queue selection and approval checks are enforced by the VM, not this helper.
    """
    _validate_address(multisig_address)
    if inner_payload is not None:
        if not isinstance(inner_payload, bytes):
            raise TypeError("inner_payload must be bytes or None")
        if not inner_payload:
            raise ValueError("provided inner_payload must not be empty")
    payload = Serializer()
    payload.serialize_u32_as_uleb128(3)  # TransactionPayload::Multisig.
    payload.serialize_fixed_bytes(multisig_address)
    payload.serialize_bool(inner_payload is not None)  # BCS Option discriminant.
    if inner_payload is not None:
        payload.serialize_fixed_bytes(inner_payload)  # Struct/enum, not vector<u8>.
    return payload.to_bytes()


def epoch_config_multisig_payload(ace_address: bytes, config_bcs: bytes) -> bytes:
    """Encode the inner payload for ``0x1::multisig_account::create_transaction``.

    ``ace_address`` is the fresh package's 32-byte account address.
    ``config_bcs`` is the already-serialized v6 epoch configuration. This
    function does not validate that config, approve it, or execute a transaction.
    The result is a MultisigTransactionPayload, not a top-level transaction.
    """
    if not isinstance(ace_address, bytes) or len(ace_address) != 32:
        raise ValueError("ace_address must be exactly 32 bytes")
    if not isinstance(config_bcs, bytes):
        raise TypeError("config_bcs must be bytes")

    argument = Serializer()
    argument.serialize_bytes(config_bcs)  # The entry parameter is vector<u8>.

    return _entry_function_payload(ace_address, "execute_epoch_config", [argument.to_bytes()])


def bootstrap_multisig_payload(
    ace_address: bytes,
    nodes: list[bytes],
    threshold: int,
    resharing_interval_secs: int,
) -> bytes:
    """Encode ``network::start_initial_epoch`` for native multisig approval.

    The threshold here is the secret-sharing threshold, not the multisig's
    mutable approval quorum. Node PKE-key registration is checked on chain.
    No account is created and no transaction is signed or submitted.
    """
    if type(threshold) is not int or not (2 <= threshold <= len(nodes) and 2 * threshold > len(nodes)):
        raise ValueError("invalid secret-sharing threshold")
    if type(resharing_interval_secs) is not int or not (30 <= resharing_interval_secs < 1 << 64):
        raise ValueError("resharing interval must be a u64 of at least 30 seconds")

    node_argument = Serializer()
    node_argument.serialize_u32_as_uleb128(len(nodes))
    seen_nodes: set[bytes] = set()
    for node in nodes:
        _validate_address(node)
        if node in seen_nodes:
            raise ValueError("node addresses must be unique")
        seen_nodes.add(node)
        node_argument.serialize_fixed_bytes(node)
    threshold_argument = Serializer()
    threshold_argument.serialize_u64(threshold)
    interval_argument = Serializer()
    interval_argument.serialize_u64(resharing_interval_secs)
    return _entry_function_payload(
        ace_address, "start_initial_epoch",
        [node_argument.to_bytes(), threshold_argument.to_bytes(), interval_argument.to_bytes()],
    )


def _validate_address(address: bytes) -> None:
    if not isinstance(address, bytes) or len(address) != 32:
        raise ValueError("account addresses must be exactly 32 bytes")


def owner_swap_multisig_payload(owners_to_add: list[bytes], owners_to_remove: list[bytes], required_signatures: int) -> bytes:
    """Build a direct native owner-swap/quorum proposal, not ACE activation.

    Lists are deltas, not the final owner set. Existing membership, overlap
    semantics, final owner-count bounds and authorization are checked on chain.
    """
    if type(required_signatures) is not int or not (1 <= required_signatures < 1 << 64):
        raise ValueError("required_signatures must be a positive u64")
    arguments = []
    for owners in (owners_to_add, owners_to_remove):
        if not isinstance(owners, list):
            raise TypeError("owner deltas must be lists of addresses")
        for owner in owners:
            _validate_address(owner)
        if len(set(owners)) != len(owners):
            raise ValueError("each owner delta must be unique")
        argument = Serializer()
        argument.serialize_u32_as_uleb128(len(owners))
        for owner in owners:
            argument.serialize_fixed_bytes(owner)
        arguments.append(argument.to_bytes())
    quorum = Serializer()
    quorum.serialize_u64(required_signatures)
    arguments.append(quorum.to_bytes())
    return _entry_function_payload(bytes(31) + b"\x01", "swap_owners_and_update_signatures_required",
                                   arguments, module="multisig_account")


def approval_quorum_multisig_payload(required_signatures: int) -> bytes:
    """Propose a native approval-quorum update, not a DKG threshold change.

    Owner-count bounds and authorization are checked by the framework at
    execution. The native entry must be targeted directly, not via ACE code.
    """
    if type(required_signatures) is not int or not (1 <= required_signatures < 1 << 64):
        raise ValueError("required_signatures must be a positive u64")
    argument = Serializer()
    argument.serialize_u64(required_signatures)
    return _entry_function_payload(bytes(31) + b"\x01", "update_signatures_required",
                                   [argument.to_bytes()], module="multisig_account")


def _entry_function_payload(ace_address: bytes, function: str, arguments: list[bytes], module: str = "network") -> bytes:
    _validate_address(ace_address)
    payload = Serializer()
    payload.serialize_u32_as_uleb128(0)  # MultisigTransactionPayload::EntryFunction.
    payload.serialize_fixed_bytes(ace_address)
    payload.serialize_str(module)
    payload.serialize_str(function)
    payload.serialize_u32_as_uleb128(0)  # No type arguments.
    payload.serialize_u32_as_uleb128(len(arguments))
    for argument in arguments:
        payload.serialize_bytes(argument)
    return payload.to_bytes()
