"""Unsigned native payload adapter for the installed Aptos SDK serializer."""
from dataclasses import dataclass, field

from aptos_sdk.bcs import Serializer
from aptos_sdk.transactions import TransactionPayload

from .governance import execution_transaction_payload_bytes


@dataclass(frozen=True)
class _NativeMultisigValue:
    body: bytes = field(repr=False)

    def serialize(self, serializer: Serializer) -> None:
        serializer.fixed_bytes(self.body)


class NativeMultisigTransactionPayload(TransactionPayload):
    """Encode variant 3 through the SDK's existing RawTransaction path.

    The SDK constructor only recognizes its older three variants. This adapter
    supplies the same variant/value protocol for native multisig serialization.
    The SDK's default deserializer still cannot read variant 3. No signing,
    account access, approval checks or submission are performed here.
    """
    def __init__(self, multisig_address: bytes, inner_payload: bytes | None = None):
        wire = execution_transaction_payload_bytes(multisig_address, inner_payload)
        self.variant = 3
        self.value = _NativeMultisigValue(wire[1:])
