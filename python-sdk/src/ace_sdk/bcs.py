# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Minimal BCS (Binary Canonical Serialization) codec matching the wire format
produced/consumed by @aptos-labs/ts-sdk's Serializer/Deserializer, restricted
to the primitives ACE actually uses: u8/u16/u32/u64/u128, bool, bytes (uleb128
length-prefixed), str (uleb128 length-prefixed utf-8), and uleb128 itself.
"""

from __future__ import annotations


class Serializer:
    def __init__(self) -> None:
        self._buf = bytearray()

    def serialize_u8(self, value: int) -> None:
        if not (0 <= value <= 0xFF):
            raise ValueError("u8 out of range")
        self._buf.append(value)

    def serialize_bool(self, value: bool) -> None:
        self._buf.append(1 if value else 0)

    def serialize_u16(self, value: int) -> None:
        if not (0 <= value <= 0xFFFF):
            raise ValueError("u16 out of range")
        self._buf += value.to_bytes(2, "little")

    def serialize_u32(self, value: int) -> None:
        if not (0 <= value <= 0xFFFFFFFF):
            raise ValueError("u32 out of range")
        self._buf += value.to_bytes(4, "little")

    def serialize_u64(self, value: int) -> None:
        if not (0 <= value <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("u64 out of range")
        self._buf += value.to_bytes(8, "little")

    def serialize_u128(self, value: int) -> None:
        if not (0 <= value <= (1 << 128) - 1):
            raise ValueError("u128 out of range")
        self._buf += value.to_bytes(16, "little")

    def serialize_u32_as_uleb128(self, value: int) -> None:
        if value < 0:
            raise ValueError("uleb128 value must be non-negative")
        v = value
        while True:
            byte = v & 0x7F
            v >>= 7
            if v != 0:
                self._buf.append(byte | 0x80)
            else:
                self._buf.append(byte)
                break

    def serialize_bytes(self, value: bytes) -> None:
        self.serialize_u32_as_uleb128(len(value))
        self._buf += value

    def serialize_fixed_bytes(self, value: bytes) -> None:
        """Raw bytes with no length prefix (BCS fixed-size arrays)."""
        self._buf += value

    def serialize_str(self, value: str) -> None:
        self.serialize_bytes(value.encode("utf-8"))

    def to_bytes(self) -> bytes:
        return bytes(self._buf)


class Deserializer:
    def __init__(self, data: bytes) -> None:
        self._data = data
        self._pos = 0

    def remaining(self) -> int:
        return len(self._data) - self._pos

    def _take(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise ValueError("unexpected end of input")
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk

    def deserialize_u8(self) -> int:
        return self._take(1)[0]

    def deserialize_bool(self) -> bool:
        b = self._take(1)[0]
        if b not in (0, 1):
            raise ValueError("invalid bool")
        return b == 1

    def deserialize_u16(self) -> int:
        return int.from_bytes(self._take(2), "little")

    def deserialize_u32(self) -> int:
        return int.from_bytes(self._take(4), "little")

    def deserialize_u64(self) -> int:
        return int.from_bytes(self._take(8), "little")

    def deserialize_u128(self) -> int:
        return int.from_bytes(self._take(16), "little")

    def deserialize_uleb128_as_u32(self) -> int:
        value = 0
        shift = 0
        while True:
            byte = self._take(1)[0]
            value |= (byte & 0x7F) << shift
            if byte & 0x80 == 0:
                break
            shift += 7
            if shift > 32:
                raise ValueError("uleb128 overflow")
        return value

    def deserialize_bytes(self) -> bytes:
        length = self.deserialize_uleb128_as_u32()
        return self._take(length)

    def deserialize_fixed_bytes(self, length: int) -> bytes:
        return self._take(length)

    def deserialize_str(self) -> str:
        return self.deserialize_bytes().decode("utf-8")


def serialize_vector(serializer: Serializer, items: list) -> None:  # type: ignore[type-arg]
    """Mirrors Serializer.serializeVector: uleb128 length prefix, then each
    item's own .serialize(serializer)."""
    serializer.serialize_u32_as_uleb128(len(items))
    for item in items:
        item.serialize(serializer)


def deserialize_vector(deserializer: Deserializer, cls: type) -> list:  # type: ignore[type-arg]
    """Mirrors Deserializer.deserializeVector(cls): uleb128 length prefix,
    then cls.deserialize(deserializer) called that many times (plain,
    non-Result-wrapped deserialize, matching cls's own convention)."""
    length = deserializer.deserialize_uleb128_as_u32()
    return [cls.deserialize(deserializer) for _ in range(length)]


def serialize_option(serializer: Serializer, value: object, fixed_len: int | None = None) -> None:
    """Mirrors Serializer.serializeOption: bool-tagged optional value. `value`
    may be None, a str, bytes, or an object with .serialize(serializer)."""
    has_value = value is not None
    serializer.serialize_bool(has_value)
    if not has_value:
        return
    if isinstance(value, str):
        serializer.serialize_str(value)
    elif isinstance(value, (bytes, bytearray)):
        if fixed_len is not None:
            serializer.serialize_fixed_bytes(bytes(value))
        else:
            serializer.serialize_bytes(bytes(value))
    else:
        value.serialize(serializer)  # type: ignore[attr-defined]


def deserialize_option_str(deserializer: Deserializer) -> str | None:
    if not deserializer.deserialize_bool():
        return None
    return deserializer.deserialize_str()


def deserialize_option_bytes(deserializer: Deserializer) -> bytes | None:
    if not deserializer.deserialize_bool():
        return None
    return deserializer.deserialize_bytes()


def deserialize_option_fixed_bytes(deserializer: Deserializer, length: int) -> bytes | None:
    if not deserializer.deserialize_bool():
        return None
    return deserializer.deserialize_fixed_bytes(length)


def deserialize_option(deserializer: Deserializer, cls: type) -> object | None:  # type: ignore[type-arg]
    if not deserializer.deserialize_bool():
        return None
    return cls.deserialize(deserializer)


def serialize_account_address(serializer: Serializer, address: object) -> None:
    """Write an aptos_sdk.account_address.AccountAddress's raw 32 bytes.

    AccountAddress.serialize() is hardwired to aptos_sdk's own bcs.Serializer
    (it calls .fixed_bytes(), a method our Serializer names
    serialize_fixed_bytes), so it cannot be used directly with this module's
    Serializer. This adapter bypasses that method and writes the raw bytes,
    which is byte-identical to what AccountAddress.serialize() would emit
    (BCS fixed-size 32-byte array, no length prefix).
    """
    serializer.serialize_fixed_bytes(address.address)  # type: ignore[attr-defined]


def deserialize_account_address(deserializer: Deserializer):  # type: ignore[no-untyped-def]
    """Read 32 raw bytes and wrap them in an AccountAddress.

    Counterpart to serialize_account_address; see its docstring for why a
    direct AccountAddress.deserialize(deserializer) call does not work here.
    """
    from aptos_sdk.account_address import AccountAddress

    return AccountAddress(deserializer.deserialize_fixed_bytes(AccountAddress.LENGTH))
