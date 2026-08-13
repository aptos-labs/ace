# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Result[T]: mirrors src/result.ts. Wraps a closure that either returns a value
or raises, capturing success/error plus an `extra` context dict (and, if
requested, execution time in ms) instead of letting exceptions propagate.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Generic, TypeVar

T = TypeVar("T")


class Result(Generic[T]):
    def __init__(
        self,
        is_ok: bool,
        ok_value: T | None = None,
        err_value: Any = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        self.is_ok = is_ok
        self.ok_value = ok_value
        self.err_value = err_value
        self.extra = extra

    @staticmethod
    def Ok(value: T, extra: dict[str, Any] | None = None) -> "Result[T]":
        return Result(is_ok=True, ok_value=value, extra=extra)

    @staticmethod
    def Err(error: Any, extra: dict[str, Any] | None = None) -> "Result[Any]":
        return Result(is_ok=False, err_value=error, extra=extra)

    @staticmethod
    def capture(
        task: Callable[[dict[str, Any]], T],
        records_execution_time_ms: bool = False,
    ) -> "Result[T]":
        extra: dict[str, Any] = {}
        start = time.perf_counter()
        try:
            ok_value = task(extra)
        except Exception as caught:  # noqa: BLE001 - mirror TS catch-all
            if records_execution_time_ms:
                extra["_sdk_execution_time_ms"] = (time.perf_counter() - start) * 1000
            return Result.Err(caught, extra)
        else:
            if records_execution_time_ms:
                extra["_sdk_execution_time_ms"] = (time.perf_counter() - start) * 1000
            return Result.Ok(ok_value, extra)

    def unwrap_or_throw(self, to_throw: Any) -> T:
        if not self.is_ok:
            raise to_throw
        return self.ok_value  # type: ignore[return-value]

    def unwrap_err_or_throw(self, to_throw: Any) -> Any:
        if self.is_ok:
            raise to_throw
        return self.err_value
