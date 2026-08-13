# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Small HTTP helpers shared by worker-facing SDK modules."""

from __future__ import annotations

from urllib.error import HTTPError
from urllib.request import Request, urlopen


def post_hex(endpoint: str, body_hex: str, timeout: float) -> str:
    request = Request(endpoint, data=body_hex.encode("utf-8"), method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", 200)
            body = response.read().decode("utf-8", errors="replace").strip()
    except HTTPError as err:
        body = err.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"HTTP {err.code}: {body[:120]}") from err
    if status < 200 or status >= 300:
        raise RuntimeError(f"HTTP {status}: {body[:120]}")
    return body
