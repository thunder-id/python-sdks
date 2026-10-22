# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Bounded HTTP with no automatic retries or redirects."""

from __future__ import annotations

import json as json_module
import ssl
from collections.abc import Mapping
from http import HTTPStatus
from typing import Any

import httpx

from .config import ThunderIDConfig
from .errors import ThunderIDAPIError, ThunderIDRuntimeError

_OAUTH_ERRORS = {
    "invalid_request",
    "invalid_client",
    "invalid_grant",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
    "authorization_pending",
    "slow_down",
    "access_denied",
    "expired_token",
    "invalid_target",
    "temporarily_unavailable",
    "server_error",
}


class _CallerOwnedTransport(httpx.AsyncBaseTransport):
    def __init__(self, transport: httpx.AsyncBaseTransport) -> None:
        self._transport = transport

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self._transport.handle_async_request(request)

    async def aclose(self) -> None:
        # The caller controls the lifetime of an injected transport.
        pass


class Transport:
    def __init__(
        self, config: ThunderIDConfig, *, transport: httpx.AsyncBaseTransport | None = None
    ) -> None:
        self._config = config
        config.validate()
        verify = config.http.verify
        if isinstance(verify, str):
            try:
                verify = ssl.create_default_context(cafile=verify)
            except (OSError, ssl.SSLError):
                raise ThunderIDRuntimeError(
                    "INVALID_CONFIG", "The TLS trust configuration is invalid."
                ) from None
        self._client = httpx.AsyncClient(
            transport=_CallerOwnedTransport(transport) if transport is not None else None,
            timeout=config.http.timeout,
            verify=verify,
            follow_redirects=False,
            trust_env=False,
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        data: Mapping[str, Any] | None = None,
        json: Any = None,
        headers: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        self._config.check_endpoint(url)
        try:
            async with self._client.stream(
                method, url, data=data, json=json, headers=headers
            ) as response:
                body = bytearray()
                async for chunk in response.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > self._config.http.max_response_bytes:
                        raise ThunderIDRuntimeError(
                            "RESPONSE_TOO_LARGE", "The server response exceeds the size limit."
                        )
                if 300 <= response.status_code < 400:
                    raise ThunderIDRuntimeError("REDIRECT_REFUSED", "HTTP redirects are refused.")
                payload: Any = {}
                if body:
                    try:
                        payload = json_module.loads(body)
                    except (ValueError, UnicodeDecodeError):
                        if response.is_success:
                            raise ThunderIDRuntimeError(
                                "INVALID_RESPONSE", "The server response is invalid."
                            ) from None
                if not response.is_success:
                    code = payload.get("error") if isinstance(payload, dict) else None
                    safe_code = (
                        code.upper()
                        if isinstance(code, str) and code in _OAUTH_ERRORS
                        else "API_ERROR"
                    )
                    try:
                        phrase = HTTPStatus(response.status_code).phrase
                    except ValueError:
                        phrase = "HTTP error"
                    raise ThunderIDAPIError(
                        safe_code, "The server rejected the request.", response.status_code, phrase
                    )
                if not isinstance(payload, dict):
                    raise ThunderIDRuntimeError(
                        "INVALID_RESPONSE", "The server response is invalid."
                    )
                return payload
        except httpx.TimeoutException:
            raise ThunderIDRuntimeError("REQUEST_TIMEOUT", "The request timed out.") from None
        except httpx.HTTPError:
            raise ThunderIDRuntimeError(
                "NETWORK_ERROR", "The request could not be completed."
            ) from None

    async def close(self) -> None:
        await self._client.aclose()
