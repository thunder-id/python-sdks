# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Asymmetric JWT verification and confidential client authentication."""

from __future__ import annotations

import asyncio
import base64
import math
import secrets
import time
from typing import Any
from urllib.parse import quote_plus

import jwt

from .config import ThunderIDConfig
from .errors import ThunderIDRuntimeError
from .transport import Transport


def build_client_auth(config: ThunderIDConfig) -> tuple[dict[str, str], dict[str, str]]:
    method = config.token_request.auth_method
    data: dict[str, str] = {}
    headers: dict[str, str] = {}
    if config.client_id:
        data["client_id"] = config.client_id
    if method == "client_secret_basic":
        credential = (
            f"{quote_plus(config.client_id or '')}:{quote_plus(config.client_secret or '')}"
        )
        headers["Authorization"] = "Basic " + base64.b64encode(credential.encode()).decode()
        data.pop("client_id", None)
    elif method == "client_secret_post":
        data["client_secret"] = config.client_secret or ""
    elif method == "private_key_jwt":
        now = int(time.time())
        try:
            assertion = jwt.encode(
                {
                    "iss": config.client_id,
                    "sub": config.client_id,
                    "aud": config.base_url,
                    "iat": now,
                    "exp": now + 60,
                    "jti": secrets.token_urlsafe(32),
                },
                config.token_request.private_key or "",
                algorithm=config.token_request.private_key_algorithm,
                headers={"kid": config.token_request.private_key_id}
                if config.token_request.private_key_id
                else None,
            )
        except (ValueError, TypeError, jwt.PyJWTError):
            raise ThunderIDRuntimeError(
                "CLIENT_AUTH_ERROR", "The client assertion could not be created."
            ) from None
        data.update(
            client_assertion_type="urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            client_assertion=assertion,
        )
    return data, headers


class JWTValidator:
    def __init__(self, config: ThunderIDConfig, transport: Transport, jwks_uri: str) -> None:
        config.check_endpoint(jwks_uri)
        self._config = config
        self._transport = transport
        self._jwks_uri = jwks_uri
        self._keys: list[dict[str, Any]] = []
        self._fetched_at: float | None = None
        self._last_refetch: float | None = None
        self._lock = asyncio.Lock()

    async def _fetch(self, *, forced: bool) -> bool:
        async with self._lock:
            now = time.monotonic()
            options = self._config.token_validation
            if self._fetched_at is not None:
                age = now - self._fetched_at
                if not forced and age < options.jwks_cache_ttl:
                    return False
            if forced:
                if (
                    self._last_refetch is not None
                    and now - self._last_refetch < options.jwks_refetch_interval
                ):
                    return False
                self._last_refetch = now
            # Rate-limit even malformed or failing fetches.
            self._fetched_at = now
            payload = await self._transport.request("GET", self._jwks_uri)
            keys = payload.get("keys")
            if (
                not isinstance(keys, list)
                or not 1 <= len(keys) <= 100
                or any(not isinstance(key, dict) for key in keys)
            ):
                raise self._invalid()
            self._keys = keys
            return True

    @staticmethod
    def _invalid() -> ThunderIDRuntimeError:
        return ThunderIDRuntimeError(
            "INVALID_ID_TOKEN", "The identity token could not be verified."
        )

    def _decode(
        self, token: str, header: dict[str, Any], nonce: str | None, *, allow_expired: bool = False
    ) -> dict[str, Any]:
        algorithm = header["alg"]
        candidates = [
            key
            for key in self._keys
            if (header.get("kid") is None or key.get("kid") == header["kid"])
            and key.get("use", "sig") == "sig"
            and key.get("alg", algorithm) == algorithm
            and ("key_ops" not in key or "verify" in key["key_ops"])
        ]
        if len(candidates) != 1:
            raise jwt.InvalidKeyError()
        key_data = candidates[0]
        expected_type = (
            "RSA"
            if algorithm.startswith(("RS", "PS"))
            else "EC"
            if algorithm.startswith("ES")
            else "OKP"
        )
        if key_data.get("kty") != expected_type or "d" in key_data:
            raise jwt.InvalidKeyError()
        key = jwt.PyJWK.from_dict(key_data, algorithm=algorithm).key
        if expected_type == "RSA" and key.key_size < 2048:
            raise jwt.InvalidKeyError()
        claims: dict[str, Any] = jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            issuer=self._config.base_url,
            audience=self._config.client_id,
            leeway=self._config.token_validation.clock_tolerance,
            options={
                "require": ["iss", "aud", "exp", "iat", "sub"],
                "verify_exp": not allow_expired,
            },
        )
        for name in ("iat", "exp"):
            if (
                isinstance(claims[name], bool)
                or not isinstance(claims[name], (int, float))
                or not math.isfinite(claims[name])
            ):
                raise jwt.InvalidTokenError()
        if not isinstance(claims["sub"], str) or not claims["sub"]:
            raise jwt.InvalidTokenError()
        audience = claims["aud"]
        if (
            isinstance(audience, list)
            and len(audience) > 1
            and claims.get("azp") != self._config.client_id
        ):
            raise jwt.InvalidTokenError()
        if "azp" in claims and claims["azp"] != self._config.client_id:
            raise jwt.InvalidTokenError()
        if nonce is not None and (
            not isinstance(claims.get("nonce"), str)
            or not secrets.compare_digest(claims["nonce"], nonce)
        ):
            raise jwt.InvalidTokenError()
        return claims

    async def validate(self, token: str, *, nonce: str | None = None) -> dict[str, Any]:
        return await self._validate(token, nonce=nonce)

    async def is_authentic_expired(self, token: str) -> bool:
        """Authenticate a stored token before deciding to discard its expired session.

        This method never returns claims and cannot accept an expired token as a session.
        """
        claims = await self._validate(token, nonce=None, allow_expired=True)
        return bool(claims["exp"] <= time.time() - self._config.token_validation.clock_tolerance)

    async def _validate(
        self, token: str, *, nonce: str | None, allow_expired: bool = False
    ) -> dict[str, Any]:
        try:
            if (
                not isinstance(token, str)
                or not 1 <= len(token) <= 65536
                or not self._config.client_id
            ):
                raise self._invalid()
            header = jwt.get_unverified_header(token)
            if (
                header.get("alg") not in self._config.token_validation.algorithms
                or header.get("crit")
                or "jku" in header
                or "x5u" in header
            ):
                raise self._invalid()
            if "kid" in header and not isinstance(header["kid"], str):
                raise self._invalid()
            await self._fetch(forced=False)
            try:
                return self._decode(token, header, nonce, allow_expired=allow_expired)
            except (jwt.InvalidSignatureError, jwt.InvalidKeyError):
                if await self._fetch(forced=True):
                    return self._decode(token, header, nonce, allow_expired=allow_expired)
                raise
        except ThunderIDRuntimeError:
            raise
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, OverflowError):
            raise self._invalid() from None
