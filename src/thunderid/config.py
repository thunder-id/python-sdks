# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Immutable client configuration and URL trust boundaries."""

from __future__ import annotations

import ipaddress
import math
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote, urlsplit

from .errors import ThunderIDRuntimeError

if TYPE_CHECKING:
    from .storage import Storage


def invalid() -> ThunderIDRuntimeError:
    return ThunderIDRuntimeError("INVALID_CONFIG", "Invalid ThunderID configuration.")


def freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise invalid()
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze(item) for item in value)
    if isinstance(value, set):
        return frozenset(freeze(item) for item in value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and math.isfinite(value):
        return value
    raise invalid()


def normalize_scopes(scopes: str | Sequence[str]) -> tuple[str, ...]:
    values = scopes.split() if isinstance(scopes, str) else scopes
    if not isinstance(values, Sequence) or any(
        not isinstance(item, str)
        or not item
        or any(c.isspace() for c in item)
        or any(ord(c) < 33 or ord(c) > 126 or c in '\\"' for c in item)
        for item in values
    ):
        raise invalid()
    return tuple(dict.fromkeys(values))


def _url(url: str) -> tuple[str, str, int, str, bool]:
    try:
        if not isinstance(url, str) or any(ord(c) <= 32 for c in url) or "\\" in url:
            raise ValueError
        parsed = urlsplit(url)
        if (
            parsed.scheme not in ("https", "http")
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            raise ValueError
        host = parsed.hostname.lower()
        try:
            loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            loopback = host == "localhost"
        path = unquote(parsed.path)
        if "\\" in path or "%" in path or any(part in (".", "..") for part in path.split("/")):
            raise ValueError
        return (
            parsed.scheme,
            host,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            path,
            loopback,
        )
    except (ValueError, TypeError):
        raise invalid() from None


@dataclass(frozen=True)
class TokenRequestOptions:
    auth_method: str = "none"
    private_key: str | None = field(default=None, repr=False)
    private_key_id: str | None = None
    private_key_algorithm: str = "RS256"


@dataclass(frozen=True)
class HttpOptions:
    timeout: float = 30.0
    verify: ssl.SSLContext | str | bool = True
    max_response_bytes: int = 1048576


@dataclass(frozen=True)
class TokenValidationOptions:
    clock_tolerance: float = 30.0
    algorithms: tuple[str, ...] = (
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "EdDSA",
    )
    jwks_cache_ttl: float = 300.0
    jwks_refetch_interval: float = 30.0

    def __post_init__(self) -> None:
        object.__setattr__(self, "algorithms", tuple(self.algorithms))


@dataclass(frozen=True)
class TokenLifecycleOptions:
    refresh_buffer: float = 30.0


@dataclass(frozen=True)
class ThunderIDConfig:
    base_url: str
    client_id: str | None = None
    client_secret: str | None = field(default=None, repr=False)
    application_id: str | None = None
    mode: str = "redirect"
    grant_type: str = "authorization_code"
    instance_id: int | None = None
    after_sign_in_url: str | None = None
    scopes: tuple[str, ...] | str = ("openid",)
    endpoints: Mapping[str, str] = field(default_factory=dict)
    allowed_external_urls: tuple[str, ...] = ()
    discovery: bool = True
    storage: Storage | None = field(default=None, repr=False)
    token_request: TokenRequestOptions = field(default_factory=TokenRequestOptions)
    http: HttpOptions = field(default_factory=HttpOptions)
    token_validation: TokenValidationOptions = field(default_factory=TokenValidationOptions)
    token_lifecycle: TokenLifecycleOptions = field(default_factory=TokenLifecycleOptions)
    sign_in_options: Mapping[str, Any] = field(default_factory=dict)
    sign_up_options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if any(
            not isinstance(value, Mapping)
            for value in (self.endpoints, self.sign_in_options, self.sign_up_options)
        ):
            raise invalid()
        if not isinstance(self.allowed_external_urls, (list, tuple)):
            raise invalid()
        object.__setattr__(self, "scopes", normalize_scopes(self.scopes))
        for name in ("endpoints", "sign_in_options", "sign_up_options"):
            object.__setattr__(self, name, freeze(getattr(self, name)))
        object.__setattr__(self, "allowed_external_urls", tuple(self.allowed_external_urls))

    def validate(self) -> None:
        if (
            not isinstance(self.token_request, TokenRequestOptions)
            or not isinstance(self.http, HttpOptions)
            or not isinstance(self.token_validation, TokenValidationOptions)
            or not isinstance(self.token_lifecycle, TokenLifecycleOptions)
        ):
            raise invalid()
        if self.instance_id is not None and (
            isinstance(self.instance_id, bool) or not isinstance(self.instance_id, int)
        ):
            raise invalid()
        scheme, _, _, _, loopback = _url(self.base_url)
        if urlsplit(self.base_url).query or (
            scheme != "https" and (not loopback or self.mode == "embedded")
        ):
            raise invalid()
        if self.mode not in ("redirect", "embedded") or self.grant_type not in (
            "authorization_code",
            "client_credentials",
        ):
            raise invalid()
        if (self.mode == "redirect" and not self.client_id) or (
            self.mode == "embedded" and not self.application_id
        ):
            raise invalid()
        if not isinstance(self.discovery, bool):
            raise invalid()
        for value in (self.client_id, self.application_id, self.client_secret):
            if value is not None and (not isinstance(value, str) or not value):
                raise invalid()
        for url in self.allowed_external_urls:
            if _url(url)[0] != "https" or urlsplit(url).query:
                raise invalid()
        known_endpoints = {
            "authorization_endpoint",
            "token_endpoint",
            "revocation_endpoint",
            "jwks_uri",
            "userinfo_endpoint",
            "flow",
            "user_profile",
            "user_schema",
            "backchannel_authentication_endpoint",
        }
        if not set(self.endpoints) <= known_endpoints:
            raise invalid()
        for url in self.endpoints.values():
            self.check_endpoint(url)
        if self.after_sign_in_url is not None:
            _url(self.after_sign_in_url)
        opts = self.http
        if isinstance(opts.verify, ssl.SSLContext) and (
            not opts.verify.check_hostname or opts.verify.verify_mode != ssl.CERT_REQUIRED
        ):
            raise invalid()
        if not isinstance(opts.max_response_bytes, int) or isinstance(
            opts.max_response_bytes, bool
        ):
            raise invalid()
        if opts.verify is False or (
            opts.verify is not True and not isinstance(opts.verify, (str, ssl.SSLContext))
        ):
            raise invalid()
        for duration in (
            opts.timeout,
            self.token_validation.clock_tolerance,
            self.token_validation.jwks_cache_ttl,
            self.token_validation.jwks_refetch_interval,
            self.token_lifecycle.refresh_buffer,
        ):
            if (
                isinstance(duration, bool)
                or not isinstance(duration, (float, int))
                or not math.isfinite(duration)
                or duration < 0
            ):
                raise invalid()
        if (
            opts.timeout <= 0
            or self.token_validation.jwks_cache_ttl <= 0
            or self.token_validation.jwks_refetch_interval <= 0
            or not 1 <= opts.max_response_bytes <= 16777216
        ):
            raise invalid()
        allowed = set(TokenValidationOptions().algorithms)
        if (
            not self.token_validation.algorithms
            or not set(self.token_validation.algorithms) <= allowed
        ):
            raise invalid()
        auth = self.token_request
        if auth.auth_method not in (
            "none",
            "client_secret_basic",
            "client_secret_post",
            "private_key_jwt",
        ):
            raise invalid()
        if auth.auth_method.startswith("client_secret_") and (
            not self.client_id or not self.client_secret
        ):
            raise invalid()
        if self.client_secret and auth.auth_method == "none":
            raise invalid()
        if auth.auth_method == "private_key_jwt" and (
            not self.client_id or not auth.private_key or auth.private_key_algorithm not in allowed
        ):
            raise invalid()

    def check_endpoint(self, url: str) -> None:
        target = _url(url)
        base = _url(self.base_url)
        if target[0] != "https" and not (
            base[0] == "http" and base[4] and target[4] and self.mode != "embedded"
        ):
            raise invalid()
        if target[:3] == base[:3]:
            return
        for allowed in self.allowed_external_urls:
            parsed = _url(allowed)
            prefix = parsed[3].rstrip("/")
            if target[:3] == parsed[:3] and (
                target[3] == prefix or target[3].startswith(prefix + "/")
            ):
                return
        raise ThunderIDRuntimeError(
            "UNTRUSTED_ENDPOINT", "The endpoint is outside the configured trust boundary."
        )
