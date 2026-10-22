# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Credential-safe response models."""

from __future__ import annotations

import math
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .errors import ThunderIDRuntimeError


@dataclass(frozen=True)
class TokenResponse:
    access_token: str = field(repr=False)
    token_type: str = "Bearer"
    expires_in: float | None = None
    refresh_token: str | None = field(default=None, repr=False)
    id_token: str | None = field(default=None, repr=False)
    scope: str | None = None
    issued_token_type: str | None = None
    expires_at: float | None = None

    def __post_init__(self) -> None:
        for value in (self.access_token, self.token_type):
            if not isinstance(value, str) or not value:
                raise ThunderIDRuntimeError("INVALID_RESPONSE", "The token response is invalid.")
        if self.token_type.lower() != "bearer":
            raise ThunderIDRuntimeError("INVALID_RESPONSE", "The token response is invalid.")
        for optional in (self.refresh_token, self.id_token, self.scope, self.issued_token_type):
            if optional is not None and (not isinstance(optional, str) or not optional):
                raise ThunderIDRuntimeError("INVALID_RESPONSE", "The token response is invalid.")
        for expiry in (self.expires_in, self.expires_at):
            if expiry is not None and (
                isinstance(expiry, bool)
                or not isinstance(expiry, (int, float))
                or not math.isfinite(expiry)
                or expiry < 0
            ):
                raise ThunderIDRuntimeError("INVALID_RESPONSE", "The token lifetime is invalid.")

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> TokenResponse:
        def fail() -> ThunderIDRuntimeError:
            return ThunderIDRuntimeError("INVALID_RESPONSE", "The token response is invalid.")

        if (
            not isinstance(data, Mapping)
            or not isinstance(data.get("access_token"), str)
            or not data["access_token"]
        ):
            raise fail()
        for key in ("token_type", "refresh_token", "id_token", "scope", "issued_token_type"):
            if key in data and (not isinstance(data[key], str) or not data[key]):
                raise fail()
        if data.get("token_type", "Bearer").lower() != "bearer":
            raise fail()
        expiry = data.get("expires_in")
        if expiry is not None and (
            isinstance(expiry, bool)
            or not isinstance(expiry, (int, float))
            or not math.isfinite(expiry)
            or expiry < 0
        ):
            raise fail()
        return cls(
            access_token=data["access_token"],
            token_type="Bearer",
            expires_in=expiry,
            refresh_token=data.get("refresh_token"),
            id_token=data.get("id_token"),
            scope=data.get("scope"),
            issued_token_type=data.get("issued_token_type"),
            expires_at=time.time() + expiry if expiry is not None else None,
        )


@dataclass(frozen=True)
class Session:
    tokens: TokenResponse = field(repr=False)
    user: dict[str, Any] | None = field(default=None, repr=False)
    context_id: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class AuthorizationRequest:
    url: str = field(repr=False)
    state: str = field(repr=False)


@dataclass(frozen=True)
class FlowResult:
    flow_id: str
    flow_status: str
    data: dict[str, Any] = field(repr=False)
    assertion: str | None = field(default=None, repr=False)

    @property
    def execution_id(self) -> str:
        return self.flow_id


@dataclass(frozen=True)
class BackchannelAuthenticationRequest:
    auth_req_id: str = field(repr=False)
    expires_in: float
    interval: float
    expires_at: float
    resource: str | None = None


@dataclass(frozen=True)
class BackchannelAuthenticationResult:
    status: str
    tokens: TokenResponse | None = field(default=None, repr=False)


@dataclass(frozen=True)
class TokenExchangeAuthorization:
    subject_token: str = field(repr=False)
    actor_token: str | None = field(default=None, repr=False)
    subject_token_type: str = "urn:ietf:params:oauth:token-type:jwt"
    actor_token_type: str = "urn:ietf:params:oauth:token-type:jwt"
