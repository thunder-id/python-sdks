# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Isolated machine, delegation, and poll-mode backchannel operations."""

from __future__ import annotations

import asyncio
import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import urlsplit
from weakref import ReferenceType, ref

from .errors import ThunderIDAPIError, ThunderIDRuntimeError
from .models import (
    BackchannelAuthenticationRequest,
    BackchannelAuthenticationResult,
    Session,
    TokenExchangeAuthorization,
    TokenResponse,
)
from .security import build_client_auth

if TYPE_CHECKING:
    from .config import ThunderIDConfig
    from .security import JWTValidator
    from .storage import Storage
    from .transport import Transport


def _invalid() -> ThunderIDRuntimeError:
    return ThunderIDRuntimeError("INVALID_REQUEST", "Invalid delegation request.")


def _scope_string(scopes: tuple[str, ...] | list[str] | None) -> str:
    if scopes is None:
        return ""
    if isinstance(scopes, str) or not isinstance(scopes, (tuple, list)):
        raise _invalid()
    if any(
        not isinstance(s, str) or not s or any(ord(c) < 33 or ord(c) > 126 or c in '\\"' for c in s)
        for s in scopes
    ):
        raise _invalid()
    return " ".join(sorted(set(scopes)))


def _target(resource: str | None) -> dict[str, str]:
    if resource is None:
        return {}
    if not isinstance(resource, str) or not resource or any(c.isspace() for c in resource):
        raise _invalid()
    try:
        parsed = urlsplit(resource)
        if not parsed.scheme or parsed.fragment:
            raise _invalid()
    except ValueError:
        raise _invalid() from None
    return {"resource": resource}


@dataclass
class _PollState:
    request: BackchannelAuthenticationRequest
    deadline: float
    scopes: str
    interval: float
    next_poll: float
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    terminal: bool = False


class DelegationMixin:
    """Methods never replace the client's primary session."""

    _config: ThunderIDConfig
    _transport: Transport
    _validator: JWTValidator | None
    _session: Session | None
    _session_authorization_root: ReferenceType[Session] | None
    _context_id: str
    _storage: Storage

    def _require_initialized(self) -> None:
        raise NotImplementedError

    def _endpoint(self, name: str) -> str:
        raise NotImplementedError

    async def _token_request(self, data: dict[str, str]) -> TokenResponse:
        raise NotImplementedError

    async def _get_session_tokens(self, *, authorization: Session | None = None) -> TokenResponse:
        raise NotImplementedError

    def _delegation_state(self) -> None:
        if not hasattr(self, "_agent_cache"):
            self._delegation_epoch = 0
            self._agent_cache: dict[tuple[str | None, str], tuple[str, float]] = {}
            self._agent_storage_keys: set[str] = set()
            self._agent_lock = asyncio.Lock()
            self._agent_storage_lock = asyncio.Lock()
            self._backchannel_requests: dict[int, _PollState] = {}
            self._backchannel_tokens: dict[
                int, tuple[ReferenceType[TokenResponse], str | None, str]
            ] = {}

    def _clear_delegation_state(self) -> None:
        self._delegation_state()
        self._delegation_epoch += 1
        self._agent_cache.clear()
        for state in self._backchannel_requests.values():
            state.terminal = True
        self._backchannel_requests.clear()
        self._backchannel_tokens.clear()

    def _check_delegation_epoch(self, epoch: int) -> None:
        if epoch != self._delegation_epoch:
            raise ThunderIDRuntimeError(
                "AUTHORIZATION_CANCELLED", "Authorization context has ended."
            )

    async def get_agent_token(
        self, resource: str | None = None, scopes: tuple[str, ...] | list[str] | None = None
    ) -> TokenResponse:
        self._require_initialized()
        data = {"grant_type": "client_credentials", **_target(resource)}
        scope = _scope_string(scopes)
        if scope:
            data["scope"] = scope
        self._delegation_state()
        key = (resource, scope)
        epoch = self._delegation_epoch
        async with self._agent_lock:
            self._check_delegation_epoch(epoch)
            async with self._agent_storage_lock:
                self._check_delegation_epoch(epoch)
                cached = self._agent_cache.get(key)
                if cached is not None:
                    storage_key, expiry = cached
                    if expiry > time.time() + 30:
                        stored = await self._storage.read(storage_key)
                        self._check_delegation_epoch(epoch)
                        if (
                            stored is not None
                            and stored.tokens.expires_at == expiry
                            and expiry > time.time() + 30
                        ):
                            return stored.tokens
                    await self._storage.clear(storage_key)
                    self._agent_storage_keys.discard(storage_key)
                    self._agent_cache.pop(key, None)
            token = await self._token_request(data)
            self._check_delegation_epoch(epoch)
            # Unknown or short lifetimes are returned directly, without retaining credentials.
            if token.expires_at is None or token.expires_at <= time.time() + 30:
                return token
            storage_key = (
                "agent:"
                + hashlib.sha256(
                    json.dumps(
                        [
                            self._config.base_url,
                            self._config.client_id,
                            self._config.mode,
                            self._config.instance_id,
                            self._context_id,
                            epoch,
                            resource,
                            scope,
                        ]
                    ).encode()
                ).hexdigest()
            )
            async with self._agent_storage_lock:
                self._check_delegation_epoch(epoch)
                self._agent_storage_keys.add(storage_key)
                write = asyncio.create_task(self._storage.write(storage_key, Session(token)))
                try:
                    await asyncio.shield(write)
                    self._check_delegation_epoch(epoch)
                except BaseException:
                    # Finish an atomic adapter write before deletion, including canceled writes.
                    try:
                        await write
                    finally:
                        await self._storage.clear(storage_key)
                        self._agent_storage_keys.discard(storage_key)
                    raise
                self._agent_cache[key] = (storage_key, token.expires_at)
                return token

    async def _clear_agent_storage(self) -> None:
        self._delegation_state()
        if not self._agent_storage_keys:
            return
        async with self._agent_storage_lock:
            first_error: Exception | None = None
            for key in tuple(self._agent_storage_keys):
                try:
                    await self._storage.clear(key)
                except Exception as exc:  # noqa: BLE001 - attempt every key before reporting failure.
                    if first_error is None:
                        first_error = exc
                else:
                    self._agent_storage_keys.discard(key)
            if first_error is not None:
                raise first_error

    async def exchange_token(
        self,
        subject_token: str,
        *,
        subject_token_type: str = "urn:ietf:params:oauth:token-type:jwt",
        actor_token: str | None = None,
        actor_token_type: str = "urn:ietf:params:oauth:token-type:jwt",
        resource: str | None = None,
        scopes: tuple[str, ...] | list[str] | None = None,
        audience: str | None = None,
        requested_token_type: str | None = None,
    ) -> TokenResponse:
        self._require_initialized()
        if (
            not isinstance(subject_token, str)
            or not subject_token
            or not isinstance(subject_token_type, str)
            or not subject_token_type
        ):
            raise _invalid()
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": subject_token,
            "subject_token_type": subject_token_type,
            **_target(resource),
        }
        for name, value in (("audience", audience), ("requested_token_type", requested_token_type)):
            if value is not None:
                if not isinstance(value, str) or not value:
                    raise _invalid()
                data[name] = value
        if actor_token is not None:
            if (
                not isinstance(actor_token, str)
                or not actor_token
                or not isinstance(actor_token_type, str)
                or not actor_token_type
            ):
                raise _invalid()
            data.update(actor_token=actor_token, actor_token_type=actor_token_type)
        scope = _scope_string(scopes)
        if scope:
            data["scope"] = scope
        return await self._token_request(data)

    async def get_obo_token(
        self,
        *,
        authorization: Session | TokenResponse | TokenExchangeAuthorization,
        resource: str | None = None,
        scopes: tuple[str, ...] | list[str] | None = None,
    ) -> TokenResponse:
        self._require_initialized()
        if isinstance(authorization, Session):
            if resource is not None or scopes is not None:
                raise ThunderIDRuntimeError(
                    "INVALID_AUTHORIZATION",
                    "Changing the authorization target requires explicit token exchange.",
                )
            return await self._get_session_tokens(authorization=authorization)
        elif isinstance(authorization, TokenResponse):
            self._delegation_state()
            owned = self._backchannel_tokens.get(id(authorization))
            if (
                owned is None
                or owned[0]() is not authorization
                or (resource is not None and resource != owned[1])
                or (scopes is not None and _scope_string(scopes) != owned[2])
            ):
                raise ThunderIDRuntimeError(
                    "INVALID_AUTHORIZATION",
                    "Token does not match an owned backchannel authorization.",
                )
            tokens = authorization
        else:
            tokens = None
        if tokens is not None:
            if (
                tokens.expires_at is None
                or not math.isfinite(tokens.expires_at)
                or tokens.expires_at <= time.time()
            ):
                raise ThunderIDRuntimeError(
                    "TOKEN_EXPIRED", "Authorization has no known valid token lifetime."
                )
            return tokens
        if not isinstance(authorization, TokenExchangeAuthorization):
            raise _invalid()
        return await self.exchange_token(
            authorization.subject_token,
            subject_token_type=authorization.subject_token_type,
            actor_token=authorization.actor_token,
            actor_token_type=authorization.actor_token_type,
            resource=resource,
            scopes=scopes,
        )

    async def initiate_backchannel_authentication(
        self,
        *,
        login_hint: str | None = None,
        id_token_hint: str | None = None,
        resource: str | None = None,
        scopes: tuple[str, ...] | list[str] | None = None,
        binding_message: str | None = None,
        requested_expiry: int | None = None,
        acr_values: str | None = None,
    ) -> BackchannelAuthenticationRequest:
        self._require_initialized()
        if (login_hint is None) == (id_token_hint is None):
            raise _invalid()
        data = _target(resource)
        for name, value in (
            ("login_hint", login_hint),
            ("id_token_hint", id_token_hint),
            ("binding_message", binding_message),
            ("acr_values", acr_values),
        ):
            if value is not None:
                if not isinstance(value, str) or not value:
                    raise _invalid()
                data[name] = value
        default_scopes = self._config.scopes
        if isinstance(default_scopes, str):
            default_scopes = tuple(default_scopes.split())
        data["scope"] = _scope_string(scopes if scopes is not None else default_scopes)
        if "openid" not in data["scope"].split():
            raise _invalid()
        if requested_expiry is not None:
            if type(requested_expiry) is not int or requested_expiry <= 0:
                raise _invalid()
            data["requested_expiry"] = str(requested_expiry)
        self._delegation_state()
        epoch = self._delegation_epoch
        auth, headers = build_client_auth(self._config)
        body = await self._transport.request(
            "POST",
            self._endpoint("backchannel_authentication_endpoint"),
            data={**data, **auth},
            headers=headers,
        )
        self._check_delegation_epoch(epoch)
        req_id, expiry, interval = (
            body.get("auth_req_id"),
            body.get("expires_in"),
            body.get("interval", 5),
        )
        if (
            not isinstance(req_id, str)
            or not req_id
            or type(expiry) is not int
            or expiry <= 0
            or type(interval) is not int
            or interval <= 0
        ):
            raise ThunderIDRuntimeError(
                "INVALID_RESPONSE", "Invalid backchannel authentication response."
            )
        request = BackchannelAuthenticationRequest(
            auth_req_id=req_id,
            expires_in=expiry,
            interval=interval,
            expires_at=time.time() + expiry,
            resource=resource,
        )
        self._delegation_state()
        now = time.monotonic()
        self._backchannel_requests = {
            k: v
            for k, v in self._backchannel_requests.items()
            if v.deadline > now and not v.terminal
        }
        self._backchannel_requests[id(request)] = _PollState(
            request, now + expiry, data["scope"], interval, now + interval
        )
        return request

    def _owned_request(self, request: BackchannelAuthenticationRequest) -> _PollState:
        self._require_initialized()
        self._delegation_state()
        state = self._backchannel_requests.get(id(request))
        if state is None or state.request is not request or state.terminal:
            raise ThunderIDRuntimeError(
                "INVALID_AUTHORIZATION", "Backchannel request is not active in this client."
            )
        return state

    async def poll_backchannel_authentication(
        self, request: BackchannelAuthenticationRequest
    ) -> BackchannelAuthenticationResult:
        state = self._owned_request(request)
        try:
            return await self._poll_backchannel_authentication(request)
        except asyncio.CancelledError:
            state.terminal = True
            raise

    async def _poll_backchannel_authentication(
        self, request: BackchannelAuthenticationRequest
    ) -> BackchannelAuthenticationResult:
        state = self._owned_request(request)
        epoch = self._delegation_epoch
        async with state.lock:
            if state.terminal:
                raise ThunderIDRuntimeError(
                    "INVALID_AUTHORIZATION", "Backchannel request is no longer active."
                )
            delay = max(0.0, state.next_poll - time.monotonic())
            remaining = state.deadline - time.monotonic()
            if remaining <= delay:
                if remaining > 0:
                    await asyncio.sleep(remaining)
                state.terminal = True
                return BackchannelAuthenticationResult(status="expired_token")
            await asyncio.sleep(delay)
            self._check_delegation_epoch(epoch)
            state.next_poll = time.monotonic() + state.interval
            try:
                tokens = await asyncio.wait_for(
                    self._token_request(
                        {
                            "grant_type": "urn:openid:params:grant-type:ciba",
                            "auth_req_id": request.auth_req_id,
                            **_target(request.resource),
                        }
                    ),
                    timeout=max(0.0, state.deadline - time.monotonic()),
                )
            except TimeoutError:
                state.terminal = True
                return BackchannelAuthenticationResult(status="expired_token")
            except asyncio.CancelledError:
                state.terminal = True
                raise
            except ThunderIDAPIError as exc:
                self._check_delegation_epoch(epoch)
                status = exc.code.lower()
                if status == "slow_down":
                    state.interval += 5
                    state.next_poll = time.monotonic() + state.interval
                elif status != "authorization_pending":
                    state.terminal = True
                if status in {
                    "authorization_pending",
                    "slow_down",
                    "access_denied",
                    "expired_token",
                }:
                    return BackchannelAuthenticationResult(status=status)
                raise
            except ThunderIDRuntimeError:
                state.terminal = True
                raise
            self._check_delegation_epoch(epoch)
            state.terminal = True
            if tokens.id_token is not None:
                if self._validator is None:
                    raise ThunderIDRuntimeError(
                        "INVALID_ID_TOKEN", "ID token validation is unavailable."
                    )
                claims = await self._validator.validate(tokens.id_token)
                binding = claims.get("urn:openid:params:jwt:claim:auth_req_id")
                # Poll mode does not require the push-mode binding claim; enforce it when supplied.
                if binding is not None and binding != request.auth_req_id:
                    raise ThunderIDRuntimeError(
                        "INVALID_ID_TOKEN", "ID token request binding does not match."
                    )
            self._check_delegation_epoch(epoch)
            self._backchannel_tokens = {
                k: v
                for k, v in self._backchannel_tokens.items()
                if (owned_token := v[0]()) is not None
                and owned_token.expires_at is not None
                and owned_token.expires_at > time.time()
            }
            self._backchannel_tokens[id(tokens)] = (ref(tokens), request.resource, state.scopes)
            return BackchannelAuthenticationResult(status="success", tokens=tokens)

    async def await_backchannel_authentication(
        self, request: BackchannelAuthenticationRequest, timeout: float | None = None
    ) -> TokenResponse:
        state = self._owned_request(request)
        if timeout is not None and (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not math.isfinite(timeout)
            or timeout <= 0
        ):
            raise _invalid()

        async def wait() -> TokenResponse:
            while True:
                result = await self.poll_backchannel_authentication(request)
                if result.tokens is not None:
                    return result.tokens
                if result.status not in {"authorization_pending", "slow_down"}:
                    raise ThunderIDRuntimeError(
                        result.status.upper(), "Backchannel authentication did not complete."
                    )

        try:
            return await asyncio.wait_for(
                wait(),
                timeout=min(
                    timeout if timeout is not None else math.inf,
                    max(0.0, state.deadline - time.monotonic()),
                ),
            )
        except TimeoutError:
            state.terminal = True
            raise ThunderIDRuntimeError(
                "AUTHENTICATION_TIMEOUT", "Backchannel authentication timed out."
            ) from None
        except asyncio.CancelledError:
            state.terminal = True
            raise
