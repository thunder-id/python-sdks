# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Asynchronous ThunderID authentication client."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import secrets
import time
from dataclasses import replace
from typing import Any, Self
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit, urlunsplit
from weakref import ReferenceType, ref

import httpx

from .config import ThunderIDConfig
from .delegation import DelegationMixin
from .errors import ThunderIDRuntimeError
from .models import AuthorizationRequest, FlowResult, Session, TokenResponse
from .security import JWTValidator, build_client_auth
from .storage import KeyringStorage
from .transport import Transport

_DEFAULTS = {
    "authorization_endpoint": "/oauth2/authorize",
    "token_endpoint": "/oauth2/token",
    "revocation_endpoint": "/oauth2/revoke",
    "jwks_uri": "/oauth2/jwks",
    "userinfo_endpoint": "/oauth2/userinfo",
    "flow": "/flow/execute",
    "user_profile": "/users/me",
    "user_schema": "/users/me/meta",
}


def _error(code: str, message: str) -> ThunderIDRuntimeError:
    return ThunderIDRuntimeError(code, message)


class AsyncThunderIDClient(DelegationMixin):
    def __init__(
        self, config: ThunderIDConfig, *, transport: httpx.AsyncBaseTransport | None = None
    ):
        self._config = config
        self._http_transport = transport
        self._transport = Transport(config, transport=transport)
        self._session_lock = asyncio.Lock()
        self._initialize_lock = asyncio.Lock()
        self._initialized = False
        self._loading = False
        self._session: Session | None = None
        self._session_authorization_root: ReferenceType[Session] | None = None
        self._context_id = secrets.token_urlsafe(32)
        self._session_key = ""
        self._session_epoch = 0
        self._pending: dict[str, tuple[str, str, str, float]] = {}
        self._endpoints: dict[str, str] = {}
        self._validator: JWTValidator
        self._storage = config.storage if config.storage is not None else KeyringStorage()

    def _require_initialized(self) -> None:
        if not self._initialized:
            raise _error("NOT_INITIALIZED", "Initialize the client before calling this operation.")

    def _require_user_grant(self) -> None:
        self._require_initialized()
        if self._config.grant_type == "client_credentials":
            raise _error(
                "UNSUPPORTED_OPERATION", "This operation requires an interactive user grant."
            )

    def _endpoint(self, name: str) -> str:
        if name not in self._endpoints:
            raise _error("UNSUPPORTED_OPERATION", "The server does not advertise this operation.")
        return self._endpoints[name]

    async def initialize(self) -> bool:
        async with self._initialize_lock:
            if self._initialized:
                return True
            self._loading = True
            try:
                self._config.validate()
                base = self._config.base_url.rstrip("/")
                endpoints = {name: base + path for name, path in _DEFAULTS.items()}
                if self._config.discovery:
                    metadata = await self._transport.request(
                        "GET", base + "/.well-known/openid-configuration"
                    )
                    if metadata.get("issuer") != self._config.base_url:
                        raise _error(
                            "ISSUER_MISMATCH",
                            "Discovery issuer does not match the configured issuer.",
                        )
                    for name in _DEFAULTS:
                        if name in metadata:
                            self._config.check_endpoint(metadata[name])
                            endpoints[name] = metadata[name]
                    if "backchannel_authentication_endpoint" in metadata:
                        value = metadata["backchannel_authentication_endpoint"]
                        self._config.check_endpoint(value)
                        endpoints["backchannel_authentication_endpoint"] = value
                endpoints.update(self._config.endpoints)
                for endpoint in endpoints.values():
                    self._config.check_endpoint(endpoint)
                self._endpoints = endpoints
                self._validator = JWTValidator(self._config, self._transport, endpoints["jwks_uri"])
                namespace = [
                    self._config.base_url,
                    self._config.client_id,
                    self._config.application_id,
                    self._config.grant_type,
                    self._config.mode,
                    self._config.instance_id
                    if self._config.instance_id is not None
                    else self._context_id,
                ]
                self._session_key = hashlib.sha256(json.dumps(namespace).encode()).hexdigest()
                stored = await self._storage.read(self._session_key)
                if stored is not None:
                    stored = replace(stored, tokens=self._validate_session_tokens(stored))
                    stored_id_token = stored.tokens.id_token
                    if stored_id_token:
                        try:
                            verified_user = await self._validator.validate(stored_id_token)
                            stored = replace(stored, user=verified_user)
                        except ThunderIDRuntimeError as error:
                            if error.code != "INVALID_ID_TOKEN":
                                raise
                            if not stored.tokens.refresh_token:
                                if await self._validator.is_authentic_expired(stored_id_token):
                                    await self._storage.clear(self._session_key)
                                    self._session = None
                                    self._initialized = True
                                    return True
                                raise
                            # An expired or otherwise unverifiable identity is never restored.
                            # The server must establish a fresh identity using the refresh grant.
                            auth, headers = build_client_auth(self._config)
                            response = await self._transport.request(
                                "POST",
                                endpoints["token_endpoint"],
                                data={
                                    "grant_type": "refresh_token",
                                    "refresh_token": stored.tokens.refresh_token,
                                    **auth,
                                },
                                headers=headers,
                            )
                            fresh = TokenResponse.from_dict(response)
                            if not fresh.id_token:
                                raise _error(
                                    "INVALID_ID_TOKEN",
                                    "Restoring an identity requires a fresh ID token.",
                                )
                            user = await self._validator.validate(fresh.id_token)
                            if fresh.refresh_token is None:
                                fresh = replace(fresh, refresh_token=stored.tokens.refresh_token)
                            stored = Session(tokens=fresh, user=user)
                            await self._storage.write(self._session_key, stored)
                    self._session = replace(stored, context_id=None)
                self._initialized = True
                return True
            finally:
                self._loading = False

    async def re_initialize(self, **changes: Any) -> bool:
        self._require_initialized()
        immutable = {"mode", "grant_type", "client_id", "application_id", "instance_id"}
        if any(
            name in changes and changes[name] != getattr(self._config, name) for name in immutable
        ):
            raise _error("IMMUTABLE_CONFIG", "This configuration field requires a new client.")
        # Trust and persistence changes require a new client so an old session cannot cross contexts.
        if any(name in changes for name in ("base_url", "storage")):
            raise _error("IMMUTABLE_CONFIG", "This configuration field requires a new client.")
        try:
            candidate = replace(self._config, **changes)
        except TypeError:
            raise _error("INVALID_CONFIG", "Invalid ThunderID configuration.") from None
        candidate.validate()
        async with self._session_lock:
            previous = (
                self._config,
                self._transport,
                self._endpoints,
                self._validator,
                self._session,
            )
            self._config = candidate
            self._initialized = False
            self._transport = Transport(candidate, transport=self._http_transport)
            try:
                result = await self.initialize()
            except BaseException:
                await self._transport.close()
                (self._config, self._transport, self._endpoints, self._validator, self._session) = (
                    previous
                )
                self._initialized = True
                raise
            self._invalidate_authorizations()
            try:
                await self._clear_agent_storage()
            finally:
                await previous[1].close()
            return result

    def get_configuration(self) -> ThunderIDConfig:
        self._require_initialized()
        return self._config

    def is_loading(self) -> bool:
        return self._loading

    async def _token_request(self, data: dict[str, Any]) -> TokenResponse:
        self._require_initialized()
        auth, headers = build_client_auth(self._config)
        response = await self._transport.request(
            "POST", self._endpoint("token_endpoint"), data={**data, **auth}, headers=headers
        )
        tokens = TokenResponse.from_dict(response)
        if tokens.id_token:
            await self._validator.validate(tokens.id_token)
        return tokens

    async def _accept_tokens(
        self,
        tokens: TokenResponse,
        nonce: str | None = None,
        *,
        trusted_context: bool = True,
        preserve_authorization_root: bool = False,
        expected_epoch: int | None = None,
    ) -> Session:
        user = None
        if tokens.id_token:
            user = await self._validator.validate(tokens.id_token, nonce=nonce)
        elif nonce is not None:
            raise _error("INVALID_TOKEN", "An OpenID Connect response requires an ID token.")
        session = Session(
            tokens=tokens, user=user, context_id=self._context_id if trusted_context else None
        )
        if expected_epoch is not None:
            self._check_session_epoch(expected_epoch)
        await self._storage.write(self._session_key, session)
        if expected_epoch is not None:
            self._check_session_epoch(expected_epoch)
        self._session = session
        if not trusted_context:
            self._session_authorization_root = None
        elif not preserve_authorization_root:
            self._session_authorization_root = ref(session)
        return session

    async def sign_in(
        self,
        *,
        execution_id: str | None = None,
        action: str | None = None,
        inputs: dict[str, str] | None = None,
        challenge_token: str | None = None,
        flow_secret: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> AuthorizationRequest | FlowResult:
        self._require_user_grant()
        if self._config.mode == "embedded":
            return await self._flow(
                "AUTHENTICATION", execution_id, action, inputs, challenge_token, flow_secret
            )
        return self._authorize({**self._config.sign_in_options, **(options or {})})

    async def sign_up(
        self,
        *,
        execution_id: str | None = None,
        action: str | None = None,
        inputs: dict[str, str] | None = None,
        challenge_token: str | None = None,
        flow_secret: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> AuthorizationRequest | FlowResult:
        self._require_user_grant()
        if self._config.mode == "embedded":
            return await self._flow(
                "REGISTRATION", execution_id, action, inputs, challenge_token, flow_secret
            )
        raise _error(
            "UNSUPPORTED_OPERATION",
            "Redirect registration is not supported by the server. Use embedded registration.",
        )

    def _authorize(self, options: dict[str, Any]) -> AuthorizationRequest:
        redirect = self._config.after_sign_in_url
        if not redirect:
            raise _error(
                "INVALID_CONFIG", "A callback URL is required for redirect authentication."
            )
        if set(parse_qs(urlsplit(redirect).query, keep_blank_values=True)) & {
            "code",
            "state",
            "error",
            "error_description",
            "error_uri",
        }:
            raise _error(
                "INVALID_CONFIG", "The redirect URI contains reserved response parameters."
            )
        verifier, state, nonce = (secrets.token_urlsafe(32) for _ in range(3))
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        parameters = {
            **options,
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": redirect,
            "scope": " ".join(self._config.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        now = time.monotonic()
        self._pending = {key: value for key, value in self._pending.items() if now - value[3] < 600}
        if len(self._pending) >= 32:
            raise _error("AUTHENTICATION_IN_PROGRESS", "Too many pending authorization requests.")
        self._pending[state] = (verifier, nonce, redirect, now)
        endpoint_parts = urlsplit(self._endpoint("authorization_endpoint"))
        extra = [
            (key, value) for key, value in parse_qsl(endpoint_parts.query) if key not in parameters
        ]
        endpoint = urlunsplit(
            (
                endpoint_parts.scheme,
                endpoint_parts.netloc,
                endpoint_parts.path,
                urlencode(extra),
                "",
            )
        )
        return AuthorizationRequest(
            endpoint + ("&" if "?" in endpoint else "?") + urlencode(parameters), state
        )

    async def handle_redirect_callback(
        self,
        callback_url: str | None = None,
        *,
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
    ) -> Session:
        self._require_user_grant()
        epoch = self._session_epoch
        parsed = None
        query: dict[str, list[str]] = {}
        if callback_url is not None:
            if any(value is not None for value in (code, state, error)):
                raise _error(
                    "INVALID_CALLBACK", "Callback URL and parameters are mutually exclusive."
                )
            try:
                if (
                    not isinstance(callback_url, str)
                    or not callback_url
                    or len(callback_url) > 32768
                ):
                    raise ValueError
                parsed = urlsplit(callback_url)
                query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=64)
                if parsed.fragment or any(len(value) != 1 for value in query.values()):
                    raise ValueError
            except (ValueError, TypeError):
                raise _error("INVALID_CALLBACK", "Invalid authorization callback.") from None
            code = query["code"][0] if "code" in query else None
            state = query["state"][0] if "state" in query else None
            error = query["error"][0] if "error" in query else None
        if (code is None) == (error is None):
            raise _error(
                "INVALID_CALLBACK", "Callback requires either an authorization code or an error."
            )
        for value in (state, code if code is not None else error):
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 16384
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
            ):
                raise _error("INVALID_CALLBACK", "Invalid authorization callback parameters.")
        if state is None:
            raise _error("INVALID_CALLBACK", "Authorization callback is missing state.")
        pending = self._pending.get(state)
        if pending is None:
            raise _error("STATE_MISMATCH", "Authorization callback state does not match.")
        verifier, nonce, redirect, created = pending
        if parsed is not None:
            expected = urlsplit(redirect)
            original_query = parse_qs(expected.query, keep_blank_values=True)
            if (parsed.scheme, parsed.netloc, parsed.path) != (
                expected.scheme,
                expected.netloc,
                expected.path,
            ) or any(query.get(key) != value for key, value in original_query.items()):
                raise _error(
                    "INVALID_CALLBACK",
                    "Authorization callback does not match the registered redirect.",
                )
        # Structured inputs use this pending request's own redirect URI, never a caller override.
        self._pending.pop(state)
        if time.monotonic() - created >= 600:
            raise _error("INVALID_CALLBACK", "Authorization callback has expired.")
        if error is not None:
            raise _error("AUTHENTICATION_FAILED", "Authorization was not completed.")
        async with self._session_lock:
            self._check_session_epoch(epoch)
            tokens = await self._token_request(
                {
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect,
                    "code_verifier": verifier,
                }
            )
            self._check_session_epoch(epoch)
            session = await self._accept_tokens(
                tokens, nonce if "openid" in self._config.scopes else None, expected_epoch=epoch
            )
            self._check_session_epoch(epoch)
            return session

    async def _flow(
        self,
        flow_type: str,
        execution_id: str | None,
        action: str | None,
        inputs: dict[str, str] | None,
        challenge_token: str | None,
        flow_secret: str | None,
    ) -> FlowResult:
        body: dict[str, Any] = {"inputs": inputs or {}}
        if execution_id:
            body.update(executionId=execution_id)
            if action is not None:
                body["action"] = action
            if challenge_token is not None:
                body["challengeToken"] = challenge_token
        else:
            body.update(applicationId=self._config.application_id, flowType=flow_type)
        headers = {"Flow-Secret": flow_secret} if flow_secret and not execution_id else None
        result = await self._transport.request(
            "POST", self._endpoint("flow"), json=body, headers=headers
        )
        if not isinstance(result.get("executionId"), str) or not isinstance(
            result.get("flowStatus"), str
        ):
            raise _error("INVALID_RESPONSE", "Invalid flow response.")
        status = result["flowStatus"]
        if status == "ERROR":
            raise _error("AUTHENTICATION_FAILED", "The authentication flow failed.")
        if status not in ("COMPLETE", "INCOMPLETE"):
            raise _error("INVALID_RESPONSE", "Invalid flow response.")
        assertion = result.get("assertion")
        if status == "COMPLETE" and (not isinstance(assertion, str) or not assertion):
            raise _error(
                "INVALID_RESPONSE", "The completed flow requires an authentication assertion."
            )
        if assertion is not None:
            config = replace(self._config, client_id=self._config.application_id)
            validator = JWTValidator(config, self._transport, self._endpoint("jwks_uri"))
            await validator.validate(assertion)
        return FlowResult(result["executionId"], result["flowStatus"], result, assertion=assertion)

    async def get_access_token(self) -> str:
        self._require_initialized()
        if self._config.grant_type == "client_credentials":
            tokens = await self.get_agent_token(scopes=list(self._config.scopes))
            return tokens.access_token
        return (await self._get_session_tokens()).access_token

    def _check_owned_session(self, authorization: Session) -> ReferenceType[Session]:
        root = self._session_authorization_root
        current = self._session
        if (
            current is None
            or root is None
            or (authorization is not current and root() is not authorization)
            or authorization.context_id != self._context_id
            or current.context_id != self._context_id
        ):
            raise _error(
                "INVALID_AUTHORIZATION", "Authorization belongs to another session context."
            )
        return root

    async def _get_session_tokens(self, *, authorization: Session | None = None) -> TokenResponse:
        self._require_initialized()
        observed = self._session
        epoch = self._session_epoch
        async with self._session_lock:
            self._check_session_epoch(epoch)
            owned_root = (
                self._check_owned_session(authorization) if authorization is not None else None
            )
            if self._session is None:
                raise _error("NO_SESSION", "No authenticated session is available.")
            tokens = self._session.tokens
            if (
                self._session is observed
                and tokens.refresh_token
                and (
                    tokens.expires_at is None
                    or tokens.expires_at
                    <= time.time() + self._config.token_lifecycle.refresh_buffer
                )
            ):
                self._loading = True
                try:
                    updated = await self._token_request(
                        {"grant_type": "refresh_token", "refresh_token": tokens.refresh_token}
                    )
                    self._check_session_epoch(epoch)
                    if authorization is not None:
                        self._check_owned_session(authorization)
                    if updated.refresh_token is None:
                        updated = replace(updated, refresh_token=tokens.refresh_token)
                    await self._accept_tokens(
                        updated,
                        trusted_context=self._session.context_id == self._context_id,
                        preserve_authorization_root=True,
                        expected_epoch=epoch,
                    )
                    tokens = updated
                finally:
                    self._loading = False
            self._check_session_epoch(epoch)
            if authorization is not None and (
                self._session_authorization_root is not owned_root
                or self._session is None
                or self._session.context_id != self._context_id
            ):
                raise _error(
                    "INVALID_AUTHORIZATION", "Authorization belongs to another session context."
                )
            if tokens.expires_at is None or tokens.expires_at <= time.time():
                raise _error("SESSION_EXPIRED", "The session has no known valid token lifetime.")
            return tokens

    async def is_signed_in(self) -> bool:
        self._require_initialized()
        if self._config.grant_type == "client_credentials":
            self._delegation_state()
            return any(expiry > time.time() for _, expiry in self._agent_cache.values())
        return (
            self._session is not None
            and self._session.tokens.expires_at is not None
            and (
                self._session.tokens.expires_at > time.time()
                or bool(self._session.tokens.refresh_token)
            )
        )

    async def set_session(self, session: Session) -> None:
        self._require_initialized()
        async with self._session_lock:
            # Imported credentials are usable, but do not acquire delegation provenance.
            tokens = self._validate_session_tokens(session)
            await self._accept_tokens(tokens, trusted_context=False)

    @staticmethod
    def _validate_session_tokens(session: Session) -> TokenResponse:
        if not isinstance(session, Session) or not isinstance(session.tokens, TokenResponse):
            raise _error("INVALID_SESSION", "The session is invalid.")
        source = session.tokens
        tokens = TokenResponse.from_dict(
            {
                name: getattr(source, name)
                for name in (
                    "access_token",
                    "token_type",
                    "expires_in",
                    "refresh_token",
                    "id_token",
                    "scope",
                    "issued_token_type",
                )
                if getattr(source, name) is not None
            }
        )
        expiry = source.expires_at
        if expiry is None and source.expires_in is not None:
            raise _error("INVALID_SESSION", "The session expiry is invalid.")
        if expiry is not None and (
            isinstance(expiry, bool)
            or not isinstance(expiry, (int, float))
            or not math.isfinite(expiry)
        ):
            raise _error("INVALID_SESSION", "The session expiry is invalid.")
        return replace(tokens, expires_at=expiry)

    def _check_session_epoch(self, epoch: int) -> None:
        if epoch != self._session_epoch:
            raise _error("AUTHORIZATION_CANCELLED", "Authorization context has ended.")

    def _invalidate_authorizations(self) -> None:
        self._session_epoch += 1
        self._session_authorization_root = None
        self._pending.clear()
        self._clear_delegation_state()

    async def clear_session(self) -> None:
        self._require_initialized()
        self._invalidate_authorizations()
        async with self._session_lock:
            try:
                await self._storage.clear(self._session_key)
            finally:
                self._session = None
                await self._clear_agent_storage()

    async def sign_out(self) -> None:
        self._require_initialized()
        self._invalidate_authorizations()
        async with self._session_lock:
            try:
                if self._session is not None:
                    tokens = self._session.tokens
                    auth, headers = build_client_auth(self._config)
                    await self._transport.request(
                        "POST",
                        self._endpoint("revocation_endpoint"),
                        data={
                            "token": tokens.refresh_token or tokens.access_token,
                            "token_type_hint": "refresh_token"
                            if tokens.refresh_token
                            else "access_token",
                            **auth,
                        },
                        headers=headers,
                    )
            finally:
                self._session = None
                try:
                    await self._storage.clear(self._session_key)
                finally:
                    await self._clear_agent_storage()

    async def get_user(self) -> dict[str, Any]:
        self._require_user_grant()
        token = await self.get_access_token()
        return await self._transport.request(
            "GET", self._endpoint("userinfo_endpoint"), headers={"Authorization": "Bearer " + token}
        )

    async def _profile_request(
        self, method: str, endpoint: str, body: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        self._require_user_grant()
        token = await self.get_access_token()
        return await self._transport.request(
            method,
            self._endpoint(endpoint),
            json=body,
            headers={"Authorization": "Bearer " + token},
        )

    async def get_user_profile(self) -> dict[str, Any]:
        result = await self._profile_request("GET", "user_profile")
        return dict(result.get("attributes", {}))

    async def update_user_profile(self, attributes: dict[str, Any]) -> dict[str, Any]:
        result = await self._profile_request("PUT", "user_profile", {"attributes": attributes})
        return dict(result.get("attributes", {}))

    async def get_user_schema(self) -> dict[str, Any]:
        result = await self._profile_request("GET", "user_schema")
        return dict(result.get("schema", {}))

    def decode_jwt_token(self, token: str) -> dict[str, Any]:
        """Decode unverified claims. Never use this result for authorization."""
        self._require_initialized()
        try:
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError
            value = json.loads(base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4)))
            if not isinstance(value, dict):
                raise TypeError
            return value
        except (ValueError, TypeError, UnicodeError):
            raise _error("INVALID_TOKEN", "Invalid JWT encoding.") from None

    async def aclose(self) -> None:
        self._invalidate_authorizations()
        async with self._session_lock:
            self._initialized = False
            try:
                await self._clear_agent_storage()
            finally:
                await self._transport.close()

    async def close(self) -> None:
        await self.aclose()

    async def __aenter__(self) -> Self:
        await self.initialize()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()
