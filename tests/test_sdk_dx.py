# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Public callback completion and automatic OBO refresh regressions."""

from __future__ import annotations

import asyncio
import time
from dataclasses import replace
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from thunderid import (
    AsyncThunderIDClient,
    AuthorizationRequest,
    MemoryStorage,
    Session,
    ThunderIDConfig,
    ThunderIDRuntimeError,
)


async def make_client(
    handler: Any, *, scopes: tuple[str, ...] = ("profile",)
) -> AsyncThunderIDClient:
    client = AsyncThunderIDClient(
        ThunderIDConfig(
            "https://issuer.invalid",
            client_id="client",
            discovery=False,
            storage=MemoryStorage(),
            scopes=scopes,
            after_sign_in_url="https://application.invalid/callback?tenant=owned",
        ),
        transport=httpx.MockTransport(handler),
    )
    await client.initialize()
    return client


async def start(client: AsyncThunderIDClient) -> AuthorizationRequest:
    request = await client.sign_in()
    assert isinstance(request, AuthorizationRequest)
    return request


async def test_structured_callback_uses_owned_redirect_and_exact_opaque_code() -> None:
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(parse_qs(request.content.decode()))
        return httpx.Response(200, json={"access_token": "access", "expires_in": 300})

    client = await make_client(handler)
    request = await start(client)
    opaque_code = "opaque&state=not-a-state"
    session = await client.handle_redirect_callback(code=opaque_code, state=request.state)
    assert session.tokens.access_token == "access"
    assert requests[0]["code"] == [opaque_code]
    assert requests[0]["redirect_uri"] == ["https://application.invalid/callback?tenant=owned"]
    assert len(requests[0]["code_verifier"][0]) == 43
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.handle_redirect_callback(code=opaque_code, state=request.state)
    assert caught.value.code == "STATE_MISMATCH"
    await client.close()


@pytest.mark.parametrize(
    "values",
    [
        {"code": "code", "error": "access_denied"},
        {"code": ""},
        {"error": ""},
        {"code": ["one", "two"]},
        {"code": "code\nsecret"},
        {},
    ],
)
async def test_ambiguous_callback_rejected_without_consuming_state(values: dict[str, Any]) -> None:
    calls = []
    client = await make_client(
        lambda request: (
            calls.append(request)
            or httpx.Response(200, json={"access_token": "a", "expires_in": 300})
        )
    )
    request = await start(client)
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.handle_redirect_callback(state=request.state, **values)
    assert caught.value.code == "INVALID_CALLBACK"
    assert not calls
    await client.handle_redirect_callback(code="valid", state=request.state)
    await client.close()


async def test_callback_url_and_keyword_inputs_are_exclusive() -> None:
    client = await make_client(
        lambda _: httpx.Response(200, json={"access_token": "a", "expires_in": 300})
    )
    request = await start(client)
    url = "https://application.invalid/callback?" + urlencode(
        {"tenant": "owned", "code": "code", "state": request.state}
    )
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.handle_redirect_callback(url, code="second", state=request.state)
    assert caught.value.code == "INVALID_CALLBACK"
    await client.handle_redirect_callback(url)
    await client.close()


async def test_invalid_location_does_not_consume_owned_request() -> None:
    client = await make_client(
        lambda _: httpx.Response(200, json={"access_token": "a", "expires_in": 300})
    )
    request = await start(client)
    with pytest.raises(ThunderIDRuntimeError):
        await client.handle_redirect_callback(
            "https://evil.invalid/callback?" + urlencode({"code": "code", "state": request.state})
        )
    await client.handle_redirect_callback(code="valid", state=request.state)
    await client.close()


async def test_structured_denial_is_sanitized_and_consumed() -> None:
    client = await make_client(lambda _: pytest.fail("denial must not exchange a code"))
    request = await start(client)
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.handle_redirect_callback(
            state=request.state, error="secret-personal-server-detail"
        )
    assert caught.value.code == "AUTHENTICATION_FAILED"
    assert "secret" not in str(caught.value)
    with pytest.raises(ThunderIDRuntimeError) as replay:
        await client.handle_redirect_callback(state=request.state, code="later")
    assert replay.value.code == "STATE_MISMATCH"
    await client.close()


async def test_structured_state_is_not_parsed_or_injected() -> None:
    client = await make_client(
        lambda _: httpx.Response(200, json={"access_token": "a", "expires_in": 300})
    )
    request = await start(client)
    for state in (request.state + "&state=other", [request.state, "other"], None):
        with pytest.raises(ThunderIDRuntimeError):
            await client.handle_redirect_callback(state=state, code="code")
    await client.handle_redirect_callback(state=request.state, code="code")
    await client.close()


async def test_expired_structured_state_fails_before_network() -> None:
    client = await make_client(lambda _: pytest.fail("expired request must not exchange"))
    request = await start(client)
    verifier, nonce, redirect, created = client._pending[request.state]
    client._pending[request.state] = (verifier, nonce, redirect, created - 601)
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.handle_redirect_callback(state=request.state, code="code")
    assert caught.value.code == "INVALID_CALLBACK"
    await client.close()


async def test_reserved_redirect_query_cannot_inject_response_parameters() -> None:
    client = AsyncThunderIDClient(
        ThunderIDConfig(
            "https://issuer.invalid",
            client_id="client",
            discovery=False,
            storage=MemoryStorage(),
            after_sign_in_url="https://application.invalid/callback?state=preconfigured",
        ),
        transport=httpx.MockTransport(lambda _: pytest.fail("local validation only")),
    )
    await client.initialize()
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.sign_in()
    assert caught.value.code == "INVALID_CONFIG"
    await client.close()


async def test_structured_callback_still_enforces_nonce_before_persistence() -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    assert isinstance(key, dict)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, json={"keys": [key | {"kid": "key", "alg": "RS256"}]})
        claims = {
            "iss": "https://issuer.invalid",
            "aud": "client",
            "sub": "person",
            "iat": time.time(),
            "exp": time.time() + 300,
            "nonce": "wrong",
        }
        return httpx.Response(
            200,
            json={
                "access_token": "a",
                "expires_in": 300,
                "id_token": jwt.encode(claims, private, algorithm="RS256", headers={"kid": "key"}),
            },
        )

    client = await make_client(handler, scopes=("openid",))
    request = await start(client)
    assert parse_qs(urlsplit(request.url).query)["nonce"] != ["wrong"]
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.handle_redirect_callback(code="code", state=request.state)
    assert caught.value.code == "INVALID_ID_TOKEN"
    assert not await client.is_signed_in()
    assert await client._storage.read(client._session_key) is None
    await client.close()


async def owned_session(handler: Any) -> tuple[AsyncThunderIDClient, Session]:
    client = await make_client(handler)
    request = await start(client)
    return client, await client.handle_redirect_callback(code="code", state=request.state)


async def test_obo_refresh_shares_deduplication_and_persists_rotation() -> None:
    calls = []

    async def handler(request: httpx.Request) -> httpx.Response:
        data = parse_qs(request.content.decode())
        calls.append(data)
        if data["grant_type"] == ["authorization_code"]:
            return httpx.Response(
                200, json={"access_token": "old", "refresh_token": "old-refresh", "expires_in": 1}
            )
        await asyncio.sleep(0)
        return httpx.Response(
            200, json={"access_token": "fresh", "refresh_token": "rotated", "expires_in": 300}
        )

    client, authorization = await owned_session(handler)
    results = await asyncio.gather(
        *(client.get_obo_token(authorization=authorization) for _ in range(5)),
        client.get_access_token(),
    )
    assert all(token.access_token == "fresh" for token in results[:-1])
    assert results[-1] == "fresh"
    assert len(calls) == 2
    stored = await client._storage.read(client._session_key)
    assert stored is not None and stored.tokens.refresh_token == "rotated"
    assert (await client.get_obo_token(authorization=authorization)).access_token == "fresh"
    assert len(calls) == 2
    await client.close()


@pytest.mark.parametrize(
    "override", [{"resource": "https://other.invalid"}, {"scopes": ["different"]}, {"copied": True}]
)
async def test_obo_invalid_authorization_fails_before_refresh(override: dict[str, Any]) -> None:
    calls = []
    client, authorization = await owned_session(
        lambda request: (
            calls.append(request)
            or httpx.Response(
                200, json={"access_token": "old", "refresh_token": "r", "expires_in": 1}
            )
        )
    )
    if override.pop("copied", False):
        authorization = replace(authorization)
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.get_obo_token(authorization=authorization, **override)
    assert caught.value.code == "INVALID_AUTHORIZATION"
    assert len(calls) == 1
    await client.close()


async def test_obo_cannot_return_refreshed_tokens_after_signout_invalidates_context() -> None:
    started, release = asyncio.Event(), asyncio.Event()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("revoke"):
            return httpx.Response(200, json={})
        data = parse_qs(request.content.decode())
        if data["grant_type"] == ["authorization_code"]:
            return httpx.Response(
                200, json={"access_token": "old", "refresh_token": "r", "expires_in": 1}
            )
        started.set()
        await release.wait()
        return httpx.Response(200, json={"access_token": "stale", "expires_in": 300})

    client, authorization = await owned_session(handler)
    refresh = asyncio.create_task(client.get_obo_token(authorization=authorization))
    await started.wait()
    signout = asyncio.create_task(client.sign_out())
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await refresh
    assert caught.value.code == "AUTHORIZATION_CANCELLED"
    await signout
    assert not await client.is_signed_in()
    assert await client._storage.read(client._session_key) is None
    await client.close()


async def test_obo_refresh_without_known_expiry_is_refused() -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            200,
            json={"access_token": "old", "refresh_token": "r", "expires_in": 1}
            if len(calls) == 1
            else {"access_token": "unknown"},
        )

    client, authorization = await owned_session(handler)
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.get_obo_token(authorization=authorization)
    assert caught.value.code == "SESSION_EXPIRED"
    await client.close()


@pytest.mark.parametrize(
    "response", [{"access_token": "expired", "expires_in": 0}, {"access_token": "unknown"}]
)
async def test_obo_without_refresh_cannot_return_expired_or_unknown_tokens(
    response: dict[str, Any],
) -> None:
    calls = []
    client, authorization = await owned_session(
        lambda request: calls.append(request) or httpx.Response(200, json=response)
    )
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.get_obo_token(authorization=authorization)
    assert caught.value.code == "SESSION_EXPIRED"
    assert len(calls) == 1
    await client.close()


async def test_obo_during_secure_write_does_not_restore_invalidated_family() -> None:
    started, release = asyncio.Event(), asyncio.Event()

    class DelayedStorage(MemoryStorage):
        async def write(self, key: str, session: Session) -> None:
            if session.tokens.access_token == "fresh":
                started.set()
                await release.wait()
            await super().write(key, session)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("revoke"):
            return httpx.Response(200, json={})
        grant = parse_qs(request.content.decode())["grant_type"]
        return httpx.Response(
            200,
            json={"access_token": "old", "refresh_token": "r", "expires_in": 1}
            if grant == ["authorization_code"]
            else {"access_token": "fresh", "expires_in": 300},
        )

    client, authorization = await owned_session(handler)
    storage = DelayedStorage()
    client._storage = storage
    refresh = asyncio.create_task(client.get_obo_token(authorization=authorization))
    await started.wait()
    signout = asyncio.create_task(client.sign_out())
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await refresh
    assert caught.value.code == "AUTHORIZATION_CANCELLED"
    await signout
    assert client._session_authorization_root is None
    assert await storage.read(client._session_key) is None
    await client.close()
