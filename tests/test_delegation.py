# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Offline delegation tests exercise the initialized public client."""

import asyncio
import time
from dataclasses import replace
from urllib.parse import parse_qs

import httpx
import pytest

from thunderid import AsyncThunderIDClient, MemoryStorage, ThunderIDConfig
from thunderid.config import TokenRequestOptions
from thunderid.errors import ThunderIDAPIError, ThunderIDRuntimeError
from thunderid.models import TokenExchangeAuthorization, TokenResponse


async def client_for(handler):
    client = AsyncThunderIDClient(
        ThunderIDConfig(
            base_url="https://issuer.example",
            client_id="agent",
            client_secret="secret",
            token_request=TokenRequestOptions(auth_method="client_secret_basic"),
            discovery=False,
            storage=MemoryStorage(),
            endpoints={
                "token_endpoint": "https://issuer.example/token",
                "backchannel_authentication_endpoint": "https://issuer.example/backchannel",
            },
        ),
        transport=httpx.MockTransport(handler),
    )
    await client.initialize()
    return client


def token_response(value="delegated"):
    return httpx.Response(200, json={"access_token": value, "expires_in": 300})


async def test_agent_cache_is_resource_scope_and_client_isolated():
    calls = []

    def handler(request):
        calls.append(parse_qs(request.content.decode()))
        return token_response(str(len(calls)))

    client = await client_for(handler)
    one = await client.get_agent_token("https://api.example/one", ["b", "a"])
    assert await client.get_agent_token("https://api.example/one", ["a", "b"]) == one
    two = await client.get_agent_token("https://api.example/two", ["a", "b"])
    three = await client.get_agent_token("https://api.example/one", ["a"])
    other = await client_for(handler)
    four = await other.get_agent_token("https://api.example/one", ["a", "b"])
    assert len({t.access_token for t in [one, two, three, four]}) == 4
    assert client._session is None
    assert calls[0]["grant_type"] == ["client_credentials"]
    await client.close()
    await other.close()


async def test_exchange_and_explicit_obo_never_replace_session():
    calls = []

    def handler(request):
        calls.append(parse_qs(request.content.decode()))
        return token_response()

    client = await client_for(handler)
    original = await client._accept_tokens(
        TokenResponse.from_dict({"access_token": "primary", "expires_in": 300})
    )
    await client.exchange_token("subject", actor_token="actor", resource="https://api.example")
    assert calls[-1]["actor_token"] == ["actor"]
    assert client._session is original
    before = len(calls)
    assert await client.get_obo_token(authorization=original) is original.tokens
    assert len(calls) == before
    with pytest.raises(ThunderIDRuntimeError):
        await client.get_obo_token(authorization=original, resource="https://new.example")
    with pytest.raises(ThunderIDRuntimeError, match="another session"):
        await client.get_obo_token(authorization=replace(original))
    await client.get_obo_token(authorization=TokenExchangeAuthorization("external", "actor"))
    assert client._session is original
    await client.close()


async def test_ciba_ownership_pending_slow_down_and_success(monkeypatch):
    calls = []
    responses = ["authorization_pending", "slow_down", None]

    def handler(request):
        calls.append(parse_qs(request.content.decode()))
        if request.url.path == "/backchannel":
            return httpx.Response(
                200, json={"auth_req_id": "request-secret", "expires_in": 90, "interval": 1}
            )
        error = responses.pop(0)
        return (
            httpx.Response(400, json={"error": error, "error_description": "secret"})
            if error
            else token_response()
        )

    client = await client_for(handler)
    request = await client.initiate_backchannel_authentication(
        login_hint="private-user", resource="https://api.example"
    )
    assert "private-user" not in repr(request) and "request-secret" not in repr(request)
    with pytest.raises(ThunderIDRuntimeError):
        await client.poll_backchannel_authentication(replace(request))
    other = await client_for(handler)
    with pytest.raises(ThunderIDRuntimeError):
        await other.poll_backchannel_authentication(request)
    state = client._backchannel_requests[id(request)]
    state.next_poll = time.monotonic()
    assert (await client.poll_backchannel_authentication(request)).status == "authorization_pending"
    state.next_poll = time.monotonic()
    assert (await client.poll_backchannel_authentication(request)).status == "slow_down"
    assert state.interval == 6
    assert state.next_poll - time.monotonic() > 5.9
    state.next_poll = time.monotonic()
    result = await client.poll_backchannel_authentication(request)
    assert result.tokens.access_token == "delegated"
    assert (
        await client.get_obo_token(
            authorization=result.tokens, resource="https://api.example", scopes=["openid"]
        )
        is result.tokens
    )
    with pytest.raises(ThunderIDRuntimeError):
        await client.get_obo_token(authorization=result.tokens, resource="https://other.example")
    assert calls[-1]["resource"] == ["https://api.example"]
    assert client._session is None
    with pytest.raises(ThunderIDRuntimeError):
        await client.poll_backchannel_authentication(request)
    await client.close()
    await other.close()


@pytest.mark.parametrize(
    "payload",
    [
        {"auth_req_id": "id", "expires_in": -1},
        {"auth_req_id": "id", "expires_in": 10, "interval": 0},
        {"auth_req_id": "id", "expires_in": True},
        {"auth_req_id": 123, "expires_in": 10},
    ],
)
async def test_ciba_rejects_malformed_response(payload):
    client = await client_for(lambda request: httpx.Response(200, json=payload))
    with pytest.raises(ThunderIDRuntimeError, match="Invalid backchannel"):
        await client.initiate_backchannel_authentication(login_hint="user")
    await client.close()


async def test_wait_timeout_and_cancellation_do_not_send_early_poll():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"auth_req_id": "id", "expires_in": 60, "interval": 5})

    client = await client_for(handler)
    request = await client.initiate_backchannel_authentication(login_hint="user")
    with pytest.raises(ThunderIDRuntimeError) as error:
        await client.await_backchannel_authentication(request, timeout=0.01)
    assert error.value.code == "AUTHENTICATION_TIMEOUT"
    assert len(calls) == 1
    request = await client.initiate_backchannel_authentication(login_hint="user")
    task = asyncio.create_task(client.await_backchannel_authentication(request))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert client._backchannel_requests[id(request)].terminal
    assert len(calls) == 2
    await client.close()


@pytest.mark.parametrize("error", ["access_denied", "expired_token", "invalid_request"])
async def test_terminal_error_prevents_additional_poll(error):
    def handler(request):
        if request.url.path == "/backchannel":
            return httpx.Response(200, json={"auth_req_id": "id", "expires_in": 60, "interval": 1})
        return httpx.Response(400, json={"error": error})

    client = await client_for(handler)
    request = await client.initiate_backchannel_authentication(login_hint="user")
    client._backchannel_requests[id(request)].next_poll = time.monotonic()
    if error == "invalid_request":
        with pytest.raises(ThunderIDAPIError):
            await client.poll_backchannel_authentication(request)
    else:
        assert (await client.poll_backchannel_authentication(request)).status == error
    with pytest.raises(ThunderIDRuntimeError):
        await client.poll_backchannel_authentication(request)
    await client.close()


@pytest.mark.parametrize("binding", [None, "id", "another-request"])
async def test_ciba_verifies_real_id_token_and_optional_poll_binding(binding):
    import json

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid="test", use="sig", alg="RS256")
    claims = {
        "iss": "https://issuer.example",
        "aud": "agent",
        "sub": "user",
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }
    if binding is not None:
        claims["urn:openid:params:jwt:claim:auth_req_id"] = binding
    encoded = jwt.encode(claims, key, algorithm="RS256", headers={"kid": "test"})

    def handler(request):
        if request.url.path == "/backchannel":
            return httpx.Response(200, json={"auth_req_id": "id", "expires_in": 90, "interval": 1})
        if request.url.path == "/oauth2/jwks":
            return httpx.Response(200, json={"keys": [jwk]})
        return httpx.Response(
            200, json={"access_token": "access", "id_token": encoded, "expires_in": 300}
        )

    client = await client_for(handler)
    request = await client.initiate_backchannel_authentication(login_hint="user")
    client._backchannel_requests[id(request)].next_poll = time.monotonic()
    if binding == "another-request":
        with pytest.raises(ThunderIDRuntimeError, match="binding"):
            await client.poll_backchannel_authentication(request)
        assert not client._backchannel_tokens
    else:
        assert (await client.poll_backchannel_authentication(request)).tokens.id_token == encoded
    assert client._session is None
    await client.close()


async def test_agent_signout_race_does_not_repopulate_cache():
    entered, release = asyncio.Event(), asyncio.Event()

    async def handler(request):
        entered.set()
        await release.wait()
        return token_response()

    client = await client_for(handler)
    task = asyncio.create_task(client.get_agent_token())
    await entered.wait()
    await client.sign_out()
    release.set()
    with pytest.raises(ThunderIDRuntimeError) as error:
        await task
    assert error.value.code == "AUTHORIZATION_CANCELLED"
    assert not client._agent_cache
    await client.close()


async def test_direct_poll_cancellation_invalidates_request():
    client = await client_for(
        lambda request: httpx.Response(
            200, json={"auth_req_id": "id", "expires_in": 60, "interval": 5}
        )
    )
    request = await client.initiate_backchannel_authentication(login_hint="user")
    task = asyncio.create_task(client.poll_backchannel_authentication(request))
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with pytest.raises(ThunderIDRuntimeError):
        await client.poll_backchannel_authentication(request)
    await client.close()


async def test_signout_during_poll_interval_prevents_network_request():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"auth_req_id": "id", "expires_in": 60, "interval": 1})

    client = await client_for(handler)
    request = await client.initiate_backchannel_authentication(login_hint="user")
    client._backchannel_requests[id(request)].next_poll = time.monotonic() + 0.01
    task = asyncio.create_task(client.poll_backchannel_authentication(request))
    await asyncio.sleep(0)
    await client.sign_out()
    with pytest.raises(ThunderIDRuntimeError) as error:
        await task
    assert error.value.code == "AUTHORIZATION_CANCELLED"
    assert len(calls) == 1
    await client.close()
