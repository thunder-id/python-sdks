# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

import asyncio
import time
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest

from thunderid import (
    AsyncThunderIDClient,
    MemoryStorage,
    Session,
    ThunderIDConfig,
    ThunderIDRuntimeError,
    TokenResponse,
)


def make_client(handler, **options):
    config = ThunderIDConfig(
        base_url="https://issuer.example",
        client_id="client",
        discovery=False,
        storage=MemoryStorage(),
        after_sign_in_url="https://app.example/callback",
        **options,
    )
    return AsyncThunderIDClient(config, transport=httpx.MockTransport(handler))


async def test_preinitialization_and_discovery_issuer():
    client = make_client(lambda r: httpx.Response(200, json={}))
    with pytest.raises(ThunderIDRuntimeError, match="Initialize"):
        await client.sign_in()
    config = ThunderIDConfig(
        base_url="https://issuer.example", client_id="client", storage=MemoryStorage()
    )
    client = AsyncThunderIDClient(
        config,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"issuer": "https://evil.example"})
        ),
    )
    with pytest.raises(ThunderIDRuntimeError) as error:
        await client.initialize()
    assert error.value.code == "ISSUER_MISMATCH"


async def test_pkce_owned_values_and_callback_replay():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json={"access_token": "access", "expires_in": 300})

    client = make_client(handler, scopes=("profile",))
    await client.initialize()
    auth = await client.sign_in(
        options={
            "state": "evil",
            "nonce": "evil",
            "redirect_uri": "https://evil.example",
            "code_challenge_method": "plain",
        }
    )
    query = parse_qs(urlsplit(auth.url).query)
    assert query["state"] == [auth.state]
    assert query["nonce"] != ["evil"]
    assert query["code_challenge_method"] == ["S256"]
    assert len(query["code_challenge"][0]) == 43
    callback = "https://app.example/callback?" + urlencode({"state": auth.state, "code": "code"})
    await client.handle_redirect_callback(callback)
    assert await client.get_access_token() == "access"
    exchange = parse_qs(requests[0].content.decode())
    assert len(exchange["code_verifier"][0]) == 43
    with pytest.raises(ThunderIDRuntimeError) as error:
        await client.handle_redirect_callback(callback)
    assert error.value.code == "STATE_MISMATCH"


async def test_callback_origin_state_and_nonce_before_storage():
    requests = []
    client = make_client(
        lambda r: requests.append(r) or httpx.Response(200, json={"access_token": "a"})
    )
    await client.initialize()
    auth = await client.sign_in()
    with pytest.raises(ThunderIDRuntimeError):
        await client.handle_redirect_callback(
            "https://evil.example/callback?" + urlencode({"state": auth.state, "code": "x"})
        )
    assert not requests
    auth = await client.sign_in()
    with pytest.raises(ThunderIDRuntimeError) as error:
        await client.handle_redirect_callback(
            "https://app.example/callback?" + urlencode({"state": auth.state, "code": "x"})
        )
    assert error.value.code == "INVALID_TOKEN"
    assert client._session is None


async def test_refresh_singleflight_and_signout_cannot_resurrect():
    started, release = asyncio.Event(), asyncio.Event()
    counts = {"refresh": 0, "revoke": 0}

    async def handler(request):
        if request.url.path.endswith("token"):
            counts["refresh"] += 1
            started.set()
            await release.wait()
            return httpx.Response(
                200, json={"access_token": "new", "refresh_token": "rotated", "expires_in": 300}
            )
        counts["revoke"] += 1
        assert b"rotated" in request.content
        return httpx.Response(200, json={})

    client = make_client(handler)
    await client.initialize()
    await client.set_session(
        Session(TokenResponse("old", refresh_token="refresh", expires_at=time.time() - 1))
    )
    calls = [asyncio.create_task(client.get_access_token()) for _ in range(8)]
    await started.wait()
    release.set()
    assert await asyncio.gather(*calls) == ["new"] * 8
    assert counts["refresh"] == 1
    await client.sign_out()
    assert client._session is None
    assert counts["revoke"] == 1


async def test_signout_failure_clears_local_state():
    client = make_client(lambda r: httpx.Response(500, json={"error_description": "secret"}))
    await client.initialize()
    await client.set_session(Session(TokenResponse("access", refresh_token="refresh")))
    with pytest.raises(Exception) as error:
        await client.sign_out()
    assert "secret" not in str(error.value)
    assert client._session is None
    await client.sign_out()


async def test_profile_wire_contract():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200,
            json={"schema": {"type": "object"}}
            if request.url.path.endswith("meta")
            else {"attributes": {"name": "A"}},
        )

    client = make_client(handler)
    await client.initialize()
    await client.set_session(Session(TokenResponse("access", expires_at=time.time() + 300)))
    assert await client.get_user_profile() == {"name": "A"}
    await client.update_user_profile({"name": "A"})
    assert seen[-1].method == "PUT"
    assert seen[-1].content == b'{"attributes":{"name":"A"}}'
    assert await client.get_user_schema() == {"type": "object"}
    assert seen[-1].url.path == "/users/me/meta"


async def test_embedded_execution_wire_and_no_fake_session():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(
            200, json={"executionId": "exec", "flowStatus": "INCOMPLETE", "data": {"inputs": []}}
        )

    config = ThunderIDConfig(
        base_url="https://issuer.example",
        application_id="app",
        mode="embedded",
        discovery=False,
        storage=MemoryStorage(),
    )
    client = AsyncThunderIDClient(config, transport=httpx.MockTransport(handler))
    await client.initialize()
    result = await client.sign_in(flow_secret="secret")
    assert result.execution_id == "exec"
    assert seen[0].headers["Flow-Secret"] == "secret"
    await client.sign_in(
        execution_id=result.execution_id, action="submit", inputs={"username": "alice"}
    )
    assert b'"executionId":"exec"' in seen[-1].content
    assert "Flow-Secret" not in seen[-1].headers
    assert client._session is None


async def test_signed_nonce_is_required_before_session_persistence():
    import json

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = "signing-key"
    nonce = "wrong-nonce"

    def handler(request):
        if request.url.path.endswith("jwks"):
            return httpx.Response(200, json={"keys": [jwk]})
        signed = jwt.encode(
            {
                "iss": "https://issuer.example",
                "aud": "client",
                "sub": "user",
                "iat": int(time.time()),
                "exp": int(time.time()) + 300,
                "nonce": nonce,
            },
            key,
            algorithm="RS256",
            headers={"kid": "signing-key"},
        )
        return httpx.Response(200, json={"access_token": "access", "id_token": signed})

    client = make_client(handler)
    await client.initialize()
    auth = await client.sign_in()
    with pytest.raises(ThunderIDRuntimeError):
        await client.handle_redirect_callback(
            "https://app.example/callback?" + urlencode({"state": auth.state, "code": "code"})
        )
    assert client._session is None
    auth = await client.sign_in()
    nonce = parse_qs(urlsplit(auth.url).query)["nonce"][0]
    session = await client.handle_redirect_callback(
        "https://app.example/callback?" + urlencode({"state": auth.state, "code": "code"})
    )
    assert session.user["sub"] == "user"


async def test_embedded_assertion_verified_for_application_and_never_oauth_session():
    import json

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    audience = "foreign-app"

    def handler(request):
        if request.url.path.endswith("jwks"):
            return httpx.Response(200, json={"keys": [jwk]})
        assertion = jwt.encode(
            {
                "iss": "https://issuer.example",
                "aud": audience,
                "sub": "user",
                "iat": int(time.time()),
                "exp": int(time.time()) + 300,
            },
            key,
            algorithm="RS256",
        )
        return httpx.Response(
            200, json={"executionId": "exec", "flowStatus": "COMPLETE", "assertion": assertion}
        )

    config = ThunderIDConfig(
        base_url="https://issuer.example",
        application_id="app",
        mode="embedded",
        discovery=False,
        storage=MemoryStorage(),
    )
    client = AsyncThunderIDClient(config, transport=httpx.MockTransport(handler))
    await client.initialize()
    with pytest.raises(ThunderIDRuntimeError):
        await client.sign_in()
    audience = "app"
    result = await client.sign_in()
    assert result.assertion is not None
    assert client._session is None


@pytest.mark.parametrize(
    "operation",
    [
        "sign_in",
        "sign_up",
        "get_access_token",
        "is_signed_in",
        "get_user",
        "get_user_profile",
        "get_user_schema",
        "clear_session",
        "sign_out",
    ],
)
async def test_required_operations_before_initialize(operation):
    client = make_client(lambda r: httpx.Response(200, json={}))
    with pytest.raises(ThunderIDRuntimeError) as error:
        await getattr(client, operation)()
    assert error.value.code == "NOT_INITIALIZED"
    await client.aclose()


async def test_reinitialize_closes_old_http_client_and_rolls_back_failure():
    client = make_client(lambda r: httpx.Response(200, json={"issuer": "wrong"}))
    await client.initialize()
    previous = client._transport
    await client.re_initialize(scopes=("profile",))
    assert previous._client.is_closed
    assert client.get_configuration().scopes == ("profile",)
    current = client._transport
    with pytest.raises(ThunderIDRuntimeError) as error:
        await client.re_initialize(discovery=True)
    assert error.value.code == "ISSUER_MISMATCH"
    assert client._transport is current
    assert not current._client.is_closed
    with pytest.raises(ThunderIDRuntimeError):
        await client.re_initialize(client_id="other")
    with pytest.raises(ThunderIDRuntimeError):
        await client.re_initialize(unknown=True)
    await client.aclose()
    assert current._client.is_closed


@pytest.mark.parametrize("operation", ["clear_session", "sign_out"])
async def test_signout_cancels_inflight_redirect_callback(operation):
    started, release = asyncio.Event(), asyncio.Event()

    async def handler(request):
        started.set()
        await release.wait()
        return httpx.Response(200, json={"access_token": "late"})

    client = make_client(handler, scopes=("profile",))
    await client.initialize()
    auth = await client.sign_in()
    callback = asyncio.create_task(
        client.handle_redirect_callback(
            "https://app.example/callback?" + urlencode({"state": auth.state, "code": "code"})
        )
    )
    await started.wait()
    ending = asyncio.create_task(getattr(client, operation)())
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(ThunderIDRuntimeError) as error:
        await callback
    assert error.value.code == "AUTHORIZATION_CANCELLED"
    await ending
    assert client._session is None


async def test_machine_acquisition_cache_and_user_operations_rejected():
    calls = []
    client = make_client(
        lambda r: (
            calls.append(r)
            or httpx.Response(200, json={"access_token": "machine", "expires_in": 300})
        ),
        grant_type="client_credentials",
        scopes=("system",),
    )
    await client.initialize()
    assert not await client.is_signed_in()
    assert await client.get_access_token() == "machine"
    assert await client.get_access_token() == "machine"
    assert len(calls) == 1
    assert await client.is_signed_in()
    for operation in (
        client.sign_in(),
        client.sign_up(),
        client.get_user(),
        client.get_user_profile(),
        client.get_user_schema(),
        client.update_user_profile({}),
        client.handle_redirect_callback("https://app.example/callback"),
    ):
        with pytest.raises(ThunderIDRuntimeError) as error:
            await operation
        assert error.value.code == "UNSUPPORTED_OPERATION"
    await client.sign_out()
    assert not await client.is_signed_in()


@pytest.mark.parametrize("expiry", [float("nan"), float("inf"), "invalid", True])
async def test_imported_session_invalid_expiry_rejected(expiry):
    client = make_client(lambda r: httpx.Response(200, json={}))
    await client.initialize()
    with pytest.raises(ThunderIDRuntimeError) as error:
        await client.set_session(Session(TokenResponse("access", expires_at=expiry)))
    assert error.value.code in ("INVALID_SESSION", "INVALID_RESPONSE")
    assert client._session is None


@pytest.mark.parametrize("status", ["ERROR", "UNKNOWN", "COMPLETE"])
async def test_embedded_terminal_invalid_or_missing_assertion(status):
    config = ThunderIDConfig(
        base_url="https://issuer.example",
        application_id="app",
        mode="embedded",
        discovery=False,
        storage=MemoryStorage(),
    )
    client = AsyncThunderIDClient(
        config,
        transport=httpx.MockTransport(
            lambda r: httpx.Response(200, json={"executionId": "exec", "flowStatus": status})
        ),
    )
    await client.initialize()
    with pytest.raises(ThunderIDRuntimeError) as error:
        await client.sign_up()
    assert error.value.code == (
        "AUTHENTICATION_FAILED" if status == "ERROR" else "INVALID_RESPONSE"
    )


async def test_decode_utility_and_reserved_endpoint_query():
    client = make_client(
        lambda r: httpx.Response(200, json={}),
        endpoints={
            "authorization_endpoint": "https://issuer.example/oauth2/authorize?state=evil&client_id=evil&custom=yes"
        },
    )
    with pytest.raises(ThunderIDRuntimeError):
        client.decode_jwt_token("a.e30.b")
    await client.initialize()
    assert client.decode_jwt_token("a.e30.b") == {}
    with pytest.raises(ThunderIDRuntimeError):
        client.decode_jwt_token("bad")
    request = await client.sign_in()
    query = parse_qs(urlsplit(request.url).query)
    assert query["state"] == [request.state]
    assert query["client_id"] == ["client"]
    assert query["custom"] == ["yes"]


async def test_redirect_registration_is_explicitly_unsupported():
    client = make_client(lambda r: httpx.Response(200, json={}))
    await client.initialize()
    with pytest.raises(ThunderIDRuntimeError) as error:
        await client.sign_up()
    assert error.value.code == "UNSUPPORTED_OPERATION"
    assert not client._pending


async def test_restore_expired_identity_requires_fresh_verified_identity():
    import json

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))

    def identity(expiry, subject="user"):
        return jwt.encode(
            {
                "iss": "https://issuer.example",
                "aud": "client",
                "sub": subject,
                "iat": int(time.time()) - 120,
                "exp": expiry,
            },
            key,
            algorithm="RS256",
        )

    fresh = identity(int(time.time()) + 300)
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path.endswith("jwks"):
            return httpx.Response(200, json={"keys": [jwk]})
        return httpx.Response(
            200,
            json={
                "access_token": "fresh",
                "refresh_token": "rotated",
                "id_token": fresh,
                "expires_in": 300,
            },
        )

    storage = MemoryStorage()
    options = ThunderIDConfig(
        base_url="https://issuer.example",
        client_id="client",
        discovery=False,
        storage=storage,
        instance_id=42,
    )
    first = AsyncThunderIDClient(options, transport=httpx.MockTransport(handler))
    await first.initialize()
    expired = identity(int(time.time()) - 60)
    await storage.write(
        first._session_key,
        Session(
            TokenResponse(
                "old", refresh_token="refresh", id_token=expired, expires_at=time.time() - 60
            ),
            user={"sub": "untrusted-stale"},
        ),
    )
    second = AsyncThunderIDClient(options, transport=httpx.MockTransport(handler))
    await second.initialize()
    assert await second.get_access_token() == "fresh"
    assert second._session.user["sub"] == "user"
    assert second._session.tokens.refresh_token == "rotated"
    assert second._session.context_id is None
    assert len([request for request in requests if request.url.path.endswith("token")]) == 1
    fresh = identity(int(time.time()) + 300, subject="tampered") + "invalid"
    await storage.write(
        first._session_key,
        Session(
            TokenResponse(
                "old", refresh_token="refresh", id_token=expired, expires_at=time.time() - 60
            )
        ),
    )
    third = AsyncThunderIDClient(options, transport=httpx.MockTransport(handler))
    with pytest.raises(ThunderIDRuntimeError) as error:
        await third.initialize()
    assert error.value.code == "INVALID_ID_TOKEN"
    assert third._session is None


async def test_storage_namespace_separates_application_and_grant():
    storage = MemoryStorage()
    clients = []
    for application in ("first", "second"):
        config = ThunderIDConfig(
            base_url="https://issuer.example",
            mode="embedded",
            application_id=application,
            instance_id=43,
            discovery=False,
            storage=storage,
        )
        client = AsyncThunderIDClient(
            config, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        )
        await client.initialize()
        clients.append(client)
    assert clients[0]._session_key != clients[1]._session_key
    await clients[0].set_session(Session(TokenResponse("first", expires_at=time.time() + 300)))
    await clients[1].clear_session()
    assert await clients[0].get_access_token() == "first"
    for grant in ("authorization_code", "client_credentials"):
        config = ThunderIDConfig(
            base_url="https://issuer.example",
            client_id="client",
            grant_type=grant,
            instance_id=43,
            discovery=False,
            storage=storage,
        )
        client = AsyncThunderIDClient(
            config, transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))
        )
        await client.initialize()
        clients.append(client)
    assert clients[2]._session_key != clients[3]._session_key


async def test_near_expiry_without_refresh_remains_valid_until_actual_expiry(monkeypatch):
    requests = []
    client = make_client(lambda request: requests.append(request) or httpx.Response(200, json={}))
    await client.initialize()
    now = time.time()
    await client.set_session(Session(TokenResponse("valid", expires_at=now + 20)))
    monkeypatch.setattr("thunderid.client.time.time", lambda: now)
    assert await client.get_access_token() == "valid"
    assert await client.is_signed_in()
    assert not requests
    monkeypatch.setattr("thunderid.client.time.time", lambda: now + 21)
    with pytest.raises(ThunderIDRuntimeError) as error:
        await client.get_access_token()
    assert error.value.code == "SESSION_EXPIRED"
    assert not await client.is_signed_in()
    assert not requests


@pytest.mark.parametrize("tampered", [False, True])
async def test_expired_persisted_identity_without_refresh_clears_only_authentic_session(tampered):
    import base64
    import json

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    token = jwt.encode(
        {
            "iss": "https://issuer.example",
            "aud": "client",
            "sub": "user",
            "iat": int(time.time()) - 120,
            "exp": int(time.time()) - 60,
        },
        key,
        algorithm="RS256",
    )
    if tampered:
        header, body, signature = token.split(".")
        raw_signature = bytearray(base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)))
        raw_signature[0] ^= 1
        token = ".".join(
            (header, body, base64.urlsafe_b64encode(raw_signature).rstrip(b"=").decode())
        )
    storage = MemoryStorage()
    config = ThunderIDConfig(
        base_url="https://issuer.example",
        client_id="client",
        instance_id=44,
        discovery=False,
        storage=storage,
    )
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json={"keys": [jwk]}))
    first = AsyncThunderIDClient(config, transport=transport)
    await first.initialize()
    await storage.write(
        first._session_key,
        Session(TokenResponse("expired", id_token=token, expires_at=time.time() - 60)),
    )
    restored = AsyncThunderIDClient(config, transport=transport)
    if tampered:
        with pytest.raises(ThunderIDRuntimeError) as error:
            await restored.initialize()
        assert error.value.code == "INVALID_ID_TOKEN"
        assert await storage.read(first._session_key) is not None
    else:
        assert await restored.initialize()
        assert not await restored.is_signed_in()
        assert await storage.read(first._session_key) is None
        await restored.clear_session()
    assert restored._session is None
