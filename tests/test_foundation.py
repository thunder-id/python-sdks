# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import time
from dataclasses import replace
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from thunderid.config import HttpOptions, ThunderIDConfig, TokenRequestOptions
from thunderid.errors import ThunderIDAPIError, ThunderIDRuntimeError
from thunderid.models import Session, TokenResponse
from thunderid.security import JWTValidator, build_client_auth
from thunderid.storage import KeyringStorage, MemoryStorage
from thunderid.transport import Transport


def config(**kwargs: Any) -> ThunderIDConfig:
    return ThunderIDConfig(base_url="https://issuer.invalid", client_id="client", **kwargs)


@pytest.mark.parametrize(
    "url",
    [
        "http://issuer.invalid",
        "https://user:pass@issuer.invalid",
        "https://issuer.invalid/#fragment",
        "https://issuer.invalid/../evil",
        "https://issuer.invalid\\@evil.invalid",
    ],
)
def test_reject_bad_urls(url: str) -> None:
    with pytest.raises(ThunderIDRuntimeError):
        ThunderIDConfig(url, client_id="client").validate()


def test_immutable_config_and_boundary() -> None:
    nested = {"extra": {"items": ["original"]}}
    cfg = config(sign_in_options=nested, allowed_external_urls=("https://api.invalid/v1",))
    nested["extra"]["items"].append("mutated")
    assert cfg.sign_in_options["extra"]["items"] == ("original",)
    cfg.check_endpoint("https://api.invalid/v1/things")
    for endpoint in (
        "https://api.invalid/v10",
        "https://api.invalid.attacker.invalid/v1",
        "https://api.invalid/v1/%2e%2e/secret",
    ):
        with pytest.raises(ThunderIDRuntimeError):
            cfg.check_endpoint(endpoint)


def test_floor_cannot_be_disabled() -> None:
    with pytest.raises(ThunderIDRuntimeError):
        config(http=HttpOptions(verify=False)).validate()
    with pytest.raises(ThunderIDRuntimeError):
        ThunderIDConfig("http://localhost:8080", application_id="app", mode="embedded").validate()
    config().validate()


async def test_transport_sanitizes_errors_and_refuses_redirects() -> None:
    secret = "token-secret-personal-data"
    calls: list[str] = []

    def handle(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        if request.url.path == "/redirect":
            return httpx.Response(302, headers={"location": "https://evil.invalid"})
        return httpx.Response(400, json={"error": "slow_down", "error_description": secret})

    transport = Transport(config(), transport=httpx.MockTransport(handle))
    with pytest.raises(ThunderIDAPIError) as caught:
        await transport.request("POST", "https://issuer.invalid/token")
    assert caught.value.code == "SLOW_DOWN"
    assert secret not in str(caught.value)
    with pytest.raises(ThunderIDRuntimeError, match="redirects"):
        await transport.request("GET", "https://issuer.invalid/redirect")
    assert len(calls) == 2
    with pytest.raises(ThunderIDRuntimeError):
        await transport.request("GET", "https://issuer.invalid.evil.invalid")
    assert len(calls) == 2
    await transport.close()


async def test_transport_bounds_response() -> None:
    transport = Transport(
        config(http=HttpOptions(max_response_bytes=10)),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"x" * 11)),
    )
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await transport.request("GET", "https://issuer.invalid/keys")
    assert caught.value.code == "RESPONSE_TOO_LARGE"
    await transport.close()


async def test_memory_isolated_and_copies_sessions() -> None:
    storage = MemoryStorage()
    session = Session(TokenResponse("secret"), user={"name": "before"})
    await storage.write("first", session)
    assert session.user is not None
    session.user["name"] = "after"
    first = await storage.read("first")
    assert first is not None and first.user == {"name": "before"}
    assert await storage.read("second") is None
    await storage.clear("first")
    assert await storage.read("first") is None
    assert "secret" not in repr(session)


async def test_keyring_rejects_insecure_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    class Fake:
        priority = 100

        def get_password(self, *args: Any) -> str:
            raise AssertionError("must not read")

    monkeypatch.setattr("keyring.get_keyring", lambda: Fake())
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await KeyringStorage().read("key")
    assert caught.value.code == "SECURE_STORAGE_UNAVAILABLE"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"access_token": "secret", "expires_in": True},
        {"access_token": "secret", "expires_in": float("nan")},
        {"access_token": "secret", "token_type": "MAC"},
    ],
)
def test_bad_token_responses(payload: dict[str, Any]) -> None:
    with pytest.raises(ThunderIDRuntimeError):
        TokenResponse.from_dict(payload)


def test_auth_uses_encoded_basic_credentials() -> None:
    cfg = config(
        client_secret="secret:a",
        token_request=TokenRequestOptions(auth_method="client_secret_basic"),
    )
    data, headers = build_client_auth(cfg)
    assert data == {}
    assert base64.b64decode(headers["Authorization"].split()[1]) == b"client:secret%3Aa"


async def test_jwt_signature_claims_and_bounded_jwks_fetch() -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    assert isinstance(key, dict)
    key.update(kid="one", alg="RS256", use="sig")
    calls = 0

    def handle(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"keys": [key]})

    transport = Transport(config(), transport=httpx.MockTransport(handle))
    validator = JWTValidator(config(), transport, "https://issuer.invalid/jwks")
    claims = {
        "iss": "https://issuer.invalid",
        "aud": "client",
        "sub": "subject",
        "iat": time.time(),
        "exp": time.time() + 300,
        "nonce": "expected",
    }
    token = jwt.encode(claims, private, algorithm="RS256", headers={"kid": "one"})
    assert (await validator.validate(token, nonce="expected"))["sub"] == "subject"
    for patch in (
        {"nonce": "wrong"},
        {"aud": "other"},
        {"iss": "https://evil.invalid"},
        {"exp": time.time() - 100},
        {"iat": True},
    ):
        bad = jwt.encode(claims | patch, private, algorithm="RS256", headers={"kid": "one"})
        with pytest.raises(ThunderIDRuntimeError):
            await validator.validate(bad, nonce="expected")
    unknown = jwt.encode(claims, private, algorithm="RS256", headers={"kid": "unknown"})
    for _ in range(5):
        with pytest.raises(ThunderIDRuntimeError):
            await validator.validate(unknown)
    assert calls == 2
    unsigned = jwt.encode(claims, key="", algorithm="none")
    with pytest.raises(ThunderIDRuntimeError):
        await validator.validate(unsigned)
    await transport.close()


def test_private_key_assertion_audience_and_uniqueness() -> None:
    from cryptography.hazmat.primitives import serialization

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    cfg = config(token_request=TokenRequestOptions(auth_method="private_key_jwt", private_key=pem))
    first, _ = build_client_auth(cfg)
    second, _ = build_client_auth(cfg)
    claims = jwt.decode(
        first["client_assertion"], private.public_key(), algorithms=["RS256"], audience=cfg.base_url
    )
    assert claims["iss"] == claims["sub"] == "client"
    assert first != second
    assert pem not in repr(cfg)
    replace(cfg, client_secret=None).validate()


async def test_jwks_rotation_refetches_once() -> None:
    first = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rotated = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    calls = 0

    def handle(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        current = first if calls == 1 else rotated
        key = jwt.algorithms.RSAAlgorithm.to_jwk(current.public_key(), as_dict=True)
        assert isinstance(key, dict)
        return httpx.Response(200, json={"keys": [key | {"kid": "same", "alg": "RS256"}]})

    cfg = config()
    transport = Transport(cfg, transport=httpx.MockTransport(handle))
    validator = JWTValidator(cfg, transport, "https://issuer.invalid/keys")
    claims = {
        "iss": cfg.base_url,
        "aud": "client",
        "sub": "subject",
        "iat": time.time(),
        "exp": time.time() + 60,
    }
    token = jwt.encode(claims, rotated, algorithm="RS256", headers={"kid": "same"})
    assert (await validator.validate(token))["sub"] == "subject"
    assert calls == 2
    await transport.close()


async def test_keyring_single_item_roundtrip(monkeypatch: pytest.MonkeyPatch) -> None:
    values: dict[str, str] = {}

    class Native:
        priority = 1

        def set_password(self, service: str, key: str, value: str) -> None:
            assert service == "thunderid"
            values[key] = value

        def get_password(self, service: str, key: str) -> str | None:
            return values.get(key)

        def delete_password(self, service: str, key: str) -> None:
            values.pop(key, None)

    Native.__module__ = "keyring.backends.macOS"
    Native.__name__ = "Keyring"
    monkeypatch.setattr("keyring.get_keyring", lambda: Native())
    storage = KeyringStorage()
    session = Session(
        TokenResponse.from_dict({"access_token": "secret", "expires_in": 50}),
        user={"sub": "person"},
        context_id="context",
    )
    await storage.write("key", session)
    assert len(values) == 1
    assert await storage.read("key") == session
    await storage.clear("key")
    assert await storage.read("key") is None


def test_tls_context_cannot_disable_verification() -> None:
    import ssl

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with pytest.raises(ThunderIDRuntimeError):
        config(http=HttpOptions(verify=context)).validate()


@pytest.mark.parametrize("expiry", [float("nan"), float("inf"), True, -1, "invalid"])
def test_direct_tokens_reject_invalid_absolute_expiry(expiry: Any) -> None:
    with pytest.raises(ThunderIDRuntimeError):
        TokenResponse("token", expires_at=expiry)


async def test_injected_transport_is_caller_owned() -> None:
    class CallerTransport(httpx.AsyncBaseTransport):
        closed = False

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            assert not self.closed
            return httpx.Response(200, json={})

        async def aclose(self) -> None:
            self.closed = True

    seam = CallerTransport()
    first = Transport(config(), transport=seam)
    await first.close()
    assert not seam.closed
    second = Transport(config(), transport=seam)
    assert await second.request("GET", "https://issuer.invalid") == {}
    await second.close()
    await seam.aclose()
    assert seam.closed


async def test_keyring_reports_failed_deletion(monkeypatch: pytest.MonkeyPatch) -> None:
    from keyring.errors import PasswordDeleteError

    class Native:
        priority = 1

        def get_password(self, *args: Any) -> str:
            return "existing-sensitive-session"

        def delete_password(self, *args: Any) -> None:
            raise PasswordDeleteError("secret-backend-detail")

    Native.__module__ = "keyring.backends.macOS"
    Native.__name__ = "Keyring"
    monkeypatch.setattr("keyring.get_keyring", lambda: Native())
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await KeyringStorage().clear("key")
    assert caught.value.code == "STORAGE_ERROR"
    assert "secret" not in str(caught.value)


def test_unknown_endpoint_and_mutable_option_objects_rejected() -> None:
    with pytest.raises(ThunderIDRuntimeError):
        config(endpoints={"typo_endpoint": "https://issuer.invalid/token"}).validate()
    with pytest.raises(ThunderIDRuntimeError):
        config(sign_in_options={"mutable": bytearray(b"value")})


async def test_authentic_expiry_check_never_trusts_invalid_stored_tokens() -> None:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key = jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key(), as_dict=True)
    assert isinstance(key, dict)
    transport = Transport(
        config(),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"keys": [key | {"kid": "key", "alg": "RS256"}]})
        ),
    )
    validator = JWTValidator(config(), transport, "https://issuer.invalid/keys")
    claims = {
        "iss": "https://issuer.invalid",
        "aud": "client",
        "sub": "subject",
        "iat": time.time() - 200,
        "exp": time.time() - 100,
    }
    expired = jwt.encode(claims, private, algorithm="RS256", headers={"kid": "key"})
    assert await validator.is_authentic_expired(expired)
    with pytest.raises(ThunderIDRuntimeError):
        await validator.validate(expired)
    valid = jwt.encode(
        claims | {"exp": time.time() + 100}, private, algorithm="RS256", headers={"kid": "key"}
    )
    assert not await validator.is_authentic_expired(valid)
    for patch in (
        {"iss": "https://evil.invalid"},
        {"aud": "other"},
        {"iat": time.time() + 100},
        {"azp": "other"},
        {"sub": 42},
    ):
        malformed = jwt.encode(claims | patch, private, algorithm="RS256", headers={"kid": "key"})
        with pytest.raises(ThunderIDRuntimeError):
            await validator.is_authentic_expired(malformed)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tampered = jwt.encode(claims, other, algorithm="RS256", headers={"kid": "key"})
    with pytest.raises(ThunderIDRuntimeError):
        await validator.is_authentic_expired(tampered)
    await transport.close()
