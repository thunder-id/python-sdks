# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Session lifetime regression checks across foundation/client boundaries."""

from __future__ import annotations

from typing import Any

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


def client_for(response: dict[str, Any]) -> AsyncThunderIDClient:
    return AsyncThunderIDClient(
        ThunderIDConfig(
            "https://issuer.invalid", client_id="client", discovery=False, storage=MemoryStorage()
        ),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json=response)),
    )


async def test_unknown_session_lifetime_is_not_authenticated_or_returned() -> None:
    client = client_for({})
    await client.initialize()
    await client.set_session(Session(TokenResponse("opaque")))
    assert not await client.is_signed_in()
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.get_access_token()
    assert caught.value.code == "SESSION_EXPIRED"
    await client.close()


async def test_unknown_lifetime_can_refresh_to_known_lifetime() -> None:
    client = client_for({"access_token": "updated", "expires_in": 60})
    await client.initialize()
    await client.set_session(Session(TokenResponse("opaque", refresh_token="refresh")))
    assert not await client.is_signed_in()
    assert await client.get_access_token() == "updated"
    assert await client.is_signed_in()
    await client.close()


async def test_refresh_without_expiry_does_not_make_cached_token_valid() -> None:
    client = client_for({"access_token": "updated"})
    await client.initialize()
    await client.set_session(Session(TokenResponse("opaque", refresh_token="refresh")))
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.get_access_token()
    assert caught.value.code == "SESSION_EXPIRED"
    assert not await client.is_signed_in()
    await client.close()


async def test_unknown_machine_token_is_returned_fresh_but_never_reused() -> None:
    from thunderid import TokenRequestOptions

    calls = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"access_token": "fresh"})

    client = AsyncThunderIDClient(
        ThunderIDConfig(
            "https://issuer.invalid",
            client_id="client",
            client_secret="secret",
            grant_type="client_credentials",
            discovery=False,
            storage=MemoryStorage(),
            token_request=TokenRequestOptions(auth_method="client_secret_basic"),
        ),
        transport=httpx.MockTransport(handler),
    )
    await client.initialize()
    assert await client.get_access_token() == "fresh"
    assert not await client.is_signed_in()
    assert await client.get_access_token() == "fresh"
    assert calls == 2
    await client.close()


async def interactive_client() -> tuple[AsyncThunderIDClient, Session]:
    from urllib.parse import urlencode

    from thunderid import AuthorizationRequest

    client = AsyncThunderIDClient(
        ThunderIDConfig(
            "https://issuer.invalid",
            client_id="client",
            discovery=False,
            storage=MemoryStorage(),
            scopes=("profile",),
            after_sign_in_url="https://application.invalid/callback",
        ),
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                json={
                    "access_token": "secret",
                    "refresh_token": "refresh",
                    "expires_in": 10,
                },
            )
        ),
    )
    await client.initialize()
    request = await client.sign_in()
    assert isinstance(request, AuthorizationRequest)
    session = await client.handle_redirect_callback(
        "https://application.invalid/callback?"
        + urlencode({"state": request.state, "code": "code"})
    )
    return client, session


async def test_original_obo_session_survives_refresh_but_copies_and_intermediates_do_not() -> None:
    from dataclasses import replace

    client, original = await interactive_client()
    await client.get_access_token()
    intermediate = client._session
    assert intermediate is not original
    assert (await client.get_obo_token(authorization=original)) is client._session.tokens
    await client.get_access_token()
    assert (await client.get_obo_token(authorization=original)) is client._session.tokens
    assert (await client.get_obo_token(authorization=client._session)) is client._session.tokens
    for invalid in (replace(original), intermediate):
        with pytest.raises(ThunderIDRuntimeError) as caught:
            await client.get_obo_token(authorization=invalid)
        assert caught.value.code == "INVALID_AUTHORIZATION"
    await client.close()


@pytest.mark.parametrize("operation", ["clear", "signout", "reinitialize", "import", "new_signin"])
async def test_original_obo_root_ends_with_its_session_family(operation: str) -> None:
    from urllib.parse import urlencode

    from thunderid import AuthorizationRequest

    client, original = await interactive_client()
    await client.get_access_token()
    if operation == "clear":
        await client.clear_session()
    elif operation == "signout":
        await client.sign_out()
    elif operation == "reinitialize":
        await client.re_initialize()
    elif operation == "import":
        await client.set_session(
            Session(TokenResponse.from_dict({"access_token": "imported", "expires_in": 60}))
        )
    else:
        request = await client.sign_in()
        assert isinstance(request, AuthorizationRequest)
        await client.handle_redirect_callback(
            "https://application.invalid/callback?"
            + urlencode({"state": request.state, "code": "new"})
        )
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.get_obo_token(authorization=original)
    assert caught.value.code == "INVALID_AUTHORIZATION"
    await client.close()


async def test_invalidation_rejects_current_session_before_signout_network_finishes() -> None:
    client, original = await interactive_client()
    client._invalidate_authorizations()
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.get_obo_token(authorization=original)
    assert caught.value.code == "INVALID_AUTHORIZATION"
    await client.close()
