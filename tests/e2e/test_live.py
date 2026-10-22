# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Opt-in integration tests against the provisioned, disposable real server."""

import json
import os
import ssl
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from thunderid import (
    AsyncThunderIDClient,
    AuthorizationRequest,
    HttpOptions,
    MemoryStorage,
    ThunderIDConfig,
    TokenExchangeAuthorization,
    TokenRequestOptions,
)

SETTINGS = os.environ.get("THUNDERID_E2E_SETTINGS")
pytestmark = pytest.mark.skipif(
    not SETTINGS, reason="Set THUNDERID_E2E_SETTINGS for real-server tests"
)


@pytest.fixture
def settings():
    return json.loads(Path(SETTINGS).read_text())


def config(settings, **changes):
    values = {
        "base_url": settings["base_url"],
        "client_id": settings["client_id"],
        "client_secret": settings["client_secret"],
        "after_sign_in_url": settings["redirect_uri"],
        "token_request": TokenRequestOptions(auth_method="client_secret_basic"),
        "storage": MemoryStorage(),
        "http": HttpOptions(verify=ssl.create_default_context(cafile=settings["ca_file"])),
    }
    values.update(changes)
    return ThunderIDConfig(**values)


async def complete_login(settings, request):
    """Drive the server-described login steps without a browser or saved auth state."""
    tls = ssl.create_default_context(cafile=settings["ca_file"])
    async with httpx.AsyncClient(verify=tls, follow_redirects=False, trust_env=False) as browser:
        response = await browser.get(request.url)
        assert response.status_code == 302
        query = parse_qs(urlsplit(response.headers["location"]).query)
        assert "executionId" in query, "Authorization did not start the authentication flow"
        execution_id = query["executionId"][0]
        response = await browser.post(
            settings["base_url"] + "/flow/execute", json={"executionId": execution_id}
        )
        assert response.status_code == 200
        step = response.json()
        actions = step["data"]["actions"]
        # Select by the server's action/input identifiers, not presentation text.
        response = await browser.post(
            settings["base_url"] + "/flow/execute",
            json={
                "executionId": execution_id,
                "action": actions[0]["ref"],
                "challengeToken": step["challengeToken"],
                "inputs": {"username": settings["username"], "password": settings["password"]},
            },
        )
        assert response.status_code == 200
        completion = response.json()
        assert completion.get("flowStatus") == "COMPLETE", "Login flow did not complete"
        response = await browser.post(
            settings["base_url"] + "/oauth2/auth/callback",
            json={"authId": query["authId"][0], "assertion": completion["assertion"]},
        )
        assert response.status_code == 200
        return response.json()["redirect_uri"]


async def test_live_agent_token_and_machine_lifecycle(settings):
    async with AsyncThunderIDClient(
        config(settings, grant_type="client_credentials", scopes=())
    ) as client:
        token = await client.get_agent_token()
        assert token.expires_in > 0
        assert await client.get_agent_token() == token
        claims = client.decode_jwt_token(token.access_token)
        # Inspection of a server-issued fixture only, never an authorization decision.
        assert claims["sub"] == "python-sdk-e2e-agent"
        await client.get_access_token()
        assert await client.is_signed_in()
        await client.sign_out()
        assert not await client.is_signed_in()


async def test_live_interactive_obo_exchange_and_signout(settings):
    async with AsyncThunderIDClient(config(settings)) as client:
        request = await client.sign_in()
        assert isinstance(request, AuthorizationRequest)
        callback = await complete_login(settings, request)
        session = await client.handle_redirect_callback(callback)
        assert session.user is not None
        assert await client.is_signed_in()
        assert await client.get_obo_token(authorization=session) is session.tokens
        claims = client.decode_jwt_token(session.tokens.access_token)
        assert claims["act"]["sub"] == "python-sdk-e2e-agent"
        agent = await client.get_agent_token()
        delegated = await client.get_obo_token(
            authorization=TokenExchangeAuthorization(
                session.tokens.access_token, agent.access_token
            ),
            scopes=["openid"],
        )
        assert delegated.access_token
        assert await client.get_access_token() == session.tokens.access_token
        await client.sign_out()
        assert not await client.is_signed_in()
