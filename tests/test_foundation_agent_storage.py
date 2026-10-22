# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Secure adapter ownership and lifecycle checks for agent caching."""

from __future__ import annotations

import asyncio
import gc
import time
import weakref
from typing import Any

import httpx
import pytest

from thunderid import (
    AsyncThunderIDClient,
    MemoryStorage,
    Session,
    ThunderIDConfig,
    ThunderIDRuntimeError,
)


class RecordingStorage(MemoryStorage):
    def __init__(self) -> None:
        super().__init__()
        self.writes: list[str] = []
        self.clears: list[str] = []
        self.fail_read = False
        self.fail_write = False
        self.fail_clear = False

    async def read(self, key: str) -> Session | None:
        if key.startswith("agent:") and self.fail_read:
            raise ThunderIDRuntimeError("STORAGE_ERROR", "Secure read failed.")
        return await super().read(key)

    async def write(self, key: str, session: Session) -> None:
        self.writes.append(key)
        if self.fail_write:
            raise ThunderIDRuntimeError("STORAGE_ERROR", "Secure write failed.")
        await super().write(key, session)

    async def clear(self, key: str) -> None:
        self.clears.append(key)
        if self.fail_clear and key.startswith("agent:"):
            raise ThunderIDRuntimeError("STORAGE_ERROR", "Secure deletion failed.")
        await super().clear(key)


async def make_client(storage: RecordingStorage, handler: Any = None) -> AsyncThunderIDClient:
    client = AsyncThunderIDClient(
        ThunderIDConfig(
            "https://issuer.invalid",
            client_id="client",
            discovery=False,
            storage=storage,
            endpoints={"backchannel_authentication_endpoint": "https://issuer.invalid/backchannel"},
        ),
        transport=httpx.MockTransport(
            handler
            or (
                lambda _: httpx.Response(200, json={"access_token": "sensitive", "expires_in": 300})
            )
        ),
    )
    await client.initialize()
    return client


async def test_cache_keeps_metadata_only_and_reads_secure_adapter() -> None:
    storage = RecordingStorage()
    client = await make_client(storage)
    token = await client.get_agent_token("https://api.invalid", ["scope"])
    token_ref = weakref.ref(token)
    assert "sensitive" not in repr(client._agent_cache)
    assert len(storage.writes) == 1 and storage.writes[0].startswith("agent:")
    del token
    gc.collect()
    assert token_ref() is None
    assert (
        await client.get_agent_token("https://api.invalid", ["scope"])
    ).access_token == "sensitive"
    storage.fail_read = True
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.get_agent_token("https://api.invalid", ["scope"])
    assert caught.value.code == "STORAGE_ERROR"
    storage.fail_read = False
    await client.close()
    assert not storage._sessions


@pytest.mark.parametrize("action", ["close", "clear_session", "sign_out", "re_initialize"])
async def test_lifecycle_deletes_auxiliary_keys(action: str) -> None:
    storage = RecordingStorage()
    client = await make_client(storage)
    await client.get_agent_token()
    key = storage.writes[0]
    await getattr(client, action)()
    assert await storage.read(key) is None
    assert not client._agent_cache
    assert not client._agent_storage_keys
    await client.close()


async def test_write_failure_never_returns_or_caches_token() -> None:
    storage = RecordingStorage()
    client = await make_client(storage)
    storage.fail_write = True
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.get_agent_token()
    assert caught.value.code == "STORAGE_ERROR"
    assert not client._agent_cache and not storage._sessions
    await client.close()


async def test_cleanup_failure_reported_and_retried() -> None:
    storage = RecordingStorage()
    client = await make_client(storage)
    await client.get_agent_token()
    storage.fail_clear = True
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await client.clear_session()
    assert caught.value.code == "STORAGE_ERROR"
    assert client._agent_storage_keys and not client._agent_cache
    storage.fail_clear = False
    await client.close()
    assert not storage._sessions


async def test_expired_entry_deleted_before_replacement(monkeypatch: pytest.MonkeyPatch) -> None:
    storage = RecordingStorage()
    client = await make_client(storage)
    await client.get_agent_token()
    key = storage.writes[0]
    now = time.time()
    monkeypatch.setattr("thunderid.delegation.time.time", lambda: now + 400)
    await client.get_agent_token()
    assert key in storage.clears
    assert len(storage.writes) == 2
    await client.close()


async def test_cancelled_write_finishes_then_deletes_without_cache_resurrection() -> None:
    started, release = asyncio.Event(), asyncio.Event()

    class DelayedStorage(RecordingStorage):
        async def write(self, key: str, session: Session) -> None:
            started.set()
            await release.wait()
            await super().write(key, session)

    storage = DelayedStorage()
    client = await make_client(storage)
    task = asyncio.create_task(client.get_agent_token())
    await started.wait()
    task.cancel()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not client._agent_cache and not storage._sessions
    await client.close()


async def test_signout_during_write_waits_for_secure_cleanup() -> None:
    started, release = asyncio.Event(), asyncio.Event()

    class DelayedStorage(RecordingStorage):
        async def write(self, key: str, session: Session) -> None:
            started.set()
            await release.wait()
            await super().write(key, session)

    storage = DelayedStorage()
    client = await make_client(storage)
    task = asyncio.create_task(client.get_agent_token())
    await started.wait()
    signout = asyncio.create_task(client.sign_out())
    await asyncio.sleep(0)
    release.set()
    with pytest.raises(ThunderIDRuntimeError) as caught:
        await task
    assert caught.value.code == "AUTHORIZATION_CANCELLED"
    await signout
    assert not storage._sessions and not client._agent_cache
    await client.close()


async def test_ciba_registry_does_not_retain_returned_credentials() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/backchannel":
            return httpx.Response(
                200, json={"auth_req_id": "request-secret", "expires_in": 60, "interval": 1}
            )
        return httpx.Response(200, json={"access_token": "ciba-secret", "expires_in": 300})

    storage = RecordingStorage()
    client = await make_client(storage, handler)
    request = await client.initiate_backchannel_authentication(login_hint="person")
    client._owned_request(request).next_poll = time.monotonic()
    result = await client.poll_backchannel_authentication(request)
    assert result.tokens is not None
    token_ref = weakref.ref(result.tokens)
    assert "ciba-secret" not in repr(client._backchannel_tokens)
    assert not storage.writes
    assert await client.get_obo_token(authorization=result.tokens) is result.tokens
    del result
    gc.collect()
    assert token_ref() is None
    await client.close()
