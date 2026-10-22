# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Async storage adapters. Memory storage is an explicit nonpersistent opt-in."""

from __future__ import annotations

import asyncio
import copy
import json
from dataclasses import asdict
from typing import ClassVar, Protocol

import keyring
from keyring.backend import KeyringBackend

from .errors import ThunderIDRuntimeError
from .models import Session, TokenResponse


class Storage(Protocol):
    async def read(self, key: str) -> Session | None: ...
    async def write(self, key: str, session: Session) -> None: ...
    async def clear(self, key: str) -> None: ...


class MemoryStorage:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = asyncio.Lock()

    async def read(self, key: str) -> Session | None:
        async with self._lock:
            return copy.deepcopy(self._sessions.get(key))

    async def write(self, key: str, session: Session) -> None:
        async with self._lock:
            self._sessions[key] = copy.deepcopy(session)

    async def clear(self, key: str) -> None:
        async with self._lock:
            self._sessions.pop(key, None)


class KeyringStorage:
    """One complete JSON session per credential-store item, replaced atomically.

    Only native OS backends are accepted. Composite, file, and third-party backends
    are refused rather than relying on their self-reported priority.
    """

    _TRUSTED: ClassVar[set[tuple[str, str]]] = {
        ("keyring.backends.macOS", "Keyring"),
        ("keyring.backends.Windows", "WinVaultKeyring"),
        ("keyring.backends.SecretService", "Keyring"),
        ("keyring.backends.kwallet", "DBusKeyring"),
        ("keyring.backends.kwallet", "DBusKeyringKWallet4"),
    }

    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    def _get_backend(self) -> KeyringBackend:
        backend = keyring.get_keyring()
        if (
            type(backend).__module__,
            type(backend).__name__,
        ) not in self._TRUSTED or backend.priority <= 0:
            raise ThunderIDRuntimeError(
                "SECURE_STORAGE_UNAVAILABLE", "A supported secure OS credential store is required."
            )
        return backend

    async def read(self, key: str) -> Session | None:
        async with self._lock:
            try:
                raw = await asyncio.to_thread(self._get_backend().get_password, "thunderid", key)
                if raw is None:
                    return None
                data = json.loads(raw)
                tokens = TokenResponse(**data["tokens"])
                return Session(
                    tokens=tokens, user=data.get("user"), context_id=data.get("context_id")
                )
            except ThunderIDRuntimeError:
                raise
            except Exception:  # noqa: BLE001 - native plugins raise backend-specific exceptions; sanitize them.
                raise ThunderIDRuntimeError(
                    "STORAGE_ERROR", "The secure session could not be read."
                ) from None

    async def write(self, key: str, session: Session) -> None:
        async with self._lock:
            try:
                raw = json.dumps(asdict(session), allow_nan=False, separators=(",", ":"))
                await asyncio.to_thread(self._get_backend().set_password, "thunderid", key, raw)
            except ThunderIDRuntimeError:
                raise
            except Exception:  # noqa: BLE001 - native plugins raise backend-specific exceptions; sanitize them.
                raise ThunderIDRuntimeError(
                    "STORAGE_ERROR", "The secure session could not be stored."
                ) from None

    async def clear(self, key: str) -> None:
        async with self._lock:
            try:
                backend = self._get_backend()
                existing = await asyncio.to_thread(backend.get_password, "thunderid", key)
                if existing is not None:
                    await asyncio.to_thread(backend.delete_password, "thunderid", key)
            except ThunderIDRuntimeError:
                raise
            except Exception:  # noqa: BLE001 - native plugins raise backend-specific exceptions; sanitize them.
                raise ThunderIDRuntimeError(
                    "STORAGE_ERROR", "The secure session could not be cleared."
                ) from None
