# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Environment-only server configuration shared by runnable examples."""

import os

from thunderid import (
    HttpOptions,
    MemoryStorage,
    ThunderIDConfig,
    TokenRequestOptions,
)


def config(
    *,
    mode: str = "redirect",
    grant_type: str = "authorization_code",
    scopes: tuple[str, ...] | None = None,
) -> ThunderIDConfig:
    return ThunderIDConfig(
        base_url=os.environ["THUNDERID_BASE_URL"],
        client_id=os.environ.get("THUNDERID_CLIENT_ID"),
        client_secret=os.environ.get("THUNDERID_CLIENT_SECRET"),
        application_id=os.environ.get("THUNDERID_APPLICATION_ID"),
        after_sign_in_url=os.environ.get("THUNDERID_CALLBACK_URL"),
        mode=mode,
        grant_type=grant_type,
        scopes=scopes
        if scopes is not None
        else tuple(os.environ.get("THUNDERID_SCOPES", "openid").split()),
        http=HttpOptions(verify=os.environ.get("THUNDERID_CA_FILE") or True),
        token_request=TokenRequestOptions(
            auth_method=os.environ.get("THUNDERID_CLIENT_AUTH_METHOD", "none")
        ),
        storage=MemoryStorage() if os.environ.get("THUNDERID_MEMORY_STORAGE") == "1" else None,
    )


def resource() -> str | None:
    return os.environ.get("THUNDERID_RESOURCE")


def permission_scopes() -> list[str]:
    return os.environ.get("THUNDERID_PERMISSION_SCOPES", "").split()
