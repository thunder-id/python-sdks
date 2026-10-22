# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Explicit RFC 8693 exchange of caller-supplied authorization."""

import asyncio
import os
from getpass import getpass

from _common import config, permission_scopes, resource

from thunderid import AsyncThunderIDClient, TokenExchangeAuthorization


async def main() -> None:
    subject = await asyncio.to_thread(getpass, "Subject token (hidden): ")
    actor = await asyncio.to_thread(getpass, "Actor token, if required (hidden, blank to omit): ")
    authorization = TokenExchangeAuthorization(
        subject_token=subject,
        actor_token=actor or None,
        subject_token_type=os.environ.get(
            "THUNDERID_SUBJECT_TOKEN_TYPE", "urn:ietf:params:oauth:token-type:jwt"
        ),
    )
    async with AsyncThunderIDClient(config()) as client:
        token = await client.get_obo_token(
            authorization=authorization, resource=resource(), scopes=permission_scopes()
        )
        print("Exchanged token acquired; known lifetime:", token.expires_in is not None)
        # The primary session is unchanged. Use the returned token only for its intended API.


if __name__ == "__main__":
    asyncio.run(main())
