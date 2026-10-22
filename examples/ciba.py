# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Wait for poll-mode approval while keeping the primary session independent."""

import asyncio
import os

from _common import config, permission_scopes, resource

from thunderid import AsyncThunderIDClient


async def main() -> None:
    async with AsyncThunderIDClient(config()) as client:
        request = await client.initiate_backchannel_authentication(
            login_hint=os.environ["THUNDERID_LOGIN_HINT"],
            resource=resource(),
            scopes=["openid", *permission_scopes()],
            binding_message=os.environ.get("THUNDERID_BINDING_MESSAGE"),
        )
        print("Approve the authentication request through the configured authentication channel.")
        tokens = await client.await_backchannel_authentication(
            request, timeout=float(os.environ.get("THUNDERID_CIBA_TIMEOUT", "120"))
        )
        token = await client.get_obo_token(authorization=tokens)
        print("Backchannel authorization completed; known lifetime:", token.expires_in is not None)


if __name__ == "__main__":
    asyncio.run(main())
