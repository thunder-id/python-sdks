# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Obtain a resource-bound machine token without displaying credentials."""

import asyncio

from _common import config, permission_scopes, resource

from thunderid import AsyncThunderIDClient


async def main() -> None:
    async with AsyncThunderIDClient(config(grant_type="client_credentials", scopes=())) as client:
        token = await client.get_agent_token(resource=resource(), scopes=permission_scopes())
        # Pass token.access_token to the intended API's Authorization header in your application.
        print("Machine token acquired; known lifetime:", token.expires_in is not None)


if __name__ == "__main__":
    asyncio.run(main())
