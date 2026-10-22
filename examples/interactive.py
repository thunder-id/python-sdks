# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Keep the client alive while completing a registered browser callback."""

import asyncio
import webbrowser
from getpass import getpass

from _common import config

from thunderid import AsyncThunderIDClient, AuthorizationRequest


async def main() -> None:
    async with AsyncThunderIDClient(config()) as client:
        request = await client.sign_in()
        assert isinstance(request, AuthorizationRequest)
        webbrowser.open(request.url)
        print("Complete sign-in in the browser, then copy the full callback URL.")
        callback = await asyncio.to_thread(getpass, "Callback URL (hidden): ")
        session = await client.handle_redirect_callback(callback)
        token = await client.get_obo_token(authorization=session)
        print("Interactive authorization completed; known lifetime:", token.expires_in is not None)
        await client.sign_out()


if __name__ == "__main__":
    asyncio.run(main())
