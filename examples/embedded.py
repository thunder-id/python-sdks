# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Drive a configured flow by its field and action identifiers."""

import asyncio
import json
from getpass import getpass

from _common import config

from thunderid import AsyncThunderIDClient, FlowResult


async def main() -> None:
    async with AsyncThunderIDClient(config(mode="embedded")) as client:
        step = await client.sign_in()
        assert isinstance(step, FlowResult)
        while step.flow_status != "COMPLETE":
            # Supply the identifiers defined by your application's configured flow.
            # A real UI renders step.data; never log its potentially sensitive contents.
            action = await asyncio.to_thread(input, "Action identifier (blank if absent): ")
            encoded = await asyncio.to_thread(getpass, "Input field/value JSON (hidden): ")
            inputs = json.loads(encoded)
            if not isinstance(inputs, dict) or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in inputs.items()
            ):
                raise ValueError("Expected an object containing string fields and values.")
            step = await client.sign_in(
                execution_id=step.execution_id, action=action or None, inputs=inputs
            )
            assert isinstance(step, FlowResult)
        print("Embedded flow completed with a verified authentication assertion.")
        # Embedded completion returns an assertion, not an OAuth access-token session.
        # Use it only with a server integration that explicitly accepts flow assertions.


if __name__ == "__main__":
    asyncio.run(main())
