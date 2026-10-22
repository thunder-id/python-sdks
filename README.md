# ThunderID Python SDK

An async Python SDK for the ThunderID open-source IAM stack, supporting humans, AI agents, and machines. Requires Python 3.11 or later. This implementation targets [SDK specification 0.5](https://github.com/thunder-id/thunderid/blob/main/docs-internals/sdk-development/spec.md); platform omissions and current limitations are listed below.

Install from a checkout:

```sh
python -m pip install .
```

Use a registered confidential client with `client_credentials` enabled and permissions on the target resource server. Supply the deployment URL and client credentials through your application's secret configuration:

```python
import asyncio
import os

from thunderid import AsyncThunderIDClient, ThunderIDConfig, TokenRequestOptions


async def main():
    config = ThunderIDConfig(
        base_url=os.environ["THUNDERID_BASE_URL"],
        client_id=os.environ["THUNDERID_CLIENT_ID"],
        client_secret=os.environ["THUNDERID_CLIENT_SECRET"],
        grant_type="client_credentials",
        scopes=(),
        token_request=TokenRequestOptions(auth_method="client_secret_basic"),
    )
    async with AsyncThunderIDClient(config) as client:
        token = await client.get_agent_token(
            resource=os.environ["THUNDERID_RESOURCE"],
            scopes=os.environ.get("THUNDERID_PERMISSION_SCOPES", "").split(),
        )
        # Send token.access_token to the intended API in an Authorization: Bearer header.
        # Never print or log the token.


asyncio.run(main())
```

The default session store uses a native OS credential store and fails closed if none is available. `MemoryStorage()` is an explicit process-only alternative for ephemeral applications or tests; it provides no secure persistence. Each client has a separate session context by default. An explicit `instance_id` enables deliberate persisted-session reuse. Use one client per user/session context in a server application.

For browser sign-in, configure `after_sign_in_url` with a registered callback URL, call `await client.sign_in()`, open the returned `AuthorizationRequest.url`, then complete on the same live client with `await client.handle_redirect_callback(url)` or structured parameters, `await client.handle_redirect_callback(code=code, state=state)`. Use `error=error` with state for a denied authorization; do not mix a URL with structured fields. The SDK verifies PKCE/state and the ID token, then stores the session. `await client.get_access_token()` and `await client.get_obo_token(authorization=session)` refresh owned interactive tokens near expiry; `await client.sign_out()` attempts revocation and clears local state even if revocation fails, reporting the error.

[API reference](docs/reference.md) covers configuration, returned types, errors, delegation, and storage. [Security notes](docs/security.md) explain trust boundaries and deployment limits.

## Runnable examples

Run `python examples/client_credentials.py` (or another example) after installation. All deployment URLs and client configuration come from environment variables. No example prints tokens. Token-exchange inputs and callback URLs use hidden prompts instead of storing bearer credentials in environment variables.

| Example | Required environment and server setup |
| --- | --- |
| [Machine identity](examples/client_credentials.py) | `THUNDERID_BASE_URL`, `THUNDERID_CLIENT_ID`, `THUNDERID_CLIENT_SECRET`, `THUNDERID_CLIENT_AUTH_METHOD=client_secret_basic`; client-credentials grant enabled. Set `THUNDERID_RESOURCE` and `THUNDERID_PERMISSION_SCOPES` for resource permissions. |
| [Interactive authorization](examples/interactive.py) | Base URL, client ID, and `THUNDERID_CALLBACK_URL`; authorization-code grant and callback registered. Uses the OS browser and a hidden callback URL prompt. Public clients omit secret/auth method. |
| [Embedded flow](examples/embedded.py) | HTTPS base URL, `THUNDERID_APPLICATION_ID`; an application with an authentication flow. Enter configured action/field identifiers and JSON input values at prompts. |
| [Explicit token exchange](examples/token_exchange.py) | Base URL, client ID/authentication; token exchange enabled and subject/actor accepted by server policy. Supply subject/actor tokens through hidden prompts. |
| [CIBA approval](examples/ciba.py) | Base URL, authenticated client, `THUNDERID_LOGIN_HINT`; poll-mode CIBA enabled and a working approval channel. Optional `THUNDERID_BINDING_MESSAGE`, `THUNDERID_CIBA_TIMEOUT`. |

Optional shared settings: `THUNDERID_CA_FILE` for a trusted CA bundle, `THUNDERID_SCOPES` for interactive scopes (default `openid`), and `THUNDERID_MEMORY_STORAGE=1` to explicitly opt into process-only sample storage. Permission scopes are space separated. The CIBA example always includes `openid`. Keep secrets out of shell history, committed files, and logs.

## Current limits

This release provides an async client, token/delegation helpers, and flow orchestration. It has no synchronous client, framework UI, management API, arbitrary outbound API proxy, access-token authorization middleware, automatic callback listener, organization switching, or backchannel logout handler. CIBA supports polling only. DPoP, encrypted ID tokens, passkey/platform APIs, isolated browser storage, and encrypted logout-token handling are unsupported. Unknown configuration keys fail rather than being silently ignored.

Redirect `sign_up()` raises `UNSUPPORTED_OPERATION` because the current server has no supported authorization registration selector; embedded registration is supported. Embedded completion returns a verified flow assertion, not an OAuth access-token session. A completed CIBA request returns a separate token response without replacing the interactive session. Machine-token cache values use the configured secure storage adapter; only their lookup metadata is process local. CIBA results belong to the caller, and the SDK retains only weak ownership references. Clearing local state cannot recall tokens already handed to your application.

## Development

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
uv build
```

Tests use mock HTTP transport and run offline. Real-server coverage and any environment requirements are recorded in [tests/e2e/README.md](tests/e2e/README.md). Follow [AGENTS.md](AGENTS.md) when contributing. Design: [discussion 5877](https://github.com/thunder-id/thunderid/discussions/5877); tracking issue: [2530](https://github.com/thunder-id/thunderid/issues/2530).

## Contributing

See the shared [Contributing Guide](https://thunderid.dev/community/overview) for ways to contribute and project guidelines.

For code contributions, follow [Contributing Code](https://thunderid.dev/community/contributing/contributing-code/prerequisites/) for prerequisites and instructions for running ThunderID in development mode. Use the Python-specific checks above for this repository.

## License

This project is licensed under the [Apache License 2.0](LICENSE).
