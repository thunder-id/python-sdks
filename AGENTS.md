# ThunderID Python SDK

Read the canonical [SDK development skill](https://github.com/thunder-id/thunderid/blob/main/.agent/skills/sdk-development/SKILL.md), [specification](https://github.com/thunder-id/thunderid/blob/main/docs-internals/sdk-development/spec.md), and [threat model](https://github.com/thunder-id/thunderid/blob/main/docs-internals/sdk-development/threat-model.md) before changing SDK code. Do not copy those documents into this repository.

Design: https://github.com/thunder-id/thunderid/discussions/5877
Issue: https://github.com/thunder-id/thunderid/issues/2530

Use Python 3.11+, typed async APIs, and the canonical SDK operation names in snake_case. Keep credentials out of logs, exceptions, and object representations. Do not disable TLS or mandatory token checks. Unit tests must run offline. Tests and local runtime secrets belong in ignored reports/.

Run `uv sync --locked`, `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy src`, `uv run pytest`, and `uv build`. See tests/e2e/README.md for real-server tests. Report skipped checks honestly.

Do not commit or publish without a user request. All requested commits require signoff. No automatic release or production credentials in samples.
