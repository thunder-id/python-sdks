# Real-server tests

The offline suite skips this directory unless `THUNDERID_E2E_SETTINGS` is set. These tests use a disposable ThunderID server with TLS verification, generated credentials, and isolated databases. They do not reuse your development stack.

Install dependencies with `uv sync --locked`. Supply a local ThunderID distribution archive for your operating system. To test a particular source revision, build its backend and pass both the binary and matching source directory:

```sh
go -C "$THUNDERID_SOURCE/backend" build -o "$PWD/reports/thunderid" ./cmd/server
uv run python tests/e2e/provision.py "$THUNDERID_ARCHIVE" \
  --directory "$PWD/reports/runtime" \
  --binary "$PWD/reports/thunderid" --source "$THUNDERID_SOURCE"
uv run python tests/e2e/run.py reports/runtime/settings.json
```

Create `reports/` before building. The target provisioning directory must not already exist. The runner starts and stops its server. Provisioning creates fresh schemas and bootstrap resources, never mutates the source checkout, and generates a trusted local certificate. Server assets must match the operating system. The scheduled workflow pins the server source revision and downloads runtime assets separately.

Generated settings, credentials, server logs, and databases stay under ignored `reports/`. Do not commit or upload them. API fixtures clean up owned resources; deleting your generated runtime directory after the run removes the remaining test-only bootstrap identity and databases.

The tests exercise actual HTTP endpoints using the SDK. A Gate-equivalent test driver completes server-described flow actions through the Flow API using action identifiers. This verifies server protocol integration, not browser UI rendering. The CLI examples are separately typechecked and compiled.

Repository setup is still required before releases: configure the protected `pypi` environment and its `PYPI_TOKEN` secret, reserve the package name, and make checks/parity required in branch protection. No package has been published by this implementation.
