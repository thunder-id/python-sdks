# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Provision a disposable real server from a locally supplied distribution archive."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import zipfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--source", type=Path)
    args = parser.parse_args()
    destination = args.directory.resolve()
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    with zipfile.ZipFile(args.archive) as archive:
        for member in archive.infolist():
            if not (destination / member.filename).resolve().is_relative_to(destination):
                raise ValueError("Unsafe distribution member")
        archive.extractall(destination)
    homes = list(destination.glob("*/deployment.yaml"))
    if len(homes) != 1:
        raise ValueError("Expected one server distribution")
    home = homes[0].parent
    # A distribution may carry initialized databases; never reuse them for this fixture.
    shutil.rmtree(home / "database", ignore_errors=True)
    (home / "database").mkdir()
    if args.binary:
        shutil.copy2(args.binary, home / "thunderid")
    if args.source:
        # Bootstrap resources and SQL schemas must match the freshly built binary.
        source = args.source.resolve()
        for path in ("bootstrap",):
            shutil.rmtree(home / path)
            shutil.copytree(source / "backend/cmd/server" / path, home / path)
        shutil.rmtree(home / "dbscripts")
        shutil.copytree(source / "backend/dbscripts", home / "dbscripts")
        shutil.copy2(
            source / "backend/cmd/server/config/default.json", home / "config/default.json"
        )
        shutil.copy2(source / "backend/cmd/server/deployment.yaml", home / "deployment.yaml")
        for name in ("setup.sh", "start.sh"):
            shutil.copy2(source / name, home / name)
        shutil.copytree(source / "scripts", home / "scripts", dirs_exist_ok=True)
    for name in ("setup.sh", "start.sh", "thunderid"):
        (home / name).chmod(0o700)
    for script in (home / "scripts").rglob("*.sh"):
        script.chmod(0o700)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    deployment = home / "deployment.yaml"
    deployment.write_text(
        re.sub(r"(?m)^(  port:)\s*\d+", rf"\g<1> {port}", deployment.read_text(), count=1)
    )
    base_url = f"https://localhost:{port}"
    client_secret = secrets.token_urlsafe(32)
    admin_password = secrets.token_urlsafe(24) + "aA1!"
    agent = {
        "resource_type": "agent",
        "id": "python-sdk-e2e-agent",
        "ouId": "01900000-0000-7000-8000-000000000001",
        "type": "default",
        "name": "Python SDK integration test",
        "authFlowId": "01900000-0000-7000-8000-000000000068",
        "inboundAuthConfig": [
            {
                "type": "oauth2",
                "config": {
                    "clientId": "python-sdk-e2e",
                    "clientSecret": client_secret,
                    "grantTypes": [
                        "client_credentials",
                        "authorization_code",
                        "refresh_token",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                        "urn:openid:params:grant-type:ciba",
                    ],
                    "responseTypes": ["code"],
                    "redirectUris": [base_url + "/sdk-callback"],
                    "tokenEndpointAuthMethod": "client_secret_basic",
                    "publicClient": False,
                    "pkceRequired": True,
                },
            }
        ],
    }
    (home / "bootstrap/99-python-sdk.yaml").write_text(json.dumps(agent))
    for database in ("configdb", "entitydb", "runtime_transient", "runtime_persistent"):
        with sqlite3.connect(home / "database" / f"{database}.db") as connection:
            connection.executescript((home / "dbscripts" / database / "sqlite.sql").read_text())
    environment = dict(os.environ, ADMIN_PASSWORD=admin_password)
    with (destination / "setup.log").open("w") as log:
        subprocess.run(
            ["bash", "setup.sh"],
            cwd=home,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
        )
    settings = {
        "base_url": base_url,
        "client_id": "python-sdk-e2e",
        "client_secret": client_secret,
        "redirect_uri": base_url + "/sdk-callback",
        "username": "admin",
        "password": admin_password,
        "ca_file": str(home / "config/certs/server.cert"),
        "server_home": str(home),
    }
    settings_path = destination / "settings.json"
    settings_path.write_text(json.dumps(settings))
    settings_path.chmod(0o600)
    print(f"Provisioned server. Settings: {settings_path}")


if __name__ == "__main__":
    main()
