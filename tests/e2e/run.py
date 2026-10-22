# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Start the provisioned server, run real-server tests, and stop owned processes."""

import json
import os
import ssl
import subprocess
import sys
import time
from pathlib import Path

import httpx


def main() -> int:
    settings_path = Path(sys.argv[1]).resolve()
    settings = json.loads(settings_path.read_text())
    home = Path(settings["server_home"])
    tls = ssl.create_default_context(cafile=settings["ca_file"])
    with (settings_path.parent / "server.log").open("w") as log:
        process = subprocess.Popen([str(home / "thunderid")], cwd=home, stdout=log, stderr=log)
        try:
            with httpx.Client(verify=tls, trust_env=False, timeout=2) as http:
                for _ in range(60):
                    if process.poll() is not None:
                        raise RuntimeError("Test server exited before becoming ready")
                    try:
                        response = http.get(
                            settings["base_url"] + "/.well-known/openid-configuration"
                        )
                        if response.status_code == 200:
                            break
                    except httpx.HTTPError:
                        pass
                    time.sleep(0.5)
                else:
                    raise RuntimeError("Test server did not become ready")
            environment = dict(os.environ, THUNDERID_E2E_SETTINGS=str(settings_path))
            return subprocess.run(
                [sys.executable, "-m", "pytest", "tests/e2e", "-q", "--tb=short"],
                env=environment,
                check=False,
            ).returncode
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


if __name__ == "__main__":
    raise SystemExit(main())
