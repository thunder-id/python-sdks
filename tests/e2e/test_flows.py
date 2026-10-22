# Copyright 2026 The ThunderID Authors
# SPDX-License-Identifier: Apache-2.0

"""Real CIBA approval using disposable API resources and a local notification sink."""

import asyncio
import json
import os
import re
import secrets
import ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

import httpx
import pytest
from test_live import complete_login

from thunderid import (
    AsyncThunderIDClient,
    HttpOptions,
    MemoryStorage,
    ThunderIDConfig,
    TokenRequestOptions,
)

SETTINGS = os.environ.get("THUNDERID_E2E_SETTINGS")
pytestmark = pytest.mark.skipif(
    not SETTINGS, reason="Set THUNDERID_E2E_SETTINGS for real-server tests"
)


def ciba_nodes(sender_id):
    inputs = [
        {"ref": "username_input", "identifier": "username", "type": "TEXT_INPUT", "required": True},
        {
            "ref": "password_input",
            "identifier": "password",
            "type": "PASSWORD_INPUT",
            "required": True,
        },
    ]

    def task(identifier, executor, successor, **extra):
        return {
            "id": identifier,
            "type": "TASK_EXECUTION",
            "executor": executor,
            "onSuccess": successor,
            **extra,
        }

    return [
        {"id": "start", "type": "START", "onSuccess": "identify"},
        task(
            "identify",
            {"name": "IdentifyingExecutor", "mode": "identify"},
            "invite",
            properties={"loginHintAttribute": "username"},
        ),
        task("invite", {"name": "InviteExecutor", "mode": "generate"}, "notify"),
        task(
            "notify",
            {"name": "SMSExecutor"},
            "sent",
            properties={"senderId": sender_id, "smsTemplate": "ciba-notification"},
        ),
        {"id": "sent", "type": "PROMPT", "next": "verify"},
        task(
            "verify",
            {
                "name": "InviteExecutor",
                "mode": "verify",
                "inputs": [
                    {
                        "ref": "invite",
                        "identifier": "inviteToken",
                        "type": "HIDDEN",
                        "required": True,
                    }
                ],
            },
            "credentials",
        ),
        {
            "id": "credentials",
            "type": "PROMPT",
            "prompts": [
                {"inputs": inputs, "action": {"ref": "authenticate", "nextNode": "authenticate"}}
            ],
        },
        task("authenticate", {"name": "CredentialsAuthExecutor", "inputs": inputs}, "assert"),
        task("assert", {"name": "AuthAssertExecutor"}, "end"),
        {"id": "end", "type": "END"},
    ]


@pytest.mark.parametrize("scenario", ["ciba", "embedded"])
async def test_live_ciba_and_embedded_flows(scenario):
    settings = json.loads(Path(SETTINGS).read_text())
    tls = ssl.create_default_context(cafile=settings["ca_file"])
    base = settings["base_url"]
    messages = []

    class Capture(BaseHTTPRequestHandler):
        def do_POST(self):
            messages.append(self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode())
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"success":true}')

        def log_message(self, *args):
            pass

    sink = ThreadingHTTPServer(("127.0.0.1", 0), Capture)
    thread = threading.Thread(target=sink.serve_forever, daemon=True)
    thread.start()
    common = {"base_url": base, "http": HttpOptions(verify=tls), "storage": MemoryStorage()}
    admin = AsyncThunderIDClient(
        ThunderIDConfig(
            **common,
            client_id="CONSOLE",
            after_sign_in_url=base + "/console",
            scopes=("openid", "system"),
        )
    )
    resources = []
    initialized = False
    try:
        await admin.initialize()
        initialized = True
        bootstrap = (
            Path(settings["server_home"]) / "bootstrap/01-default-resources.yaml"
        ).read_text()
        resource = next(
            block
            for block in bootstrap.split("---")
            if "resource_type: resource_server" in block and "name: System" in block
        )
        identifier = re.search(r'(?m)^identifier:\s*["]?([^"\s]+)', resource).group(1)
        authorization = await admin.sign_in(
            options={"resource": settings.get("admin_resource", identifier)}
        )
        await admin.handle_redirect_callback(await complete_login(settings, authorization))
        admin_token = await admin.get_access_token()
        async with httpx.AsyncClient(
            verify=tls, trust_env=False, headers={"Authorization": "Bearer " + admin_token}
        ) as api:

            async def create(path, payload):
                response = await api.post(base + path, json=payload)
                assert response.status_code == 201, (
                    f"Fixture creation failed at {path}: HTTP {response.status_code}"
                )
                value = response.json()
                resources.append((path, value["id"]))
                return value

            try:
                suffix = secrets.token_hex(6)
                ou = await create(
                    "/organization-units",
                    {"name": "Python SDK CIBA " + suffix, "handle": "python-sdk-" + suffix},
                )
                handle = "python-sdk-" + suffix
                await create(
                    "/user-types",
                    {
                        "handle": handle,
                        "displayName": "Python SDK CIBA",
                        "ouId": ou["id"],
                        "allowSelfRegistration": True,
                        "schema": {
                            "username": {"type": "string"},
                            "password": {"type": "string", "credential": True},
                            "mobile_number": {"type": "string"},
                        },
                    },
                )
                password = secrets.token_urlsafe(24) + "aA1!"
                username = "python-" + suffix
                await create(
                    "/users",
                    {
                        "ouId": ou["id"],
                        "type": handle,
                        "attributes": {
                            "username": username,
                            "password": password,
                            "mobile_number": "+1987654321",
                        },
                    },
                )
                sender = await create(
                    "/connections/sms-gateway",
                    {
                        "name": "Python SDK CIBA " + suffix,
                        "url": f"http://127.0.0.1:{sink.server_port}/send",
                        "httpMethod": "POST",
                        "contentType": "JSON",
                    },
                )
                flow = await create(
                    "/flows",
                    {
                        "name": "Python SDK CIBA " + suffix,
                        "handle": handle,
                        "flowType": "AUTHENTICATION",
                        "nodes": ciba_nodes(sender["id"]),
                    },
                )
                if scenario == "embedded":
                    authentication_nodes = [
                        {"id": "start", "type": "START", "onSuccess": "credentials"},
                        *ciba_nodes(sender["id"])[6:],
                    ]
                    authentication = await create(
                        "/flows",
                        {
                            "name": "Python SDK embedded " + suffix,
                            "handle": handle + "-auth",
                            "flowType": "AUTHENTICATION",
                            "nodes": authentication_nodes,
                        },
                    )
                    registration_nodes = json.loads(json.dumps(authentication_nodes))
                    registration_nodes[0]["onSuccess"] = "resolve-type"
                    registration_nodes.insert(
                        1,
                        {
                            "id": "resolve-type",
                            "type": "TASK_EXECUTION",
                            "executor": {"name": "UserTypeResolver"},
                            "onSuccess": "credentials",
                        },
                    )
                    next(node for node in registration_nodes if node["id"] == "authenticate")[
                        "executor"
                    ]["name"] = "ProvisioningExecutor"
                    registration = await create(
                        "/flows",
                        {
                            "name": "Python SDK registration " + suffix,
                            "handle": handle + "-registration",
                            "flowType": "REGISTRATION",
                            "nodes": registration_nodes,
                        },
                    )
                    application = await create(
                        "/applications",
                        {
                            "name": "Python SDK embedded " + suffix,
                            "ouId": ou["id"],
                            "type": "fullstack",
                            "authFlowId": authentication["id"],
                            "registrationFlowId": registration["id"],
                            "isRegistrationFlowEnabled": True,
                            "allowedUserTypes": [handle],
                        },
                    )
                    async with AsyncThunderIDClient(
                        ThunderIDConfig(**common, mode="embedded", application_id=application["id"])
                    ) as embedded:
                        step = await embedded.sign_in(flow_secret=application["flowSecret"])
                        assert step.flow_status == "INCOMPLETE"
                        completed = await embedded.sign_in(
                            execution_id=step.execution_id,
                            action=step.data["data"]["actions"][0]["ref"],
                            challenge_token=step.data["challengeToken"],
                            inputs={"username": username, "password": password},
                        )
                        assert completed.flow_status == "COMPLETE" and completed.assertion
                        assert not await embedded.is_signed_in()
                        step = await embedded.sign_up(flow_secret=application["flowSecret"])
                        assert step.flow_status == "INCOMPLETE"
                        registered_username = username + "-registered"
                        completed = await embedded.sign_up(
                            execution_id=step.execution_id,
                            action=step.data["data"]["actions"][0]["ref"],
                            challenge_token=step.data["challengeToken"],
                            inputs={"username": registered_username, "password": password},
                        )
                        assert completed.flow_status == "COMPLETE" and completed.assertion
                        # This assertion was verified by the SDK for this exact application.
                        registered_id = embedded.decode_jwt_token(completed.assertion)["sub"]
                        resources.append(("/users", registered_id))
                        assert not await embedded.is_signed_in()
                    return
                client_id, client_secret = "python-ciba-" + suffix, secrets.token_urlsafe(32)
                await create(
                    "/applications",
                    {
                        "name": "Python SDK CIBA " + suffix,
                        "ouId": ou["id"],
                        "type": "fullstack",
                        "authFlowId": flow["id"],
                        "isRegistrationFlowEnabled": False,
                        "allowedUserTypes": [handle],
                        "inboundAuthConfig": [
                            {
                                "type": "oauth2",
                                "config": {
                                    "clientId": client_id,
                                    "clientSecret": client_secret,
                                    "grantTypes": [
                                        "urn:openid:params:grant-type:ciba",
                                        "refresh_token",
                                    ],
                                    "tokenEndpointAuthMethod": "client_secret_basic",
                                },
                            }
                        ],
                    },
                )
                async with AsyncThunderIDClient(
                    ThunderIDConfig(
                        **common,
                        client_id=client_id,
                        client_secret=client_secret,
                        token_request=TokenRequestOptions(auth_method="client_secret_basic"),
                    )
                ) as client:
                    request = await client.initiate_backchannel_authentication(
                        login_hint=username, scopes=["openid"]
                    )
                    pending = await client.poll_backchannel_authentication(request)
                    assert pending.status == "authorization_pending"
                    assert messages, "The controlled notification sink received no approval invite"
                    message = messages[-1]

                    def parameter(name):
                        match = re.search(re.escape(name) + r'=([^&"\s\\]+)', message)
                        assert match is not None, "Approval invite omitted a required parameter"
                        return unquote(match[1])

                    assert parameter("auth_req_id") == request.auth_req_id
                    execution_id = parameter("executionId")
                    response = await api.post(
                        base + "/flow/execute",
                        json={
                            "executionId": execution_id,
                            "inputs": {"inviteToken": parameter("inviteToken")},
                        },
                    )
                    assert response.status_code == 200
                    step = response.json()
                    response = await api.post(
                        base + "/flow/execute",
                        json={
                            "executionId": execution_id,
                            "action": step["data"]["actions"][0]["ref"],
                            "challengeToken": step["challengeToken"],
                            "inputs": {"username": username, "password": password},
                        },
                    )
                    assert response.status_code == 200
                    completion = response.json()
                    assert completion.get("flowStatus") == "COMPLETE", (
                        "Approval authentication did not complete"
                    )
                    response = await api.post(
                        base + "/oauth2/auth/callback",
                        json={
                            "authId": request.auth_req_id,
                            "assertion": completion["assertion"],
                            "type": "urn:openid:params:grant-type:ciba",
                        },
                    )
                    assert response.status_code == 200
                    tokens = await client.await_backchannel_authentication(request, timeout=30)
                    assert tokens.id_token and tokens.access_token
                    assert await client.get_obo_token(authorization=tokens) is tokens
                    assert not await client.is_signed_in()
                    response = await api.post(
                        base + "/oauth2/revoke",
                        data={
                            "token": tokens.refresh_token or tokens.access_token,
                            "token_type_hint": "refresh_token"
                            if tokens.refresh_token
                            else "access_token",
                        },
                        auth=(client_id, client_secret),
                    )
                    assert response.status_code == 200
            finally:
                cleanup_errors = []
                for path, identifier in reversed(resources):
                    response = await api.delete(base + path + "/" + identifier)
                    if response.status_code not in (200, 204):
                        cleanup_errors.append(f"{path}: HTTP {response.status_code}")
                assert not cleanup_errors, "Fixture cleanup failed: " + ", ".join(cleanup_errors)
    finally:
        try:
            if initialized:
                await admin.sign_out()
        finally:
            await admin.aclose()
            await asyncio.to_thread(sink.shutdown)
            sink.server_close()
            thread.join(timeout=2)
