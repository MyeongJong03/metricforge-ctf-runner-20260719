#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import pathlib
import re
import subprocess
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET


ROLE_ARN = "arn:aws:iam::125746528491:role/metricforge-entry-b8358a07fc"
ROLE_NAME = "metricforge-entry-b8358a07fc"
REGION = "ap-northeast-2"
BUCKET = "metricforge-recovery-artifacts-125746528491"


def result_error(stderr: str) -> dict:
    match = re.search(r"An error occurred \(([^)]+)\)", stderr)
    return {"ok": False, "error": match.group(1) if match else "command_failed"}


def aws(env: dict, args: list[str]) -> dict:
    proc = subprocess.run(
        ["aws", *args],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=45,
    )
    if proc.returncode:
        return result_error(proc.stderr)
    try:
        value = json.loads(proc.stdout) if proc.stdout.strip() else None
    except json.JSONDecodeError:
        value = proc.stdout.strip()
    return {"ok": True, "value": value}


def mint_oidc_token() -> str:
    request = urllib.request.Request(
        os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"] + "&audience=sts.amazonaws.com",
        headers={"Authorization": "bearer " + os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"]},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)["value"]


def assume_entry_role(token: str) -> dict:
    body = urllib.parse.urlencode(
        {
            "Action": "AssumeRoleWithWebIdentity",
            "Version": "2011-06-15",
            "RoleArn": ROLE_ARN,
            "RoleSessionName": "metricforge-stage",
            "WebIdentityToken": token,
            "DurationSeconds": "3600",
        }
    ).encode()
    request = urllib.request.Request("https://sts.amazonaws.com/", data=body)
    with urllib.request.urlopen(request, timeout=30) as response:
        root = ET.fromstring(response.read())
    namespace = {"s": "https://sts.amazonaws.com/doc/2011-06-15/"}
    credentials = root.find(".//s:Credentials", namespace)
    if credentials is None:
        raise RuntimeError("credentials_missing")
    return {
        "AWS_ACCESS_KEY_ID": credentials.findtext("s:AccessKeyId", namespaces=namespace),
        "AWS_SECRET_ACCESS_KEY": credentials.findtext("s:SecretAccessKey", namespaces=namespace),
        "AWS_SESSION_TOKEN": credentials.findtext("s:SessionToken", namespaces=namespace),
    }


def safe_role_details(value: dict) -> dict:
    role = (value or {}).get("Role", {})
    return {
        "path": role.get("Path"),
        "max_session_duration": role.get("MaxSessionDuration"),
        "assume_role_policy": role.get("AssumeRolePolicyDocument"),
    }


def main() -> None:
    report: dict = {"stage": "entry-role", "assume_ok": False}
    try:
        token = mint_oidc_token()
        credentials = assume_entry_role(token)
    except Exception as error:
        report["assume_error"] = type(error).__name__
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    report["assume_ok"] = True
    env = os.environ.copy()
    env.update(credentials)
    env.update(
        {
            "AWS_DEFAULT_REGION": REGION,
            "AWS_REGION": REGION,
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_PAGER": "",
        }
    )

    get_role = aws(env, ["iam", "get-role", "--role-name", ROLE_NAME, "--output", "json"])
    report["get_role"] = (
        {"ok": True, "value": safe_role_details(get_role["value"])}
        if get_role.get("ok")
        else get_role
    )

    inline = aws(
        env,
        ["iam", "list-role-policies", "--role-name", ROLE_NAME, "--output", "json"],
    )
    report["inline_policy_names"] = inline
    if inline.get("ok"):
        report["inline_policies"] = []
        for policy_name in inline["value"].get("PolicyNames", []):
            policy = aws(
                env,
                [
                    "iam",
                    "get-role-policy",
                    "--role-name",
                    ROLE_NAME,
                    "--policy-name",
                    policy_name,
                    "--output",
                    "json",
                ],
            )
            report["inline_policies"].append(
                {"name": policy_name, "result": policy}
            )

    attached = aws(
        env,
        ["iam", "list-attached-role-policies", "--role-name", ROLE_NAME, "--output", "json"],
    )
    report["attached_policies"] = attached

    objects = aws(
        env,
        ["s3api", "list-objects-v2", "--bucket", BUCKET, "--output", "json"],
    )
    if objects.get("ok"):
        contents = objects["value"].get("Contents", [])
        report["bucket"] = {
            "ok": True,
            "objects": [
                {"key": item.get("Key"), "size": item.get("Size")}
                for item in contents
            ],
        }
        recovered = []
        total = 0
        for item in contents:
            key = item.get("Key", "")
            size = int(item.get("Size", 0))
            if size > 100_000 or total + size > 250_000:
                continue
            target = pathlib.Path("/tmp/mf-stage-object.bin")
            fetched = aws(
                env,
                ["s3api", "get-object", "--bucket", BUCKET, "--key", key, str(target), "--output", "json"],
            )
            if fetched.get("ok") and target.exists():
                raw = target.read_bytes()
                recovered.append(
                    {
                        "key": key,
                        "size": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "base64": base64.b64encode(raw).decode(),
                    }
                )
                total += len(raw)
                target.unlink(missing_ok=True)
        report["recovered_objects"] = recovered
    else:
        report["bucket"] = objects

    report["describe_images"] = aws(
        env,
        [
            "ec2",
            "describe-images",
            "--owners",
            "125746528491",
            "--filters",
            "Name=name,Values=metricforge-recovery-*",
            "--query",
            "Images[].ImageId",
            "--output",
            "json",
        ],
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
