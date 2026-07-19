#!/usr/bin/env python3
import json
import os

from role_stage import aws, assume_entry_role, mint_oidc_token, safe_role_details


REGION = "ap-northeast-2"
BROKER_ARN = "arn:aws:iam::125746528491:role/metricforge-broker-9d7a0ac7cc"
BROKER_NAME = "metricforge-broker-9d7a0ac7cc"
EXTERNAL_ID = "mf-broker-bdeeb30544829362"
BUCKET = "metricforge-recovery-artifacts-125746528491"


def credential_env(credentials: dict) -> dict:
    env = os.environ.copy()
    env.update(
        {
            "AWS_ACCESS_KEY_ID": credentials["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": credentials["SecretAccessKey"],
            "AWS_SESSION_TOKEN": credentials["SessionToken"],
            "AWS_DEFAULT_REGION": REGION,
            "AWS_REGION": REGION,
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_PAGER": "",
        }
    )
    return env


def entry_env() -> dict:
    token = mint_oidc_token()
    raw = assume_entry_role(token)
    return credential_env(
        {
            "AccessKeyId": raw["AWS_ACCESS_KEY_ID"],
            "SecretAccessKey": raw["AWS_SECRET_ACCESS_KEY"],
            "SessionToken": raw["AWS_SESSION_TOKEN"],
        }
    )


def inspect_inline_policies(env: dict, role_name: str) -> dict:
    names = aws(
        env,
        ["iam", "list-role-policies", "--role-name", role_name, "--output", "json"],
    )
    result = {"names": names}
    if names.get("ok"):
        result["policies"] = []
        for name in names["value"].get("PolicyNames", []):
            policy = aws(
                env,
                [
                    "iam",
                    "get-role-policy",
                    "--role-name",
                    role_name,
                    "--policy-name",
                    name,
                    "--output",
                    "json",
                ],
            )
            result["policies"].append({"name": name, "result": policy})
    return result


def main() -> None:
    report = {"stage": "broker-role", "entry_assume_ok": False, "broker_assume_ok": False}
    try:
        first_env = entry_env()
        report["entry_assume_ok"] = True
    except Exception as error:
        report["entry_error"] = type(error).__name__
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    role = aws(
        first_env,
        ["iam", "get-role", "--role-name", BROKER_NAME, "--output", "json"],
    )
    report["broker_role"] = (
        {"ok": True, "value": safe_role_details(role["value"])}
        if role.get("ok")
        else role
    )
    report["broker_inline"] = inspect_inline_policies(first_env, BROKER_NAME)

    assumed = aws(
        first_env,
        [
            "sts",
            "assume-role",
            "--role-arn",
            BROKER_ARN,
            "--role-session-name",
            "metricforge-broker-stage",
            "--external-id",
            EXTERNAL_ID,
            "--output",
            "json",
        ],
    )
    if not assumed.get("ok"):
        report["broker_assume"] = assumed
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    credentials = assumed["value"].get("Credentials", {})
    if not all(credentials.get(key) for key in ("AccessKeyId", "SecretAccessKey", "SessionToken")):
        report["broker_assume"] = {"ok": False, "error": "credentials_missing"}
        print(json.dumps(report, indent=2, sort_keys=True))
        return

    report["broker_assume_ok"] = True
    broker_env = credential_env(credentials)
    report["bucket"] = aws(
        broker_env,
        ["s3api", "list-objects-v2", "--bucket", BUCKET, "--output", "json"],
    )
    report["ssm_parameters"] = aws(
        broker_env,
        [
            "ssm",
            "describe-parameters",
            "--parameter-filters",
            "Key=Name,Option=Contains,Values=metricforge",
            "--output",
            "json",
        ],
    )
    report["secrets"] = aws(
        broker_env,
        ["secretsmanager", "list-secrets", "--output", "json"],
    )
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
