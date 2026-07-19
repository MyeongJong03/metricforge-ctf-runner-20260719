#!/usr/bin/env python3
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ACCOUNT = "125746528491"
TOKEN = os.environ["MF_OIDC_TOKEN"]

arns = [
    f"arn:aws:iam::{ACCOUNT}:role/*",
    f"arn:aws:iam::{ACCOUNT}:role/?",
    f"arn:aws:iam::{ACCOUNT}:role/**",
    f"arn:aws:iam::{ACCOUNT}:role/metricforge-*",
    f"arn:aws:iam::{ACCOUNT}:role/metricforge-recovery-*",
    f"arn:aws:iam::{ACCOUNT}:role/%2A",
    f"arn:aws:iam::{ACCOUNT}:role//",
    f"arn:aws:iam::{ACCOUNT}:role/../*",
    f"arn:aws:iam::{ACCOUNT}:role",
    f"arn:aws:iam::{ACCOUNT}:root",
    f"arn:aws:iam::{ACCOUNT}:role/definitely-nonexistent-protocol-control-4f8796b2",
]


def xml_text(raw, tag):
    try:
        root = ET.fromstring(raw)
        node = next((n for n in root.iter() if n.tag.rsplit("}", 1)[-1] == tag), None)
        return node.text if node is not None else None
    except ET.ParseError:
        return None


results = []
for arn in arns:
    data = urllib.parse.urlencode({
        "Action": "AssumeRoleWithWebIdentity",
        "Version": "2011-06-15",
        "RoleArn": arn,
        "RoleSessionName": "oidc-30b28c53",
        "WebIdentityToken": TOKEN,
        "DurationSeconds": "900",
    }).encode()
    req = urllib.request.Request("https://sts.amazonaws.com/", data=data, method="POST")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read()
            elapsed = round(time.monotonic() - started, 3)
            access = xml_text(raw, "AccessKeyId")
            secret = xml_text(raw, "SecretAccessKey")
            session = xml_text(raw, "SessionToken")
            item = {"arn": arn, "http": response.status, "elapsed": elapsed, "success": True}
            if access and secret and session:
                env = dict(os.environ)
                env.update(AWS_ACCESS_KEY_ID=access, AWS_SECRET_ACCESS_KEY=secret,
                           AWS_SESSION_TOKEN=session, AWS_DEFAULT_REGION="ap-northeast-2")
                proc = subprocess.run([
                    "aws", "ec2", "describe-images", "--region", "ap-northeast-2",
                    "--owners", ACCOUNT, "--filters", "Name=name,Values=metricforge-recovery-*",
                    "--query", "Images[].{ImageId:ImageId,Name:Name,SnapshotId:BlockDeviceMappings[0].Ebs.SnapshotId}",
                ], env=env, capture_output=True, text=True, timeout=30)
                item["describe_images_rc"] = proc.returncode
                if proc.returncode == 0:
                    item["images"] = json.loads(proc.stdout)
                else:
                    item["describe_images_error"] = proc.stderr[-500:]
            results.append(item)
    except urllib.error.HTTPError as exc:
        raw = exc.read(16384)
        results.append({
            "arn": arn,
            "http": exc.code,
            "elapsed": round(time.monotonic() - started, 3),
            "success": False,
            "code": xml_text(raw, "Code"),
            "message": xml_text(raw, "Message"),
        })
    except Exception as exc:
        results.append({"arn": arn, "success": False, "error_type": type(exc).__name__})

with open("entry.json", "w", encoding="utf-8") as handle:
    json.dump({"results": results}, handle, indent=2)
