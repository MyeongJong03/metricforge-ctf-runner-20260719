#!/usr/bin/env python3
import concurrent.futures
import itertools
import json
import os
import random
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

ACCOUNT = "125746528491"
SESSION = "oidc-30b28c53"
SUFFIXES = ("", "-30b28c53", "30b28c53", "-5be46435", "-20260417")
TOKEN = os.environ.get("MF_OIDC_TOKEN", "")
if not TOKEN:
    raise SystemExit("missing OIDC token")


def pascal(value: str) -> str:
    return "".join(part.capitalize() for part in value.split("-"))


def candidates():
    phrases = {
        "entry",
        "entry-role",
        "oidc-entry",
        "oidc-entry-role",
        "github-entry",
        "github-entry-role",
        "github-oidc",
        "github-oidc-role",
        "github-oidc-entry",
        "github-oidc-entry-role",
        "github-actions-entry",
        "github-actions-entry-role",
        "github-actions-oidc",
        "github-actions-oidc-role",
        "recovery",
        "recovery-role",
        "recovery-entry",
        "recovery-entry-role",
        "recovery-oidc",
        "recovery-oidc-role",
        "recovery-oidc-entry",
        "recovery-oidc-entry-role",
        "recovery-github",
        "recovery-github-role",
        "recovery-github-entry",
        "recovery-github-entry-role",
        "recovery-github-oidc",
        "recovery-github-oidc-role",
        "recovery-github-oidc-entry",
        "recovery-github-oidc-entry-role",
        "recovery-github-actions",
        "recovery-github-actions-role",
        "recovery-github-actions-entry",
        "recovery-github-actions-entry-role",
        "recovery-github-actions-oidc",
        "recovery-github-actions-oidc-role",
        "restore",
        "restore-role",
        "restore-entry",
        "restore-entry-role",
        "restore-oidc",
        "restore-oidc-role",
        "restore-oidc-entry",
        "restore-oidc-entry-role",
        "bootstrap",
        "bootstrap-role",
        "bootstrap-entry",
        "bootstrap-entry-role",
        "recovery-bootstrap",
        "recovery-bootstrap-role",
        "recovery-bootstrap-entry",
        "recovery-bootstrap-entry-role",
        "reader",
        "read-role",
        "recovery-reader",
        "recovery-reader-role",
        "recovery-read-only",
        "recovery-read-only-role",
        "recovery-investigator",
        "recovery-investigator-role",
        "recovery-forensics",
        "recovery-forensics-role",
        "ami-reader",
        "ami-reader-role",
        "recovery-ami-reader",
        "recovery-ami-reader-role",
        "snapshot-reader",
        "snapshot-reader-role",
        "recovery-snapshot-reader",
        "recovery-snapshot-reader-role",
        "recovery-workflow",
        "recovery-workflow-role",
        "recovery-workflows",
        "recovery-workflows-role",
        "workflow-entry",
        "workflow-entry-role",
    }
    artifact_phrases = {
        "artifact",
        "artifact-role",
        "artifact-entry",
        "artifact-entry-role",
        "artifact-reader",
        "artifact-reader-role",
        "artifact-read-role",
        "artifact-access",
        "artifact-access-role",
        "artifacts",
        "artifacts-role",
        "artifacts-entry",
        "artifacts-entry-role",
        "artifacts-reader",
        "artifacts-reader-role",
        "artifacts-read-role",
        "artifacts-access",
        "artifacts-access-role",
        "recovery-artifact",
        "recovery-artifact-role",
        "recovery-artifact-entry",
        "recovery-artifact-entry-role",
        "recovery-artifact-reader",
        "recovery-artifact-reader-role",
        "recovery-artifact-read-role",
        "recovery-artifact-access",
        "recovery-artifact-access-role",
        "recovery-artifacts",
        "recovery-artifacts-role",
        "recovery-artifacts-entry",
        "recovery-artifacts-entry-role",
        "recovery-artifacts-reader",
        "recovery-artifacts-reader-role",
        "recovery-artifacts-read-role",
        "recovery-artifacts-access",
        "recovery-artifacts-access-role",
        "recovery-artifacts-oidc",
        "recovery-artifacts-oidc-role",
        "recovery-artifacts-oidc-entry",
        "recovery-artifacts-oidc-entry-role",
        "recovery-channel",
        "recovery-channel-role",
        "recovery-channel-entry",
        "recovery-channel-entry-role",
        "recovery-channel-reader",
        "recovery-channel-reader-role",
        "recovery-channel-access",
        "recovery-channel-access-role",
        "build-artifacts",
        "build-artifacts-role",
        "build-artifacts-reader",
        "build-artifacts-reader-role",
        "builder-artifacts",
        "builder-artifacts-role",
        "builder-artifacts-reader",
        "builder-artifacts-reader-role",
    }
    author_phrases = {
        "github-actions",
        "github-actions-role",
        "github-actions-terraform",
        "github-actions-recovery",
        "github-actions-recovery-role",
        "github-actions-recovery-entry",
        "github-actions-recovery-entry-role",
        "github-actions-restore",
        "github-actions-restore-role",
        "github-actions-restore-entry",
        "github-actions-restore-entry-role",
        "github-actions-metricforge",
        "github-actions-metricforge-role",
        "github-actions-metricforge-entry",
        "github-actions-metricforge-entry-role",
        "github-actions-metricforge-recovery",
        "github-actions-metricforge-recovery-role",
        "github-actions-metricforge-recovery-entry",
        "github-actions-metricforge-recovery-entry-role",
        "github-actions-recovery-artifacts",
        "github-actions-recovery-artifacts-role",
        "github-actions-recovery-artifacts-reader",
        "github-actions-recovery-artifacts-reader-role",
        "github-actions-artifacts",
        "github-actions-artifacts-reader",
        "github-oidc-recovery",
        "github-oidc-recovery-role",
        "github-oidc-recovery-entry",
        "github-oidc-recovery-entry-role",
    }
    if os.environ.get("MF_ONLY_AUTHOR"):
        phrases = author_phrases
    elif os.environ.get("MF_ONLY_ARTIFACTS"):
        phrases = artifact_phrases
    else:
        phrases |= artifact_phrases | author_phrases
    names = set()
    for phrase in phrases:
        kebab_forms = (phrase, f"metricforge-{phrase}", f"mf-{phrase}")
        pascal_forms = (pascal(phrase), f"MetricForge{pascal(phrase)}", f"MF{pascal(phrase)}")
        for base in kebab_forms + pascal_forms:
            for suffix in SUFFIXES:
                names.add(base + suffix)
        # Common role paths are part of the ARN after role/.
        for path in ("metricforge", "metricforge-recovery", "recovery", "github-actions", "service-role"):
            names.add(f"{path}/{phrase}")
            names.add(f"{path}/{phrase}-30b28c53")
            names.add(f"{path}/{pascal(phrase)}")
            names.add(f"{path}/{pascal(phrase)}-30b28c53")

    # Common IaC logical-role spellings and suffix placement.
    for words in (
        ("MetricForge", "Recovery", "Entry", "Role"),
        ("MetricForge", "Recovery", "OIDC", "Entry", "Role"),
        ("MetricForge", "GitHub", "OIDC", "Entry", "Role"),
        ("MetricForge", "Recovery", "GitHub", "OIDC", "Role"),
        ("MetricForge", "Recovery", "GitHub", "OIDC", "Entry", "Role"),
        ("MetricForge", "Recovery", "Artifacts", "Reader", "Role"),
        ("MetricForge", "Recovery", "Artifacts", "Entry", "Role"),
        ("MetricForge", "Recovery", "Artifacts", "OIDC", "Entry", "Role"),
    ):
        joined = "".join(words)
        for sep in ("", "-", "_"):
            names.add(joined + sep + "30b28c53")
            names.add("30b28c53" + sep + joined)
            names.add("/".join(("metricforge", joined + sep + "30b28c53")))

    if os.environ.get("MF_ONLY_ARTIFACTS") or os.environ.get("MF_ONLY_AUTHOR"):
        bases = list(names)
        for base in bases:
            parts = base.split("/")
            leaf = parts[-1]
            prefix = "/".join(parts[:-1])
            for marker in ("30b28c53", "125746528491"):
                tokens = leaf.split("-")
                for index in range(1, len(tokens)):
                    inserted = "-".join(tokens[:index] + [marker] + tokens[index:])
                    names.add(f"{prefix}/{inserted}" if prefix else inserted)
        names.update({
            "metricforge-recovery-artifacts-125746528491",
            "metricforge-recovery-artifacts-125746528491-reader",
            "metricforge-recovery-artifacts-125746528491-entry",
            "metricforge-recovery-artifacts-30b28c53-reader",
            "metricforge-recovery-artifacts-30b28c53-entry",
            "metricforge-recovery-30b28c53-artifacts-reader",
            "metricforge-recovery-30b28c53-artifacts-entry",
        })

    # Deterministic ordering with previously tested exact names removed only to
    # reduce noise; keeping them would be harmless.
    return sorted(names)


lock = threading.Lock()
done = 0
found = threading.Event()
result = {}


def parse_success(raw: bytes, role_arn: str):
    root = ET.fromstring(raw)
    ns = {"s": "https://sts.amazonaws.com/doc/2011-06-15/"}
    creds = root.find(".//s:Credentials", ns)
    user = root.find(".//s:AssumedRoleUser", ns)
    if creds is None or user is None:
        return None
    def text(path, parent=root):
        node = parent.find(path, ns)
        return node.text if node is not None else None
    return {
        "Credentials": {
            "AccessKeyId": text("s:AccessKeyId", creds),
            "SecretAccessKey": text("s:SecretAccessKey", creds),
            "SessionToken": text("s:SessionToken", creds),
            "Expiration": text("s:Expiration", creds),
        },
        "SubjectFromWebIdentityToken": text(".//s:SubjectFromWebIdentityToken"),
        "AssumedRoleUser": {
            "AssumedRoleId": text("s:AssumedRoleId", user),
            "Arn": text("s:Arn", user),
        },
        "Provider": text(".//s:Provider"),
        "Audience": text(".//s:Audience"),
        "_RoleArn": role_arn,
    }


def attempt(name: str):
    global done, result
    if found.is_set():
        return
    role_arn = f"arn:aws:iam::{ACCOUNT}:role/{name}"
    data = urllib.parse.urlencode({
        "Action": "AssumeRoleWithWebIdentity",
        "Version": "2011-06-15",
        "RoleArn": role_arn,
        "RoleSessionName": SESSION,
        "WebIdentityToken": TOKEN,
        "DurationSeconds": "3600",
    }).encode()
    req = urllib.request.Request("https://sts.amazonaws.com/", data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=12, context=ssl.create_default_context()) as response:
            parsed = parse_success(response.read(), role_arn)
            if parsed:
                with lock:
                    if not found.is_set():
                        result = parsed
                        found.set()
    except urllib.error.HTTPError as exc:
        # Drain bounded error data but never print token-bearing request data.
        exc.read(8192)
        if exc.code in (429, 500, 502, 503, 504):
            time.sleep(0.2 + random.random() * 0.3)
    except Exception:
        pass
    finally:
        with lock:
            done += 1
            if done % 500 == 0:
                print(f"checked {done} role ARN candidates", flush=True)


names = candidates()
print(f"probing {len(names)} bounded role ARN candidates", flush=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
    futures = [pool.submit(attempt, name) for name in names]
    for future in concurrent.futures.as_completed(futures):
        future.result()
        if found.is_set():
            for pending in futures:
                pending.cancel()
            break

if not found.is_set():
    print("no matching role in bounded candidate set", file=sys.stderr)
    raise SystemExit(1)

role_arn = result.pop("_RoleArn")
with open("entry.json", "w", encoding="utf-8") as handle:
    json.dump(result, handle)
print("matched role ARN: " + re.sub(r"[^A-Za-z0-9_+=,.@/-]", "?", role_arn), flush=True)
