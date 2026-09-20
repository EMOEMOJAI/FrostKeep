#!/usr/bin/env python3
"""Deliver bounded FrostKeep events using a separately configured HTTPS webhook."""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Webhook redirects are refused")


def load(path):
    path = Path(path)
    info = path.lstat()
    if not path.is_absolute() or path.resolve() != path or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("Webhook configuration must be a private regular file")
    cfg = json.loads(path.read_text())
    if not isinstance(cfg, dict) or set(cfg) - {"url", "format", "headers"}:
        raise ValueError("Invalid webhook configuration")
    url = cfg.get("url", "")
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment or any(ord(c) < 33 for c in url):
        raise ValueError("Webhook requires an HTTPS URL without user credentials or fragment")
    if cfg.get("format", "generic") not in ("generic", "discord", "slack"):
        raise ValueError("Unsupported webhook format")
    headers = cfg.get("headers", {})
    if not isinstance(headers, dict) or any(not isinstance(k, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", k) or k.lower() in ("host", "content-length", "content-type", "transfer-encoding") or not isinstance(v, str) or any(ord(c) < 32 or ord(c) > 126 for c in v) for k, v in headers.items()):
        raise ValueError("Invalid webhook headers")
    return cfg


def payload(event, style):
    allowed = {"event", "status", "at", "checked_at", "reasons", "run_id", "started_at", "finished_at", "completed_count", "expected_count"}
    if not isinstance(event, dict) or set(event) - allowed or event.get("status") not in ("complete", "failed", "interrupted", "healthy", "unhealthy"):
        raise ValueError("Invalid notification event")
    if len(json.dumps(event)) > 8192:
        raise ValueError("Notification event is too large")
    if style == "generic":
        return event
    # Plain text prevents supplied text from tagging chat participants.
    message = "FrostKeep: " + event["status"]
    if type(event.get("completed_count")) is int and type(event.get("expected_count")) is int:
        message += f" ({event['completed_count']}/{event['expected_count']} guests)"
    if event.get("reasons"):
        reasons = event["reasons"]
        if not isinstance(reasons, list) or not all(isinstance(r, str) and re.fullmatch(r"[a-z_]{1,64}", r) for r in reasons):
            raise ValueError("Invalid health reason codes")
        message += ": " + ", ".join(reasons)
    if style == "discord":
        return {"content": message, "allowed_mentions": {"parse": []}}
    return {"text": message, "mrkdwn": False}


def deliver(cfg, event, opener=None):
    body = json.dumps(payload(event, cfg.get("format", "generic"))).encode()
    headers = dict(cfg.get("headers", {}), **{"Content-Type": "application/json", "User-Agent": "FrostKeep-webhook"})
    request = urllib.request.Request(cfg["url"], data=body, headers=headers, method="POST")
    opener = opener or urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=10) as response:
        if not 200 <= response.status < 300:
            raise ValueError("Webhook delivery failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Private webhook JSON config on this host")
    args = parser.parse_args()
    try:
        cfg = load(args.config)
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise ValueError("Event too large")
        deliver(cfg, json.loads(raw))
        return 0
    except Exception:
        # Exceptions can contain webhook tokens, headers or response bodies.
        print("FrostKeep webhook delivery failed; check private configuration and connectivity.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
