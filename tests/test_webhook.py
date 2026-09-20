import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("webhook", Path(__file__).resolve().parents[1] / "scripts/notify-webhook.py")
webhook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(webhook)


class WebhookTests(unittest.TestCase):
    def test_private_config_and_https_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "webhook.json"
            path.write_text(json.dumps({"url": "https://example.invalid/hook", "format": "generic"}))
            path.chmod(0o600)
            self.assertEqual(webhook.load(path)["format"], "generic")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                webhook.load(path)
            path.chmod(0o600)
            path.write_text(json.dumps({"url": "http://example.invalid/hook"}))
            with self.assertRaises(ValueError):
                webhook.load(path)

    def test_post_uses_bounded_timeout_and_json(self):
        opener = Mock()
        opener.open.return_value.__enter__ = Mock(return_value=Mock(status=204))
        opener.open.return_value.__exit__ = Mock(return_value=False)
        event = {"event": "health", "status": "unhealthy", "reasons": ["backup_overdue"]}
        webhook.deliver({"url": "https://example.invalid/hook"}, event, opener)
        args, kwargs = opener.open.call_args
        self.assertEqual(args[0].method, "POST")
        self.assertEqual(json.loads(args[0].data), event)
        self.assertEqual(kwargs["timeout"], 10)

    def test_chat_payloads_disable_mentions(self):
        event = {"status": "complete", "completed_count": 2, "expected_count": 2}
        self.assertEqual(webhook.payload(event, "discord")["allowed_mentions"], {"parse": []})
        self.assertFalse(webhook.payload(event, "slack")["mrkdwn"])
        with self.assertRaises(ValueError):
            webhook.payload({"status": "unhealthy", "reasons": ["@everyone"]}, "discord")
        with self.assertRaises(ValueError):
            webhook.payload(dict(event, hostname="private-host"), "generic")

    def test_redirects_are_refused(self):
        with self.assertRaises(ValueError):
            webhook.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid/other")

    def test_delivery_errors_never_echo_secret(self):
        stream = io.StringIO()
        with patch("sys.argv", ["hook", "--config", "/private-config.json"]), patch.object(webhook, "load", side_effect=ValueError("synthetic-sensitive-token")), contextlib.redirect_stderr(stream):
            self.assertEqual(webhook.main(), 1)
        self.assertNotIn("synthetic-sensitive-token", stream.getvalue())
