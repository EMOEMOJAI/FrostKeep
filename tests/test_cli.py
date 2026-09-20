"""Exercise the real Python CLI in child processes without a host or cloud."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CLI = Path(__file__).resolve().parents[1] / 'lib/frostkeep/frostkeep.py'


class CLIProcessTests(unittest.TestCase):
    def run_cli(self, *args):
        # A different working directory also exercises inherited coverage paths.
        with tempfile.TemporaryDirectory() as directory:
            return subprocess.run(
                [sys.executable, str(CLI), '--config', str(Path(directory) / 'missing.json'), *args],
                cwd=directory, capture_output=True, text=True, timeout=30,
            )

    def test_help_and_version_do_not_require_configuration(self):
        help_result = self.run_cli('--help')
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        for command in ('backup', 'restore', 'cleanup', 'health'):
            self.assertIn(command, help_result.stdout)
        version = self.run_cli('--version')
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertRegex(version.stdout, r'^FrostKeep \d+\.\d+\.\d+\s*$')

    def test_invalid_command_is_rejected_before_configuration(self):
        result = self.run_cli('not-a-command')
        self.assertEqual(result.returncode, 2)
        self.assertIn('invalid choice', result.stderr)
        self.assertNotIn('Traceback', result.stderr)

    def test_guest_restore_requires_destination_arguments(self):
        result = self.run_cli('restore', 'guest', 'example-run', 'example.tar.zst')
        self.assertEqual(result.returncode, 2)
        for option in ('--file', '--target-id', '--storage'):
            self.assertIn(option, result.stderr)
