"""Runs report_secret_scan.py on planted result directories and checks what it reports."""

import base64
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

SCRIPT = pathlib.Path(__file__).resolve().with_name("report_secret_scan.py")
PLANTED_CLIENT_VALUE = "world-client-secret-4f19c2"
PLANTED_HARNESS_VALUE = "harness-test-token-8e03d7"
PLANTED_SHORT_VALUE = "tiny-value"
KEY_LINE = "MIGHAgEAMBMG" + "ByqGSM49AgEGCCqGSM49"
PEM_BEGIN = "-----BEGIN " + "PRIVATE KEY-----"
PEM_END = "-----END " + "PRIVATE KEY-----"
JWT = "eyJ" + "a" * 10 + ".eyJ" + "b" * 10 + "." + "c" * 10
HYDRA_TOKEN = "ory_" + "at_" + "x" * 20
WORLD_TEMPLATE = '{"clientA": {"id": "client-a", "secret": %s}, "key": {"privatePem": %s}}'


class ScanTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = pathlib.Path(tmp.name)
        self.results = root / "results"
        self.results.mkdir()
        self.world = root / "world.json"
        self.world.write_text(
            WORLD_TEMPLATE % (json.dumps(PLANTED_CLIENT_VALUE), json.dumps(f"{PEM_BEGIN}\n{KEY_LINE}\n{PEM_END}\n"))
        )
        self.harness_dir = root / "secrets"
        self.harness_dir.mkdir()
        (self.harness_dir / "test-token").write_text(PLANTED_HARNESS_VALUE + "\n")
        (self.harness_dir / "short").write_text(PLANTED_SHORT_VALUE)

    def plant(self, name, data):
        path = self.results / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def scan(self, *args):
        argv = args or (self.results, self.world, self.harness_dir)
        return subprocess.run(
            [sys.executable, "-I", "-B", str(SCRIPT), *map(str, argv)],
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_found(self, value, expected_hit):
        completed = self.scan()
        self.assertEqual(completed.returncode, 1, completed.stdout)
        self.assertIn(expected_hit, completed.stderr)
        self.assertNotIn(value, completed.stderr + completed.stdout)

    def test_a_clean_result_dir_passes_and_counts_the_run_secrets(self):
        self.plant("report.json", b'{"status":"passed"}')
        completed = self.scan()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout.strip(), "secret scan: 1 result files clean, 3 run secrets checked")

    def test_a_jwt_fails_the_scan(self):
        self.plant("data/response.json", JWT.encode())
        self.assert_found(JWT, "data/response.json: JWT")

    def test_a_pem_private_key_with_escaped_newlines_fails_the_scan(self):
        body = "A" * 20
        self.plant("results.json", f'"{PEM_BEGIN}\\n{body}"'.encode())
        self.assert_found(body, "results.json: PEM private key")

    def test_a_hydra_access_token_fails_the_scan(self):
        self.plant("log.txt", HYDRA_TOKEN.encode())
        self.assert_found(HYDRA_TOKEN, "log.txt: Hydra access token")

    def test_a_world_client_secret_fails_the_scan(self):
        self.plant("stdout.txt", PLANTED_CLIENT_VALUE.encode())
        self.assert_found(PLANTED_CLIENT_VALUE, "stdout.txt: client secret of clientA")

    def test_a_signing_key_line_fails_the_scan(self):
        self.plant("stdout.txt", KEY_LINE.encode())
        self.assert_found(KEY_LINE, "stdout.txt: signing key line 1")

    def test_a_harness_secret_fails_the_scan(self):
        self.plant("stdout.txt", PLANTED_HARNESS_VALUE.encode())
        self.assert_found(PLANTED_HARNESS_VALUE, "stdout.txt: harness secret test-token")

    def test_a_secret_inside_a_zip_embedded_in_an_html_page_fails_the_scan(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
            zipped.writestr("attachment.txt", f"client_secret={PLANTED_CLIENT_VALUE}")
        encoded = base64.b64encode(archive.getvalue())
        self.plant("html/index.html", b'<script>window.r="data:application/zip;base64,' + encoded + b'"</script>')
        self.assert_found(PLANTED_CLIENT_VALUE, "html/index.html!attachment.txt: client secret of clientA")

    def test_a_secret_shorter_than_the_minimum_is_ignored(self):
        self.plant("stdout.txt", PLANTED_SHORT_VALUE.encode())
        completed = self.scan()
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_the_wrong_number_of_arguments_is_a_usage_error(self):
        completed = self.scan(self.results)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("Usage: report_secret_scan.py", completed.stderr)


if __name__ == "__main__":
    unittest.main()
