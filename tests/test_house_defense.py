"""Smoke tests with benign placeholder data only."""
import importlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))

import check_sender  # noqa: E402

# Live-settings env vars. Tests must never inherit a developer's values,
# or a baseline/check/intake run can overwrite a real manifest or
# quarantine folder.
LIVE_SETTINGS_ENV = (
    "INTEGRITY_ROOT",
    "INTEGRITY_CONFIG",
    "INTEGRITY_MANIFEST",
    "INTEGRITY_TZ",
    "QUARANTINE_DIR",
)


def run(script, *args, env=None):
    full = dict(os.environ)
    for key in LIVE_SETTINGS_ENV:
        full.pop(key, None)
    full.update(env or {})
    return subprocess.run([sys.executable, str(HERE / script), *args],
                          capture_output=True, text=True, env=full)


class IntegrityTests(unittest.TestCase):
    def test_baseline_check_and_drift(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "notes").mkdir()
            (root / "README.md").write_text("hello\n")
            (root / "notes" / "a.txt").write_text("one\n")
            (root / "notes" / "live.lock").write_text("x\n")
            cfg = root / "cfg.json"
            manifest = root / "integrity-manifest.json"
            cfg.write_text(json.dumps({"include": ["README.md", "notes"], "exclude": ["*.lock"]}))
            env = {
                "INTEGRITY_ROOT": str(root),
                "INTEGRITY_CONFIG": str(cfg),
                "INTEGRITY_MANIFEST": str(manifest),
            }
            self.assertEqual(run("integrity.py", "baseline", env=env).returncode, 0)
            self.assertEqual(run("integrity.py", "check", env=env).returncode, 0)
            # Excluded files may change freely.
            (root / "notes" / "live.lock").write_text("y\n")
            self.assertEqual(run("integrity.py", "check", env=env).returncode, 0)
            # A watched change is flagged.
            (root / "notes" / "a.txt").write_text("changed\n")
            r = run("integrity.py", "check", env=env)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_preset_integrity_manifest_is_left_untouched(self):
        """A pre-set INTEGRITY_MANIFEST pointing at a real file must be left
        untouched after a baseline run against a temp fixture."""
        with tempfile.TemporaryDirectory() as raw:
            raw = Path(raw)
            live = raw / "real-manifest.json"
            sentinel = '{"sentinel": "live-baseline", "files": {"keep": true}}\n'
            live.write_text(sentinel, encoding="utf-8")

            fixture = raw / "fixture"
            fixture.mkdir()
            (fixture / "README.md").write_text("hello\n")
            cfg = fixture / "cfg.json"
            cfg.write_text(json.dumps({"include": ["README.md"], "exclude": []}))

            old = os.environ.get("INTEGRITY_MANIFEST")
            os.environ["INTEGRITY_MANIFEST"] = str(live)
            try:
                # Same keys the drift test used to pass, without an explicit
                # INTEGRITY_MANIFEST override. run() must drop the live var.
                env = {
                    "INTEGRITY_ROOT": str(fixture),
                    "INTEGRITY_CONFIG": str(cfg),
                }
                r = run("integrity.py", "baseline", env=env)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertEqual(live.read_text(encoding="utf-8"), sentinel)
                written = fixture / "integrity-manifest.json"
                self.assertTrue(written.is_file())
                self.assertNotEqual(written.read_text(encoding="utf-8"), sentinel)
            finally:
                if old is None:
                    os.environ.pop("INTEGRITY_MANIFEST", None)
                else:
                    os.environ["INTEGRITY_MANIFEST"] = old


class QuarantineTests(unittest.TestCase):
    def test_intake_flags_script_and_passes_text(self):
        with tempfile.TemporaryDirectory() as raw:
            qdir = Path(raw) / "q"
            env = {"QUARANTINE_DIR": str(qdir)}
            plain = Path(raw) / "notes.txt"
            plain.write_text("just some notes\n")
            sneaky = Path(raw) / "photo.jpg"
            sneaky.write_text("#!/bin/sh\necho placeholder\n")
            r1 = run("quarantine.py", "intake", str(plain), env=env)
            r2 = run("quarantine.py", "intake", str(sneaky), env=env)
            self.assertEqual(r1.returncode, 0, r1.stdout + r1.stderr)
            self.assertNotIn("HELD", r1.stdout)
            self.assertIn("HELD", r2.stdout)
            self.assertIn("mismatch", r2.stdout.lower())

    def test_zip_with_traversal_is_flagged(self):
        with tempfile.TemporaryDirectory() as raw:
            qdir = Path(raw) / "q"
            z = Path(raw) / "bundle.zip"
            with zipfile.ZipFile(z, "w") as handle:
                handle.writestr("../escape.txt", "placeholder")
            r = run("quarantine.py", "intake", str(z), env={"QUARANTINE_DIR": str(qdir)})
            self.assertIn("HELD", r.stdout)
            self.assertIn("traversal", r.stdout.lower())


RAW_SPOOF = """From: "Pat Example" <pat.example@gmai1.com>
To: helper@example.org
Subject: hello
Authentication-Results: mx.example.org; spf=fail; dkim=none

Please buy gift cards right now and don't tell anyone.
"""

RAW_CLEAN = """From: "Newsletter" <news@example.org>
To: helper@example.org
Subject: weekly notes
Authentication-Results: mx.example.org; spf=pass; dkim=pass; dmarc=pass

Here are this week's garden notes.
"""


class CheckSenderTests(unittest.TestCase):
    def _report(self, raw, *args):
        with tempfile.NamedTemporaryFile("w", suffix=".eml", delete=False) as handle:
            handle.write(raw)
            path = handle.name
        try:
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = check_sender.main([path, *args])
            return code, out.getvalue()
        finally:
            os.unlink(path)

    def test_lookalike_and_protected_name(self):
        code, out = self._report(RAW_SPOOF, "--protected-names", "Pat Example")
        self.assertNotEqual(code, 0, out)
        self.assertIn("gmai1.com", out)

    def test_clean_mail_is_not_identity(self):
        code, out = self._report(RAW_CLEAN)
        self.assertEqual(code, 0, out)
        self.assertIn("not identity confirmation", out)

    def test_no_default_names(self):
        self.assertEqual(tuple(check_sender.DEFAULT_PROTECTED_NAMES), ())


if __name__ == "__main__":
    unittest.main()
