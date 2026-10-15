#!/usr/bin/env python3
"""Black-box regression tests using synthetic Git repos and the real hash helper."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CommittedReviewsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.deno = shutil.which("deno") or str(Path.home() / ".swamp/deno/deno")
        if not Path(cls.deno).is_file():
            raise RuntimeError("Deno is required; pre-cache scripts/content-hash.ts dependencies")
        cls.pool = tempfile.TemporaryDirectory(prefix="committed-review-regression-")
        cls.base = Path(cls.pool.name)
        cls.template = cls.base / "template"
        cls.template.mkdir()
        (cls.template / "scripts").mkdir()
        for name in ("check-review-verdicts.sh", "check-committed-reviews.py", "content-hash.ts"):
            shutil.copy2(ROOT / "scripts" / name, cls.template / "scripts" / name)
        (cls.template / "scripts/check-review-verdicts.sh").chmod(0o755)
        (cls.template / "feature").mkdir()
        (cls.template / "feature/manifest.yaml").write_text(json.dumps({
            "manifestVersion": 1, "name": "@fixture/feature", "version": "1.0.0",
            "paths": {"base": "manifest"}, "models": ["thing.txt"],
            "additionalFiles": ["README.md"]}) + "\n")
        (cls.template / "feature/thing.txt").write_text("reviewed source\n")
        (cls.template / "feature/README.md").write_text("synthetic fixture\n")
        (cls.template / ".gitignore").write_text("reviews/**/*.tmp\nreviews/ignored/\n*.swp\n")
        cls.command(cls.template, ["git", "init", "-b", "main"])
        cls.command(cls.template, ["git", "config", "user.name", "Fixture"])
        cls.command(cls.template, ["git", "config", "user.email", "fixture@example.invalid"])
        cls.command(cls.template, ["git", "config", "commit.gpgsign", "false"])
        cls.hash = cls.command(cls.template, [cls.deno, "run", "--cached-only", "--allow-read", "--allow-run",
                                 "scripts/content-hash.ts", "feature/manifest.yaml"]).stdout.strip()
        cls.review = "reviews/feature/" + cls.hash + ".md"
        (cls.template / cls.review).parent.mkdir(parents=True)
        (cls.template / cls.review).write_text("verdict: PASS\n\nSynthetic existing verdict.\n")
        cls.command(cls.template, ["git", "add", "."])
        cls.command(cls.template, ["git", "commit", "-m", "Synthetic reviewed baseline"])

    @classmethod
    def tearDownClass(cls):
        cls.pool.cleanup()

    @staticmethod
    def command(cwd, argv, *, check=True, data=None, env=None):
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, input=data,
                           env=env, timeout=30)
        if check and p.returncode:
            raise AssertionError(str(argv) + "\n" + p.stdout + p.stderr)
        return p

    def setUp(self):
        self.repo = Path(tempfile.mkdtemp(dir=self.base, prefix="case-"))
        self.command(self.base, ["git", "clone", "--no-local", str(self.template), str(self.repo)])
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")

    def git(self, *args, data=None):
        return self.command(self.repo, ["git", *args], data=data)

    def write(self, name, text="verdict: FAIL\n"):
        p = self.repo / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def check(self, allowed=False, env=None, manifests=None):
        p = self.command(self.repo, ["bash", "scripts/check-review-verdicts.sh", *(manifests or [])],
                         check=False, env=env)
        self.assertEqual(p.returncode, 0 if allowed else 1, p.stdout + p.stderr)
        if allowed:
            self.assertIn("HEAD=", p.stdout)
            self.assertIn("blob=", p.stdout)
        else:
            self.assertIn("REFUSING", p.stderr)
            self.assertNotIn("PASS     ", p.stdout)
        return p

    def test_committed_pass_and_hash_reuse(self):
        self.check(allowed=True)
        self.git("commit", "--allow-empty", "-m", "Unrelated commit preserves content identity")
        self.check(allowed=True, manifests=["feature/manifest.yaml"])

    def test_incident_old_pass_with_untracked_new_fail(self):
        self.write("reviews/feature/" + "a" * 64 + ".md")
        self.check()

    def test_untracked_current_pass_is_not_committed_evidence(self):
        self.git("rm", "--cached", self.review)
        self.git("commit", "-m", "Remove verdict from source authority")
        self.check()

    def test_staged_verdict(self):
        self.write(self.review)
        self.git("add", self.review)
        self.check()

    def test_modified_verdict(self):
        self.write(self.review)
        self.check()

    def test_deleted_verdict(self):
        (self.repo / self.review).unlink()
        self.check()

    def test_staged_deleted_verdict(self):
        self.git("rm", self.review)
        self.check()

    def test_ignored_temporary_review(self):
        self.write(self.review + ".tmp")
        self.assertEqual(self.git("status", "--porcelain").stdout, "")
        self.check()

    def test_unrelated_ignored_review_subtree(self):
        self.write("reviews/ignored/crashed-round/output")
        self.assertEqual(self.git("status", "--porcelain").stdout, "")
        self.check()

    def test_tracked_temporary_is_never_a_verdict(self):
        self.write(self.review + ".tmp")
        self.git("add", "-f", self.review + ".tmp")
        self.git("commit", "-m", "Synthetic tracked scratch")
        self.check()

    def test_review_symlink(self):
        (self.repo / self.review).unlink()
        (self.repo / self.review).symlink_to("../../feature/README.md")
        self.check()

    def test_review_directory_symlink(self):
        source = self.repo / "reviews/feature"
        source.rename(self.repo / "saved-review-fixture")
        source.symlink_to("../saved-review-fixture", target_is_directory=True)
        self.check()

    def test_committed_symlink_verdict(self):
        (self.repo / self.review).unlink()
        (self.repo / self.review).symlink_to("../../feature/README.md")
        self.git("add", self.review)
        self.git("commit", "-m", "Synthetic symlink verdict")
        self.check()

    def test_assume_unchanged_review(self):
        self.git("update-index", "--assume-unchanged", self.review)
        self.write(self.review)
        self.assertEqual(self.git("status", "--porcelain").stdout, "")
        self.check()

    def test_skip_worktree_review(self):
        self.git("update-index", "--skip-worktree", self.review)
        self.write(self.review)
        self.assertEqual(self.git("status", "--porcelain").stdout, "")
        self.check()

    def test_conflicted_review(self):
        oid = self.git("rev-parse", "HEAD:" + self.review).stdout.strip()
        self.git("update-index", "--index-info", data="0 " + "0" * 40 + "\t" + self.review + "\n" +
                 "100644 " + oid + " 1\t" + self.review + "\n" + "100644 " + oid + " 2\t" + self.review + "\n")
        self.check()

    def test_index_writer_in_progress(self):
        self.write(".git/index.lock", "")
        self.check()

    def test_committed_fail_is_rejected_for_release(self):
        self.write(self.review)
        self.git("add", self.review)
        self.git("commit", "-m", "Synthetic FAIL verdict")
        self.check()

    def test_unstaged_published_source(self):
        self.write("feature/thing.txt", "changed source\n")
        self.check()

    def test_imported_helpers_and_release_assets_invalidate_review(self):
        self.write("feature/manifest.yaml", json.dumps({
            "manifestVersion": 1, "name": "@fixture/feature", "version": "1.0.0",
            "paths": {"base": "manifest"}, "models": ["thing.ts"],
            "include": ["job.ts"], "binaries": ["runner.sh"],
            "additionalFiles": ["README.md"]}) + "\n")
        self.write("feature/thing.ts", 'export { value } from "./nested/helper.ts";\n')
        self.write("feature/nested/helper.ts", "export const value = 1;\n")
        self.write("feature/job.ts", "export const job = 1;\n")
        self.write("feature/runner.sh", "#!/bin/sh\nexit 0\n")
        self.write("feature/quality.yaml", "accept: []\n")
        self.write("deno.json", "{}\n")
        command = [self.deno, "run", "--cached-only", "--allow-read", "--allow-run",
                   "scripts/content-hash.ts", "feature/manifest.yaml"]
        files = self.command(self.repo, [*command, "--list"]).stdout.splitlines()
        for name in ("feature/nested/helper.ts", "feature/job.ts", "feature/runner.sh",
                     "feature/quality.yaml", "deno.json"):
            self.assertIn(name, files)
        digest = self.command(self.repo, command).stdout.strip()
        self.git("rm", self.review)
        review = "reviews/feature/" + digest + ".md"
        self.write(review, "verdict: PASS\n\nSynthetic reviewed release inputs.\n")
        self.git("add", ".")
        self.git("commit", "-m", "Synthetic reviewed package with imports and assets")
        self.check(allowed=True)
        for name in ("feature/nested/helper.ts", "feature/job.ts", "feature/runner.sh",
                     "feature/quality.yaml", "deno.json"):
            previous = (self.repo / name).read_text()
            self.write(name, previous + "\n")
            self.assertNotEqual(digest, self.command(self.repo, command).stdout.strip())
            self.check()
            self.write(name, previous)

    def test_staged_published_source(self):
        self.write("feature/thing.txt", "changed source\n")
        self.git("add", "feature/thing.txt")
        self.check()

    def test_concealed_published_source(self):
        self.git("update-index", "--skip-worktree", "feature/thing.txt")
        self.write("feature/thing.txt", "changed source\n")
        self.check()

    def test_deleted_optional_readme_is_rejected(self):
        (self.repo / "feature/README.md").unlink()
        self.check()

    def test_helper_modification_is_rejected(self):
        self.write("scripts/content-hash.ts", "console.log('untrusted');\n")
        self.check()

    def test_missing_committed_verdict_for_new_content(self):
        self.write("feature/thing.txt", "changed source\n")
        self.git("add", "feature/thing.txt")
        self.git("commit", "-m", "Synthetic new content without matching review")
        self.check()

    def mutation_deno(self, mutation):
        bindir = Path(tempfile.mkdtemp(dir=self.base, prefix="runner-bin-"))
        self.wrapper = bindir / "deno"
        wrapper = bindir / "deno"
        wrapper.write_text("#!" + sys.executable + "\n" +
            "import pathlib, subprocess, sys\n" +
            "p = subprocess.run([" + repr(self.deno) + ", *sys.argv[1:]])\n" +
            "marker = pathlib.Path('.race-test-done')\n" +
            "if '--list' not in sys.argv and not marker.exists():\n" +
            "    marker.write_text('mutated')\n" +
            "    " + mutation + "\n" + "sys.exit(p.returncode)\n")
        wrapper.chmod(0o755)
        env = os.environ.copy()
        env['PATH'] = str(bindir) + os.pathsep + env.get('PATH', '')
        return env

    def test_concurrent_review_after_hash(self):
        env = self.mutation_deno("pathlib.Path(" + repr(self.review + '.tmp') + ").write_text('pending')")
        self.check(env=env)

    def test_concurrent_head_change(self):
        env = self.mutation_deno("subprocess.run(['git','commit','--allow-empty','-m','Concurrent commit'], check=True, stdout=subprocess.DEVNULL)")
        self.check(env=env)

    def test_new_optional_license_during_check(self):
        env = self.mutation_deno("pathlib.Path('feature/LICENSE').write_text('new published file')")
        self.check(env=env)

    def baseline(self):
        self.write("reviews/KNOWN-NOT-PASS.txt", "# Existing private CI debt\nfeature\n")
        self.write(self.review)
        self.git("add", "reviews")
        self.git("commit", "-m", "Preserve explicit private CI debt")

    def test_committed_ci_baseline_never_becomes_pass_or_release(self):
        self.baseline()
        p = self.command(self.repo, ["bash", "scripts/check-review-verdicts.sh"], check=False)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("DEBT", p.stdout)
        self.assertNotIn("PASS     ", p.stdout)
        self.check(manifests=["feature/manifest.yaml"])

    def test_ci_baseline_cannot_hide_new_review_output(self):
        self.baseline()
        self.write("reviews/feature/pending.tmp")
        self.check()

    def test_dirty_ci_baseline_is_rejected(self):
        self.baseline()
        self.write("reviews/KNOWN-NOT-PASS.txt", "feature\nanother\n")
        self.check()

    def test_checkout_tool_injection_is_rejected(self):
        bindir = self.repo / "fake-tools"
        bindir.mkdir()
        shim = bindir / "deno"
        shim.write_text("#!/bin/sh\necho untrusted-runtime\n")
        shim.chmod(0o755)
        env = {**os.environ, "PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")}
        result = self.check(env=env)
        self.assertIn("outside the checkout", result.stderr)

    def test_git_path_injection_cannot_hide_pending_review(self):
        bindir = self.repo / "fake-tools"
        bindir.mkdir()
        shim = bindir / "git"
        shim.write_text("#!/bin/sh\nexit 0\n")
        shim.chmod(0o755)
        self.write("reviews/pending.tmp")
        self.check(env={**os.environ, "PATH": str(bindir) + os.pathsep + os.environ.get("PATH", "")})

    def test_helper_error_fails_closed(self):
        env = self.mutation_deno("pass")
        wrapper = self.wrapper
        wrapper.write_text("#!/bin/sh\nexit 9\n")
        self.check(env=env)


if __name__ == "__main__":
    unittest.main(verbosity=2)
