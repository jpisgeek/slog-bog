#!/usr/bin/env python3
"""Prove local release inputs and PASS verdict bytes exist in captured HEAD.

This is a fail-closed CI check. It is not a lock, a review-round registry, an
agent launcher, or a security boundary against an actor who can rewrite it.
"""
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys


class Rejected(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Rejected(message)


class Checker:
    def __init__(self, root):
        self.root = root
        # The runner supplies tool installation and cache paths. Repository-local
        # PATH shims cannot replace Git or the hash runtime.
        self.env = {k: os.environ[k] for k in ("HOME", "TMPDIR", "DENO_DIR", "SSL_CERT_FILE", "SSL_CERT_DIR") if k in os.environ}
        self.env["PATH"] = "/usr/bin:/bin"
        self.env.update(GIT_NO_REPLACE_OBJECTS="1", GIT_CONFIG_NOSYSTEM="1",
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS="0")
        self.head = self.git("rev-parse", "--verify", "HEAD^{commit}").decode().strip()
        self.tree = self.read_tree()
        self.blobs = {}
        self.deno = shutil.which("deno")
        if self.deno is None:
            candidate = Path.home() / ".swamp/deno/deno"
            if candidate.is_file() and os.access(candidate, os.X_OK):
                self.deno = str(candidate)
        require(self.deno, "deno not found (install deno or swamp)")
        executable = Path(self.deno).resolve(strict=True)
        require(executable != self.root and self.root not in executable.parents,
                "Deno must come from the runner installation outside the checkout")
        require(executable.is_file() and os.access(executable, os.X_OK), "Deno is not executable")
        self.deno = str(executable)

    def git(self, *args, data=None):
        p = subprocess.run(["/usr/bin/git", "-C", str(self.root), *args], input=data,
                           capture_output=True, env=self.env, timeout=30)
        require(p.returncode == 0, "Git check failed: " + p.stderr.decode(errors="replace").strip())
        return p.stdout

    def read_tree(self):
        result = {}
        for row in self.git("ls-tree", "-rz", "--full-tree", self.head).split(b"\0"):
            if row:
                meta, path = row.split(b"\t", 1)
                mode, kind, oid = meta.decode().split()
                result[os.fsdecode(path)] = (mode, kind, oid)
        return result

    def index(self):
        lock = self.git("rev-parse", "--git-path", "index.lock").decode().strip()
        lockpath = Path(lock) if Path(lock).is_absolute() else self.root / lock
        require(not os.path.lexists(lockpath), "index write is in progress (index.lock)")
        records = {}
        for row in self.git("ls-files", "--stage", "-z").split(b"\0"):
            if row:
                meta, path = row.split(b"\t", 1)
                mode, oid, stage = meta.decode().split()
                records.setdefault(os.fsdecode(path), []).append((mode, oid, stage))
        flags = {}
        for row in self.git("ls-files", "-v", "-z").split(b"\0"):
            if row:
                flags[os.fsdecode(row[2:])] = chr(row[0])
        return records, flags

    def safe_path(self, name):
        p = PurePosixPath(name)
        require(name and not p.is_absolute() and str(p) == name and
                all(x not in ("..", ".git") for x in p.parts) and
                not any(ord(c) < 32 or ord(c) == 127 for c in name),
                "unsafe path: " + repr(name))
        result = self.root
        for part in p.parts[:-1]:
            result /= part
            require(stat.S_ISDIR(result.lstat().st_mode), "non-directory path component: " + repr(name))
        return self.root / name

    def disk_blob(self, name):
        path = self.safe_path(name)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as f:
            before = os.fstat(f.fileno())
            require(stat.S_ISREG(before.st_mode), "not a regular file: " + repr(name))
            content = f.read()
            after = os.fstat(f.fileno())
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode)
        require(identity(before) == identity(after), "file changed while reading: " + repr(name))
        mode = "100755" if before.st_mode & 0o111 else "100644"
        return mode, content

    def committed_blob(self, name):
        entry = self.tree.get(name)
        require(entry and entry[0] in ("100644", "100755") and entry[1] == "blob",
                "missing regular Git blob in HEAD: " + repr(name))
        if entry[2] not in self.blobs:
            self.blobs[entry[2]] = self.git("cat-file", "blob", entry[2])
        return entry[0], self.blobs[entry[2]]

    def verify_file(self, name, index):
        records, flags = index
        committed = self.committed_blob(name)
        require(records.get(name) == [(self.tree[name][0], self.tree[name][2], "0")],
                "index differs from HEAD or is conflicted: " + repr(name))
        flag = flags.get(name, "")
        require(flag == "H", "concealed or nonordinary index entry: " + repr(name) + " (" + flag + ")")
        disk = self.disk_blob(name)
        require(disk == committed, "working file differs from HEAD: " + repr(name))
        return disk

    @staticmethod
    def temporary(name):
        base = PurePosixPath(name).name
        return (base.endswith((".tmp", ".swp", ".swo", ".bak", "~")) or
                base.startswith((".#", "#")) or base == ".DS_Store")

    def review_snapshot(self, index):
        records, flags = index
        scope = lambda p: p == "reviews" or p.startswith("reviews/")
        expected = {p for p in self.tree if scope(p)}
        indexed = {p for p in records if scope(p)}
        require(indexed == expected, "review index paths differ from HEAD")
        expected_dirs = {"reviews"}
        for name in expected:
            expected_dirs.update(str(p) for p in PurePosixPath(name).parents if str(p) != ".")
        found = set()
        directories = set()
        start = self.root / "reviews"
        if os.path.lexists(start):
            require(stat.S_ISDIR(start.lstat().st_mode), "reviews must be a regular directory")
            def visit(directory):
                rel = directory.relative_to(self.root).as_posix()
                directories.add(rel)
                with os.scandir(directory) as entries:
                    for entry in entries:
                        name = Path(entry.path).relative_to(self.root).as_posix()
                        require(not self.temporary(name), "pending temporary review output: " + repr(name))
                        mode = entry.stat(follow_symlinks=False).st_mode
                        if stat.S_ISDIR(mode):
                            visit(Path(entry.path))
                        else:
                            require(stat.S_ISREG(mode), "nonregular review output: " + repr(name))
                            found.add(name)
            visit(start)
        require(found == expected, "review disk paths differ from HEAD (untracked, ignored, deleted, or pending output)")
        require(directories <= expected_dirs, "untracked review directory or pending review output")
        values = {name: self.verify_file(name, index) for name in sorted(expected)}
        return values, directories, {p: flags[p] for p in indexed}

    def helper(self, manifest, listing=False):
        args = [self.deno, "run", "--allow-read", "--allow-run", "scripts/content-hash.ts", manifest]
        if listing:
            args.append("--list")
        p = subprocess.run(args, cwd=self.root, capture_output=True, env=self.env, timeout=90)
        require(p.returncode == 0, "content-hash helper failed: " + p.stderr.decode(errors="replace").strip())
        return p.stdout.decode("utf-8")

    def check(self, manifests):
        before_index = self.index()
        before_reviews = self.review_snapshot(before_index)
        helper = "scripts/content-hash.ts"
        before_files = {helper: self.verify_file(helper, before_index)}
        # Preserve the private branch's committed CI debt list, if present.
        # Explicit manifest checks (review/release) always require exact PASS.
        allowed = set()
        baseline = "reviews/KNOWN-NOT-PASS.txt"
        if not manifests and baseline in self.tree:
            raw = self.verify_file(baseline, before_index)[1].decode("utf-8")
            for line in raw.splitlines():
                name = line.strip()
                if name and not name.startswith("#"):
                    require(re.fullmatch(r"[A-Za-z0-9_-]+", name), "invalid committed CI baseline")
                    allowed.add(name)
        if not manifests:
            tracked = {p for p in self.tree if len(PurePosixPath(p).parts) == 2 and p.endswith("/manifest.yaml")}
            present = {p.relative_to(self.root).as_posix() for p in self.root.glob("*/manifest.yaml")}
            manifests = sorted(tracked | present)
        require(manifests, "no committed extension manifests found")
        reports = []
        resolved = {}
        for manifest in manifests:
            before_files[manifest] = self.verify_file(manifest, before_index)
            for side in ("README.md", "LICENSE"):
                sidepath = str(PurePosixPath(manifest).parent / side)
                if sidepath in self.tree:
                    before_files[sidepath] = self.verify_file(sidepath, before_index)
            files = self.helper(manifest, listing=True).splitlines()
            require(files and manifest in files and len(files) == len(set(files)), "invalid content-hash file list")
            digest = hashlib.sha256()
            for name in files:
                value = self.verify_file(name, before_index)
                before_files[name] = value
                data = value[1]
                digest.update(("=== " + name + " (" + str(len(data)) + ") ===\n").encode())
                digest.update(data)
                digest.update(b"\n")
            content_hash = self.helper(manifest).strip()
            require(re.fullmatch(r"[0-9a-f]{64}", content_hash) and digest.hexdigest() == content_hash,
                    "content hash does not match captured committed bytes")
            resolved[manifest] = (files, content_hash)
            name = PurePosixPath(manifest).parent.name
            verdict = "reviews/" + name + "/" + content_hash + ".md"
            if verdict not in self.tree and name in allowed:
                reports.append("DEBT     " + name + "  missing exact-hash verdict  HEAD=" + self.head + "  [CI baseline; no release authority]")
                continue
            verdict_bytes = self.verify_file(verdict, before_index)[1]
            # Keep the existing anchored PASS rule and content-hash reuse policy.
            passed = any(re.fullmatch(rb"verdict:\s*PASS\s*", line) for line in verdict_bytes.splitlines())
            if not passed and name in allowed:
                reports.append("DEBT     " + name + "  committed non-PASS  HEAD=" + self.head + "  blob=" + self.tree[verdict][2] + "  [CI baseline; no release authority]")
                continue
            require(passed,
                    "NOT-PASS " + name + " (committed verdict does not contain the required PASS line)")
            reports.append("PASS     " + name + "  " + content_hash + "  HEAD=" + self.head + "  blob=" + self.tree[verdict][2])
        for manifest, (files, content_hash) in resolved.items():
            require(self.helper(manifest, listing=True).splitlines() == files and
                    self.helper(manifest).strip() == content_hash,
                    "published file set or content changed during verification")
        after_index = self.index()
        require(before_reviews == self.review_snapshot(after_index), "review output changed during verification")
        for name, value in before_files.items():
            require(value == self.verify_file(name, after_index), "published inputs changed during verification")
        require(self.git("rev-parse", "--verify", "HEAD^{commit}").decode().strip() == self.head,
                "HEAD changed during verification")
        for report in reports:
            print(report)


def main():
    try:
        root = Path(__file__).resolve().parent.parent
        Checker(root).check(sys.argv[1:])
    except (Rejected, OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as e:
        print("check-review-verdicts: REFUSING: " + str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
