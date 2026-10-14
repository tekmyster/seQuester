# Copyright (c) 2026 Tekmyster Industries, LLC. All Rights Reserved.
# seQuester — Proprietary Commercial License.

"""Check locked library licenses and source notices without executing package code."""

import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request
import xml.etree.ElementTree as ET

OWNER = "Copyright (c) 2026 Tekmyster Industries, LLC. All Rights Reserved."
TERMS = "seQuester — Proprietary Commercial License."
ALLOWED = re.compile(r"^(MIT|Apache-2\.0)(\s+(AND|OR)\s+(MIT|Apache-2\.0))*$")
ROOT = Path(__file__).resolve().parents[1]


def dependencies(root):
    packages = set()
    for lock in (root / "src").glob("*/packages.lock.json"):
        for target in json.loads(lock.read_text(encoding="utf-8-sig"))["dependencies"].values():
            for name, value in target.items():
                if value.get("type") != "Project" and value.get("resolved"):
                    packages.add((name, value["resolved"]))
    return sorted(packages, key=lambda pair: (pair[0].lower(), pair[1]))


def package_license(package):
    name, version = package
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", name + version):
        return name, version, None, "invalid package identity"
    cache = Path(os.environ.get("NUGET_PACKAGES", Path.home() / ".nuget" / "packages"))
    nuspec = cache / name.lower() / version.lower() / (name.lower() + ".nuspec")
    try:
        if nuspec.exists():
            data = nuspec.read_bytes()
        else:
            url = f"https://api.nuget.org/v3-flatcontainer/{name.lower()}/{version.lower()}/{name.lower()}.nuspec"
            with urllib.request.urlopen(url, timeout=20) as response:
                data = response.read(2 * 1024 * 1024 + 1)
            if len(data) > 2 * 1024 * 1024:
                raise ValueError("metadata exceeds limit")
        metadata = next(node for node in ET.fromstring(data) if node.tag.rsplit("}", 1)[-1] == "metadata")
        fields = {node.tag.rsplit("}", 1)[-1]: node for node in metadata}
        if fields["id"].text.lower() != name.lower() or fields["version"].text.lower() != version.lower():
            raise ValueError("package identity mismatch")
        license_node = fields.get("license")
        if license_node is None:
            return name, version, None, "license metadata unavailable"
        if license_node.attrib.get("type") != "expression":
            return name, version, None, "file-based license requires review: " + (license_node.text or "unknown")
        expression = (license_node.text or "").strip()
        return name, version, expression, None
    except (OSError, ValueError, ET.ParseError, KeyError, StopIteration):
        return name, version, None, "package metadata unavailable or invalid"


def check_headers(root, base):
    files = subprocess.check_output(
        ["git", "diff", "--name-only", "--diff-filter=A", "-z", base, "HEAD"], cwd=root
    ).decode("utf-8").split("\0")
    failures = []
    for name in filter(None, files):
        file = root / name
        if not file.is_file():
            continue
        try:
            text = file.read_text(encoding="utf-8-sig")[:4096]
        except UnicodeError:
            text = ""
        if OWNER in text and TERMS in text:
            continue
        sidecar = Path(str(file) + ".license")
        if sidecar.is_file():
            text = sidecar.read_text(encoding="utf-8-sig")[:4096]
            if OWNER in text and TERMS in text:
                continue
        failures.append(f"{name}: copyright/license notice missing; use a valid header or .license sidecar")
    return failures


def audit(root):
    failures = []
    notices = (root / "THIRD-PARTY-NOTICES.md").read_text(encoding="utf-8")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        records = list(pool.map(package_license, dependencies(root)))
    for name, version, expression, error in records:
        if error or not ALLOWED.fullmatch(expression or ""):
            failures.append(f"{name} {version}: {error or expression}; not approved MIT/Apache-2.0")
        if f"| {name} | {version} |" not in notices:
            failures.append(f"{name} {version}: missing from THIRD-PARTY-NOTICES.md")
        if name.startswith("SQLitePCLRaw.lib."):
            failures.append(f"{name} {version}: embedded SQLite public-domain engine is outside the specified license allowlist")
        if name.startswith("SkiaSharp.NativeAssets."):
            failures.append(f"{name} {version}: embedded Skia BSD terms require resolution; wrapper license alone is insufficient")
    for file in (root / "src").rglob("*"):
        if not file.is_file() or any(part in {"bin", "obj"} for part in file.parts):
            continue
        if file.suffix not in {".c", ".h", ".cpp", ".cs"}:
            continue
        text = file.read_text(encoding="utf-8-sig", errors="replace")
        relative = file.relative_to(root).as_posix()
        if re.search(r"SPDX-License-Identifier:[^\r\n]*(?:GPL|LGPL|AGPL)", text) or re.search(r'MODULE_LICENSE\("GPL', text):
            failures.append(f"{relative}: copyleft component retains its license; strict core inclusion requires boundary review")
        if "DllImport" in text and re.search(r"libbpf|libauparse", text):
            failures.append(f"{relative}: native library outside MIT/Apache-2.0 policy; see notices")
    return records, failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", help="Check headers on new files since this Git ref")
    parser.add_argument("--headers-only", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        for expression in ("MIT", "Apache-2.0", "MIT OR Apache-2.0"):
            assert ALLOWED.fullmatch(expression)
        for expression in ("GPL-2.0-only", "LGPL-2.1-only", "BSD-3-Clause", "MIT OR GPL-2.0-only", "", "LicenseRef-Commercial"):
            assert not ALLOWED.fullmatch(expression)
        required_files = [ROOT / "LICENSE", ROOT / "LICENSE-COMMERCIAL", ROOT / "PRIVATE-LICENSE.md", ROOT / "THIRD-PARTY-NOTICES.md", ROOT / "docs/EDITIONS.md", Path(__file__), ROOT / ".github/workflows/license-policy.yml"]
        for file in required_files:
            text = file.read_text(encoding="utf-8")[:4096]
            assert OWNER in text and TERMS in text, f"Required header missing: {file.name}"
        with tempfile.TemporaryDirectory(prefix="sequester-license-check-") as directory:
            fixture = Path(directory)
            def git(*arguments):
                return subprocess.check_output(["git", "-c", "user.name=License policy fixture", "-c", "user.email=fixture@localhost", *arguments], cwd=fixture, stderr=subprocess.DEVNULL).decode().strip()
            git("init", "-q")
            (fixture / "baseline.md").write_text("Baseline\n", encoding="utf-8")
            git("add", ".")
            git("commit", "-qm", "baseline")
            base = git("rev-parse", "HEAD")
            header = f"// {OWNER}\n// {TERMS}\n"
            (fixture / "valid.cs").write_text(header + "class Valid {}\n", encoding="utf-8")
            (fixture / "missing.cs").write_text("class Missing {}\n", encoding="utf-8")
            (fixture / "data.json").write_text('{"value":1}\n', encoding="utf-8")
            (fixture / "data.json.license").write_text(header, encoding="utf-8")
            git("add", ".")
            git("commit", "-qm", "header controls")
            failures = check_headers(fixture, base)
            assert len(failures) == 1 and failures[0].startswith("missing.cs:"), failures
        print("PASS: allowed/rejected expressions, required headers, missing-header rejection and JSON sidecars")
        return 0
    if args.headers_only and not args.base:
        parser.error("--headers-only requires --base")
    failures = check_headers(ROOT, args.base) if args.base else []
    count = 0
    if not args.headers_only:
        records, policy_failures = audit(ROOT)
        count = len(records)
        failures.extend(policy_failures)
    print(json.dumps({"packages_checked": count, "compliant": not failures, "failures": failures}, indent=2))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
