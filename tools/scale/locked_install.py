"""Attest native Windows installations of a pinned product lock, not local installs."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))


def normalized(value):
    return re.sub(r"[-_.]+", "-", value).lower()


def applies(marker, platform_name):
    match = re.fullmatch(r"sys_platform == '([^']+)'", marker)
    if match is not None:
        return platform_name == match[1]
    # Only the hosted harness imports this dependency, never an engine process.
    from packaging.markers import Marker, default_environment
    environment = default_environment()
    environment["sys_platform"] = platform_name
    return Marker(marker).evaluate(environment)


def validate(lock, project, installed, profile, platform_name=None):
    platform_name = platform_name or sys.platform
    if profile == "runtime":
        # The measured subject has a standard-library-only runtime closure.
        if project["project"]["dependencies"]:
            raise ValueError("runtime_dependency_closure_needs_resolution")
        expected = {}
    else:
        packages = {normalized(p["name"]): p for p in lock["package"]}
        expected, pending, expanded = {}, [], set()
        for requirement in project["dependency-groups"]["dev"]:
            match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([^; ]+)(?:;\s*(.*))?", requirement)
            if match is None:
                raise ValueError("unqualified_root_requirement")
            name, version, marker = match.groups()
            if marker is not None and not applies(marker, platform_name):
                continue
            if packages[normalized(name)]["version"] != version:
                raise ValueError("declared_development_pin_mismatch")
            pending.append((normalized(name), ()))
        while pending:
            name, extras = pending.pop()
            key = (name, extras)
            if key in expanded:
                continue
            expanded.add(key)
            package = packages[name]
            expected[name] = package["version"]
            dependencies = list(package.get("dependencies", []))
            for extra in extras:
                dependencies.extend(package["optional-dependencies"][extra])
            for dependency in dependencies:
                marker = dependency.get("marker")
                if marker is not None:
                    if not applies(marker, platform_name):
                        continue
                pending.append((normalized(dependency["name"]), tuple(sorted(dependency.get("extra", [])))))
    if installed != expected:
        raise ValueError("locked_install_mismatch:" + json.dumps({"expected": expected, "actual": installed}, sort_keys=True))
    return expected


def validate_hooks(rows, installed, profile):
    for row in rows:
        if not row["owner"] or normalized(row["owner"]) not in installed:
            raise ValueError("startup_hook_ownership")
        if row["sha256"] != row["record_sha256"]:
            raise ValueError("startup_hook_record_digest")
        if profile == "runtime" and row["class"] == "executable":
            raise ValueError("runtime_startup_code")
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--subject", type=Path, required=True)
    parser.add_argument("--profile", choices=("runtime", "dev"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    from tools.scale.measure import shape
    runtime = args.subject / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    inspector = str(Path(__file__).with_name("inspect_install.py").resolve())
    lock_path, project_path = args.subject / "uv.lock", args.subject / "pyproject.toml"
    lock = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    project = tomllib.loads(project_path.read_text(encoding="utf-8"))
    prestart = json.loads(subprocess.check_output([str(runtime), "-I", "-S", inspector], encoding="utf-8"))
    preinstalled = {normalized(k): v for k, v in prestart["installed"].items()}
    expected = validate(lock, project, preinstalled, args.profile)
    validate_hooks(prestart["hooks"], expected, args.profile)
    observed = json.loads(subprocess.check_output([str(runtime), "-I", inspector], encoding="utf-8"))
    installed = {normalized(k): v for k, v in observed["installed"].items()}
    validate(lock, project, installed, args.profile)
    if preinstalled != installed or prestart["hooks"] != observed["hooks"]:
        raise ValueError("locked_startup_environment_changed")
    observed["prestart_no_site_census"] = prestart
    observed["startup_allowlist"] = validate_hooks(observed["hooks"], expected, args.profile)
    observed.update({"schema": 1, "status": "pass", "profile": args.profile,
                     "runner": shape(), "expected": expected,
                     "subject_head": subprocess.check_output(["git", "-C", str(args.subject), "rev-parse", "HEAD"], encoding="ascii").strip(),
                     "lock_sha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
                     "project_sha256": hashlib.sha256(project_path.read_bytes()).hexdigest(),
                     "editable_install": "virtual project in authoritative lock; no editable install or project .pth",
                     "scope": "full currently declared product runtime/dev set; future dependency changes require requalification"})
    references = {}
    for no_site in (False, True):
        flags = ["-I"] + (["-S"] if no_site else [])
        command = [str(runtime.absolute())] + flags + [str(ROOT / "tools" / "scale" / "startup_reference.py")]
        first = subprocess.check_output(command)
        if first != subprocess.check_output(command):
            raise ValueError("locked_environment_startup_baseline_unstable")
        references["no_site" if no_site else "site"] = json.loads(first)
    observed["clean_role_references"] = references
    if args.profile == "dev":
        # Optional -S launch: append the locked purelib/platlib directly, never
        # invoke site.addsitedir or execute an editable .pth hook.
        code = "import sys,sysconfig;sys.path.extend(dict.fromkeys([sysconfig.get_path('purelib'),sysconfig.get_path('platlib')]));import pytest,hypothesis,grimp;assert sys.flags.no_site == 1;"
        if "coverage" in expected:
            code += "import coverage;from coverage.tracer import CTracer;"
        code += "print('locked development imports and selected native extensions succeeded under -S')"
        observed["manual_no_site_development_imports"] = subprocess.check_output([str(runtime.absolute()), "-I", "-S", "-c", code], encoding="utf-8").strip()
    args.out.write_text(json.dumps(observed, sort_keys=True, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
