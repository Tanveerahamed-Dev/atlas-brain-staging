"""L-c: compare the full confined run with an unconfined native host run."""
import argparse
import json
from pathlib import Path


def compare(confined, host):
    if len(confined) != 5 or len(host) != 1 or any(r["status"] != "ok" for r in confined + host):
        raise ValueError("comparison_missing_runs")
    if any(not r["container"] or r["cap_bytes"] != 2**31 or not r["cap_verified"] for r in confined) or host[0]["container"] or host[0]["cap_bytes"]:
        raise ValueError("comparison_profiles")
    manifests = [r["manifest_sha256"] for r in confined + host]
    if len(set(manifests)) != 1:
        raise ValueError("comparison_bytes_differ")
    return {"schema": 1, "status": "pass", "profile": "S0-e full 1000-device container/host equality", "manifests": manifests}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("confined", type=Path)
    parser.add_argument("host", type=Path)
    args = parser.parse_args()
    def rows(root):
        data = [json.loads(p.read_bytes()) for p in root.rglob("measurement.json")]
        return [r for r in data if r["size"] == 1000 and not r["dense"]]
    result = compare(rows(args.confined), rows(args.host))
    (args.host / "comparison.json").write_text(json.dumps(result, sort_keys=True) + "\n", encoding="ascii")
