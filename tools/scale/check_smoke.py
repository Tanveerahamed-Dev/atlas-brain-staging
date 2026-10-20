"""Verify the end-to-end slice actually exercises its declared work."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from spike.estate import CHECKS


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("run", type=Path)
    args = parser.parse_args()
    estate = json.loads((args.run / "estate.json").read_bytes())
    receipt = json.loads((args.run / "engine.json").read_bytes())
    if set(row[0] for row in estate["checks"]) != set(CHECKS):
        raise ValueError("six_checks_not_exercised")
    if len(receipt["facts_per_device"]) != 100 or receipt["facts"] != 232835 or any(count < 100 for _, count in receipt["facts_per_device"]):
        raise ValueError("facts_missing")
    if not any(c["variant"] == "observed" and c["complete"] and all(h["state"] == "problem" for h in c["hops"]) for c in estate["correlations"]):
        raise ValueError("three_hop_example_missing")
    if not any(c["variant"] == "unknown-middle" and c["stopped_at"] == 1 and c["hops"][1]["reason"] == "PEER_NOT_COLLECTED" and not c["complete"] for c in estate["correlations"]):
        raise ValueError("unknown_bridge")
    if any(row[3] != "unknown" for row in estate["checks"] if row[0] == CHECKS[4] and int(row[1][3:]) % 20 == 18):
        raise ValueError("unparsed_nx_stp_not_unknown")
    stp_states = {row[3] for row in estate["checks"] if row[0] == CHECKS[4]}
    if stp_states != {"ok", "problem", "unknown"}:
        raise ValueError("stp_positive_negative_unknown_not_exercised")
    print("six checks, three-hop chain, unknown stop, per-device facts: passed")
