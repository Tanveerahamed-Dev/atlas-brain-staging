"""Planted violations precede implementation; acceptance runs only in hosted CI."""
import dataclasses
import json
from pathlib import Path
import tempfile
import unittest

from tools.scale import workload
from tools.scale.thresholds import judge
from spike.parsers import parse_capture, PARSERS
from spike.estate import ospf_verdict, correlate


class FrozenWorkloadTests(unittest.TestCase):
    def test_manifest_totals_are_independent_constants(self):
        spec = workload.load_spec()
        self.assertEqual(spec["totals"], {
            "devices": 1000, "interfaces": 58200, "mac": 620000,
            "arp": 314000, "routes": 379000, "neighbors": 11100,
            "ospf_neighbors": 1400, "ospf_interfaces": 4000,
            "syslog": 1000000, "artifacts": 20000,
            "bytes": 1127218550})

    def test_manifest_tamper_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "manifest.json"
            path.write_bytes(workload.SPEC.read_bytes().replace(b'58200', b'58201'))
            with self.assertRaisesRegex(ValueError, "manifest_digest"):
                workload.load_spec(path)

    def test_wrong_mix_or_size_is_refused_before_generation(self):
        with self.assertRaisesRegex(ValueError, "size"):
            workload.expected(101, False)
        profiles = workload.profiles(100)
        profiles[0] = "wan"
        with self.assertRaisesRegex(ValueError, "mix"):
            workload.validate_mix(profiles, 100)

    def test_generator_refuses_existing_or_tampered_estate(self):
        with tempfile.TemporaryDirectory() as root:
            estate = Path(root) / "input"
            workload.generate(estate, 100, False)
            workload.verify(estate)
            with self.assertRaises(FileExistsError):
                workload.generate(estate, 100, False)
            capture = next(estate.glob("sw-*/*.txt"))
            capture.write_bytes(capture.read_bytes() + b"planted violation\n")
            with self.assertRaisesRegex(ValueError, "capture"):
                workload.verify(estate)

    def test_rehashed_wrong_row_count_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            estate = Path(root) / "input"
            doc = workload.generate(estate, 100, False)
            item = next(a for a in doc["artifacts"] if a["form"] == "mac")
            capture = estate / item["path"]
            raw = capture.read_bytes().replace(b"DYNAMIC", b"INVALID", 1)
            capture.write_bytes(raw)
            item["sha256"] = workload.digest(raw)
            (estate / "ESTATE.json").write_bytes(workload.canonical(doc))
            with self.assertRaisesRegex(ValueError, "capture_rows"):
                workload.verify(estate)

    def test_dense_exact_bytes_and_counts(self):
        self.assertEqual(workload.expected(1000, True)["bytes"], 1686962550)
        self.assertEqual(workload.expected(1000, True)["mac"], 1240000)

    def test_logical_interfaces_are_inside_the_frozen_denominator(self):
        spec = workload.load_spec()
        for profile, expected in spec["profiles"].items():
            running = workload.render("running", profile, 18, 100, False).decode("ascii")
            interfaces = workload.render("interfaces", profile, 18, 100, False).decode("ascii")
            configured = [line.split()[1] for line in running.splitlines() if line.startswith("interface ")]
            observed = [line.split()[0] for line in interfaces.splitlines() if " is up, line protocol" in line]
            self.assertEqual(len(configured), expected["interfaces"])
            self.assertEqual(set(configured), set(observed))
            self.assertIn("Port-channel1", observed)


class ParserTests(unittest.TestCase):
    def test_exactly_sixteen_variants(self):
        self.assertEqual(len(PARSERS), 16)
        self.assertEqual(sum(f == "iosxe" for f, _ in PARSERS), 12)

    def test_all_lines_accounted_and_spans_resolve(self):
        for family, form in PARSERS:
            body = workload.render(form, "core_nx" if family == "nxos" else "core_xe", 18, 100, False)
            result = parse_capture(family, form, body)
            self.assertEqual(result["unrecognized"], [], (family, form))
            self.assertEqual(sum(result["accounting"].values()), len(body.splitlines()))
            for row in result["rows"]:
                self.assertTrue(body[row.start:row.end].strip())
                self.assertGreaterEqual(row.line, 1)

    def test_unrecognized_line_cannot_disappear(self):
        result = parse_capture("iosxe", "interfaces", b"planted unknown token\n")
        self.assertEqual(result["unrecognized"], [1])

    def test_oversize_and_pathological_line_refused(self):
        with self.assertRaisesRegex(ValueError, "line_budget"):
            parse_capture("iosxe", "interfaces", b"a" * 65537 + b"!\n")

    def test_blank_and_unmapped_are_unknown(self):
        result = parse_capture("iosxe", "interfaces", b"GigabitEthernet1/0/1 is up, line protocol is down\n  MTU 1500 bytes, UNKNOWN-duplex\n")
        self.assertEqual(result["rows"][1].values[-1], "unknown")

    def test_ospf_two_way_semantics(self):
        self.assertEqual(ospf_verdict("2WAY", "BROADCAST", "DROTHER", "DROTHER"), "ok")
        self.assertEqual(ospf_verdict("2WAY", "POINT_TO_POINT", "DROTHER", "DROTHER"), "problem")
        self.assertEqual(ospf_verdict("2WAY", "BROADCAST", "DR", "DROTHER"), "problem")
        self.assertEqual(ospf_verdict("2WAY", "unknown", "unknown", "unknown"), "unknown")
        self.assertEqual(ospf_verdict("EXSTART", "BROADCAST", "DR", "DROTHER"), "problem")

    def test_unknown_middle_hop_stops_correlation(self):
        chain = correlate("problem", "unknown", "problem")
        self.assertEqual(chain["stopped_at"], 1)
        self.assertEqual(chain["hops"][1]["reason"], "PEER_NOT_COLLECTED")
        self.assertFalse(chain["complete"])

    def test_unparsed_nx_stp_is_unknown(self):
        from spike.estate import device_checks
        result = device_checks({"name": "sw-00018", "profile": "core_nx", "estate_rows": []})
        self.assertEqual(result[0][0], "l2.stp.root_placement")
        self.assertEqual(result[0][3], "unknown")

    def test_priorities_alone_cannot_prove_root_identity(self):
        from spike.estate import device_checks
        rows = [["root_priority", ["0100", "4096"], ["evidence", 0, 1, 1]],
                ["bridge_priority", ["0100", "4096"], ["evidence", 1, 2, 2]]]
        result = device_checks({"name": "sw-00016", "profile": "core_xe", "estate_rows": rows})
        self.assertEqual(result[0][3], "unknown")

    def test_same_vlan_without_evidenced_links_is_not_one_domain(self):
        from spike.estate import estate_stages
        nodes = [{"name": name, "profile": "access", "estate_rows": [["trunk", ["GigabitEthernet1/0/1", "100"], ["evidence", 0, 1, 1]]],
                  "route_summary": {"complete": False, "expected_present": False, "evidence": []}} for name in ("sw-00000", "sw-00001")]
        self.assertEqual(len(estate_stages(nodes)["l2_domains"]), 2)

    def test_known_healthy_middle_hop_cannot_complete_fault_chain(self):
        self.assertFalse(correlate("problem", "ok", "problem")["complete"])

    def test_root_placement_needs_printed_identity_and_explicit_intent(self):
        from spike.estate import device_checks
        rows = [["root_address", ["0100", "0200.0000.0010"], ["capture", 0, 10, 1]],
                ["bridge_address", ["0100", "0200.0000.0011"], ["capture", 10, 20, 2]]]
        node = {"name": "sw-00017", "profile": "core_xe", "estate_rows": rows,
                "stp_expected_root": "0200.0000.0010", "stp_expected_vlan": "0100", "stp_intent_ref": ["manifest", "/intent/stp_root_mac/17"]}
        result = device_checks(node)
        self.assertEqual(result[0][3], "ok")
        node["stp_expected_root"] = "0200.0000.0024"
        self.assertEqual(device_checks(node)[0][3], "problem")
        node.pop("stp_expected_root")
        self.assertEqual(device_checks(node)[0][3], "unknown")

    def test_stp_intent_wraps_at_the_selected_size(self):
        self.assertEqual(workload.stp_root(16, 100), 16)
        self.assertEqual(workload.stp_root(19, 100), 36)
        self.assertEqual(workload.stp_root(99, 100), 16)


class ThresholdTests(unittest.TestCase):
    def test_determinism_covering_design(self):
        from collections import Counter
        design = json.loads(workload.SPEC.with_name("determinism-design.json").read_bytes())
        self.assertEqual(len(design), 12)
        for axis in ("interpreter", "seed", "workers", "recycle", "path", "drive", "tz", "lang", "capped", "container"):
            self.assertGreaterEqual(min(Counter(row[axis] for row in design).values()), 2, axis)

    def test_private_runner_never_gets_reference_pass(self):
        rows = [{"status": "ok", "size": 1000, "dense": False,
                 "wall_s": 100, "cap_bytes": 2**31,
                 "runner": {"cpu_count": 2, "memory_bytes": 8 * 2**30},
                 "os": "Linux", "stages": {}}] * 5
        verdict = judge(rows)
        self.assertEqual(verdict["reference_verdict"], "not_verified")
        self.assertTrue(verdict["missing"])

    def test_failure_and_missing_stages_never_pass(self):
        verdict = judge([{"status": "watchdog", "size": 300, "os": "Linux"}])
        self.assertEqual(verdict["observed_status"], "failed")
        self.assertEqual(verdict["reference_verdict"], "not_verified")


if __name__ == "__main__":
    unittest.main()
