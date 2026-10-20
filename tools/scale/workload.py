"""Frozen WL-1 generation; no network, packages or device access."""
import argparse
import hashlib
import json
from pathlib import Path

SPEC = Path(__file__).with_name("WL-1.json")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"


def strict_json(raw):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError("duplicate_key")
            out[key] = value
        return out
    def constant(_):
        raise ValueError("nonfinite")
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_spec(path=SPEC):
    raw = path.read_bytes()
    frozen = SPEC.with_suffix(".sha256").read_text(encoding="ascii").split()[0]
    if digest(raw) != frozen:
        raise ValueError("manifest_digest")
    spec = strict_json(raw)
    if digest(Path(__file__).read_bytes()) != spec["generator_sha256"]:
        raise ValueError("generator_digest")
    return spec


def profiles(size):
    if size not in load_spec()["sizes"]:
        raise ValueError("size")
    return (["access"] * 16 + ["core_xe"] * 2 + ["core_nx", "wan"]) * (size // 20)


def validate_mix(items, size):
    spec = load_spec()
    if len(items) != size or any(items.count(key) != row["count"] * size // 1000 for key, row in spec["profiles"].items()):
        raise ValueError("mix")


def expected(size, dense):
    spec = load_spec()
    if size not in spec["sizes"]:
        raise ValueError("size")
    out = {k: v * size // 1000 for k, v in spec["totals"].items()}
    if dense:
        for key in spec["dense"]["double"]:
            out[key] *= 2
        out["bytes"] = spec["dense"]["bytes"] * size // 1000
    return out


def iface(profile, index):
    return f"Ethernet1/{index + 1}" if profile == "core_nx" else f"GigabitEthernet1/0/{index + 1}"


def padded(line, width):
    if len(line) > width - 1:
        raise ValueError("row_width")
    return line.ljust(width - 1) + "\n"


def render(form, profile, node, size, dense):
    row = load_spec()["profiles"][profile]
    interface = lambda i: "Port-channel1" if i == row["interfaces"] - 1 else iface(profile, i)
    count = lambda key: row[key] * (2 if dense and key in ("mac", "arp", "syslog") else 1)
    lines = []
    if form == "interfaces":
        for i in range(row["interfaces"]):
            # Public example header is retained exactly for NX-OS port 2.
            lines.append(f"{interface(i)} is up, line protocol is {'down' if i == 3 and node % 20 == 0 else 'up'}\n")
            lines.append(f"  MTU {1600 if profile == 'core_nx' and i == 0 else 1500} bytes, Full-duplex\n")
    elif form == "running":
        lines = ["system mtu 1500\n", "vlan 100\n", "router ospf 1\n"]
        for i in range(row["interfaces"]):
            lines += [f"interface {interface(i)}\n", " no shutdown\n", " switchport trunk native vlan 100\n"]
            if i == 0:
                lines.append(" channel-group 1 mode active\n")
        lines.append(" mtu 1500\n")  # Last declared interface is the logical channel.
    elif form in ("cdp", "lldp"):
        for i in range(row["neighbors"] // 2):
            slot = i * 2 + (form == "lldp")
            peer = (node + 1) % size if slot == 0 else (node - 1) % size if slot == 1 else size + node * 40 + slot
            peer_profile = profiles(size)[peer] if peer < size else "access"
            peer_port = iface(peer_profile, 1 if slot == 0 else 0)
            lines += [f"Device ID: sw-{peer:05d}\n", f"Interface: {interface(slot)}, Port ID (outgoing port): {peer_port}\n"]
    elif form == "trunk":
        lines = ["Port  Mode  Encapsulation  Status  Native vlan\n"]
        lines += [f"{interface(i)} on 802.1q trunking 100\n" for i in range(2)]
    elif form == "stp":
        lines = ["VLAN0100\n", "  Root ID Priority 4096\n", f"  Bridge ID Priority {4096 if profile.startswith('core') else 32768}\n"]
    elif form == "mac":
        lines = ["Vlan Mac Address Type Ports\n"]
        lines += [padded(f"100 0200.0000.{i:04x} DYNAMIC {interface(i % row['interfaces'])}", 80) for i in range(count("mac"))]
    elif form == "arp":
        lines = ["Protocol Address Age Hardware Addr Type Interface\n"]
        lines += [padded(f"Internet 192.0.2.{i % 254 + 1} 1 0200.0000.{i:04x} ARPA {interface(i % row['interfaces'])}", 96) for i in range(count("arp"))]
    elif form == "routes":
        for vrf in range(row["vrfs"]):
            lines.append(f"Routing Table: vrf-{vrf}\n")
            lines += [f"O 203.0.113.{i % 254 + 1}/32 via 198.51.100.1, {interface(i % row['interfaces'])}\n" for i in range(vrf, row["routes"], row["vrfs"])]
    elif form == "ospf_neighbors":
        lines = ["Neighbor ID Pri State Dead Time Address Interface\n"]
        for i in range(row["ospf_neighbors"]):
            state = "EXSTART/DR" if i == (1 if profile == "wan" else 0) else "2WAY/DROTHER" if i == 1 else "FULL/DR"
            lines.append(f"192.0.2.{i+1} 1 {state} 00:00:30 198.51.100.{i+1} {interface(i)}\n")
    elif form == "ospf_interfaces":
        for i in range(row["ospf_interfaces"]):
            lines += [f"{interface(i)} is up, line protocol is up\n", "  Network Type BROADCAST, State DROTHER\n"]
    elif form == "logging":
        lines = [padded(f"Jan  1 00:00:00: %LINK-3-UPDOWN: event {i:06d} Interface {interface(i % row['interfaces'])}, changed state to up; " + "synthetic-detail " * 20, 480) for i in range(count("syslog"))]
    else:
        lines = [f"! synthetic admitted evidence: {form}\n"]
    return "".join(lines).encode("ascii")


def generate(root, size, dense):
    spec = load_spec()
    mix = profiles(size)
    validate_mix(mix, size)
    totals = expected(size, dense)
    root.mkdir(parents=True, exist_ok=False)
    artifacts = []
    for node, profile in enumerate(mix):
        name = f"sw-{node:05d}"
        folder = root / name
        folder.mkdir()
        bodies = [render(form, profile, node, size, dense) for form in spec["forms"]]
        target = spec["profiles"][profile]["bytes"]
        if dense:
            target += sum(spec["profiles"][profile][k] * width for k, width in spec["dense"]["row_bytes"].items())
        missing = target - sum(map(len, bodies))
        if missing < 0:
            raise ValueError("manifest_byte_budget")
        # Filler remains admitted, hashed and segmented, explicitly unclaimed.
        filler = b"! synthetic admitted filler\n"
        bodies[-1] += filler * (missing // len(filler))
        rest = missing % len(filler)
        bodies[-1] += (b"!" + b" " * (rest - 2) + b"\n") if rest >= 2 else b"\n" * rest
        for form, body in zip(spec["forms"], bodies, strict=True):
            rel = f"{name}/{form}.txt"
            (root / rel).write_bytes(body)
            artifacts.append({"path": rel, "sha256": digest(body), "bytes": len(body), "form": form, "node": node, "profile": profile})
    manifest = {"schema": 1, "workload": spec["id"], "frozen_sha256": digest(SPEC.read_bytes()), "size": size, "dense": dense, "totals": totals, "artifacts": artifacts,
                "public_excerpt_sha256": [digest(item["excerpt"].encode("ascii")) for item in strict_json(SPEC.with_name("provenance.json").read_bytes())["public_material"]]}
    (root / "ESTATE.json").write_bytes(canonical(manifest))
    verify(root)
    return manifest


def verify(root):
    spec = load_spec()
    if root.is_symlink():
        raise ValueError("capture_symlink")
    root = root.resolve()
    doc = strict_json((root / "ESTATE.json").read_bytes())
    size, dense = doc["size"], doc["dense"]
    if type(size) is not int or type(dense) is not bool or doc["schema"] != 1 or doc["workload"] != "WL-1":
        raise ValueError("estate_schema")
    mix = profiles(size)
    if doc["totals"] != expected(size, dense) or doc["frozen_sha256"] != digest(SPEC.read_bytes()):
        raise ValueError("manifest_counts")
    wanted = {f"sw-{i:05d}/{form}.txt" for i in range(size) for form in spec["forms"]}
    found, byte_count = set(), 0
    per_node = [0] * size
    for item in doc["artifacts"]:
        name = item["path"]
        if name not in wanted or name in found:
            raise ValueError("capture_path")
        path = root / name
        if path.is_symlink() or path.parent.is_symlink() or not path.is_file():
            raise ValueError("capture_link")
        body = path.read_bytes()
        node = item["node"]
        if type(node) is not int or not 0 <= node < size or name != f"sw-{node:05d}/{item['form']}.txt" or item["profile"] != mix[node]:
            raise ValueError("capture_identity")
        if len(body) != item["bytes"] or digest(body) != item["sha256"]:
            raise ValueError("capture_digest")
        profile = spec["profiles"][mix[node]]
        counters = {"interfaces": (b" is up, line protocol is ", profile["interfaces"]),
                    "running": (b"\ninterface ", profile["interfaces"]),
                    "mac": (b" DYNAMIC ", profile["mac"]), "arp": (b"Internet ", profile["arp"]),
                    "routes": (b"O 203.0.113.", profile["routes"]),
                    "cdp": (b"Device ID: ", profile["neighbors"] // 2),
                    "lldp": (b"Device ID: ", profile["neighbors"] // 2),
                    "ospf_neighbors": (b" 1 ", profile["ospf_neighbors"]),
                    "ospf_interfaces": (b" is up, line protocol is ", profile["ospf_interfaces"]),
                    "logging": (b"%LINK-3-UPDOWN:", profile["syslog"])}
        if item["form"] in counters:
            token, required = counters[item["form"]]
            if dense and item["form"] in ("mac", "arp", "logging"):
                required *= 2
            if body.count(token) != required:
                raise ValueError("capture_rows")
        found.add(name)
        byte_count += len(body)
        per_node[node] += len(body)
    actual = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and p.name != "ESTATE.json"}
    if found != wanted or actual != wanted or byte_count != doc["totals"]["bytes"]:
        raise ValueError("manifest_artifacts")
    for node, profile in enumerate(mix):
        target = spec["profiles"][profile]["bytes"]
        if dense:
            target += sum(spec["profiles"][profile][k] * w for k, w in spec["dense"]["row_bytes"].items())
        if per_node[node] != target:
            raise ValueError("manifest_device_bytes")
    return doc


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--size", type=int, choices=(100, 300, 1000), default=100)
    parser.add_argument("--dense", action="store_true")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    manifest = verify(args.root) if args.verify else generate(args.root, args.size, args.dense)
    print(json.dumps({"size": manifest["size"], "totals": manifest["totals"]}, sort_keys=True))
