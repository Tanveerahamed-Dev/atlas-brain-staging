"""Sixteen intentionally spike-grade parsers with byte spans and total accounting."""
from dataclasses import dataclass
import re

IOS_FORMS = ("interfaces", "running", "cdp", "lldp", "trunk", "stp", "mac", "arp", "routes", "ospf_neighbors", "ospf_interfaces", "logging")
NX_FORMS = ("interfaces", "running", "cdp", "ospf_neighbors")
PARSERS = {(family, form) for family, forms in (("iosxe", IOS_FORMS), ("nxos", NX_FORMS)) for form in forms}


@dataclass(frozen=True, slots=True)
class Row:
    kind: str
    values: tuple[str, ...]
    start: int
    end: int
    line: int

    def __post_init__(self):
        if self.start < 0 or self.end <= self.start or self.line < 1 or not self.values:
            raise ValueError("fact_span")


def rx(pattern):
    return re.compile(pattern, re.ASCII)


RULES = {
    "interfaces": [("interface", rx(r"(\S+) is (up|down|administratively down), line protocol is (up|down)")),
                   ("interface_attributes", rx(r"  MTU (\d+) bytes, (\S+)-duplex"))],
    "running": [("system_mtu", rx(r"system mtu (\d+)")), ("vlan", rx(r"vlan (\d+)")),
                ("ospf_process", rx(r"router ospf (\d+)")), ("config_interface", rx(r"interface (\S+)")),
                ("admin", rx(r" (no shutdown|shutdown)")), ("native", rx(r" switchport trunk native vlan (\d+)")),
                ("channel", rx(r" channel-group (\d+) mode (active|passive|on)")), ("interface_mtu", rx(r" mtu (\d+)"))],
    "cdp": [("peer", rx(r"Device ID: (\S+)")), ("neighbor", rx(r"Interface: (\S+), Port ID \(outgoing port\): (\S+)"))],
    "lldp": [("peer", rx(r"Device ID: (\S+)")), ("neighbor", rx(r"Interface: (\S+), Port ID \(outgoing port\): (\S+)"))],
    "trunk": [("trunk", rx(r"(\S+) on 802\.1q trunking (\d+)"))],
    "stp": [("stp_vlan", rx(r"VLAN(\d+)")), ("root_priority", rx(r"  Root ID Priority (\d+)")), ("bridge_priority", rx(r"  Bridge ID Priority (\d+)")), ("stp_address", rx(r"             Address +(\S+)"))],
    "mac": [("mac", rx(r"(\d+) (\S+) (DYNAMIC|STATIC) (\S+) *"))],
    "arp": [("arp", rx(r"Internet (\S+) (\d+) (\S+) ARPA (\S+) *"))],
    "routes": [("vrf", rx(r"Routing Table: (\S+)")), ("route", rx(r"(O|C|S) (\S+) via (\S+), (\S+)"))],
    "ospf_neighbors": [("ospf_neighbor", rx(r"(\S+) (\d+) ([A-Z0-9]+)/(DR|BDR|DROTHER|-) (\S+) (\S+) (\S+)"))],
    "ospf_interfaces": [("ospf_interface", rx(r"(\S+) is (up|down), line protocol is (up|down)")),
                        ("ospf_network", rx(r"  Network Type (BROADCAST|POINT_TO_POINT), State (DR|BDR|DROTHER)"))],
    "logging": [("event", rx(r"Jan  1 00:00:00: %(LINK-3-UPDOWN): event (\d+) Interface (\S+), changed state to (up|down); [\x20-\x7e]*"))],
}
HEADERS = {"Port  Mode  Encapsulation  Status  Native vlan", "Vlan Mac Address Type Ports",
           "Protocol Address Age Hardware Addr Type Interface", "Neighbor ID Pri State Dead Time Address Interface"}


def parse_capture(family, form, body):
    counts = {"consumed": 0, "ignored": 0, "unrecognized": 0, "unclaimed": 0}
    rows, unknown = [], []
    offset, context, stp_area = 0, "unknown", None
    parsed = (family, form) in PARSERS
    for number, raw in enumerate(body.splitlines(keepends=True), 1):
        end = offset + len(raw)
        if len(raw.rstrip(b"\n")) > 65536:
            raise ValueError("line_budget")
        text = raw.rstrip(b"\n").decode("ascii")
        if not parsed:
            counts["unclaimed"] += 1
        elif not text or text in HEADERS or text.startswith("! synthetic admitted"):
            counts["ignored"] += 1
        else:
            for kind, pattern in RULES[form]:
                match = pattern.fullmatch(text)
                if match is None:
                    continue
                values = match.groups()
                if kind in ("root_priority", "bridge_priority"):
                    stp_area = kind.split("_")[0]
                if kind == "stp_address":
                    if stp_area is None:
                        continue
                    kind = stp_area + "_address"
                if kind in ("interface", "config_interface", "ospf_interface", "peer", "vrf", "stp_vlan"):
                    context = values[0]
                elif kind in ("interface_attributes", "admin", "native", "channel", "interface_mtu", "neighbor", "route", "ospf_network", "root_priority", "bridge_priority", "root_address", "bridge_address"):
                    if kind == "interface_attributes":
                        mtu, token = values
                        values = (mtu, {"Full": "full", "Half": "half"}.get(token, "unknown"))
                    values = (context,) + values
                rows.append(Row(kind, values, offset, end, number))
                counts["consumed"] += 1
                break
            else:
                counts["unrecognized"] += 1
                unknown.append(number)
        offset = end
    return {"rows": rows, "accounting": counts, "unrecognized": unknown}
