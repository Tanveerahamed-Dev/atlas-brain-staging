"""Device and estate checks; evidence references accompany every conclusion."""
CHECKS = ("l1.interface.admin_up_oper_down", "l1.link.duplex", "l2.mtu.link_mtu_mismatch",
          "l2.vlan_trunk.link_native_vlan", "l2.stp.root_placement", "l3.ospf.adjacency_expected")


def ospf_verdict(state, network, local_role, peer_role):
    if state == "FULL":
        return "ok"
    if state == "EXSTART":
        return "problem"
    if state == "2WAY":
        if network == "unknown" or local_role == "unknown" or peer_role == "unknown":
            return "unknown"
        if network == "BROADCAST" and local_role == "DROTHER" and peer_role == "DROTHER":
            return "ok"
        return "problem"
    return "unknown"


def correlate(mtu, adjacency, missing_route, middle_reason="PEER_NOT_COLLECTED"):
    hops = [{"state": mtu, "reason": "observed_mtu"},
            {"state": adjacency, "reason": middle_reason if adjacency == "unknown" else "observed_adjacency"},
            {"state": missing_route, "reason": "expected_route_missing"}]
    stop = next((i for i, hop in enumerate(hops) if hop["state"] == "unknown"), None)
    return {"hops": hops, "stopped_at": stop, "complete": stop is None and all(h["state"] == "problem" for h in hops),
            "label": "root_cause_candidate", "next_evidence": "collect peer OSPF state" if stop is not None else "validate MTU intent"}


def by_kind(rows, kind):
    return [r for r in rows if r[0] == kind]


def device_checks(node):
    rows, checks = node["estate_rows"], []
    for row in by_kind(rows, "interface"):
        port, admin, oper = row[1]
        state = "problem" if admin == "up" and oper == "down" else "ok" if admin == "up" and oper == "up" else "unknown"
        checks.append([CHECKS[0], node["name"], port, state, [row[2]], "collect explicit admin and peer interface state"])
    roots, bridges = by_kind(rows, "root_address"), by_kind(rows, "bridge_address")
    desired = node.get("stp_expected_root")
    if not roots or not bridges or desired is None or not node.get("stp_intent_ref"):
        checks.append([CHECKS[4], node["name"], "node", "unknown", [], "collect spanning-tree and root intent"])
    else:
        for root, bridge in zip(roots, bridges):
            scoped = root[1][0] == bridge[1][0] == node.get("stp_expected_vlan")
            state = "unknown" if not scoped else "ok" if root[1][1] == desired else "problem"
            checks.append([CHECKS[4], node["name"], root[1][0], state, [root[2], bridge[2], node["stp_intent_ref"]], "validate root placement intent"])
    return checks


def estate_stages(nodes):
    # Identity resolution is exact on synthetic stable node ids. No inferred aliases.
    indexed = {node["name"]: node for node in nodes}
    ports, neighbors, trunks, ospf, route_evidence = {}, {}, {}, {}, {}
    router_owners, local_ids, adjacency_rows, by_pair = {}, {}, {}, {}
    for node in nodes:
        ids = by_kind(node["estate_rows"], "router_id")
        local_ids[node["name"]] = [r[1][0] for r in ids]
        for row in ids:
            router_owners.setdefault(row[1][0], []).append(node["name"])
    checks, domains, correlations, parents = [], {}, [], {}
    def find(key):
        parents.setdefault(key, key)
        while parents[key] != key:
            parents[key] = parents[parents[key]]
            key = parents[key]
        return key
    def join(a, b):
        left, right = find(a), find(b)
        parents[max(left, right)] = min(left, right)
    for node in nodes:
        name, rows = node["name"], node["estate_rows"]
        if not node.get("analysis_failed"):
            checks.extend(device_checks(node))
        global_mtu = by_kind(rows, "system_mtu")
        configured = {r[1][0]: r for r in by_kind(rows, "interface_mtu")}
        for row in by_kind(rows, "interface_attributes"):
            port, printed_mtu, duplex = row[1]
            # IOS-XE uses the global system MTU evidence; NX-OS uses printed per-port MTU.
            mtu_row = row if node["profile"] == "core_nx" else global_mtu[0] if global_mtu else None
            mtu = printed_mtu if node["profile"] == "core_nx" else global_mtu[0][1][0] if global_mtu else "unknown"
            ports[(name, port)] = (mtu, duplex, row[2], mtu_row[2] if mtu_row else row[2])
        # Resolve port-channel inheritance before native-VLAN consumption.
        natives = {r[1][0]: r for r in by_kind(rows, "native")}
        for row in by_kind(rows, "channel"):
            port, channel, _ = row[1]
            inherited = natives.get(f"Port-channel{channel}")
            if inherited:
                natives[port] = inherited
        for row in by_kind(rows, "trunk"):
            port, vlan = row[1]
            configured_native = natives.get(port)
            trunks[(name, port)] = (vlan, row[2], configured_native[2] if configured_native else row[2])
            key = (vlan, name)
            find(key)
            domains.setdefault(key, []).append([name, port, row[2]])
        for row in by_kind(rows, "neighbor"):
            peer, port, remote_port = row[1]
            neighbors[(name, port)] = (peer, remote_port, row[2])
        networks = {r[1][0]: r for r in by_kind(rows, "ospf_network")}
        for row in by_kind(rows, "ospf_neighbor"):
            peer_id, _, state, peer_role, _, _, port = row[1]
            network = networks.get(port)
            verdict = ospf_verdict(state, network[1][1] if network else "unknown", network[1][2] if network else "unknown", peer_role)
            refs = [row[2]] + ([network[2]] if network else [])
            record = {"state": verdict, "refs": refs, "peer_id": peer_id}
            adjacency_rows[(name, port)] = record
            by_pair.setdefault((name, peer_id), []).append(record)
        route_evidence[name] = node["route_summary"]
    for (name, port), record in sorted(adjacency_rows.items()):
        owners = router_owners.get(record["peer_id"], [])
        refs, reason, joined = list(record["refs"]), "PEER_NOT_COLLECTED", "unknown"
        if len(local_ids[name]) != 1:
            reason = "LOCAL_IDENTITY_MISSING" if not local_ids[name] else "IDENTITY_AMBIGUOUS"
        elif len(owners) == 1:
            reciprocal = by_pair.get((owners[0], local_ids[name][0]), [])
            reason = "PEER_EVIDENCE_MISSING"
            if reciprocal:
                for peer_record in reciprocal:
                    refs.extend(peer_record["refs"])
                states = [record["state"]] + [r["state"] for r in reciprocal]
                joined = "problem" if "problem" in states else "ok" if all(s == "ok" for s in states) else "unknown"
                reason = "PEER_STATE_UNKNOWN" if joined == "unknown" else "observed_adjacency"
        elif len(owners) > 1:
            reason = "IDENTITY_AMBIGUOUS"
        ospf[(name, port)] = (joined, refs, reason)
        checks.append([CHECKS[5], name, port, joined, refs, "collect both OSPF router identities, interfaces and neighbor state"])
    for (name, port), (peer, remote_port, neighbor_ref) in sorted(neighbors.items()):
        reverse = neighbors.get((peer, remote_port))
        left, right = ports.get((name, port)), ports.get((peer, remote_port))
        two_ended = reverse is not None and reverse[:2] == (name, port)
        if not two_ended or left is None or right is None:
            for check in CHECKS[1:4]:
                checks.append([check, name, port, "unknown", [neighbor_ref], "collect peer interface and neighbor state"])
            continue
        refs = [neighbor_ref, reverse[2], left[2], right[2]]
        duplex = "unknown" if "unknown" in (left[1], right[1]) else "ok" if left[1] == right[1] == "full" else "problem"
        mtu = "unknown" if "unknown" in (left[0], right[0]) else "ok" if left[0] == right[0] else "problem"
        checks += [[CHECKS[1], name, port, duplex, refs, "collect explicit duplex"],
                   [CHECKS[2], name, port, mtu, refs + [left[3], right[3]], "collect link MTU intent"]]
        lt, rt = trunks.get((name, port)), trunks.get((peer, remote_port))
        native = "unknown" if lt is None or rt is None else "ok" if lt[0] == rt[0] else "problem"
        if native == "ok":
            join((lt[0], name), (rt[0], peer))
        checks.append([CHECKS[3], name, port, native, refs + ([lt[1], rt[1]] if lt and rt else []), "collect trunk and native VLAN state"])
        adj, adjrefs, reason = ospf.get((name, port), ("unknown", [neighbor_ref], "PEER_NOT_COLLECTED"))
        route = route_evidence[name]
        if mtu == "problem":
            chain = correlate(mtu, adj, "problem" if route["complete"] and not route["expected_present"] else "unknown", reason)
            chain.update({"node": name, "port": port, "variant": "unknown-middle" if adj == "unknown" else "observed",
                          "evidence": [refs + [left[3], right[3]], adjrefs, route["evidence"]]})
            correlations.append(chain)
    components = {}
    for key, items in sorted(domains.items()):
        components.setdefault(find(key), []).extend(items)
    return {"schema": 1, "spike_only": True, "identities": sorted(indexed),
            "l2_domains": [[list(key), sorted(items)] for key, items in sorted(components.items())],
            "checks": sorted(checks), "correlations": sorted(correlations, key=lambda c: (c["node"], c["port"], c["variant"]))}
