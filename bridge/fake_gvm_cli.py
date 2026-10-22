#!/usr/bin/env python3
"""TEST DOUBLE for `gvm-cli`. It is NOT Greenbone and performs no scanning or network access.

It answers the handful of GMP commands the bridge issues (get_version, get_targets, get_tasks,
create_target, create_task, start_task) from a JSON state file, so the bridge and PrimeSEC can be
tested end to end without a scanner. Use it via GVM_CLI_PATH="python /path/to/fake_gvm_cli.py".
"""
import json
import os
import sys
import uuid
from xml.etree import ElementTree as ET

STATE = os.getenv("FAKE_GVM_STATE", os.path.join(os.path.dirname(os.path.abspath(__file__)), ".fake-gvm-state.json"))
EXPECT_PASSWORD = os.getenv("FAKE_GVM_EXPECT_PASSWORD", "")


def load():
    try:
        with open(STATE, encoding="utf8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"targets": [], "tasks": []}


def save(state):
    with open(STATE, "w", encoding="utf8") as f:
        json.dump(state, f)


def arg(flag):
    return sys.argv[sys.argv.index(flag) + 1] if flag in sys.argv else None


# Findings the test double "discovers" on a scanned host. Both GMP shapes are used on purpose: CVEs as
# <refs><ref type="cve"> (current GMP) and as legacy <cve> text, plus a Log result and a no-CVE result.
VULNS = [
    ("1.3.6.1.4.1.25623.1.0.117721", "Apache HTTP Server 2.4.49 Path Traversal", "80/tcp", 9.8, "High", ["CVE-2021-41773", "CVE-2021-42013"], "refs", "Update to Apache HTTP Server 2.4.51 or later."),
    ("1.3.6.1.4.1.25623.1.0.105611", "SSH Weak Encryption Algorithms Supported", "22/tcp", 5.3, "Medium", [], "legacy", "Disable the weak ciphers in sshd_config."),
    ("1.3.6.1.4.1.25623.1.0.117274", "TLS 1.0 Protocol Detection", "443/tcp", 4.3, "Medium", ["CVE-2011-3389"], "legacy", "Disable TLS 1.0 and 1.1."),
    ("1.3.6.1.4.1.25623.1.0.103674", "Operating System End Of Life Detection", "general/tcp", 10.0, "High", [], "refs", "Upgrade to a supported operating system."),
    ("1.3.6.1.4.1.25623.1.0.103190", "ICMP Timestamp Reply Information Disclosure", "general/icmp", 2.1, "Low", ["CVE-1999-0524"], "refs", "Filter ICMP timestamp requests."),
    ("1.3.6.1.4.1.25623.1.0.10330", "Services Detection", "80/tcp", 0.0, "Log", [], "refs", "")
]


def hosts_of(spec):
    """One host for a single address, two for a CIDR (.10 and .11), so reports look like a small network."""
    base = spec.split("/")[0]
    if "/" in spec and not spec.endswith("/32"):
        a, b, c, _ = base.split(".")
        return [f"{a}.{b}.{c}.10", f"{a}.{b}.{c}.11"]
    return [base]


def build_reports(state):
    fixed = {x for x in os.getenv("FAKE_GVM_FIXED", "").split(",") if x}      # NVT oids a RETEST scan no longer finds
    status = os.getenv("FAKE_GVM_REPORT_STATUS", "Done")                      # Done | Running | Interrupted ...
    unreachable = {x for x in os.getenv("FAKE_GVM_UNREACHABLE", "").split(",") if x}  # hosts a RETEST scan could not reach
    reports = []
    for t in reversed(state["tasks"]):                                       # newest report first, like sort-reverse=creation_time
        target = next((x for x in state["targets"] if x["name"] == t["targetName"]), None)
        if target is None:
            continue
        results = []
        host_entries = []
        retest = "Retest" in t["name"]
        for host in hosts_of(target["hosts"]):
            if retest and host in unreachable:
                continue                                  # host down: no <host> entry and no results, yet the scan is Done
            host_entries.append(f'<host><ip>{host}</ip><asset asset_id="a-{host}"/><start>2026-10-20T10:00:00Z</start><end>2026-10-20T10:05:00Z</end></host>')
            for oid, name, port, sev, threat, cves, style, solution in VULNS:
                if oid in fixed and "Retest" in t["name"]:   # older reports of the same host still list it
                    continue
                refs = "".join(f'<ref type="cve" id="{c}"/>' for c in cves) if style == "refs" else ""
                legacy = f'<cve>{", ".join(cves) if cves else "NOCVE"}</cve>' if style == "legacy" else ""
                results.append(
                    f'<result id="{t["id"]}-{host}-{oid}"><name>{name}</name><host>{host}<asset asset_id="a-{host}"/></host><port>{port}</port>'
                    f'<nvt oid="{oid}"><type>nvt</type><name>{name}</name><refs>{refs}</refs>{legacy}<solution type="VendorFix">{solution}</solution></nvt>'
                    f'<threat>{threat}</threat><severity>{sev}</severity><description>{name} on {host}</description>'
                    f'<creation_time>2026-10-20T10:00:00Z</creation_time></result>'
                )
        reports.append(
            f'<report id="rep-{t["id"]}"><report id="rep-{t["id"]}"><task id="{t["id"]}"><name>{t["name"]}</name></task>'
            f'<scan_run_status>{status}</scan_run_status><timestamp>2026-10-20T10:05:00Z</timestamp>{"".join(host_entries)}'
            f'<results start="1" max="1000">{"".join(results)}</results></report></report>'
        )
    return f'<get_reports_response status="200" status_text="OK">{"".join(reports)}</get_reports_response>'


def main():
    # authentication, like the real client: either --config FILE or --gmp-username/--gmp-password
    if arg("--config"):
        if not os.path.exists(arg("--config")):
            sys.exit(2)
    elif EXPECT_PASSWORD and arg("--gmp-password") != EXPECT_PASSWORD:
        sys.exit(3)
    xml = arg("--xml")
    if not xml or "socket" not in sys.argv:
        sys.exit(4)
    root = ET.fromstring(xml)
    state = load()
    tag = root.tag

    if tag == "get_version":
        out = '<get_version_response status="200" status_text="OK"><version>22.4 (fake)</version></get_version_response>'
    elif tag == "get_targets":
        items = "".join(f'<target id="{t["id"]}"><name>{t["name"]}</name><hosts>{t["hosts"]}</hosts><comment/></target>' for t in state["targets"])
        out = f'<get_targets_response status="200" status_text="OK">{items}</get_targets_response>'
    elif tag == "get_tasks":
        items = "".join(
            f'<task id="{t["id"]}"><name>{t["name"]}</name><status>{t["status"]}</status><progress>{t["progress"]}</progress>'
            f'<target><name>{t["targetName"]}</name></target></task>'
            for t in reversed(state["tasks"])
        )
        out = f'<get_tasks_response status="200" status_text="OK">{items}</get_tasks_response>'
    elif tag == "create_target":
        t = {"id": str(uuid.uuid4()), "name": root.findtext("name", ""), "hosts": root.findtext("hosts", "")}
        state["targets"].append(t)
        out = f'<create_target_response status="201" status_text="OK, resource created" id="{t["id"]}"/>'
    elif tag == "create_task" and os.getenv("FAKE_GVM_FAIL") == "create_task":
        out = '<create_task_response status="404" status_text="Failed to find config (test double)"/>'
    elif tag == "start_task" and os.getenv("FAKE_GVM_FAIL") == "start_task":
        out = '<start_task_response status="500" status_text="Scanner unavailable (test double)"/>'
    elif tag == "get_reports":
        out = build_reports(state)
    elif tag == "delete_target":
        state["targets"] = [t for t in state["targets"] if t["id"] != root.attrib.get("target_id")]
        out = '<delete_target_response status="200" status_text="OK"/>'
    elif tag == "delete_task":
        state["tasks"] = [t for t in state["tasks"] if t["id"] != root.attrib.get("task_id")]
        out = '<delete_task_response status="200" status_text="OK"/>'
    elif tag == "create_task":
        target = next((t for t in state["targets"] if t["id"] == root.find("target").attrib.get("id")), None)
        if target is None:
            out = '<create_task_response status="404" status_text="Target not found"/>'
        else:
            t = {"id": str(uuid.uuid4()), "name": root.findtext("name", ""), "status": "New", "progress": "0", "targetName": target["name"]}
            state["tasks"].append(t)
            out = f'<create_task_response status="201" status_text="OK, resource created" id="{t["id"]}"/>'
    elif tag == "start_task":
        for t in state["tasks"]:
            if t["id"] == root.attrib.get("task_id"):
                t["status"], t["progress"] = "Requested", "0"
        out = f'<start_task_response status="202" status_text="OK, request submitted"><report_id>{uuid.uuid4()}</report_id></start_task_response>'
    else:
        out = '<response status="400" status_text="Unsupported command in test double"/>'
    save(state)
    print(out)


if __name__ == "__main__":
    main()
