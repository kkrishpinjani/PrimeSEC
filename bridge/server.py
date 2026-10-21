#!/usr/bin/env python3
"""PrimeSEC <-> Greenbone bridge: a small authenticated HTTP service in front of gvm-cli / GMP.

Run it on the Greenbone host (it needs the gvmd Unix socket). Binds to loopback by default.
It only ever creates + starts scans for targets that pass `valid_target`, and, if
GREENBONE_ALLOWED_RANGES is set, only inside those ranges. That is a second, independent
allow-list owned by whoever runs Greenbone, in addition to PrimeSEC's approved scopes.

Only scan systems you are explicitly authorised to assess.
"""
import datetime
import hmac
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import traceback
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.etree import ElementTree as ET

HOST = os.getenv("GREENBONE_BRIDGE_HOST", "127.0.0.1")
PORT = int(os.getenv("GREENBONE_BRIDGE_PORT", "8787"))
TOKEN = os.getenv("GREENBONE_BRIDGE_TOKEN", "")
SOCKET = os.getenv("GREENBONE_GMP_SOCKET", "/run/gvmd/gvmd.sock")
GMP_USER = os.getenv("GREENBONE_GMP_USERNAME", "")
GMP_PASSWORD = os.getenv("GREENBONE_GMP_PASSWORD", "")
# Preferred over GMP_PASSWORD: a gvm-tools config file (mode 0600) keeps the password out of `ps`.
GVM_CONFIG = os.getenv("GVM_CLI_CONFIG", "")
GVM_CLI = os.getenv("GVM_CLI_PATH", "gvm-cli")
SCAN_CONFIG = os.getenv("GREENBONE_SCAN_CONFIG_ID", "daba56c8-73ec-11df-a475-002264764cea")
PORT_LIST = os.getenv("GREENBONE_PORT_LIST_ID", "33d0cd82-57c6-11e1-8ed1-406186ea4fc5")
SCANNER_ID = os.getenv("GREENBONE_SCANNER_ID", "08b69003-5fc2-4037-a479-93b440211c73")
TIMEOUT = int(os.getenv("GREENBONE_COMMAND_TIMEOUT", "45"))
ALLOWED_RANGES = [r.strip() for r in os.getenv("GREENBONE_ALLOWED_RANGES", "").split(",") if r.strip()]
MIN_TOKEN_LENGTH = 32
REPORT_ROWS = int(os.getenv("GREENBONE_REPORT_ROWS", "25"))      # how many recent reports a sync reads
MAX_FINDINGS = int(os.getenv("GREENBONE_MAX_FINDINGS", "2000"))  # hard cap per sync; a capped import says so

# Never scannable, regardless of any approval: the scanner host itself, link-local (cloud metadata), multicast, reserved.
RESERVED = [ipaddress.ip_network(n) for n in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")]


class BridgeError(Exception):
    pass


def log_unexpected(where):
    """Unexpected errors go to the bridge's own stderr (never to the caller). Tracebacks hold no credentials:
    the gvm-cli command line, which does, is only ever built inside subprocess.run and its errors are caught."""
    print(f"ERROR in {where}:\n{traceback.format_exc()}", file=sys.stderr, flush=True)


def gvm_command(xml):
    base = shlex.split(GVM_CLI, posix=(os.name != "nt"))
    if GVM_CONFIG:
        auth = ["--config", GVM_CONFIG]
    elif GMP_USER and GMP_PASSWORD:
        auth = ["--gmp-username", GMP_USER, "--gmp-password", GMP_PASSWORD]
    else:
        raise BridgeError("Greenbone credentials are not configured on the bridge host.")
    return base + auth + ["socket", "--socketpath", SOCKET, "--xml", xml]


def cmd(xml):
    try:
        result = subprocess.run(gvm_command(xml), capture_output=True, text=True, timeout=TIMEOUT, check=False)
    except FileNotFoundError:
        raise BridgeError("gvm-cli was not found. Install gvm-tools on the bridge host.")
    except subprocess.TimeoutExpired:
        raise BridgeError("Greenbone GMP command timed out.")
    if result.returncode != 0:
        # Never return the command line, credentials or raw stderr to the caller.
        raise BridgeError("Greenbone GMP command failed. Check socket permissions, credentials, and gvmd logs.")
    try:
        root = ET.fromstring(result.stdout.strip())
    except ET.ParseError:
        raise BridgeError("Greenbone returned an unexpected GMP response.")
    if root.attrib.get("status", "200").startswith(("4", "5")):
        raise BridgeError("Greenbone rejected the request: " + root.attrib.get("status_text", "GMP operation failed")[:180])
    return root


def text(el, path, default=""):
    found = el.find(path)
    return (found.text or "").strip() if found is not None and found.text else default


def parse_targets(root):
    return [
        {"id": t.attrib.get("id", ""), "name": text(t, "name"), "hosts": text(t, "hosts"), "comment": text(t, "comment")}
        for t in root.findall(".//target")
        if t.find("name") is not None
    ]


def parse_tasks(root):
    items = []
    for t in root.findall(".//task"):
        report = t.find("last_report/report")
        items.append({
            "id": t.attrib.get("id", ""),
            "name": text(t, "name"),
            "status": text(t, "status", "Unknown"),
            "progress": text(t, "progress", "0"),
            "target": text(t, "target/name"),
            "lastReportId": report.attrib.get("id", "") if report is not None else "",
        })
    return items


def get_overview():
    version = cmd("<get_version/>")
    targets = cmd('<get_targets filter="rows=100 sort=name"/>')
    tasks = cmd('<get_tasks filter="rows=100 sort-reverse=creation_time"/>')
    return {
        "connected": True,
        "version": text(version, "version", "Unknown"),
        "targets": parse_targets(targets),
        "tasks": parse_tasks(tasks),
        "message": "Connected to Greenbone GMP.",
    }


def parse_findings(root, max_findings=None):
    """Normalises get_reports(details=1) into flat findings. Returns (findings, truncated).

    A GMP report is wrapped in an outer <report> that contains an inner <report> holding <results>; only the
    one that directly holds <results> is read, so nothing is counted twice. CVEs come from
    nvt/refs/ref[@type='cve'] (current GMP) and, for older releases, the nvt/cve text.
    """
    limit = MAX_FINDINGS if max_findings is None else max_findings
    findings, seen = [], set()
    outers = root.findall("report") or list(root.iter("report"))
    for report_index, outer in enumerate(outers):  # reports arrive newest first (sort-reverse=creation_time)
        inner = outer.find("report") if outer.find("report") is not None else outer
        results = inner.find("results")
        if results is None:
            continue
        report_id = inner.attrib.get("id", "") or outer.attrib.get("id", "")
        task_name = text(outer, "task/name") or text(inner, "task/name")
        for result in results.findall("result"):
            result_id = result.attrib.get("id", "")
            if result_id:
                if result_id in seen:
                    continue
                seen.add(result_id)
            nvt = result.find("nvt")
            cves = set()
            if nvt is not None:
                for ref in nvt.findall("refs/ref"):
                    if ref.attrib.get("type", "").lower() == "cve" and ref.attrib.get("id"):
                        cves.add(ref.attrib["id"].strip())
                for part in text(nvt, "cve").split(","):
                    part = part.strip()
                    if part and part.upper() != "NOCVE":
                        cves.add(part)
            try:
                severity = float(text(result, "severity", "0"))
            except ValueError:
                severity = 0.0
            if len(findings) >= limit:
                return findings, True
            findings.append({
                "reportId": report_id,
                "taskName": task_name,
                "host": text(result, "host"),
                "port": text(result, "port"),
                "name": (text(nvt, "name") if nvt is not None else "") or text(result, "name") or "Unnamed vulnerability result",
                "oid": nvt.attrib.get("oid", "") if nvt is not None else "",
                "cves": sorted(cves),
                "severity": severity,
                "threat": text(result, "threat", "Log"),
                "description": text(result, "description")[:6000],
                "solution": text(nvt, "solution")[:3000] if nvt is not None else "",
                "creationTime": text(result, "creation_time") or text(result, "modification_time"),
                "resultId": result_id,
                "reportIndex": report_index,
            })
    return findings, False


def get_findings():
    # ignore_pagination: read every result of each report, not just the first page (checked against the GMP docs, not a live Greenbone)
    reports = cmd(f'<get_reports filter="rows={REPORT_ROWS} sort-reverse=creation_time" details="1" ignore_pagination="1"/>')
    findings, truncated = parse_findings(reports)
    return {
        "findings": findings,
        "truncated": truncated,
        "source": "Greenbone GMP",
        "retrievedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def valid_target(value):
    """Strict: IPv4 only, /24 or narrower, no host bits set, never a reserved range, inside ALLOWED_RANGES if configured."""
    try:
        net = ipaddress.ip_network(str(value).strip(), strict=True)
    except ValueError:
        raise BridgeError("Target must be an IPv4 address or a CIDR with no host bits set.")
    if net.version != 4:
        raise BridgeError("Only IPv4 targets are enabled.")
    if net.num_addresses > 256:
        raise BridgeError("For safety, a single scan target must be /24 or narrower.")
    if any(net.overlaps(r) for r in RESERVED):
        raise BridgeError("That range can never be scanned (loopback, link-local, multicast or reserved).")
    if ALLOWED_RANGES and not any(net.subnet_of(ipaddress.ip_network(r, strict=False)) for r in ALLOWED_RANGES):
        raise BridgeError("Target is outside this bridge's GREENBONE_ALLOWED_RANGES.")
    return str(net.network_address) if net.prefixlen == 32 else str(net)


def discard(kind, object_id):
    """Best-effort removal of a Greenbone object created by a launch that then failed, so retries do not litter it."""
    xml = f'<delete_{kind} {kind}_id="{object_id}" ultimate="1"/>'
    try:
        cmd(xml)
    except BridgeError:
        print(f"WARNING: could not remove orphaned {kind} {object_id}; delete it in Greenbone.", file=sys.stderr, flush=True)


def create_assessment(data):
    target = valid_target(data.get("target", ""))
    name = re.sub(r"[^A-Za-z0-9 ._-]", "", str(data.get("name", "PrimeSEC assessment")))[:80].strip() or "PrimeSEC assessment"
    suffix = uuid.uuid4().hex[:8]
    label = f"PrimeSEC {name} {suffix}"

    target_el = ET.Element("create_target")
    ET.SubElement(target_el, "name").text = label
    ET.SubElement(target_el, "hosts").text = target
    ET.SubElement(target_el, "port_list", {"id": PORT_LIST})
    target_id = cmd(ET.tostring(target_el, encoding="unicode")).attrib.get("id")
    if not target_id:
        raise BridgeError("Greenbone did not return a target ID; verify the configured port-list UUID.")

    task_el = ET.Element("create_task")
    ET.SubElement(task_el, "name").text = label
    ET.SubElement(task_el, "config", {"id": SCAN_CONFIG})
    ET.SubElement(task_el, "target", {"id": target_id})
    if SCANNER_ID:
        ET.SubElement(task_el, "scanner", {"id": SCANNER_ID})
    try:
        task_id = cmd(ET.tostring(task_el, encoding="unicode")).attrib.get("id")
        if not task_id:
            raise BridgeError("Greenbone did not return a task ID; verify the scan configuration and scanner IDs.")
    except BridgeError:
        discard("target", target_id)  # do not leave the target behind
        raise

    try:
        started = cmd(ET.tostring(ET.Element("start_task", {"task_id": task_id}), encoding="unicode"))
    except BridgeError:
        discard("task", task_id)
        discard("target", target_id)
        raise
    return {
        "targetId": target_id, "targetName": label, "taskId": task_id,
        "reportId": text(started, "report_id") or None, "target": target, "status": "Requested",
        "message": "Scan start request accepted by Greenbone. Check task status for progress.",
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "PrimeSEC-Greenbone-Bridge/1.1"

    def log_message(self, fmt, *args):
        # Never log auth headers or request bodies.
        print("%s - %s" % (self.client_address[0], fmt % args), flush=True)

    def send_json(self, code, data):
        payload = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def authorized(self):
        provided = self.headers.get("Authorization", "")
        return bool(TOKEN) and hmac.compare_digest(provided.encode(), ("Bearer " + TOKEN).encode())

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            return self.send_json(200, {
                "service": "PrimeSEC Greenbone bridge",
                "configured": bool(TOKEN and (GVM_CONFIG or (GMP_USER and GMP_PASSWORD))),
                "socketConfigured": os.path.exists(SOCKET),
                "authRequired": True,
                "allowedRangesConfigured": bool(ALLOWED_RANGES),
            })
        if not self.authorized():
            return self.send_json(401, {"error": "Authentication required"})
        try:
            if path == "/v1/overview":
                return self.send_json(200, get_overview())
            if path == "/v1/findings":
                return self.send_json(200, get_findings())
            return self.send_json(404, {"error": "Not found"})
        except BridgeError as e:
            return self.send_json(502, {"error": str(e)})
        except Exception:
            log_unexpected(f"{self.command} {self.path}")
            return self.send_json(500, {"error": "Unexpected bridge error. Check bridge logs."})

    def do_POST(self):
        if not self.authorized():
            return self.send_json(401, {"error": "Authentication required"})
        if self.path.split("?", 1)[0] != "/v1/assessments":
            return self.send_json(404, {"error": "Not found"})
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 1 or length > 8192:
                return self.send_json(400, {"error": "Invalid request body size"})
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                return self.send_json(400, {"error": "Invalid JSON body"})
            return self.send_json(201, create_assessment(data))
        except (ValueError, json.JSONDecodeError):
            return self.send_json(400, {"error": "Invalid JSON body"})
        except BridgeError as e:
            # a refused target is a client error, everything else is an upstream problem
            code = 400 if str(e).startswith(("Target ", "Only IPv4", "For safety", "That range")) else 502
            return self.send_json(code, {"error": str(e)})
        except Exception:
            log_unexpected(f"{self.command} {self.path}")
            return self.send_json(500, {"error": "Unexpected bridge error. Check bridge logs."})


def main():
    if len(TOKEN) < MIN_TOKEN_LENGTH:
        raise SystemExit(f"Set GREENBONE_BRIDGE_TOKEN to a random secret of at least {MIN_TOKEN_LENGTH} characters before starting the bridge.")
    if not GVM_CONFIG and GMP_PASSWORD:
        print("WARNING: GREENBONE_GMP_PASSWORD is passed to gvm-cli on its command line and is visible to other local users. "
              "Prefer GVM_CLI_CONFIG (a mode-0600 gvm-tools config file).", file=sys.stderr, flush=True)
    for r in ALLOWED_RANGES:
        try:
            net = ipaddress.ip_network(r, strict=False)
        except ValueError:
            raise SystemExit(f"GREENBONE_ALLOWED_RANGES contains an invalid network: {r!r}")
        if net.version != 4:
            raise SystemExit(f"GREENBONE_ALLOWED_RANGES must be IPv4 only (the bridge only scans IPv4): {r!r}")
    print(f"PrimeSEC Greenbone bridge listening on http://{HOST}:{PORT}; socket={SOCKET}; "
          f"allowed ranges={ALLOWED_RANGES or 'not restricted'}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
