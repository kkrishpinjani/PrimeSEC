"""Tests for the bridge's read-only scan-platform view: parsers, secret handling, per-section failure isolation.
Run: npm run test:bridge   (python -I scripts/test_bridge_platform.py)"""
import importlib.util
import os
import sys
import xml.etree.ElementTree as ET

here = os.path.dirname(os.path.abspath(__file__))
os.environ["GREENBONE_BRIDGE_TOKEN"] = "t" * 40
spec = importlib.util.spec_from_file_location("bridge_server", os.path.join(here, "..", "bridge", "server.py"))
B = importlib.util.module_from_spec(spec)
spec.loader.exec_module(B)

passed = failed = 0
def ok(name, cond, extra=""):
    global passed, failed
    if cond: passed += 1
    else: failed += 1; print("FAIL:", name, extra)

X = lambda s: ET.fromstring(s)

# ---- scanners ----
sc = B.parse_scanners(X('<get_scanners_response status="200"><scanner id="s1"><name>OpenVAS Default</name><type>2</type><host>/run/ospd/ospd-openvas.sock</host><port>0</port></scanner><scanner id="s2"><name>CVE</name><type>3</type></scanner><scanner id="s3"><name>Other</name><type>9</type></scanner></get_scanners_response>'))
ok("scanners are parsed with a readable type", sc[0] == {"id": "s1", "name": "OpenVAS Default", "type": "OpenVAS", "host": "/run/ospd/ospd-openvas.sock", "port": "0"} and sc[1]["type"] == "CVE")
ok("an unknown scanner type is shown as such, not guessed", sc[2]["type"] == "type 9")

# ---- configs, port lists, schedules ----
cf = B.parse_configs(X('<get_configs_response><config id="c1"><name>Full and fast</name><comment>x</comment><family_count>76<growing>1</growing></family_count><nvt_count>90000<growing>1</growing></nvt_count></config></get_configs_response>'))
ok("scan configs carry NVT and family counts", cf[0]["name"] == "Full and fast" and cf[0]["nvtCount"] == "90000" and cf[0]["familyCount"] == "76")
pl = B.parse_port_lists(X('<get_port_lists_response><port_list id="p1"><name>All IANA assigned TCP</name><port_count><all>5995</all><tcp>5995</tcp><udp>0</udp></port_count></port_list></get_port_lists_response>'))
ok("port lists carry their port count", pl[0] == {"id": "p1", "name": "All IANA assigned TCP", "ports": "5995"})
sh = B.parse_schedules(X('<get_schedules_response><schedule id="h1"><name>Weekly</name><comment/><timezone>UTC</timezone><icalendar>BEGIN:VCALENDAR secret-ish</icalendar></schedule></get_schedules_response>'))
ok("schedules show name and timezone but not the raw calendar", sh[0]["timezone"] == "UTC" and "icalendar" not in sh[0] and "VCALENDAR" not in str(sh))

# ---- alert definitions: names only, never method data ----
al = B.parse_alert_definitions(X('''<get_alerts_response><alert id="a1"><name>Notify SOC</name><event>Task run status changed<data>Done<name>status</name></data></event><condition>Always</condition>
<method>HTTP Get<data>https://hooks.example/path?token=SUPERSECRET<name>URL</name></data><data>smtp-password-123<name>password</name></data></method><active>1</active></alert></get_alerts_response>'''))
dump = str(al)
ok("alert definitions give name, event, condition, method name and state", al[0]["name"] == "Notify SOC" and al[0]["method"] == "HTTP Get" and al[0]["active"] == "1" and al[0]["condition"] == "Always")
ok("alert method data (URLs, tokens, passwords) is never returned", "SUPERSECRET" not in dump and "smtp-password" not in dump and "hooks.example" not in dump)

# ---- feeds ----
fd = B.parse_feeds(X('<get_feeds_response><feed><type>NVT</type><name>Greenbone Community Feed</name><version>202610301544</version></feed><feed><type>SCAP</type><name>SCAP</name><version>202611020218</version><currently_syncing><timestamp>x</timestamp></currently_syncing></feed></get_feeds_response>'))
ok("feeds show version and whether one is syncing now", fd[0]["version"] == "202610301544" and fd[0]["syncing"] is False and fd[1]["syncing"] is True)

# ---- failure isolation ----
def fake_cmd(xml):
    if xml.startswith("<get_schedules"): raise B.BridgeError("Greenbone GMP command failed. Check socket permissions, credentials, and gvmd logs.")
    return X("<r/>")
B.cmd = fake_cmd
p = B.get_platform()
ok("one failing section does not hide the others", p["schedules"]["items"] == [] and "failed" in p["schedules"]["error"] and p["scanners"]["items"] == [] and "error" not in p["scanners"])
ok("the view declares itself read-only and has every section", p["readOnly"] is True and set(p) == {"scanners", "configs", "portLists", "schedules", "alerts", "feeds", "readOnly"})

# ---- every GMP command the view sends is a read ----
sent = []
B.cmd = lambda xml: (sent.append(xml), X("<r/>"))[1]
B.get_platform()
ok("only get_* commands are sent", len(sent) == 6 and all(c.startswith("<get_") for c in sent), str(sent))

print(f"bridge platform: {passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
