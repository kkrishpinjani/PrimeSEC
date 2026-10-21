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
