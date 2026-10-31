
import json
import os
import ctypes
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

import win32evtlog

LOG_NAME = "Security"
EVENT_ID = 4688
OUTPUT_DIR = r"C:\GraySentinel\logs"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "process_events.json")

# Native Windows Event Log handle cleanup
wevtapi = ctypes.WinDLL("wevtapi.dll")
wevtapi.EvtClose.argtypes = [ctypes.c_void_p]
wevtapi.EvtClose.restype = ctypes.c_bool


def close_handle(handle):
    if handle:
        wevtapi.EvtClose(int(handle))


def collect_process_events():
    print("[GraySentinel] Starting process event collection...")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    query = "*[System[(EventID=4688) and (EventRecordID=1642672)]]"
    events = []

    handle = win32evtlog.EvtQuery(
        LOG_NAME,
        win32evtlog.EvtQueryReverseDirection,
        query
    )

    try:
        records = win32evtlog.EvtNext(handle, 200, 5000, 0)

        for record in records:
            try:
                xml_data = win32evtlog.EvtRender(
                    record,
                    win32evtlog.EvtRenderEventXml
                )

                root = ET.fromstring(xml_data)

                namespace = {
                    "e": "http://schemas.microsoft.com/win/2004/08/events/event"
                }

                system = root.find("e:System", namespace)
                event_data = root.find("e:EventData", namespace)

                if system is None or event_data is None:
                    continue

                timestamp = system.find("e:TimeCreated", namespace)

                fields = {
                    item.attrib.get("Name", "Unknown"): item.text or ""
                    for item in event_data.findall("e:Data", namespace)
                }

                events.append({
                    "timestamp": (
                        timestamp.attrib.get("SystemTime")
                        if timestamp is not None else None
                    ),
                    "event_id": EVENT_ID,
                    "source": "Windows Security",
                    "process_name": fields.get("NewProcessName"),
                    "process_id": fields.get("NewProcessId"),
                    "command_line": fields.get("CommandLine"),
                    "parent_process": fields.get("ParentProcessName"),
		    "parent_process_id": fields.get("ProcessId"),
                    "user": fields.get("SubjectUserName"),
                    "domain": fields.get("SubjectDomainName"),
                    "collected_at": datetime.now(
                        timezone.utc
                    ).isoformat()
                })

            except Exception as error:
                print("[WARNING] Event parsing error:", error)

            finally:
                close_handle(record)

    finally:
        close_handle(handle)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(events, file, indent=4)

    print(f"[SUCCESS] Collected {len(events)} events.")
    print(f"[OUTPUT] {OUTPUT_FILE}")

    for event in events[:5]:
        print(
            event.get("process_name"),
            "| Parent:",
            event.get("parent_process")
        )


if __name__ == "__main__":
    try:
        collect_process_events()
    except Exception as error:
        print("[ERROR]", repr(error))
