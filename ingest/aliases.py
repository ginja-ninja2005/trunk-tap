"""
Import aliases from ~/SDRTrunk/playlist/default.xml so the dashboard shows
"County PD Dispatch" and not just talkgroup 2001.

Every alias in the playlist maps a talkgroup id to a human name, group ("Law",
"County Fire", "County EMS", ...) and priority, and belongs to an alias list.
The alias list says nothing about the network by itself, so the list is mapped
to a system through the playlist's channels: a channel names the alias list it
uses and carries the system attribute ("Alabama Interoperable Radio System
(AIRS)"), the same label SDRTrunk sends as systemLabel on RDIO call uploads.
Enabled channels win; lists no channel references are skipped (reported in
the result) rather than turned into bogus systems. LIST_TO_SYSTEM overrides
that mapping for specific list names.
"""
import os
import xml.etree.ElementTree as ET
from pathlib import Path

from db import db, upsert_system, upsert_talkgroup, canonical_system
from ingest import eventlog

_SDRTRUNK_HOME = Path(os.environ.get("SDRTRUNK_HOME", Path.home() / "SDRTrunk"))
DEFAULT_PLAYLIST = Path(os.environ.get("SDRTRUNK_PLAYLIST",
                                       _SDRTRUNK_HOME / "playlist" / "default.xml"))

# alias_list_name -> system label we use in DB (explicit overrides; anything
# not listed here is resolved from the playlist's channels)
LIST_TO_SYSTEM = {
    "Countywide": "Countywide",
    "City P25": "City P25",
    "State P25 Region": "State P25",
}


def import_from(path=DEFAULT_PLAYLIST):
    path = Path(path)
    if not path.exists():
        return {"imported": 0, "error": f"not found: {path}"}
    tree = ET.parse(path)
    root = tree.getroot()

    list_systems = dict(eventlog.alias_list_systems(path))
    list_systems.update(LIST_TO_SYSTEM)

    n = 0
    skipped_lists = {}
    system_ids = {}
    for alias in root.findall("alias"):
        list_name = alias.get("list", "") or ""
        system_label = list_systems.get(list_name)
        if not system_label:
            skipped_lists[list_name or "(none)"] = skipped_lists.get(list_name or "(none)", 0) + 1
            continue
        system_label = canonical_system(system_label)
        system_id = system_ids.get(system_label)
        if system_id is None:
            system_id = upsert_system(system_label, protocol="APCO-25", label=system_label)
            system_ids[system_label] = system_id

        name = (alias.get("name") or "").strip() or None
        group = (alias.get("group") or "").strip() or None

        tgid = None
        priority = None
        for aid in alias.findall("id"):
            t = aid.get("type")
            if t == "talkgroup":
                try:
                    tgid = int(aid.get("value"))
                except (TypeError, ValueError):
                    pass
            elif t == "priority":
                try:
                    priority = int(aid.get("priority"))
                except (TypeError, ValueError):
                    pass

        if tgid is None:
            continue

        upsert_talkgroup(system_id, tgid, alias=name, tg_group=group,
                         priority=priority)
        n += 1
    out = {"imported": n, "path": str(path),
           "systems": sorted(system_ids), "lists": sorted(set(list_systems) & {
               (a.get("list") or "") for a in root.findall("alias")})}
    if skipped_lists:
        out["skipped_lists"] = skipped_lists
    return out


if __name__ == "__main__":
    import sys, json
    print(json.dumps(import_from(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PLAYLIST), indent=2))
