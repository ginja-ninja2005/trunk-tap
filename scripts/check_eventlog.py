#!/usr/bin/env python3
"""
Feed SDRTrunk *_call_events.log files through the dashboard's parser
(ingest/eventlog.py, stdlib only) and print what the tailer would make of them:
rows per EVENT type, how many carry a talkgroup / radio, how many are flagged
encrypted, and how many distinct events (EVENT_IDs) they collapse to.

    python3 scripts/check_eventlog.py ~/SDRTrunk/event_logs/*_0_Hz_*_call_events.log
    python3 scripts/check_eventlog.py ~/SDRTrunk/event_logs_archive      # folder: recursive
    python3 scripts/check_eventlog.py --playlist ~/SDRTrunk/playlist/default.xml FILE...

Exits 1 if any Group/Encrypted/Patch Call row with a TO field has no talkgroup,
or if an "Encrypted ..." row is not flagged encrypted. Set SDRTRUNK_TZ (or TZ)
to the zone SDRTrunk runs in to see correctly converted timestamps.
"""
import argparse
import collections
import csv
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ingest import eventlog as E  # noqa: E402


def expand(paths):
    for p in paths:
        p = Path(p).expanduser()
        if p.is_dir():
            yield from sorted(p.rglob("*" + E.CALL_EVENTS_SUFFIX))
        else:
            yield p


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+", help="log files or folders")
    ap.add_argument("--playlist", default=os.environ.get(
        "SDRTRUNK_PLAYLIST", str(Path(os.environ.get("SDRTRUNK_HOME", Path.home() / "SDRTrunk"))
                                / "playlist" / "default.xml")))
    ap.add_argument("--skip-empty", action="store_true", help="do not list header-only files")
    args = ap.parse_args()

    channel_map = E.load_channel_map(args.playlist)
    print(f"zone: {E.event_zone() or 'process local'}   playlist: {args.playlist} "
          f"({len(channel_map)} channels)")

    per_type = collections.Counter()
    with_tg = collections.Counter()
    with_from = collections.Counter()
    with_to_rid = collections.Counter()
    enc = collections.Counter()
    ids = collections.defaultdict(set)
    bad = []
    files = 0
    empty = 0
    ts_min = ts_max = None
    t0 = time.time()

    for path in expand(args.paths):
        parsed = E.parse_filename(path.name)
        if not parsed:
            continue
        files += 1
        size = path.stat().st_size
        if size <= E.HEADER_ONLY_BYTES:
            empty += 1
            if not args.skip_empty:
                print(f"  header-only: {path.name}")
            continue
        system, site = E.channel_identity(channel_map, parsed["channel"])
        print(f"  {path.name}: {size} bytes, channel {parsed['channel']!r} -> "
              f"system {system or '(from filename: ' + (E.system_label_from_filename(path.name) or '?') + ')'}"
              f"{', site ' + site if site else ''}")
        with open(path, newline="") as fh:
            for row in csv.DictReader(fh):
                e = E.classify(row)
                t = e["event_type"]
                per_type[t] += 1
                ids[t].add((parsed["start"], e["event_id"]))
                if e["to_tgid"] is not None:
                    with_tg[t] += 1
                elif E.is_group_call(t) and (row.get("TO") or "").strip():
                    bad.append((path.name, row))
                if e["from_rid"] is not None:
                    with_from[t] += 1
                if e["to_rid"] is not None:
                    with_to_rid[t] += 1
                if e["encrypted"]:
                    enc[t] += 1
                elif t.startswith("Encrypted"):
                    bad.append((path.name, row))
                ts_min = e["ts"] if ts_min is None else min(ts_min, e["ts"])
                ts_max = e["ts"] if ts_max is None else max(ts_max, e["ts"])

    total = sum(per_type.values())
    print(f"\n{files} files ({empty} header-only), {total} rows in {time.time() - t0:.1f}s")
    if ts_min is not None:
        fmt = lambda t: time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(t))
        print(f"event time span: {fmt(ts_min)} .. {fmt(ts_max)}  (epoch {ts_min:.0f} .. {ts_max:.0f})")
    print("%-24s %7s %8s %9s %8s %7s %8s" % ("EVENT", "rows", "to_tgid", "from_rid", "to_rid", "enc", "events"))
    for t, n in per_type.most_common():
        print("%-24s %7d %8d %9d %8d %7d %8d" % (t, n, with_tg[t], with_from[t], with_to_rid[t], enc[t], len(ids[t])))
    if bad:
        print(f"\n{len(bad)} problem rows, e.g.:")
        for name, row in bad[:5]:
            print(f"  {name}: {row}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
