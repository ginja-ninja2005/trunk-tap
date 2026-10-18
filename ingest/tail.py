"""
Tail SDRTrunk event log CSVs and ingest EVERY row.

Each log filename encodes the channel: 20260310_133013.747_0_Hz_Control_call_events.log
Header row:
  TIMESTAMP,DURATION_MS,PROTOCOL,EVENT,FROM,TO,CHANNEL_NUMBER,FREQUENCY,TIMESLOT,DETAILS,EVENT_ID

Row parsing lives in ingest/eventlog.py (stdlib only, unit-tested). This module
owns the DB side and the folder watcher.

Identity: a log's system and site come from the playlist channel it belongs to
(channel name from the filename, "T-<name>" for traffic channels), then through
canonical_system(), so events land under the same system as the RDIO call
uploads. Without a readable playlist the channel name itself is used, as before.

Watching: SDRTrunk never rotates or truncates, it just appends and flushes each
line, and opens a new pair of files for every traffic-channel grant -- so the
folder gathers thousands of header-only files per hour. Each tick lists the
folder by name (cheap) and stats only files that were recently modified or
that watchdog flagged; idle files are re-checked every 30 s, cold ones every
10 min. Header-only files are never opened until they grow. An optional
archive directory (where sdrtrunk-ingest moves finished files) is swept
recursively every 30 s and each file in it is read once.
"""
import csv
import io
import json
import os
import re
import sqlite3
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

from db import (db, upsert_radio, upsert_site, upsert_system, upsert_talkgroup,
                canonical_system)
from ingest import eventlog

# Per-system log files: every ingested event is also appended to
# ~/Desktop/trunk-tap-export/logs/<System>.log as a normalized TSV row so
# each radio system's traffic can be sorted/grepped on its own.
# (override root with SDRTD_EXPORT_DIR)
EXPORT_ROOT = Path(os.environ.get("SDRTD_EXPORT_DIR",
                                  Path.home() / "Desktop" / "trunk-tap-export"))
SYSLOG_DIR = EXPORT_ROOT / "logs"
SYSLOG_DIR.mkdir(parents=True, exist_ok=True)
_syslog_lock = threading.Lock()

SDRTRUNK_HOME = Path(os.environ.get("SDRTRUNK_HOME", Path.home() / "SDRTrunk"))
PLAYLIST_PATH = Path(os.environ.get("SDRTRUNK_PLAYLIST",
                                    SDRTRUNK_HOME / "playlist" / "default.xml"))

# Only events this recent are pushed over the websocket; older ones are
# backfill and reach the UI through /api/events instead.
LIVE_WINDOW_S = 120


def _syslog_name(label):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", label.strip()) or "unknown"


def syslog_event(system_label, ts, event_type, from_rid, to_tgid, to_rid,
                 site, frequency, duration_ms, encrypted, details):
    line = "\t".join([
        time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(ts)),
        event_type or "",
        str(from_rid or ""), str(to_tgid or ""), str(to_rid or ""),
        site or "", str(frequency or ""), str(duration_ms or ""),
        "ENC" if encrypted else "",
        (details or "").replace("\t", " ").replace("\n", " "),
    ]) + "\n"
    with _syslog_lock:
        with open(SYSLOG_DIR / f"{_syslog_name(system_label)}.log", "a") as f:
            f.write(line)


def write_transcript_file(system_label, ts, tgid, tg_alias, rid, call_id,
                          text, engine=None, model=None, lang=None, ms=None,
                          conf=None, audio_path=None, frequency=None,
                          encrypted=False):
    """Write one transcript to
    EXPORT_ROOT/transcripts/<System>/<YYYY-MM-DD>/<HHMMSS>_TG.._RID..._callN.txt
    with a metadata header. Returns the path written."""
    d = time.localtime(ts)
    day = time.strftime("%Y-%m-%d", d)
    hms = time.strftime("%H%M%S", d)
    alias_bit = f"_{_syslog_name(tg_alias)}" if tg_alias else ""
    fname = f"{hms}_TG{tgid or 0}{alias_bit}_RID{rid or 0}_call{call_id}.txt"
    outdir = EXPORT_ROOT / "transcripts" / _syslog_name(system_label) / day
    header = (f"# {time.strftime('%Y-%m-%dT%H:%M:%S', d)}  "
              f"system={system_label}  tg={tgid} \"{tg_alias or ''}\"  "
              f"rid={rid}  freq={frequency or ''}  enc={'yes' if encrypted else 'no'}\n"
              f"# engine={engine} model={model} lang={lang} ms={ms} conf={conf}\n"
              f"# audio={audio_path or ''}\n\n")
    with _syslog_lock:
        outdir.mkdir(parents=True, exist_ok=True)
        dest = outdir / fname
        dest.write_text(header + (text or "") + "\n")
    return dest


def _record_anomaly(ts, kind, system_id=None, site_id=None, rid=None, tgid=None, details=None, socketio=None):
    """Insert an anomaly row and (optionally) emit it over WS."""
    c = db()
    cur = c.execute("""INSERT INTO anomalies(ts, kind, system_id, site_id, rid, tgid, details)
                       VALUES (?,?,?,?,?,?,?)""",
                    (ts, kind, system_id, site_id, rid, tgid, details))
    if socketio is not None and time.time() - ts < LIVE_WINDOW_S:
        socketio.emit("anomaly", {
            "id": cur.lastrowid, "ts": ts, "kind": kind,
            "system_id": system_id, "site_id": site_id,
            "rid": rid, "tgid": tgid, "details": details,
        })


def _detect_novelty(system_id, site_id, from_rid, to_tgid, ts, socketio=None):
    """Emit anomalies for genuinely first-seen combinations."""
    c = db()
    # These upserts have already run in ingest_row; check first_seen == ts to
    # know this is the first sighting.
    if from_rid is not None and system_id is not None:
        row = c.execute("SELECT first_seen FROM radios WHERE system_id=? AND rid=?",
                        (system_id, from_rid)).fetchone()
        if row and row["first_seen"] == ts:
            _record_anomaly(ts, "new_rid", system_id=system_id, rid=from_rid,
                            details=f"first sighting of RID {from_rid}",
                            socketio=socketio)

    if to_tgid is not None and system_id is not None:
        row = c.execute("SELECT first_seen FROM talkgroups WHERE system_id=? AND tgid=?",
                        (system_id, to_tgid)).fetchone()
        if row and row["first_seen"] == ts:
            _record_anomaly(ts, "new_tg", system_id=system_id, tgid=to_tgid,
                            details=f"first sighting of TG {to_tgid}",
                            socketio=socketio)

    if site_id is not None:
        row = c.execute("SELECT first_seen FROM sites WHERE id=?", (site_id,)).fetchone()
        if row and row["first_seen"] == ts:
            _record_anomaly(ts, "new_site", system_id=system_id, site_id=site_id,
                            details=f"first sighting of site",
                            socketio=socketio)

    # New RID on TG (dyad)
    if from_rid is not None and to_tgid is not None:
        seen = c.execute("""SELECT 1 FROM events WHERE from_rid=? AND to_tgid=?
                             AND ts < ? LIMIT 1""",
                         (from_rid, to_tgid, ts)).fetchone()
        if not seen:
            _record_anomaly(ts, "new_rid_on_tg", system_id=system_id,
                            rid=from_rid, tgid=to_tgid,
                            details=f"RID {from_rid} first heard on TG {to_tgid}",
                            socketio=socketio)

    # New RID at site (roaming to a site not previously seen)
    if from_rid is not None and site_id is not None:
        seen = c.execute("""SELECT 1 FROM roaming WHERE rid=? AND site_id=?
                             AND ts < ? LIMIT 1""",
                         (from_rid, site_id, ts)).fetchone()
        if not seen:
            _record_anomaly(ts, "new_rid_at_site", system_id=system_id,
                            site_id=site_id, rid=from_rid,
                            details=f"RID {from_rid} first observed at this site",
                            socketio=socketio)


def _spike_check(system_id, from_rid, ts, socketio=None, window_sec=60, threshold=8):
    """Flag a RID that transmits > threshold times in the last window."""
    if from_rid is None or system_id is None:
        return
    c = db()
    count = c.execute("""SELECT COUNT(*) FROM events WHERE system_id=? AND from_rid=?
                          AND ts BETWEEN ? AND ?""",
                      (system_id, from_rid, ts - window_sec, ts)).fetchone()[0]
    if count >= threshold:
        # Rate-limit: don't spam the same RID more than once per window
        last = c.execute("""SELECT ts FROM anomalies WHERE kind='spike' AND rid=? AND system_id=?
                          ORDER BY ts DESC LIMIT 1""", (from_rid, system_id)).fetchone()
        if last and (ts - last["ts"]) < window_sec:
            return
        _record_anomaly(ts, "spike", system_id=system_id, rid=from_rid,
                        details=f"RID {from_rid} sent {count} events in {window_sec}s",
                        socketio=socketio)


# ---- filename / identity -----------------------------------------------------
# Kept for callers that import these from here.
system_label_from_filename = eventlog.system_label_from_filename
_parse_ts = eventlog.parse_timestamp


class _Playlist:
    """mtime-cached view of the playlist's channels: name -> system / site."""

    def __init__(self, path=PLAYLIST_PATH):
        self.path = Path(path)
        self._mtime = None
        self._map = {}
        self._warned = False

    def channel_map(self):
        try:
            mtime = self.path.stat().st_mtime
        except OSError:
            if self._map or not self._warned:
                if not self._warned:
                    print(f"[tail] playlist not readable at {self.path}; "
                          f"using channel names as system labels", flush=True)
                self._warned = True
            self._map, self._mtime = {}, None
            return self._map
        if mtime != self._mtime:
            self._map = eventlog.load_channel_map(self.path)
            self._mtime = mtime
            self._warned = False
        return self._map

    def identity(self, fname):
        """(system_label, site_label) for a log file name."""
        parsed = eventlog.parse_filename(fname)
        channel = parsed["channel"] if parsed else None
        system, site = eventlog.channel_identity(self.channel_map(), channel)
        if not system:
            system = eventlog.system_label_from_filename(fname) or Path(fname).stem
            site = None
        return canonical_system(system), site


_playlist = _Playlist()

# (system_label, site_label) -> (system_id, site_id, last_touch_ts). Saves a
# SELECT+UPDATE per table per row; last_seen is still refreshed every 10 s.
_ident_cache = {}
_IDENT_REFRESH_S = 10


def _resolve_ids(system_label, site_label, protocol, ts):
    key = (system_label, site_label)
    hit = _ident_cache.get(key)
    if hit and abs(ts - hit[2]) < _IDENT_REFRESH_S:
        return hit[0], hit[1]
    system_id = upsert_system(system_label, protocol=protocol, label=system_label, now=ts)
    site_id = (upsert_site(system_id, site_label, name=site_label, now=ts)
               if site_label else None)
    _ident_cache[key] = (system_id, site_id, ts)
    return system_id, site_id


# ---- ingestion ---------------------------------------------------------------
def ingest_row(system_label, row, socketio=None, site_label=None, event_scope=None):
    """Ingest one CSV row (dict keyed by the header).

    system_label: already the playlist/canonical name (see _Playlist.identity);
    canonical_system() is applied again so direct callers get the same folding.
    site_label:   the playlist channel's site, or None (sites are NOT derived
                  from CHANNEL_NUMBER -- that is a P25 channel id).
    event_scope:  the log's start stamp; EVENT_ID is only unique within one
                  SDRTrunk run, so the stored id is "<scope>:<EVENT_ID>".
    """
    system_label = canonical_system(system_label)
    e = eventlog.classify(row)
    ts = e["ts"]
    event_type = e["event_type"]
    from_rid, to_tgid, to_rid = e["from_rid"], e["to_tgid"], e["to_rid"]
    duration, frequency, details = e["duration_ms"], e["frequency"], e["details"]
    encrypted = e["encrypted"]
    ev_id = f"{event_scope}:{e['event_id']}" if (event_scope and e["event_id"]) else e["event_id"]

    if os.environ.get("SDRTD_DEBUG_TAIL") and "Call" in event_type:
        print(f"[debug] type={event_type!r} dur_raw={row.get('DURATION_MS')!r} "
              f"dur={duration!r} tg={to_tgid} rid={from_rid} enc={encrypted}", flush=True)

    system_id, site_id = _resolve_ids(system_label, site_label, e["protocol"], ts)
    site_str = site_label

    # upserts
    if to_tgid is not None:
        upsert_talkgroup(system_id, to_tgid, alias=e["to_alias"],
                         encrypted=bool(encrypted), now=ts)
    if from_rid is not None:
        upsert_radio(system_id, from_rid, alias=e["from_alias"], now=ts)
    if to_rid is not None:
        upsert_radio(system_id, to_rid, now=ts)

    c = db()
    # Dedup by SDRTrunk's event_id. SDRTrunk writes SEVERAL log rows per event
    # as the call progresses -- the first row (the grant) usually has no
    # DURATION_MS and no FROM; update rows fill them in, the duration grows,
    # and the type can flip to "Encrypted ..." once the traffic channel shows
    # encryption. So on re-observation merge the new info into the existing
    # row, and re-emit when we learn who is talking.
    if ev_id is not None:
        existing = c.execute("SELECT id, duration_ms, from_rid, encrypted FROM events "
                             "WHERE system_id=? AND event_id=?",
                             (system_id, ev_id)).fetchone()
    else:
        existing = None
    if existing is not None:
        learned_from = existing["from_rid"] is None and from_rid is not None
        durs = [d for d in (existing["duration_ms"], duration) if d is not None]
        new_dur = max(durs) if durs else None
        c.execute("""UPDATE events SET
                         duration_ms = ?,
                         from_rid    = COALESCE(from_rid, ?),
                         to_tgid     = COALESCE(to_tgid, ?),
                         to_rid      = COALESCE(to_rid, ?),
                         frequency   = COALESCE(NULLIF(frequency, 0), ?),
                         encrypted   = MAX(encrypted, ?),
                         event_type  = ?,
                         details     = ?
                     WHERE id=?""",
                  (new_dur, from_rid, to_tgid, to_rid, frequency,
                   encrypted, event_type, details, existing["id"]))
        if learned_from and socketio is not None and time.time() - ts < LIVE_WINDOW_S:
            socketio.emit("event", {
                "ts": ts, "system": system_label, "type": event_type,
                "from": from_rid, "to_tg": to_tgid, "to_rid": to_rid,
                "site": site_str, "freq": frequency, "duration_ms": new_dur,
                "encrypted": bool(encrypted or existing["encrypted"]),
                "details": details,
            })
        return  # derived tables only on first sighting

    cur = c.execute("""INSERT INTO events(ts, system_id, site_id, protocol,
                            event_type, from_rid, to_tgid, to_rid, channel,
                            frequency, timeslot, duration_ms, details, event_id,
                            encrypted)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (ts, system_id, site_id, e["protocol"], event_type, from_rid,
                     to_tgid, to_rid, e["channel"], frequency, e["timeslot"],
                     duration, details, ev_id, encrypted))

    # Per-system log file (sortable TSV)
    try:
        syslog_event(system_label, ts, event_type, from_rid, to_tgid, to_rid,
                     site_str, frequency, duration, encrypted, details)
    except Exception as ex:
        print(f"[syslog] err: {ex!r}")

    # Side tables
    if event_type == "Response" and to_tgid is not None and from_rid is not None:
        c.execute("INSERT INTO affiliations(ts, system_id, site_id, rid, tgid) VALUES (?,?,?,?,?)",
                  (ts, system_id, site_id, from_rid, to_tgid))
    if site_id is not None and from_rid is not None:
        c.execute("INSERT INTO roaming(ts, system_id, site_id, rid) VALUES (?,?,?,?)",
                  (ts, system_id, site_id, from_rid))
    if e["deny"]:
        c.execute("INSERT INTO denies(ts, system_id, site_id, rid, tgid, reason) VALUES (?,?,?,?,?,?)",
                  (ts, system_id, site_id, from_rid, to_tgid, details))
    if "ADJACENT" in details.upper():
        c.execute("INSERT INTO adjacent_sites(ts, system_id, from_site_id, neighbor_site, frequency) VALUES (?,?,?,?,?)",
                  (ts, system_id, site_id, details, frequency))
    if "PATCH" in event_type.upper():
        children = e["patch_members"] if e["patch_members"] is not None else {"details": details}
        c.execute("INSERT INTO patches(ts, system_id, supergroup, child_tgs) VALUES (?,?,?,?)",
                  (ts, system_id, to_tgid, json.dumps(children)))
        for child in (e["patch_members"] or []):
            upsert_talkgroup(system_id, child, now=ts)

    # Anomaly detection (novelty + spike + emergency). Runs after all upserts
    # so first_seen comparison is meaningful.
    try:
        if e["emergency"]:
            _record_anomaly(ts, "emergency", system_id=system_id, site_id=site_id,
                            rid=from_rid, tgid=to_tgid,
                            details=details or "EMERGENCY", socketio=socketio)
        _detect_novelty(system_id, site_id, from_rid, to_tgid, ts, socketio=socketio)
        _spike_check(system_id, from_rid, ts, socketio=socketio)
    except Exception as ex:
        print(f"[anomaly] err: {ex!r}")

    if socketio is not None and time.time() - ts < LIVE_WINDOW_S:
        socketio.emit("event", {
            "ts": ts,
            "system": system_label,
            "type": event_type,
            "from": from_rid,
            "to_tg": to_tgid,
            "to_rid": to_rid,
            "site": site_str,
            "freq": frequency,
            "duration_ms": duration,
            "encrypted": bool(encrypted),
            "details": details,
        })


# ---- watcher -----------------------------------------------------------------
class _FileState:
    __slots__ = ("path", "name", "scope", "offset", "size", "mtime", "cols",
                 "next_stat", "done", "rows")

    def __init__(self, path, name, scope, offset=0):
        self.path = path
        self.name = name
        self.scope = scope
        self.offset = offset
        self.size = None
        self.mtime = None
        self.cols = None
        self.next_stat = 0.0
        self.done = False       # immutable (archived) file fully read
        self.rows = 0


class _Tailer:
    """Follows one live folder plus optional archive folders.

    State is keyed by file NAME (unique: start stamp + frequency + channel), so a
    file that sdrtrunk-ingest moves into the archive is not read twice."""

    IDLE_AFTER_S = 120      # mtime older than this: stat every SLOW_EVERY_S
    COLD_AFTER_S = 3600     # ... older than this and fully read: every COLD_EVERY_S
    SLOW_EVERY_S = 30
    COLD_EVERY_S = 600
    COMMIT_EVERY_ROWS = 500

    def __init__(self, log_dir, socketio=None, archive_dirs=(), playlist=None):
        self.log_dir = Path(log_dir)
        self.archive_dirs = [Path(p) for p in (archive_dirs or ()) if p]
        self.socketio = socketio
        self.playlist = playlist or _playlist
        self.files = {}         # name -> _FileState
        self.lock = threading.Lock()
        self._dirty = set()
        self._dirty_lock = threading.Lock()
        self._next_archive_scan = 0.0
        self.stats = {"stats": 0, "reads": 0, "rows": 0, "files": 0}
        self._state_loaded = False
        self._saved_offsets = {}

    # -- persisted offsets --------------------------------------------------
    def _load_saved_offsets(self):
        if self._state_loaded:
            return
        c = db()
        for r in c.execute("SELECT path, offset FROM ingest_state"):
            # Older versions stored full paths; key by basename either way.
            self._saved_offsets[Path(r["path"]).name] = r["offset"]
        self._state_loaded = True

    def _save_state(self, st):
        c = db()
        c.execute("""INSERT INTO ingest_state(path, offset, last_ts) VALUES(?,?,?)
                     ON CONFLICT(path) DO UPDATE SET offset=excluded.offset, last_ts=excluded.last_ts""",
                  (st.name, st.offset, time.time()))

    # -- watchdog hook ------------------------------------------------------
    def flag(self, path):
        name = Path(path).name
        if name.endswith(eventlog.CALL_EVENTS_SUFFIX):
            with self._dirty_lock:
                self._dirty.add(name)

    # -- scanning -----------------------------------------------------------
    def scan_once(self):
        now = time.time()
        with self.lock:
            self._load_saved_offsets()
            if self.log_dir.is_dir():
                self._scan_dir(self.log_dir, now, recursive=False, immutable=False)
            if self.archive_dirs and now >= self._next_archive_scan:
                for d in self.archive_dirs:
                    if d.is_dir():
                        self._scan_dir(d, now, recursive=True, immutable=True)
                self._next_archive_scan = now + self.SLOW_EVERY_S
            with self._dirty_lock:
                dirty, self._dirty = self._dirty, set()
            for name in dirty:
                st = self.files.get(name)
                if st is not None and not st.done:
                    self._check(st, now, immutable=False)

    def _iter_names(self, d, recursive):
        if recursive:
            for root, _dirs, names in os.walk(d):
                for n in names:
                    if n.endswith(eventlog.CALL_EVENTS_SUFFIX):
                        yield Path(root) / n
        else:
            with os.scandir(d) as it:
                for entry in it:
                    if entry.name.endswith(eventlog.CALL_EVENTS_SUFFIX):
                        yield Path(entry.path)

    def _scan_dir(self, d, now, recursive, immutable):
        try:
            paths = list(self._iter_names(d, recursive))
        except OSError as ex:
            print(f"[tail] cannot list {d}: {ex!r}", flush=True)
            return
        for path in paths:
            name = path.name
            st = self.files.get(name)
            if st is None:
                parsed = eventlog.parse_filename(name)
                scope = parsed["start"] if parsed else None
                st = _FileState(path, name, scope, offset=self._saved_offsets.get(name, 0))
                self.files[name] = st
                self.stats["files"] += 1
            elif st.path != path:
                st.path = path          # moved (live -> archive)
            if st.done:
                continue
            if now >= st.next_stat:
                self._check(st, now, immutable)

    def _check(self, st, now, immutable):
        try:
            stt = os.stat(st.path)
        except FileNotFoundError:
            # moved away (archived) or deleted; the archive sweep will find it
            st.next_stat = now + self.SLOW_EVERY_S
            return
        except OSError as ex:
            print(f"[tail] stat {st.path}: {ex!r}", flush=True)
            st.next_stat = now + self.SLOW_EVERY_S
            return
        self.stats["stats"] += 1
        size, mtime = stt.st_size, stt.st_mtime
        st.size, st.mtime = size, mtime
        if size < st.offset:
            st.offset = 0           # truncated / replaced
        # Header-only files (one per traffic-channel grant) are never opened
        # until they grow past the header.
        if size > st.offset and size > eventlog.HEADER_ONLY_BYTES:
            self._read_new(st, size)
        age = now - mtime
        caught_up = st.offset >= size or size <= eventlog.HEADER_ONLY_BYTES
        if immutable:
            st.done = caught_up
            st.next_stat = now + self.SLOW_EVERY_S
        elif age > self.COLD_AFTER_S and caught_up:
            st.next_stat = now + self.COLD_EVERY_S
        elif age > self.IDLE_AFTER_S:
            st.next_stat = now + self.SLOW_EVERY_S
        else:
            st.next_stat = 0.0

    def _read_new(self, st, size):
        try:
            with open(st.path, "rb") as f:
                f.seek(st.offset)
                chunk = f.read(size - st.offset)
                new_offset = f.tell()
        except OSError as ex:
            print(f"[tail] read {st.path}: {ex!r}", flush=True)
            return
        self.stats["reads"] += 1
        text = chunk.decode("utf-8", errors="replace")

        # If we started at 0, first line is header
        if st.offset == 0:
            first_nl = text.find("\n")
            if first_nl == -1:
                return
            st.cols = next(csv.reader(io.StringIO(text[:first_nl])))
            text = text[first_nl + 1:]
        if st.cols is None:
            # resumed mid-file: load the header from the file start
            try:
                with open(st.path, encoding="utf-8", errors="replace") as f:
                    st.cols = next(csv.reader(io.StringIO(f.readline())))
            except (OSError, StopIteration):
                st.cols = list(eventlog.HEADER)
        cols = st.cols

        # Process only complete lines; keep tail for next round
        last_nl = text.rfind("\n")
        if last_nl == -1:
            return
        complete = text[:last_nl + 1]
        new_offset -= len(text) - (last_nl + 1)

        system_label, site_label = self.playlist.identity(st.name)

        # One write transaction per chunk (committed every COMMIT_EVERY_ROWS
        # rows so the RDIO upload handler and whisper worker never wait long).
        # BEGIN IMMEDIATE takes the write lock up front: a deferred BEGIN would
        # start on a read snapshot and every later write could fail with
        # "database is locked" (SQLITE_BUSY_SNAPSHOT, which the busy timeout
        # cannot retry) whenever another thread committed in between.
        # Parse errors are per row; SQLite errors abort the chunk so the
        # offset is not advanced past rows that were never stored.
        c = db()
        n = 0
        in_tx = False
        try:
            c.execute("BEGIN IMMEDIATE")
            in_tx = True
            for row_list in csv.reader(io.StringIO(complete)):
                if not row_list:
                    continue
                row = dict(zip(cols, row_list))
                try:
                    ingest_row(system_label, row, self.socketio,
                               site_label=site_label, event_scope=st.scope)
                except sqlite3.Error:
                    raise
                except Exception as ex:
                    print(f"[tail] parse error in {st.name}: {ex!r}", flush=True)
                n += 1
                if n % self.COMMIT_EVERY_ROWS == 0:
                    c.execute("COMMIT")
                    c.execute("BEGIN IMMEDIATE")
            st.offset = new_offset
            self._save_state(st)
            c.execute("COMMIT")
            in_tx = False
        except Exception as ex:
            print(f"[tail] {st.name}: {ex!r} (will retry)", flush=True)
            if in_tx:
                try:
                    c.execute("ROLLBACK")
                except Exception:
                    pass
            return
        st.rows += n
        self.stats["rows"] += n


class _FSEvents(FileSystemEventHandler):
    def __init__(self, tailer):
        self.tailer = tailer

    def on_created(self, event):
        if not event.is_directory:
            self.tailer.flag(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.tailer.flag(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self.tailer.flag(getattr(event, "dest_path", event.src_path))


def default_archive_dirs():
    """SDRTD_ARCHIVE_DIRS (os.pathsep separated) or <SDRTRUNK_HOME>/event_logs_archive."""
    raw = os.environ.get("SDRTD_ARCHIVE_DIRS")
    if raw is not None:
        return [Path(p) for p in raw.split(os.pathsep) if p]
    return [SDRTRUNK_HOME / "event_logs_archive"]


def start_tail(log_dir, socketio=None, poll_interval=1.0, archive_dirs=None):
    """Start following `log_dir` (and any existing archive dirs) in a daemon
    thread. The initial backfill of existing files runs in that thread too so
    the HTTP server comes up immediately."""
    if archive_dirs is None:
        archive_dirs = [d for d in default_archive_dirs() if d.is_dir()]
    tailer = _Tailer(log_dir, socketio=socketio, archive_dirs=archive_dirs)

    zone = eventlog.event_zone()
    print(f"[tail] zone for SDRTrunk timestamps: {zone or 'process local'}; "
          f"playlist: {PLAYLIST_PATH} ({'found' if PLAYLIST_PATH.exists() else 'missing'}); "
          f"archive dirs: {[str(d) for d in tailer.archive_dirs] or 'none'}", flush=True)

    try:
        observer = Observer()
        observer.schedule(_FSEvents(tailer), str(log_dir), recursive=False)
        observer.daemon = True
        observer.start()
    except Exception as ex:
        print(f"[tail] watchdog unavailable ({ex!r}); polling only", flush=True)

    def _poll():
        t0 = time.time()
        try:
            tailer.scan_once()
            print(f"[tail] backfill done: {tailer.stats['files']} files, "
                  f"{tailer.stats['rows']} rows in {time.time() - t0:.1f}s", flush=True)
        except Exception as ex:
            print(f"[tail] initial scan error: {ex!r}", flush=True)
        while True:
            time.sleep(poll_interval)
            try:
                tailer.scan_once()
            except Exception as ex:
                print(f"[tail] scan error: {ex!r}", flush=True)

    t = threading.Thread(target=_poll, name="sdr-tail-poll", daemon=True)
    t.start()
    return tailer
