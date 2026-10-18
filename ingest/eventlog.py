"""
Pure parsing for SDRTrunk event logs. Standard library only, no DB access, so
it runs (and is unit-tested) on any Python >= 3.9 and is shared by the tailer
and by scripts/check_eventlog.py.

What SDRTrunk writes (verified against the nightly builds):

  * One `*_call_events.log` per channel start, named
    <yyyyMMdd>_<HHmmss.SSS>_<freqHz>_Hz_<ChannelName>_call_events.log.
    Traffic channels are "T-<name>"; a control channel on a multi-frequency
    source logs "0_Hz". System and site are NOT in the name -- they come from
    the playlist channel the log belongs to (see load_channel_map).
  * CSV with an unquoted header and all-quoted rows:
    TIMESTAMP,DURATION_MS,PROTOCOL,EVENT,FROM,TO,CHANNEL_NUMBER,FREQUENCY,TIMESLOT,DETAILS,EVENT_ID
    TIMESTAMP is the event *start* as local wall-clock time (yyyy:MM:dd:HH:mm:ss),
    FREQUENCY is MHz (0.000000 until the traffic channel is known), the same
    EVENT_ID is re-written on every update (duration grows, FROM fills in).
  * CHANNEL_NUMBER is the P25 channel identifier ("0-629" = band 0, channel
    629). It is NOT a site id.
"""
import datetime as _dt
import os
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path

CALL_EVENTS_SUFFIX = "_call_events.log"
HEADER = ["TIMESTAMP", "DURATION_MS", "PROTOCOL", "EVENT", "FROM", "TO",
          "CHANNEL_NUMBER", "FREQUENCY", "TIMESLOT", "DETAILS", "EVENT_ID"]
HEADER_LINE = ",".join(HEADER)
# A freshly opened log holds just the header + newline. Most traffic-channel
# logs never grow past this (SDRTrunk opens one per grant).
HEADER_ONLY_BYTES = len(HEADER_LINE) + 1

# P25 reserved addresses SDRTrunk prints in FROM/TO. They are the fixed network
# equipment (FNE) or broadcast placeholders, never a subscriber radio.
FNE_IDS = {16777213, 16777214, 16777215}   # 0xFFFFFD..0xFFFFFF
BROADCAST_IDS = {65535, 16777215}

# ---- filename ----------------------------------------------------------------
_FNAME_RE = re.compile(
    r"^(?P<date>\d{8})_(?P<time>\d{6}\.\d+)_(?P<freq>\d+)_Hz_(?P<label>.+?)"
    r"_call_events\.log$")


def parse_filename(fname):
    """Pieces of a call-events log name, or None if it is not one.

    {"start": "20261017_163143.690", "freq_hz": 0, "channel": "T-Control",
     "parent_channel": "Control", "traffic": True}
    `start` is unique per channel start and is used to scope EVENT_IDs, which
    SDRTrunk only keeps unique within one run."""
    m = _FNAME_RE.match(Path(fname).name)
    if not m:
        return None
    channel = m.group("label")
    traffic = channel.startswith("T-")
    return {
        "start": f"{m.group('date')}_{m.group('time')}",
        "freq_hz": int(m.group("freq")),
        "channel": channel,
        "parent_channel": channel[2:] if traffic else channel,
        "traffic": traffic,
    }


def system_label_from_filename(fname):
    """Legacy fallback: the channel name with -/_ as spaces ("T Control").
    Only used when the playlist cannot tell us the channel's system."""
    p = parse_filename(fname)
    if not p:
        return None
    return p["channel"].replace("-", " ").replace("_", " ").strip()


# ---- timestamps --------------------------------------------------------------
_zone_cache = {"key": None, "zone": None}


def event_zone():
    """Zone SDRTrunk's naive timestamps are written in. SDRTRUNK_TZ wins, then
    TZ; None means "the process's local zone" (datetime.timestamp() semantics).
    Set SDRTRUNK_TZ when the dashboard runs in a container whose TZ differs
    from the machine SDRTrunk runs on."""
    key = os.environ.get("SDRTRUNK_TZ") or os.environ.get("TZ") or ""
    if _zone_cache["key"] != key:
        zone = None
        if key:
            try:
                from zoneinfo import ZoneInfo
                zone = ZoneInfo(key)
            except Exception:
                zone = None
        _zone_cache["key"], _zone_cache["zone"] = key, zone
    return _zone_cache["zone"]


def parse_timestamp(raw, default=None):
    """'2026:10:17:16:31:44' (local wall clock) -> epoch seconds."""
    try:
        parts = raw.strip().split(":")
        if len(parts) >= 6:
            dt = _dt.datetime(int(parts[0]), int(parts[1]), int(parts[2]),
                              int(parts[3]), int(parts[4]), int(parts[5]),
                              tzinfo=event_zone())
            return dt.timestamp()
    except (AttributeError, ValueError, OverflowError):
        pass
    return time.time() if default is None else default


# ---- fields ------------------------------------------------------------------
_ALIAS_ID_RE = re.compile(r"^\[(?P<alias>.*?)\]\s*\((?P<id>\d+)\)\s*$")
_BARE_ID_RE = re.compile(r"^\((?P<id>\d+)\)\s*$")
_ID_ONLY_RE = re.compile(r"^(?P<id>\d+)$")
# Patch (supergroup) target: "[Mt Olive FD Disp, Cane Creek Fire] (P:1785 [2541, 1679])"
_PATCH_RE = re.compile(
    r"^(?:\[(?P<alias>.*?)\]\s*)?\(P:(?P<id>\d+)\s*\[(?P<members>[^\]]*)\]\)\s*$")


def parse_actor(field):
    """FROM/TO field -> (id, alias, patch_members).

    '[Label] (3001)' -> (3001, 'Label', None)
    ' (220026)'      -> (220026, None, None)
    '45021'          -> (45021, None, None)
    '[A, B] (P:1785 [2541, 1679])' -> (1785, 'A, B', [2541, 1679])
    'ISSI 1.2.3' / 'TA-...' / '10.51.4.116' (talker alias or IP) -> (None, text, None)
    ''               -> (None, None, None)
    """
    if field is None:
        return None, None, None
    field = field.strip()
    if not field:
        return None, None, None
    m = _ALIAS_ID_RE.match(field)
    if m:
        return int(m.group("id")), (m.group("alias").strip() or None), None
    m = _BARE_ID_RE.match(field)
    if m:
        return int(m.group("id")), None, None
    m = _ID_ONLY_RE.match(field)
    if m:
        return int(m.group("id")), None, None
    m = _PATCH_RE.match(field)
    if m:
        members = [int(x) for x in re.findall(r"\d+", m.group("members") or "")]
        alias = (m.group("alias") or "").strip() or None
        return int(m.group("id")), alias, members
    return None, field, None


def parse_int(x):
    try:
        return int(x) if x not in (None, "", " ") else None
    except (TypeError, ValueError):
        return None


# ---- LRRP requests -----------------------------------------------------------
# "Motorola LRRP" events (PROTOCOL "LRRP", FROM the location server's IP, TO the
# radio) carry the request text in DETAILS, twice: once as the event and once
# inside the IP packet text that follows it. SDRTrunk has printed two forms:
#
#   legacy (nightlies up to Aug 2026): decimal id read little-endian, integer
#   tokens read as one byte, parameters misnamed; skipped value bytes end up in
#   UNRECOGNIZED(...):
#     LRRP TRIGGERED LOCATION START REQUEST ID:15663103 TRIGGER ON GPIO
#       TRIGGER EVERY:132 SECS REQUESTED TOKENS [TIME,REQUEST-64,REQUEST-62,
#       HORIZONTAL DIRECTION,TIMESTAMP,UNRECOGNIZED(10,44,58,9C)]
#   current (lrrp-request-varint patch): hex id as transmitted, 7-bit varints:
#     LRRP TRIGGERED LOCATION START REQUEST ID:FFFFEE PERIODIC INTERVAL:600 SECS
#       PARAM-42:3600 PARAM-44:100 REQUESTED TOKENS [TIME,HORIZONTAL SPEED,
#       HORIZONTAL DIRECTION]
#     ... ID:FFFF02 PERIODIC TRIGGER CONDITION:EMERGENCY PARAM-42:3600 ...
#
# parse_lrrp_request reads both and gives the request id the same way for both
# (request_id_hex = the transmitted bytes as the current form prints them), so a
# request profile can be followed across the SDRTrunk upgrade. Legacy trigger
# words are kept verbatim; their real values cannot be recovered from the text.
_LRRP_PACKET_TYPES = (
    "TRIGGERED LOCATION START RESPONSE", "TRIGGERED LOCATION START REQUEST",
    "TRIGGERED LOCATION STOP RESPONSE", "TRIGGERED LOCATION STOP REQUEST",
    "IMMEDIATE LOCATION RESPONSE", "IMMEDIATE LOCATION REQUEST",
    "PROTOCOL VERSION RESPONSE", "PROTOCOL VERSION REQUEST",
    "TRIGGERED LOCATION",
)
_LRRP_TYPE_RE = re.compile(
    r"\bLRRP (?P<type>TYPE:UNKNOWN \[\d+\]|" + "|".join(re.escape(t) for t in _LRRP_PACKET_TYPES)
    + r")(?=\s|$)")
_LRRP_IP_RE = re.compile(r"\s+IP FROM:")
_LRRP_TOKEN_RE = re.compile(r"""
    \bID:(?P<id>[0-9A-Fa-f]+)
  | \bREQUESTED\ TOKENS\ \[(?P<requested>[^\]]*)\]
  | \bPERIODIC\b(?P<periodic>)
  | \bINTERVAL:(?P<interval>\d+)\ SECS
  | \bTRIGGER\ CONDITION:(?P<condition>PTT\ EMERGENCY|PIN\ STATUS\ CHANGE|EMERGENCY|PTT|UNKNOWN\[0x[0-9A-Fa-f]+\])
  | \bTRIGGER\ DISTANCE:(?P<distance>\d+)\ METERS
  | \bPARAM-(?P<param_id>[0-9A-Fa-f]+):(?P<param_value>\d+)
  | (?P<legacy>\bTRIGGER\ ON\ GPIO\b|\bTRIGGER\ ON\ MOVE\b|\bTRIGGER\ EVERY:\d+\ SECS|\bTRIGGER\ DISTANCE:\d+)
  | (?P<other>\S+)
""", re.X)
_LRRP_UNRECOGNIZED_RE = re.compile(r"UNRECOGNIZED\((?P<ids>[^)]*)\)")
# Requested-token names only one form prints (0x62: REQUEST-62 -> HORIZONTAL
# SPEED; 0x34 is TIMESTAMP in a response but the PERIODIC flag in a request).
_LRRP_LEGACY_NAMES = {"REQUEST-62", "TIMESTAMP"}
_LRRP_CURRENT_NAMES = {"HORIZONTAL SPEED"}
# The current form's trigger-condition label must not read as an emergency event.
_LRRP_CONDITION_RE = re.compile(r"TRIGGER CONDITION:(?:PTT )?EMERGENCY")


def find_lrrp_text(text):
    """The first 'LRRP <type> <tokens>' run in text, without the IP text after it."""
    m = _LRRP_TYPE_RE.search(text or "")
    if not m:
        return None
    end = len(text)
    nxt = _LRRP_TYPE_RE.search(text, m.end())
    if nxt:
        end = nxt.start()
    ip = _LRRP_IP_RE.search(text, m.end(), end)
    if ip:
        end = ip.start()
    return text[m.start():end].strip()


def legacy_lrrp_id(legacy_id):
    """Undo the legacy little-endian read: 15663103 (0xEEFFFF) -> (0xFFFFEE, 'FFFFEE').
    The shortest byte count that holds the value is assumed."""
    if legacy_id < 0:
        return None, None
    n = max(1, (legacy_id.bit_length() + 7) // 8)
    value = int.from_bytes(legacy_id.to_bytes(n, "little"), "big")
    return value, "%0*X" % (2 * n, value)


def parse_lrrp_request(text, legacy=None):
    """The first LRRP request printed in text (either form) -> dict, or None.

    {"packet_type", "form" ('legacy' | 'current'), "request_id" (int, big-endian
     as transmitted), "request_id_hex", "legacy_id" (the decimal the legacy form
     printed), "periodic", "interval_secs", "condition", "distance_m",
     "params" ({0x42: 3600, 0x44: 100}), "legacy_tokens", "requested",
     "unrecognized", "other"}
    A request showing neither form's words (digits-only id, plain token list)
    is read as the current form unless `legacy` says otherwise.
    """
    run = find_lrrp_text(text)
    if run is None:
        return None
    m = _LRRP_TYPE_RE.match(run)
    r = {"packet_type": m.group("type"), "form": "current", "request_id": None,
         "request_id_hex": None, "legacy_id": None, "periodic": False,
         "interval_secs": None, "condition": None, "distance_m": None,
         "params": {}, "legacy_tokens": [], "requested": [], "unrecognized": [],
         "other": []}
    ids = []
    for t in _LRRP_TOKEN_RE.finditer(run[m.end():]):
        if t.group("id") is not None:
            ids.append(t.group("id"))
        elif t.group("requested") is not None:
            body = t.group("requested")
            um = _LRRP_UNRECOGNIZED_RE.search(body)
            if um:
                r["unrecognized"].extend(h.strip() for h in um.group("ids").split(",") if h.strip())
                body = body[:um.start()] + body[um.end():]
            r["requested"].extend(n.strip() for n in body.split(",") if n.strip())
        elif t.group("periodic") is not None:
            r["periodic"] = True
        elif t.group("interval") is not None:
            r["interval_secs"] = int(t.group("interval"))
        elif t.group("condition") is not None:
            r["condition"] = t.group("condition")
        elif t.group("distance") is not None:
            r["distance_m"] = int(t.group("distance"))
        elif t.group("param_id") is not None:
            r["params"][int(t.group("param_id"), 16)] = int(t.group("param_value"))
        elif t.group("legacy") is not None:
            r["legacy_tokens"].append(t.group("legacy"))
        else:
            r["other"].append(t.group("other"))

    # Words only the current decoder prints decide first, then words only the
    # legacy decoder prints (it also dumped a corrupted identity token in hex, so
    # letters in the id prove nothing); a request with neither is read as current.
    current_words = (r["periodic"] or r["interval_secs"] is not None or r["condition"] is not None
                     or r["distance_m"] is not None or bool(r["params"])
                     or any(n in _LRRP_CURRENT_NAMES for n in r["requested"]))
    legacy_words = bool(r["legacy_tokens"]) or any(n in _LRRP_LEGACY_NAMES for n in r["requested"])
    if legacy is None:
        legacy = legacy_words and not current_words
    r["form"] = "legacy" if legacy else "current"

    if ids:
        first, rest = ids[0], ids[1:]
        if legacy:
            if first.isdigit():
                r["legacy_id"] = int(first)
                r["request_id"], r["request_id_hex"] = legacy_lrrp_id(r["legacy_id"])
            else:
                # 'ID:2200E2FF0252': the legacy build dumped the raw token of a
                # corrupted packet; there is no identifier to recover.
                rest.insert(0, first)
        else:
            r["request_id"] = int(first, 16)
            r["request_id_hex"] = first.upper()
        r["other"].extend("ID:" + i for i in rest)
    return r


def parse_freq_hz(x):
    """MHz string -> Hz int. SDRTrunk writes 0.000000 until the traffic channel
    is assigned; report that as None so a later row can fill it in."""
    try:
        if x in (None, "", " "):
            return None
        hz = int(round(float(x) * 1_000_000))
        return hz or None
    except (TypeError, ValueError):
        return None


# ---- event classification ----------------------------------------------------
# EVENT values seen from a P25 Phase 1 control channel (SDRTrunk DecodeEventType
# labels): Group Call, Encrypted Group Call, Patch Call, Encrypted Patch Call,
# Call, Encrypted Call, Unit Call, Encrypted Unit Call, Telephone Interconnect,
# Data Call, Register, Deregister, Response, Query, Command, Page, EMERGENCY,
# plus packet/LRRP/ARS types on traffic channels.

_UNIT_TARGET_WORDS = ("Unit", "Telephone", "Data Call", "Individual")


def is_group_call(event_type):
    """True for voice calls addressed to a talkgroup (incl. encrypted/patch)."""
    et = event_type or ""
    if "Call" not in et:
        return False
    return not any(w in et for w in _UNIT_TARGET_WORDS)


def classify(row):
    """One CSV row (dict keyed by HEADER) -> normalized event dict.

    Keys: ts, duration_ms, protocol, event_type, from_rid, from_alias, to_tgid,
    to_rid, to_alias, patch_members, channel, frequency, timeslot, details,
    event_id, encrypted (0/1), deny (bool), emergency (bool), lrrp (the parsed
    LRRP request for a Motorola LRRP event, see parse_lrrp_request, else None).
    Reserved FNE/broadcast addresses are never reported as radios."""
    event_type = (row.get("EVENT") or "").strip()
    protocol = (row.get("PROTOCOL") or "").strip() or "APCO-25"
    details = row.get("DETAILS") or ""
    details_u = details.upper()
    lrrp = parse_lrrp_request(details) if (protocol == "LRRP" or "LRRP " in details) else None

    from_id, from_alias, _ = parse_actor(row.get("FROM"))
    to_id, to_alias, members = parse_actor(row.get("TO"))

    from_rid = from_id if from_id is not None and from_id not in FNE_IDS else None
    to_tgid = to_rid = None

    if is_group_call(event_type) or event_type.upper() == "EMERGENCY":
        # Group Call / Encrypted Group Call / Patch Call / Call / EMERGENCY:
        # TO is "[alias] (tgid)" or a patch supergroup "(P:tgid [members])".
        to_tgid = to_id
    elif "Call" in event_type:
        # Unit Call, Telephone Interconnect, Data Call (SNDCP grant to a unit)
        to_rid = to_id
    elif event_type in ("Register", "Deregister", "Response"):
        # FROM is empty (or the FNE); the subscriber is in TO. Promote it so
        # analytics see who registered / affiliated.
        if from_rid is None and to_id is not None and to_id not in FNE_IDS:
            from_rid = to_id
        if event_type == "Response":
            m = re.search(r"AFFILIATION GROUP:\s*(\d+)", details)
            if m:
                to_tgid = int(m.group(1))
        elif event_type == "Register":
            m = re.search(r"\bGROUP:\s*(\d+)", details)
            if m:
                to_tgid = int(m.group(1))
    elif event_type in ("Query", "Command"):
        # FNE -> radio: the radio being queried/commanded is the target.
        to_rid = to_id if to_id not in FNE_IDS else None
    elif event_type == "Page":
        # Radio asks for a data page; TO is the 65535 placeholder.
        to_rid = None if to_id in BROADCAST_IDS else to_id
    else:
        # Packet / LRRP / ARS / Request on traffic channels: TO is the unit
        # (FROM is an IP address, which parse_actor leaves as the alias).
        to_rid = to_id if to_id not in FNE_IDS | BROADCAST_IDS else None

    if to_tgid is not None and to_tgid in BROADCAST_IDS:
        to_tgid = None

    encrypted = 1 if (event_type.startswith("Encrypted")
                      or "ENCRYPTED" in details_u
                      or "ENCRYPTION:" in details_u) else 0

    # "DENY: GROUP VOICE SERVICE REQUEST ...", "DENIED LOCATION REGISTRATION",
    # "REFUSED UNIT REGISTRATION". (SDRTrunk's own "CHANNEL START REJECTED
    # TUNER UNAVAILABLE" is a receiver limitation, not a system denial.)
    deny = ("DENY" in event_type.upper() or "DENY" in details_u
            or "REFUSED" in details_u)
    # An LRRP request's "TRIGGER CONDITION:EMERGENCY" is the condition under
    # which the radio should report its position, not an emergency.
    emergency = (event_type.upper() == "EMERGENCY"
                 or "EMERGENCY" in _LRRP_CONDITION_RE.sub("", details_u))

    return {
        "ts": parse_timestamp(row.get("TIMESTAMP", "")),
        "duration_ms": parse_int(row.get("DURATION_MS")),
        "protocol": protocol,
        "event_type": event_type,
        "from_rid": from_rid,
        "from_alias": from_alias if from_rid is not None else None,
        "to_tgid": to_tgid,
        "to_rid": to_rid,
        "to_alias": to_alias,
        "patch_members": members,
        "channel": (row.get("CHANNEL_NUMBER") or "").strip() or None,
        "frequency": parse_freq_hz(row.get("FREQUENCY")),
        "timeslot": parse_int(row.get("TIMESLOT")),
        "details": details,
        "event_id": (row.get("EVENT_ID") or "").strip() or None,
        "encrypted": encrypted,
        "deny": deny,
        "emergency": emergency,
        "lrrp": lrrp,
    }


# ---- playlist (system / site per channel) ------------------------------------
def load_channel_map(playlist_path):
    """SDRTrunk playlist XML -> {channel_name: {"system", "site", "enabled",
    "alias_list"}}. An enabled channel wins over disabled ones with the same
    name (SDRTrunk only logs for running channels). {} if unreadable."""
    try:
        root = ET.parse(str(playlist_path)).getroot()
    except (OSError, ET.ParseError):
        return {}
    out = {}
    for ch in root.findall("channel"):
        name = (ch.get("name") or "").strip()
        if not name:
            continue
        enabled = (ch.get("enabled") or "").lower() == "true"
        al = ch.find("alias_list_name")
        entry = {
            "system": (ch.get("system") or "").strip() or None,
            "site": (ch.get("site") or "").strip() or None,
            "enabled": enabled,
            "alias_list": (al.text or "").strip() if al is not None and al.text else None,
        }
        prev = out.get(name)
        if prev is None or (enabled and not prev["enabled"]):
            out[name] = entry
    return out


def channel_identity(channel_map, channel_name):
    """(system, site) for a log's channel name ("T-Control" -> "Control")."""
    if not channel_map or not channel_name:
        return None, None
    name = channel_name[2:] if channel_name.startswith("T-") else channel_name
    entry = channel_map.get(name) or channel_map.get(channel_name)
    if not entry:
        return None, None
    return entry["system"], entry["site"]


def alias_list_systems(playlist_path):
    """{alias_list_name: system} from the playlist's channels, enabled channels
    first. Alias lists no channel references are left out."""
    try:
        root = ET.parse(str(playlist_path)).getroot()
    except (OSError, ET.ParseError):
        return {}
    out, enabled_lists = {}, set()
    for ch in root.findall("channel"):
        al = ch.find("alias_list_name")
        list_name = (al.text or "").strip() if al is not None and al.text else ""
        system = (ch.get("system") or "").strip()
        if not list_name or not system:
            continue
        enabled = (ch.get("enabled") or "").lower() == "true"
        if enabled:
            out[list_name] = system
            enabled_lists.add(list_name)
        elif list_name not in enabled_lists:
            out.setdefault(list_name, system)
    return out
