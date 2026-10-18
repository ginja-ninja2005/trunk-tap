"""
Unit tests for ingest/eventlog.py (stdlib only; runs on the host's Python 3.9
or inside the container):

    python3 -m unittest discover -s tests -t .

The fixture tests/fixtures/control_excerpt.csv holds real rows from an
SDRTrunk P25 Phase 1 control channel plus a few traffic-channel rows, one or
more per EVENT type and DETAILS shape. The last test runs over the real
Control logs when they are present (SDRTRUNK_EVENT_LOGS can point at a folder;
default ~/SDRTrunk/event_logs and ~/SDRTrunk/event_logs_archive).
"""
import collections
import csv
import glob
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ingest import eventlog as E  # noqa: E402

FIXTURE = ROOT / "tests" / "fixtures" / "control_excerpt.csv"


def _rows(path=FIXTURE):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


class FilenameTests(unittest.TestCase):
    def test_control(self):
        p = E.parse_filename("20261017_163143.690_0_Hz_Control_call_events.log")
        self.assertEqual(p, {"start": "20261017_163143.690", "freq_hz": 0,
                             "channel": "Control", "parent_channel": "Control",
                             "traffic": False})

    def test_traffic(self):
        p = E.parse_filename("/x/y/20261017_162203.545_854512500_Hz_T-Control_call_events.log")
        self.assertEqual(p["channel"], "T-Control")
        self.assertEqual(p["parent_channel"], "Control")
        self.assertTrue(p["traffic"])
        self.assertEqual(p["freq_hz"], 854512500)

    def test_other_files(self):
        self.assertIsNone(E.parse_filename("20261017_163143.691_0_Hz_Control_decoded_messages.log"))
        self.assertIsNone(E.parse_filename("notes.txt"))

    def test_legacy_label(self):
        self.assertEqual(E.system_label_from_filename(
            "20260310_133013.747_0_Hz_County-P25-East_call_events.log"), "County P25 East")
        self.assertEqual(E.system_label_from_filename(
            "20261017_162203.545_854512500_Hz_T-Control_call_events.log"), "T Control")


class TimestampTests(unittest.TestCase):
    def setUp(self):
        self._env = {k: os.environ.get(k) for k in ("SDRTRUNK_TZ", "TZ")}

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_zone_from_sdrtrunk_tz(self):
        os.environ["SDRTRUNK_TZ"] = "America/Chicago"
        os.environ["TZ"] = "UTC"
        # 16:31:44 CDT == 21:31:44 UTC
        self.assertEqual(E.parse_timestamp("2026:10:17:16:31:44"), 1792272704.0)

    def test_zone_from_tz(self):
        os.environ.pop("SDRTRUNK_TZ", None)
        os.environ["TZ"] = "America/Chicago"
        self.assertEqual(E.parse_timestamp("2026:10:17:16:56:54"), 1792274214.0)

    def test_utc_differs_by_five_hours(self):
        os.environ["SDRTRUNK_TZ"] = "UTC"
        self.assertEqual(E.parse_timestamp("2026:10:17:16:31:44"), 1792272704.0 - 5 * 3600)

    def test_garbage(self):
        self.assertEqual(E.parse_timestamp("nope", default=7.0), 7.0)
        self.assertEqual(E.parse_timestamp("", default=7.0), 7.0)


class ActorTests(unittest.TestCase):
    def test_shapes(self):
        self.assertEqual(E.parse_actor("[Brmnghm Police S] (3153)"), (3153, "Brmnghm Police S", None))
        self.assertEqual(E.parse_actor(" (2291)"), (2291, None, None))
        self.assertEqual(E.parse_actor("45021"), (45021, None, None))
        self.assertEqual(E.parse_actor(""), (None, None, None))
        self.assertEqual(E.parse_actor(None), (None, None, None))
        self.assertEqual(E.parse_actor("ISSI 1.2.3"), (None, "ISSI 1.2.3", None))
        self.assertEqual(E.parse_actor("10.51.4.116"), (None, "10.51.4.116", None))

    def test_patch(self):
        got = E.parse_actor("[Mt Olive FD Disp, Cane Creek Fire] (P:1785 [2541, 1679, 1631, 2185])")
        self.assertEqual(got, (1785, "Mt Olive FD Disp, Cane Creek Fire", [2541, 1679, 1631, 2185]))
        self.assertEqual(E.parse_actor("(P:1785 [])"), (1785, None, []))

    def test_freq(self):
        self.assertEqual(E.parse_freq_hz("854.937500"), 854937500)
        self.assertIsNone(E.parse_freq_hz("0.000000"))
        self.assertIsNone(E.parse_freq_hz(""))


def _row(event, frm="", to="", details="", dur="", chan="0-629", freq="854.937500", evid="1"):
    return {"TIMESTAMP": "2026:10:17:16:31:44", "DURATION_MS": dur, "PROTOCOL": "APCO-25",
            "EVENT": event, "FROM": frm, "TO": to, "CHANNEL_NUMBER": chan,
            "FREQUENCY": freq, "TIMESLOT": "", "DETAILS": details, "EVENT_ID": evid}


class ClassifyTests(unittest.TestCase):
    def test_group_call_types_yield_talkgroup(self):
        for et in ("Group Call", "Encrypted Group Call", "Call", "Encrypted Call"):
            e = E.classify(_row(et, "4210514", "[X] (2291)", "PHASE 1 CHANNEL GRANT "))
            self.assertEqual(e["to_tgid"], 2291, et)
            self.assertIsNone(e["to_rid"], et)
            self.assertEqual(e["from_rid"], 4210514, et)
            self.assertEqual(e["to_alias"], "X")
            self.assertEqual(e["encrypted"], 1 if et.startswith("Encrypted") else 0, et)
        for et in ("Patch Call", "Encrypted Patch Call"):
            e = E.classify(_row(et, "4045224", "[A, B] (P:1785 [2541, 1679])", "PHASE 1 CHANNEL GRANT PRI0 CIRCUIT"))
            self.assertEqual(e["to_tgid"], 1785, et)
            self.assertEqual(e["patch_members"], [2541, 1679])
            self.assertEqual(e["encrypted"], 1 if et.startswith("Encrypted") else 0, et)

    def test_encryption_from_details(self):
        e = E.classify(_row("Group Call", "", " (2291)",
                            "PHASE 1 CALL PRI0 ENCRYPTED CIRCUIT ENCRYPTION:MOTOROLA ADP 40-BIT RC4 KEY:1"))
        self.assertEqual(e["encrypted"], 1)
        e = E.classify(_row("Group Call", "", " (2291)", "PHASE 1 CHANNEL GRANT  ENCRYPTION:AES-256 KEY:2"))
        self.assertEqual(e["encrypted"], 1)
        e = E.classify(_row("Group Call", "", " (2291)", "PHASE 1 CHANNEL GRANT PRI4 CIRCUIT"))
        self.assertEqual(e["encrypted"], 0)

    def test_unit_targets(self):
        e = E.classify(_row("Data Call", "", " (4017073)", "PHASE 1 DATA CHANNEL GRANT "))
        self.assertEqual((e["to_tgid"], e["to_rid"]), (None, 4017073))
        e = E.classify(_row("Unit Call", "45021", " (4017073)", ""))
        self.assertEqual((e["from_rid"], e["to_tgid"], e["to_rid"]), (45021, None, 4017073))

    def test_register_deregister_response(self):
        e = E.classify(_row("Register", "", " (4043469)", "ACCEPTED UNIT REGISTRATION - UNIT ID:4043469"))
        self.assertEqual((e["from_rid"], e["to_tgid"], e["deny"]), (4043469, None, False))
        e = E.classify(_row("Register", "", " (4043469)", "ACCEPTED LOCATION REGISTRATION - GROUP:2143"))
        self.assertEqual((e["from_rid"], e["to_tgid"]), (4043469, 2143))
        e = E.classify(_row("Register", "", " (4006732)", "REFUSED UNIT REGISTRATION - UNIT ID:4006732"))
        self.assertTrue(e["deny"])
        e = E.classify(_row("Deregister", "", " (4046286)", "ACKNOWLEDGE UNIT DE-REGISTRATION"))
        self.assertEqual((e["from_rid"], e["to_rid"]), (4046286, None))
        e = E.classify(_row("Response", "", " (4006594)",
                            "ACCEPTED AFFILIATION GROUP: 3155 (LOCAL) ANNOUNCEMENT GROUP:3285"))
        self.assertEqual((e["from_rid"], e["to_tgid"]), (4006594, 3155))
        e = E.classify(_row("Response", "16777213", " (4210588)", "ACKNOWLEDGE GROUP AFFILIATION QUERY RESPONSE"))
        self.assertEqual((e["from_rid"], e["to_rid"]), (4210588, None))  # FNE id never a radio
        e = E.classify(_row("Response", "16777213", " (4210588)",
                            "DENY: GROUP VOICE SERVICE REQUEST REASON: PTT_BONK - INFO: 0C0"))
        self.assertTrue(e["deny"])

    def test_query_command_page(self):
        e = E.classify(_row("Query", "16777213", " (4210588)", "GROUP AFFILIATION"))
        self.assertEqual((e["from_rid"], e["to_rid"], e["to_tgid"]), (None, 4210588, None))
        e = E.classify(_row("Command", "16777214", " (4210398)", "UNIT REGISTRATION"))
        self.assertEqual((e["from_rid"], e["to_rid"]), (None, 4210398))
        e = E.classify(_row("Page", "4006517", " (65535)", "SNDCP DATA PAGE REQUEST"))
        self.assertEqual((e["from_rid"], e["to_rid"], e["to_tgid"]), (4006517, None, None))
        e = E.classify(_row("Page", "45803", " (4210919)", "CALL ALERT"))
        self.assertEqual((e["from_rid"], e["to_rid"]), (45803, 4210919))

    def test_emergency(self):
        e = E.classify(_row("EMERGENCY", "4007399", "[Brmnghm Police W] (3155)", "RADIO EMERGENCY ALARM ACTIVATION"))
        self.assertEqual((e["from_rid"], e["to_tgid"], e["emergency"]), (4007399, 3155, True))

    def test_traffic_channel_packets(self):
        e = E.classify(_row("Motorola LRRP", "10.51.4.116", " (4006361)", "LRRP ...", chan="0-857"))
        self.assertEqual((e["from_rid"], e["to_rid"]), (None, 4006361))
        e = E.classify(_row("Data Packet", "", "", "NAC:1120 PDU ..."))
        self.assertEqual((e["from_rid"], e["to_rid"], e["to_tgid"]), (None, None, None))

    def test_channel_number_is_not_a_site(self):
        e = E.classify(_row("Group Call", "", " (2291)", "PHASE 1 CHANNEL GRANT ", chan="0-629"))
        self.assertEqual(e["channel"], "0-629")
        self.assertNotIn("site", e)

    def test_zero_frequency_is_none(self):
        e = E.classify(_row("Group Call", "", " (2291)", "PHASE 1 CHANNEL GRANT ", freq="0.000000"))
        self.assertIsNone(e["frequency"])


class FixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows = _rows()
        cls.events = [E.classify(r) for r in cls.rows]

    def test_every_call_row_has_a_talkgroup(self):
        for r, e in zip(self.rows, self.events):
            if E.is_group_call(r["EVENT"]) and r["TO"].strip():
                self.assertIsNotNone(e["to_tgid"], r)

    def test_encrypted_rows(self):
        for r, e in zip(self.rows, self.events):
            if r["EVENT"].startswith("Encrypted"):
                self.assertEqual(e["encrypted"], 1, r)
            if "ENCRYPT" in r["DETAILS"].upper():
                self.assertEqual(e["encrypted"], 1, r)
            if r["EVENT"] == "Group Call" and "ENCRYPT" not in r["DETAILS"].upper():
                self.assertEqual(e["encrypted"], 0, r)

    def test_fne_ids_never_radios(self):
        for e in self.events:
            self.assertNotIn(e["from_rid"], E.FNE_IDS)
            self.assertNotIn(e["to_rid"], E.FNE_IDS | E.BROADCAST_IDS)

    def test_update_sequence_merges(self):
        """Rows for one EVENT_ID: duration grows and FROM fills in later."""
        by_id = collections.defaultdict(list)
        for e in self.events:
            by_id[e["event_id"]].append(e)
        multi = [v for v in by_id.values() if len(v) >= 3 and E.is_group_call(v[0]["event_type"])]
        self.assertTrue(multi, "fixture should hold a full update sequence")
        for seq in multi:
            durs = [e["duration_ms"] for e in seq if e["duration_ms"] is not None]
            self.assertEqual(durs, sorted(durs))
            # the very first grant row can have an empty TO; after that the
            # talkgroup never changes for one EVENT_ID
            self.assertEqual(len({e["to_tgid"] for e in seq if e["to_tgid"] is not None}), 1)

    def test_types_covered(self):
        types = {r["EVENT"] for r in self.rows}
        for t in ("Group Call", "Encrypted Group Call", "Patch Call", "Data Call", "Register",
                  "Deregister", "Response", "Query", "Command", "Page", "EMERGENCY"):
            self.assertIn(t, types)


class PlaylistTests(unittest.TestCase):
    PLAYLIST = """<?xml version="1.0"?>
<playlist>
  <alias list="AIRS_NEW_NEW" group="G" name="Irondale Police"><id type="talkgroup" protocol="APCO25" value="2089"/></alias>
  <channel system="Alabama Interoperable Radio System (AIRS)" enabled="false" site="Jefferson" name="Control">
    <alias_list_name>Irondale</alias_list_name></channel>
  <channel system="Alabama Interoperable Radio System (AIRS)" enabled="true" site="Jefferson County Simulcast" name="Control">
    <alias_list_name>AIRS_NEW_NEW</alias_list_name></channel>
  <channel system="Data" enabled="false" site="Jefferson" name="Control">
    <alias_list_name>AIRS_NEW_NEW</alias_list_name></channel>
  <channel system="Other" enabled="false" site="S2" name="Second"><alias_list_name>L2</alias_list_name></channel>
</playlist>"""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.NamedTemporaryFile("w", suffix=".xml", delete=False)
        self.tmp.write(self.PLAYLIST)
        self.tmp.close()

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_enabled_channel_wins(self):
        cm = E.load_channel_map(self.tmp.name)
        self.assertEqual(cm["Control"]["system"], "Alabama Interoperable Radio System (AIRS)")
        self.assertEqual(cm["Control"]["site"], "Jefferson County Simulcast")
        self.assertTrue(cm["Control"]["enabled"])
        self.assertEqual(cm["Second"]["system"], "Other")

    def test_identity_for_traffic_channel(self):
        cm = E.load_channel_map(self.tmp.name)
        self.assertEqual(E.channel_identity(cm, "T-Control"),
                         ("Alabama Interoperable Radio System (AIRS)", "Jefferson County Simulcast"))
        self.assertEqual(E.channel_identity(cm, "Nope"), (None, None))
        self.assertEqual(E.channel_identity({}, "Control"), (None, None))

    def test_alias_lists(self):
        self.assertEqual(E.alias_list_systems(self.tmp.name),
                         {"AIRS_NEW_NEW": "Alabama Interoperable Radio System (AIRS)",
                          "Irondale": "Alabama Interoperable Radio System (AIRS)",
                          "L2": "Other"})

    def test_missing_playlist(self):
        self.assertEqual(E.load_channel_map("/nonexistent/default.xml"), {})
        self.assertEqual(E.alias_list_systems("/nonexistent/default.xml"), {})


# The two LRRP request profiles on this system as the patched SDRTrunk (lrrp-request-varint)
# prints them; the strings are the ones SDRTrunk's own LRRPPacketTest asserts.
LRRP_PERIODIC = ("LRRP TRIGGERED LOCATION START REQUEST ID:FFFFEE PERIODIC INTERVAL:600 SECS PARAM-42:3600 "
                 "PARAM-44:100 REQUESTED TOKENS [TIME,HORIZONTAL SPEED,HORIZONTAL DIRECTION]")
LRRP_EMERGENCY = ("LRRP TRIGGERED LOCATION START REQUEST ID:FFFF02 PERIODIC TRIGGER CONDITION:EMERGENCY "
                  "PARAM-42:3600 PARAM-44:100 REQUESTED TOKENS [TIME,HORIZONTAL SPEED,HORIZONTAL DIRECTION]")
# The same two as the August 2026 nightly printed them (real lines).
LRRP_LEGACY_PERIODIC = ("LRRP TRIGGERED LOCATION START REQUEST ID:15663103 TRIGGER ON GPIO TRIGGER EVERY:132 SECS "
                        "REQUESTED TOKENS [TIME,REQUEST-64,REQUEST-62,HORIZONTAL DIRECTION,TIMESTAMP,UNRECOGNIZED(10,44,58,9C)]")
LRRP_LEGACY_EMERGENCY = ("LRRP TRIGGERED LOCATION START REQUEST ID:196607 TRIGGER ON GPIO TRIGGER DISTANCE:2 "
                         "REQUESTED TOKENS [TIME,REQUEST-64,REQUEST-62,HORIZONTAL DIRECTION,TIMESTAMP,UNRECOGNIZED(10,44,9C)]")


def _lrrp_details(request, radio_ip="10.71.195.19"):
    """DETAILS as SDRTrunk writes it for a Motorola LRRP event: the request, then the IP packet text."""
    return "%s IP FROM:10.51.4.116 TO:%s UDP PORT FROM:4001 TO:4001 %s" % (request, radio_ip, request)


def _lrrp_row(request, to=" (4006363)"):
    row = _row("Motorola LRRP", "10.51.4.116", to, _lrrp_details(request), chan="0-857", freq="856.362500")
    row["PROTOCOL"] = "LRRP"
    return row


class LRRPTests(unittest.TestCase):
    def test_current_form(self):
        r = E.parse_lrrp_request(LRRP_PERIODIC)
        self.assertEqual((r["packet_type"], r["form"]), ("TRIGGERED LOCATION START REQUEST", "current"))
        self.assertEqual((r["request_id"], r["request_id_hex"], r["legacy_id"]), (0xFFFFEE, "FFFFEE", None))
        self.assertEqual((r["periodic"], r["interval_secs"], r["condition"], r["distance_m"]), (True, 600, None, None))
        self.assertEqual(r["params"], {0x42: 3600, 0x44: 100})
        self.assertEqual(r["requested"], ["TIME", "HORIZONTAL SPEED", "HORIZONTAL DIRECTION"])
        self.assertEqual((r["unrecognized"], r["legacy_tokens"], r["other"]), ([], [], []))
        r = E.parse_lrrp_request(LRRP_EMERGENCY)
        self.assertEqual((r["request_id_hex"], r["periodic"], r["interval_secs"], r["condition"]),
                         ("FFFF02", True, None, "EMERGENCY"))
        r = E.parse_lrrp_request("LRRP TYPE:UNKNOWN [163] ID:FFFFEE PERIODIC INTERVAL:600 SECS PARAM-42:3600 "
                                 "PARAM-44:100 REQUESTED TOKENS [TIME,HORIZONTAL SPEED,HORIZONTAL DIRECTION]")
        self.assertEqual((r["packet_type"], r["request_id_hex"], r["interval_secs"]), ("TYPE:UNKNOWN [163]", "FFFFEE", 600))
        r = E.parse_lrrp_request("LRRP TRIGGERED LOCATION START REQUEST ID:0A TRIGGER DISTANCE:150 METERS "
                                 "TRIGGER CONDITION:PTT EMERGENCY REQUEST-73:4 REQUESTED TOKENS [TIME]")
        self.assertEqual((r["request_id"], r["distance_m"], r["condition"], r["other"]), (10, 150, "PTT EMERGENCY", ["REQUEST-73:4"]))
        self.assertEqual(E.parse_lrrp_request("LRRP PROTOCOL VERSION REQUEST")["request_id"], None)
        self.assertIsNone(E.parse_lrrp_request("ARS REGISTRATION SUCCESS REFRESH IN:240mins"))
        self.assertIsNone(E.parse_lrrp_request(""))

    def test_legacy_form(self):
        r = E.parse_lrrp_request(LRRP_LEGACY_PERIODIC)
        self.assertEqual((r["form"], r["legacy_id"], r["request_id"], r["request_id_hex"]),
                         ("legacy", 15663103, 0xFFFFEE, "FFFFEE"))
        self.assertEqual(r["legacy_tokens"], ["TRIGGER ON GPIO", "TRIGGER EVERY:132 SECS"])
        self.assertEqual((r["periodic"], r["interval_secs"], r["params"]), (False, None, {}))
        self.assertEqual(r["requested"], ["TIME", "REQUEST-64", "REQUEST-62", "HORIZONTAL DIRECTION", "TIMESTAMP"])
        self.assertEqual(r["unrecognized"], ["10", "44", "58", "9C"])
        r = E.parse_lrrp_request(LRRP_LEGACY_EMERGENCY)
        self.assertEqual((r["request_id_hex"], r["legacy_tokens"], r["distance_m"]),
                         ("FFFF02", ["TRIGGER ON GPIO", "TRIGGER DISTANCE:2"], None))
        # Corrupted packets: a raw token dump instead of an id, or a second id
        r = E.parse_lrrp_request("LRRP TRIGGERED LOCATION START REQUEST ID:2200E2FF0252 TRIGGER ON GPIO "
                                 "REQUESTED TOKENS [TIME,REQUEST-64,UNKNOWN 23,UNRECOGNIZED(02,02,03,2E,44,60,9C,AE,E2,FF)]")
        self.assertEqual((r["form"], r["request_id_hex"], r["other"]), ("legacy", None, ["ID:2200E2FF0252"]))
        self.assertEqual(r["requested"], ["TIME", "REQUEST-64", "UNKNOWN 23"])
        r = E.parse_lrrp_request("LRRP TRIGGERED LOCATION START REQUEST ID:196607 ID:227200000000 TRIGGER ON GPIO "
                                 "REQUESTED TOKENS [TIME,REQUEST-64,UNRECOGNIZED(10,17,44,74,9C,F6)]")
        self.assertEqual((r["request_id_hex"], r["other"]), ("FFFF02", ["ID:227200000000"]))

    def test_same_id_in_both_forms(self):
        self.assertEqual(E.parse_lrrp_request(LRRP_LEGACY_PERIODIC)["request_id_hex"],
                         E.parse_lrrp_request(LRRP_PERIODIC)["request_id_hex"])
        self.assertEqual(E.parse_lrrp_request(LRRP_LEGACY_EMERGENCY)["request_id_hex"],
                         E.parse_lrrp_request(LRRP_EMERGENCY)["request_id_hex"])
        self.assertEqual(E.legacy_lrrp_id(15663103), (0xFFFFEE, "FFFFEE"))
        self.assertEqual(E.legacy_lrrp_id(196607), (0xFFFF02, "FFFF02"))
        self.assertEqual(E.legacy_lrrp_id(65503), (0xDFFF, "DFFF"))
        self.assertEqual(E.legacy_lrrp_id(0), (0, "00"))
        # Digits-only id without either form's words: current unless told otherwise
        text = "LRRP TRIGGERED LOCATION START REQUEST ID:196607 REQUESTED TOKENS [TIME]"
        self.assertEqual(E.parse_lrrp_request(text)["request_id_hex"], "196607")
        self.assertEqual(E.parse_lrrp_request(text, legacy=True)["request_id_hex"], "FFFF02")

    def test_details_column_is_read_once(self):
        details = _lrrp_details(LRRP_PERIODIC)
        self.assertEqual(E.find_lrrp_text(details), LRRP_PERIODIC)
        self.assertEqual(E.parse_lrrp_request(details)["other"], [])

    def test_classify_both_forms(self):
        for request, form, rid in ((LRRP_PERIODIC, "current", "FFFFEE"), (LRRP_EMERGENCY, "current", "FFFF02"),
                                   (LRRP_LEGACY_PERIODIC, "legacy", "FFFFEE"), (LRRP_LEGACY_EMERGENCY, "legacy", "FFFF02")):
            e = E.classify(_lrrp_row(request))
            self.assertEqual((e["protocol"], e["event_type"], e["from_rid"], e["to_rid"], e["to_tgid"]),
                             ("LRRP", "Motorola LRRP", None, 4006363, None), request)
            self.assertEqual(e["details"], _lrrp_details(request))        # kept verbatim, brackets and commas included
            self.assertEqual((e["encrypted"], e["deny"], e["emergency"]), (0, False, False), request)
            self.assertEqual((e["lrrp"]["form"], e["lrrp"]["request_id_hex"]), (form, rid), request)
        # Real legacy row from the fixture
        rows = [r for r in _rows() if r["EVENT"] == "Motorola LRRP" and "ID:196607 TRIGGER ON GPIO TRIGGER DISTANCE:2" in r["DETAILS"]]
        self.assertTrue(rows)
        e = E.classify(rows[0])
        self.assertEqual((e["to_rid"], e["lrrp"]["form"], e["lrrp"]["request_id_hex"]), (4006361, "legacy", "FFFF02"))

    def test_trigger_condition_is_not_an_emergency(self):
        e = E.classify(_lrrp_row(LRRP_EMERGENCY))
        self.assertFalse(e["emergency"])
        # The same request text inside a Data Packet event (PROTOCOL APCO-25)
        e = E.classify(_row("Data Packet", "", " (4006363)", "NAC:1120/x460 IPPKT LLID:4006363 NSAPI:1 " + _lrrp_details(LRRP_EMERGENCY)))
        self.assertEqual((e["emergency"], e["lrrp"]["request_id_hex"]), (False, "FFFF02"))
        # Real emergencies still count
        e = E.classify(_row("EMERGENCY", "4007399", "[Brmnghm Police W] (3155)", "RADIO EMERGENCY ALARM ACTIVATION"))
        self.assertTrue(e["emergency"])
        e = E.classify(_row("Group Call", "4007399", " (3155)", "PHASE 1 CHANNEL GRANT EMERGENCY"))
        self.assertTrue(e["emergency"])
        self.assertIsNone(e["lrrp"])


def _real_control_files():
    roots = [os.environ.get("SDRTRUNK_EVENT_LOGS")] if os.environ.get("SDRTRUNK_EVENT_LOGS") else []
    home = Path(os.environ.get("SDRTRUNK_HOME", Path.home() / "SDRTrunk"))
    roots += [home / "event_logs", home / "event_logs_archive"]
    files = []
    for r in roots:
        if r and Path(r).is_dir():
            files += glob.glob(str(Path(r) / "**" / "*_0_Hz_*_call_events.log"), recursive=True)
    return sorted(set(files))


class RealLogTests(unittest.TestCase):
    """Runs only where SDRTrunk's Control logs are available."""

    @classmethod
    def setUpClass(cls):
        cls.files = _real_control_files()
        if not cls.files:
            raise unittest.SkipTest("no SDRTrunk control-channel logs found")

    def test_counts(self):
        per_type = collections.Counter()
        with_tg = collections.Counter()
        enc = collections.Counter()
        for f in self.files:
            for r in _rows(f):
                e = E.classify(r)
                t = e["event_type"]
                per_type[t] += 1
                if e["to_tgid"] is not None:
                    with_tg[t] += 1
                if e["encrypted"]:
                    enc[t] += 1
        self.assertGreater(per_type["Group Call"], 0)
        for t in ("Group Call", "Encrypted Group Call", "Patch Call"):
            if per_type[t]:
                # the odd row has an empty TO (SDRTrunk logs the grant before it
                # knows the group); everything else must carry the talkgroup
                self.assertGreaterEqual(with_tg[t], 0.99 * per_type[t], t)
        self.assertEqual(enc["Encrypted Group Call"], per_type["Encrypted Group Call"])
        self.assertEqual(with_tg["Data Call"], 0)
        if len(self.files) >= 3 and per_type["Encrypted Group Call"]:
            # the three 2026-10-17 Control files hold ~20k Encrypted Group Call rows
            self.assertGreater(per_type["Encrypted Group Call"], 10000)


if __name__ == "__main__":
    unittest.main()
