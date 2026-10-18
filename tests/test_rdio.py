"""
Tests for the RDIO Scanner upload endpoint (ingest/rdio.py): the multipart
POST SDRTrunk sends per call, and the talkerAlias field in particular.

The upload tests need Flask, so they run inside the container (the image has
everything; mount the checkout over /app to test uncommitted edits):

    docker run --rm --entrypoint python -v "$PWD":/app trunk-tap-trunk-tap \
        -m unittest discover -s tests -t .

On a bare host without Flask they are skipped; the migration test still runs.
"""
import io
import itertools
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Scratch data dir, set BEFORE importing the app: db.DB_PATH and
# rdio.AUDIO_DIR are derived from SDRTD_DATA_DIR at import time.
_TMP = tempfile.mkdtemp(prefix="trunk-tap-test-")
os.environ["SDRTD_DATA_DIR"] = _TMP
os.environ["SDRTD_EXPORT_DIR"] = os.path.join(_TMP, "export")
os.environ["SDRTD_RDIO_KEY"] = ""

import db as D  # noqa: E402

try:
    from app import app  # noqa: E402
except ImportError:  # flask / flask-socketio / watchdog not installed
    app = None

# The endpoint dedupes on (system, dateTime, talkgroup, source), so every
# upload gets its own timestamp.
_TS = itertools.count(1792286144)


def _upload(client, **fields):
    """POST one call the way SDRTrunk's RdioScannerBroadcaster does. A field
    set to None is left out of the form."""
    form = {
        "key": "", "system": "44", "systemLabel": "Test System",
        "dateTime": str(next(_TS)), "talkgroup": "941",
        "talkgroupLabel": "TEST DISP", "talkgroupGroup": "Test Group",
        "source": "4165226", "frequency": "856362500", "patches": "[]",
        "talkerAlias": "",
    }
    form.update(fields)
    form = {k: v for k, v in form.items() if v is not None}
    form["audio"] = (io.BytesIO(b"\xff\xfb\x90\x00" + b"\x00" * 64),
                     "20261017_201546.121.mp3", "audio/mpeg")
    return client.post("/api/call-upload", data=form,
                       content_type="multipart/form-data")


@unittest.skipUnless(app, "flask not installed; run inside the container")
class UploadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        D.init_db()
        cls.client = app.test_client()

    def _last_call(self):
        return D.db().execute("SELECT * FROM calls ORDER BY id DESC LIMIT 1").fetchone()

    def test_talker_alias_stored(self):
        r = _upload(self.client, talkerAlias="BC911 4165226 ")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_data(as_text=True), "Call imported successfully.")
        row = self._last_call()
        self.assertEqual(row["source_rid"], 4165226)
        self.assertEqual(row["talker_alias"], "BC911 4165226")  # trimmed
        # the field as sent is still in the forensics blob
        self.assertEqual(json.loads(row["raw_json"])["talkerAlias"], "BC911 4165226 ")

    def test_ta_prefix_dropped(self):
        _upload(self.client, talkerAlias="TA-58SO Pressley")
        self.assertEqual(self._last_call()["talker_alias"], "58SO Pressley")

    def test_empty_alias_is_null(self):
        _upload(self.client, talkerAlias="")
        self.assertIsNone(self._last_call()["talker_alias"])
        _upload(self.client, talkerAlias="  ")
        self.assertIsNone(self._last_call()["talker_alias"])

    def test_missing_field_is_null(self):
        # builds of SDRTrunk that predate the field don't send it at all
        _upload(self.client, talkerAlias=None)
        self.assertIsNone(self._last_call()["talker_alias"])

    def test_call_apis_return_alias_next_to_source(self):
        _upload(self.client, source="4165225", talkerAlias="BC911 4165225 ")
        row = self.client.get("/api/calls?limit=1").get_json()[0]
        self.assertEqual(row["source_rid"], 4165225)
        self.assertEqual(row["talker_alias"], "BC911 4165225")
        row = self.client.get("/api/rid/4165225").get_json()["calls"][0]
        self.assertEqual(row["talker_alias"], "BC911 4165225")
        row = self.client.get("/api/tg/941").get_json()["calls"][0]
        self.assertEqual(row["source_rid"], 4165225)
        self.assertEqual(row["talker_alias"], "BC911 4165225")


class MigrationTests(unittest.TestCase):
    def test_adds_talker_alias_to_old_database(self):
        # a calls table from before the column existed
        conn = sqlite3.connect(os.path.join(_TMP, "old.db"))
        conn.execute("CREATE TABLE calls (id INTEGER PRIMARY KEY, ts REAL, source_rid INTEGER)")
        D._migrate(conn)
        D._migrate(conn)  # idempotent
        cols = [r[1] for r in conn.execute("PRAGMA table_info(calls)")]
        self.assertEqual(cols, ["id", "ts", "source_rid", "talker_alias"])
        conn.close()


if __name__ == "__main__":
    unittest.main()
