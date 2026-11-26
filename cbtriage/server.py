#
# Copyright (c) 2026-Present Couchbase, Inc All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Local HTTP server (stdlib only) exposing the event store as a JSON API and
serving the single-file timeline UI. Binds to localhost; nothing is uploaded.
"""
import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import db
from . import leadership
from . import orchestration
from .discovery import open_text
from .parsers.ns_server import _HEADER_RE, MAX_RAW

_UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
_LIST_KEYS = ("nodes", "sources", "categories", "severities", "subsystems",
              "services")


def _read_raw(log_path, byte_off):
    """Re-read an event's full raw text from the original log on disk (the lazy
    index stores log_path + byte_off instead of raw). Seek to the entry's start,
    then for an ns_server ALE entry — detected by the header pattern — fold the
    continuation lines up to the next header; for single-line sources
    (http_access) return that one line. Folding/truncation mirror ns_server._build
    exactly (cap at MAX_RAW bytes + the same marker) so the re-read is byte-for-
    byte identical to a stored raw. Returns None if the file/offset can't be read
    (e.g. the cbcollect moved)."""
    if not log_path or byte_off is None:
        return None
    try:
        with open_text(log_path) as f:
            f.seek(byte_off)
            first = f.readline()
            if not first:
                return None
            first = first.rstrip("\n")
            if not _HEADER_RE.match(first):
                return first              # single-line event (http_access, ...)
            collected, acc = [first], len(first)
            while acc <= MAX_RAW:         # enough to fill the cap; stop early
                line = f.readline()
                if not line or _HEADER_RE.match(line):
                    break                 # EOF or the next entry begins
                line = line.rstrip("\n")
                collected.append(line)
                acc += 1 + len(line)
            raw = "\n".join(collected)
            if len(raw) > MAX_RAW:        # identical to _build's truncation
                raw = raw[:MAX_RAW] + "\n... [truncated]"
            return raw
    except (OSError, UnicodeError, ValueError):
        return None


def _status_range(s):
    """Map a status filter to a half-open [lo, hi) range: a class like '5xx'
    -> 500..600, an exact code like '404' -> 404..405. None if unparseable."""
    s = s.strip().lower()
    if re.fullmatch(r"[1-5]xx", s):
        lo = int(s[0]) * 100
        return (lo, lo + 100)
    if s.isdigit():
        n = int(s)
        return (n, n + 1)
    return None


def _filters(qs):
    f = {}
    for k in _LIST_KEYS:
        if k in qs and qs[k][0]:
            f[k] = [v for v in qs[k][0].split(",") if v]
    for k in ("start", "end"):
        if k in qs and qs[k][0]:
            try:
                f[k] = float(qs[k][0])
            except ValueError:
                pass
    if qs.get("q", [""])[0]:
        f["q"] = qs["q"][0]
    # HTTP-only filters (ignored by non-http rows, which lack these fields).
    if qs.get("min_resp_ms", [""])[0]:
        try:
            f["min_resp_ms"] = float(qs["min_resp_ms"][0])
        except ValueError:
            pass
    if qs.get("status", [""])[0]:
        rng = _status_range(qs["status"][0])
        if rng:
            f["status"] = rng
    if qs.get("path", [""])[0]:
        f["path"] = qs["path"][0]
    if qs.get("anchored_only", [""])[0] in ("1", "true"):
        f["anchored_only"] = True
    # Pin to a finding's related event IDs (set when a finding is clicked).
    if qs.get("ids", [""])[0]:
        try:
            f["ids"] = [int(x) for x in qs["ids"][0].split(",") if x]
        except ValueError:
            pass
    return f


def make_handler(db_path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass  # quiet

        def _send(self, obj, ctype="application/json"):
            body = (json.dumps(obj).encode() if ctype == "application/json"
                    else obj)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _file(self, name, ctype):
            path = os.path.join(_UI_DIR, name)
            with open(path, "rb") as fh:
                self._send(fh.read(), ctype)

        def do_GET(self):
            u = urlparse(self.path)
            qs = parse_qs(u.query)
            try:
                if u.path in ("/", "/index.html"):
                    return self._file("index.html", "text/html; charset=utf-8")
                if u.path == "/app.js":
                    return self._file("app.js",
                                      "application/javascript; charset=utf-8")
                conn = db.connect(db_path)
                try:
                    if u.path == "/api/meta":
                        return self._send(db.query_meta(conn))
                    if u.path == "/api/findings":
                        return self._send(db.query_findings(conn))
                    if u.path == "/api/histogram":
                        return self._send(
                            db.query_histogram(conn, _filters(qs)))
                    if u.path == "/api/pressure":
                        return self._send(
                            db.query_pressure(conn, _filters(qs)))
                    if u.path == "/api/process_dumps":
                        return self._send(db.list_process_dumps(conn))
                    if u.path == "/api/snapshot":
                        return self._send(db.query_snapshot(conn))
                    if u.path == "/api/process_dump":
                        ts = qs.get("capture_ts", [None])[0]
                        mq = qs.get("min_mq", [None])[0]
                        return self._send(db.query_process_dump(
                            conn,
                            node=qs.get("node", [None])[0],
                            source=qs.get("source", [None])[0],
                            capture_ts=float(ts) if ts not in (None, "") else None,
                            name=qs.get("name", [None])[0],
                            location=qs.get("location", [None])[0],
                            min_mq=int(mq) if mq not in (None, "") else None,
                            order=qs.get("order", [None])[0]))
                    if u.path == "/api/service":
                        return self._send(db.query_service(
                            conn,
                            qs.get("name", [""])[0],
                            node=qs.get("node", [None])[0] or None))
                    if u.path == "/api/operation":
                        # The ops band joins to the report by operation_id;
                        # a miss is answered, not 404'd (only 5 are retained).
                        return self._send(db.query_operation(
                            conn, qs.get("id", [""])[0]))
                    if u.path == "/api/overview":
                        # One payload, one x-axis: mastership belief per node,
                        # and the operations that ran over it.
                        return self._send(orchestration.overview(conn))
                    if u.path == "/api/events":
                        limit = int(qs.get("limit", ["2000"])[0])
                        offset = int(qs.get("offset", ["0"])[0])
                        order = qs.get("order", [""])[0] or None
                        rows, total = db.query_events(
                            conn, _filters(qs), limit=limit, offset=offset,
                            order=order)
                        return self._send({"events": rows, "total": total})
                    if u.path == "/api/event":
                        eid = int(qs.get("id", ["0"])[0])
                        row = conn.execute(
                            "SELECT * FROM events WHERE id=?", (eid,)).fetchone()
                        if not row:
                            return self._send({})
                        ev = dict(row)
                        # Lazy index: raw wasn't stored -> re-read it from the
                        # original file via log_path + byte_off.
                        if not ev.get("raw") and ev.get("byte_off") is not None:
                            ev["raw"] = _read_raw(ev.get("log_path"),
                                                  ev["byte_off"])
                            ev["lazy"] = True
                        return self._send(ev)
                finally:
                    conn.close()
                self.send_error(404)
            except BrokenPipeError:
                pass
            except Exception as e:  # surface API errors as JSON
                self._send({"error": str(e)})

    return Handler


def serve(db_path, host="127.0.0.1", port=8765):
    if not os.path.exists(db_path):
        raise FileNotFoundError(
            f"{db_path} not found — run 'ingest' first")
    httpd = ThreadingHTTPServer((host, port), make_handler(db_path))
    url = f"http://{host}:{port}/"
    print(f"\ncbtriage serving {db_path}\n  {url}\n"
          f"  (Ctrl-C to stop; nothing leaves this machine)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
        httpd.shutdown()
