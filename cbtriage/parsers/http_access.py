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
"""Parser for ns_server http_access.log / http_access_internal.log (CLF-ish).

  ::1 - Administrator [21/May/2026:15:02:48 -0700] "PUT /x HTTP/1.1" 400 31 - "ua" 0

Trailing integer is the request time as logged by ns_server. We surface 4xx as
warn and 5xx as error so the timeline highlights API-level failures.
"""
import re

from ..events import Event, CLOCK_EXACT
from ..clock import parse_clf
from ..discovery import open_text
from ..seek import seek_start

# Referrer and user-agent may each be a quoted string OR a bare '-'
# (http_access_internal.log frequently logs a bare '-' user-agent).
_LINE_RE = re.compile(
    r'^(?P<host>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)\s+'
    r'(?:"[^"]*"|\S+)\s+'                       # referrer (quoted or bare)
    r'(?:"(?P<ua>[^"]*)"|(?P<ua_bare>\S+))\s+'  # user-agent (quoted or bare)
    r'(?P<lat>\d+)\s*$')


def _severity(status):
    if 500 <= status < 600:
        return "error"
    if 400 <= status < 500:
        return "warn"
    return "info"


def _line_epoch(line):
    """UTC epoch of an access-log line (used by the --start byte-seek)."""
    m = _LINE_RE.match(line.rstrip("\n"))
    return parse_clf(m.group("ts"))[0] if m else None


def parse(node_name, source, path, ctx, start_epoch=None):
    off = seek_start(path, start_epoch, _line_epoch)
    seeked = off > 0
    with open_text(path) as f:
        if off:
            f.seek(off)
        i = 0
        while True:
            pos = f.tell()        # byte offset (cookie) for lazy raw re-read
            line = f.readline()
            if not line:
                break
            i += 1
            m = _LINE_RE.match(line.rstrip("\n"))
            if not m:
                continue
            g = m.groupdict()
            status = int(g["status"])
            req = g["req"].split()
            method = req[0] if req else ""
            urlpath = req[1] if len(req) > 1 else ""
            path_base = urlpath.split("?", 1)[0]
            epoch, off = parse_clf(g["ts"])
            resp_ms = int(g["lat"])
            # Inferred start = completion - elapsed (parse_http_access.py logic);
            # enables stall-window detection (e.g. /pools/default pile-ups).
            start_epoch = epoch - resp_ms / 1000.0 if epoch is not None else None
            summary = (f"{method} {urlpath} -> {status} "
                       f"({resp_ms}ms, {g['size']}b)").strip()
            yield Event(
                node=node_name,
                source=source,
                ts_utc_epoch=epoch,
                ts_local=g["ts"],
                tz_offset_min=off,
                severity=_severity(status),
                category="http",
                subsystem=None,
                pid=None,
                summary=summary,
                raw=line.rstrip("\n"),
                fields={
                    "method": method, "path": urlpath, "path_base": path_base,
                    "status": status, "size": g["size"], "resp_ms": resp_ms,
                    "start_epoch": start_epoch, "user": g["user"],
                    "host": g["host"],
                    "ua": g["ua"] or g.get("ua_bare") or "-",
                },
                clock_confidence=CLOCK_EXACT,
                log_path=str(path),
                line_no=None if seeked else i,
                byte_off=pos,
            )
