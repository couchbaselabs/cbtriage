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
"""Parsers for the trusted structured sources: event_log and master_events.log.

event_log entries are JSON objects (timestamp/severity/component/event_id/
description). master_events.log is master_activity_events "kind-of-json" output.

Both are best-effort tolerant parsers; field shapes are validated against a real
generated cbcollect (cluster_run does not produce these files).
"""
import json
import re

from ..events import (Event, categorize, normalize_severity,
                      CLOCK_EXACT, CLOCK_INFERRED, CLOCK_UNANCHORED)
from ..clock import parse_iso_offset
from ..discovery import read_text

# Gregorian seconds (since year 0) -> unix epoch offset.
_GREGORIAN_OFFSET = 62167219200


def _iter_json_objects(text):
    """Yield top-level JSON objects from text that may be a JSON array,
    newline-delimited objects, or concatenated objects."""
    text = text.strip()
    if not text:
        return
    # Whole-document array or single object.
    try:
        doc = json.loads(text)
        if isinstance(doc, list):
            yield from (o for o in doc if isinstance(o, dict))
            return
        if isinstance(doc, dict):
            yield doc
            return
    except json.JSONDecodeError:
        pass
    # Brace-balanced scan (handles NDJSON and concatenated objects, skipping
    # braces inside strings).
    depth = 0
    start = None
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                chunk = text[start:i + 1]
                try:
                    obj = json.loads(chunk)
                    if isinstance(obj, dict):
                        yield obj
                except json.JSONDecodeError:
                    pass
                start = None


def event_from_log_obj(node_name, obj, log_path=None):
    """Build an Event from one event_log JSON object. Shared by the (rarely
    usable) standalone event_log file and the diag.log 'Event Logs:' section --
    in real cbcollects the standalone file is zlib+ETF, so diag.log's JSON dump
    is the source that actually parses (see diag.parse_event_logs)."""
    ts = obj.get("timestamp") or obj.get("ts")
    epoch, conf = None, CLOCK_UNANCHORED
    if isinstance(ts, str):
        epoch, _off = parse_iso_offset(ts.replace("Z", "+00:00"))
        conf = CLOCK_EXACT if epoch else CLOCK_UNANCHORED
    comp = obj.get("component")
    desc = obj.get("description") or obj.get("event_id") or ""
    sev = normalize_severity(obj.get("severity"))
    extras = {k: v for k, v in obj.items()
              if k not in ("timestamp", "ts", "component", "description",
                           "severity")}
    return Event(
        node=node_name,
        source="event_log",
        ts_utc_epoch=epoch,
        ts_local=ts if isinstance(ts, str) else "",
        severity=sev if sev != "unknown" else "info",
        category=categorize("event_log", comp, desc),
        subsystem=comp,
        summary=(f"[{comp}] {desc}" if comp else str(desc))[:300],
        raw=json.dumps(obj, indent=1)[:8000],
        fields=extras,
        clock_confidence=conf,
        log_path=log_path,
    )


def parse_event_log(node_name, source, path, ctx):
    for obj in _iter_json_objects(read_text(path)):
        yield event_from_log_obj(node_name, obj, str(path))


def _master_epoch(ts):
    """master_events.log ts -> (epoch, confidence). Per
    scripts/master_events_epoch_time_converter.py, ts is UNIX epoch seconds in
    UTC (float, e.g. 1675955945.324646)."""
    if not isinstance(ts, (int, float)):
        return None, CLOCK_UNANCHORED
    if ts > 1e12:                       # milliseconds (defensive)
        return ts / 1000.0, CLOCK_EXACT
    if ts > 1e9:                        # unix seconds
        return float(ts), CLOCK_EXACT
    return None, CLOCK_UNANCHORED


def parse_master_events(node_name, source, path, ctx):
    for obj in _iter_json_objects(read_text(path)):
        ts = obj.get("ts")
        epoch, conf = _master_epoch(ts)
        etype = obj.get("type") or "master_event"
        extras = {k: v for k, v in obj.items() if k not in ("ts", "type")}
        summary = etype
        for k in ("bucket", "node", "service", "chk", "pid"):
            if k in extras:
                summary += f" {k}={extras[k]}"
        yield Event(
            node=node_name,
            source="master_events",
            ts_utc_epoch=epoch,
            ts_local=str(ts) if ts is not None else "",
            severity="info",
            category=categorize("master_events", etype, summary),
            subsystem=etype,
            summary=summary[:300],
            raw=json.dumps(obj)[:8000],
            fields=extras,
            clock_confidence=conf,
            log_path=str(path),
        )
