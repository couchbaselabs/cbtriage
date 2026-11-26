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
"""Per-process dumps from Erlang `diag_handler:grab_process_info/1`.

The SAME proplist is emitted by two paths, so one parser serves both:

  * diag.log `per_node_processes(<node>) = ...` -- a snapshot at COLLECTION
    time (the cbcollect moment), one dump per node.
  * timeout_diag_logger -- on a gen_server/multi_call timeout it logs every
    process via `?log_error("~n~p", [{Pid, Info}])` into debug.log, so each
    process is one ALE entry stamped with the INCIDENT time, and a node can
    have many such dumps across the timeline.

A "dump" is the set of per-process records sharing (node, capture_ts, source).
Both feed the same `process_dump` table; the `source` column ('diag' vs
'timeout') keeps collection-time state distinct from incident-time evidence.
"""
import re

from .. import discovery
from ..events import CLOCK_INFERRED, CLOCK_UNANCHORED

# A backed-up mailbox is the headline overload signal; below this it's noise.
MIN_QUEUE = 50

_PID_RE = re.compile(r"(<\d+\.\d+\.\d+>)")
_NAME_RE = re.compile(r"\{registered_name,\s*([^}\]]+)\}")
_STATUS_RE = re.compile(r"\{status,\s*(\w+)\}")
_MQ_RE = re.compile(r"\{message_queue_len,\s*(\d+)\}")
_MEM_RE = re.compile(r"\{memory,\s*(\d+)\}")
_RED_RE = re.compile(r"\{reductions,\s*(\d+)\}")
_INITCALL_RE = re.compile(r"\{initial_call,\s*\{([^}]+)\}\}")
# Capture only module,function,arity: the 4th tuple element is [] for NIFs but
# [{file,...},{line,...}] elsewhere, whose braces broke a [^}]+ capture -- and
# dropping file/line is what lets identical hang sites cluster when sorting.
_CURLOC_RE = re.compile(r"\{current_location,\s*\{([^,{}]+,\s*[^,{}]+,\s*\d+)")
_TRAP_RE = re.compile(r"\{trap_exit,\s*(true|false)\}")

# A process record begins with the `{<Pid>,` of the {Pid, Info} tuple.
_PROC_START_RE = re.compile(r"^\s*\{(<\d+\.\d+\.\d+>),")
# Literal markers of timeout_diag_logger's do_diag header line
# ("Got timeout ~p~nProcesses snapshot is: ~n"). Used to tell the header from a
# per-process {Pid,Info} entry EXPLICITLY -- never by "parse_proc failed",
# because a truncated/odd process entry (big mailbox/backtrace can run past the
# raw-fold cap) can fail to parse yet is NOT a header; misreading it as one
# resets the snapshot anchor mid-dump and splits one snapshot into two.
_TIMEOUT_HEADER_MARKS = ("Processes snapshot is:", "Got timeout")


def is_timeout_header(raw):
    """True for do_diag's header line, False for a per-process {Pid,Info} entry."""
    return bool(raw) and any(m in raw for m in _TIMEOUT_HEADER_MARKS)
# diag.log section header: per_node_processes / _babysitter_processes /
# _couchdb_processes -- all carry grab_process_info dumps.
_SECTION_RE = re.compile(r"per_node_\w*processes\(")
# Cap a stored block; backtraces/messages can be large.
_MAX_RAW = 16_384


def parse_proc(text, pid=None):
    """Extract the scalar fields from one `{Pid, Info}` block. Returns None if
    the text isn't a recognizable process record. `text` may span many lines
    (the proplist is `~p`-pretty-printed and wraps)."""
    if "registered_name" not in text and "message_queue_len" not in text:
        return None

    def g(rx, cast=None):
        m = rx.search(text)
        if not m:
            return None
        v = m.group(1).strip()
        return cast(v) if cast else v

    name = g(_NAME_RE)
    if name in ("[]", "", None):
        name = None
    raw = text if len(text) <= _MAX_RAW else text[:_MAX_RAW] + "\n... [truncated]"
    if pid is None:
        m = _PID_RE.search(text)
        pid = m.group(1) if m else None
    return {
        "pid": pid,
        "name": name,
        "status": g(_STATUS_RE),
        "message_queue_len": g(_MQ_RE, int),
        "memory": g(_MEM_RE, int),
        "reductions": g(_RED_RE, int),
        "initial_call": g(_INITCALL_RE),
        "current_location": g(_CURLOC_RE),
        "trap_exit": g(_TRAP_RE),
        "raw": raw,
    }


def _row(node, source, capture_ts, capture_local, tz_off, conf, rec, path, line):
    """Shape a parsed proc dict into a process_dump table row."""
    who = rec["name"] or rec["initial_call"] or rec["pid"] or "?"
    return {
        "node": node,
        "source": source,
        "capture_ts": capture_ts,
        "capture_local": capture_local,
        "tz_offset_min": tz_off,
        "clock": conf,
        "pid": rec["pid"],
        "name": who,
        "status": rec["status"],
        "current_location": rec["current_location"],
        "initial_call": rec["initial_call"],
        "message_queue_len": rec["message_queue_len"],
        "memory": rec["memory"],
        "reductions": rec["reductions"],
        "trap_exit": rec["trap_exit"],
        "raw": rec["raw"],
        "log_path": str(path),
        "line_no": line,
    }


def mq_events(rows):
    """Timeline events for backed-up mailboxes (>= MIN_QUEUE) in the diag.log
    collection-time snapshot. NOT used for timeout_diag_logger dumps: those list
    every process, so emitting one event per backed-up mailbox floods the
    timeline -- their long mailboxes are surfaced by findings._message_queue
    (off the process_dump table) instead. `dump_source` records the kind."""
    from ..events import Event
    for r in rows:
        q = r.get("message_queue_len")
        if q is None or q < MIN_QUEUE:
            continue
        who = r["name"] or r["pid"] or "?"
        yield Event(
            node=r["node"], source=r["source"],
            ts_utc_epoch=r["capture_ts"], ts_local=r["capture_local"],
            tz_offset_min=r["tz_offset_min"],
            severity="error" if q >= 1000 else "warn",
            category="other", subsystem="message_queue", pid=r["pid"],
            summary=f"message_queue_len={q} on {who}",
            raw=r["raw"],
            fields={"message_queue_len": q, "process": who,
                    "dump_source": r["source"]},
            clock_confidence=r["clock"], log_path=r["log_path"],
            line_no=r["line_no"])


# The section header on bytes, for locating dumps without a Python line loop:
# diag.log embeds the collected logs and can run to hundreds of MB, while the
# process sections are a few MB. Plain files get a chunked byte scan + seek;
# .gz can't seek cheaply and falls back to one sequential text pass.
_SECTION_BYTES_RE = re.compile(rb"per_node_\w*processes\(")
_SCAN_CHUNK = 8 << 20


def _find_sections(path):
    """[(byte_offset, line_no)] of every section header in a PLAIN diag.log."""
    out = []
    with open(path, "rb") as f:
        overlap = b""
        buf_start = 0       # absolute offset of buf[0]
        lines_before = 0    # newlines in bytes [0, buf_start)
        while True:
            chunk = f.read(_SCAN_CHUNK)
            if not chunk:
                break
            buf = overlap + chunk
            for m in _SECTION_BYTES_RE.finditer(buf):
                off = buf_start + m.start()
                if not out or off > out[-1][0]:
                    out.append(
                        (off, lines_before + buf[:m.start()].count(b"\n") + 1))
            overlap = buf[-64:]     # catch a header split across chunks
            advanced = len(buf) - len(overlap)
            lines_before += buf[:advanced].count(b"\n")
            buf_start += advanced
    return out


def _fold_section(lines):
    """Fold (line_no, text) pairs into {Pid, Info} blocks until the section's
    terminating blank line (write_processes ends with "\\n\\n"); yields
    (rec, first_line_no) per parsed block."""
    buf, buf_pid, line0 = [], None, None
    for no, line in lines:
        if line.strip() == "":
            break
        m = _PROC_START_RE.match(line)
        if m:
            if buf:
                rec = parse_proc("".join(buf), buf_pid)
                if rec:
                    yield rec, line0
            buf, buf_pid, line0 = [line], m.group(1), no
        elif buf:
            buf.append(line)
    if buf:
        rec = parse_proc("".join(buf), buf_pid)
        if rec:
            yield rec, line0


def iter_procs(path):
    """Yield (rec, line_no) for every process block in each per_node_*
    processes( section of diag.log. Used by the ingest path (iter_diag)."""
    p = str(path)
    if p.endswith(".gz"):
        with discovery.open_text(p) as f:
            it = enumerate(f, 1)
            for no, line in it:
                if _SECTION_RE.search(line):
                    yield from _fold_section(it)
        return
    with open(p, "rb") as f:
        for off, header_no in _find_sections(p):
            f.seek(off)
            f.readline()        # rest of the section-header line
            def _lines(no=header_no):
                for raw in iter(f.readline, b""):
                    no += 1
                    yield no, raw.decode("utf-8", "replace")
            yield from _fold_section(_lines())


def iter_diag(node, path, ctx):
    """Yield process_dump rows from diag.log's per_node*processes sections.
    Snapshot at collection time -> source='diag', capture_ts=collection_epoch."""
    epoch = ctx.collection_epoch
    conf = CLOCK_INFERRED if epoch else CLOCK_UNANCHORED
    for rec, line0 in iter_procs(path):
        yield _row(node, "diag", epoch, "(collection snapshot)", None,
                   conf, rec, path, line0)


# timeout_diag_logger dumps AT MOST once per MIN_LOG_INTERVAL (timeout_diag_
# logger.erl: 5000ms) -- maybe_spawn_diag drops requests inside that window. So
# two process lines >= this apart belong to DIFFERENT snapshots; within one
# snapshot the ~1000 lines are logged in a tight lists:foreach, ms apart (a
# snapshot can still straddle a wall-clock second, e.g. 05:14:26 -> :27).
_TIMEOUT_DUMP_GAP_S = 5.0


def iter_timeout(node, path, ctx, start_epoch=None):
    """Yield process_dump rows from timeout_diag_logger blocks in debug.log.
    timeout_diag_logger logs the "Got timeout ... Processes snapshot is:" header
    then one ALE entry PER process, each with its OWN (ms-apart) timestamp. We
    stamp every process in a snapshot with one shared capture_ts so they group
    into ONE dump (like the diag collection snapshot) -- otherwise process_dump's
    GROUP BY (node, source, capture_ts) splits the ~1000 lines into ~1000 dumps
    of 1-2 procs. The anchor ts is the snapshot's HEADER when present; if no
    header was seen (rotated out, or a windowed seek landed mid-snapshot) the
    rate limit lets us still cluster: a >= _TIMEOUT_DUMP_GAP_S gap from the prior
    line starts a new dump. Reuses the ns_server parser's multi-line folding (and
    its seek-to-start when windowed)."""
    from . import ns_server
    cur_ts = cur_local = cur_off = cur_clock = None   # current dump's anchor
    last_ts = None                                    # prior line's own ts
    for ev in ns_server.parse(node, "debug", path, ctx, start_epoch=start_epoch):
        if ev.subsystem != "timeout_diag_logger" or not ev.raw:
            continue
        if is_timeout_header(ev.raw):        # authoritative new dump
            cur_ts, cur_local = ev.ts_utc_epoch, ev.ts_local
            cur_off, cur_clock = ev.tz_offset_min, ev.clock_confidence
            last_ts = ev.ts_utc_epoch
            continue
        rec = parse_proc(ev.raw)
        if not rec:                          # unparseable process entry: drop it,
            continue                         # but do NOT reset the snapshot anchor
        # No header yet, or a >=5s gap from the prior line (snapshots are >=5s
        # apart) => this process starts a new headerless dump anchored on itself.
        if cur_ts is None or (ev.ts_utc_epoch is not None and last_ts is not None
                              and ev.ts_utc_epoch - last_ts >= _TIMEOUT_DUMP_GAP_S):
            cur_ts, cur_local = ev.ts_utc_epoch, ev.ts_local
            cur_off, cur_clock = ev.tz_offset_min, ev.clock_confidence
        if ev.ts_utc_epoch is not None:
            last_ts = ev.ts_utc_epoch
        yield _row(node, "timeout", cur_ts, cur_local, cur_off, cur_clock,
                   rec, path, ev.line_no)
