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
"""Ingest driver: discover -> per-node clock context -> parse -> SQLite ->
findings."""
import multiprocessing as mp
import os
import re

from . import db, findings, platform
from .clock import build_clock_context, find_uptime_secs, parse_iso_offset
from .discovery import discover, read_text
from .parsers import get_parser, SKIP_SOURCES, SEEKABLE_SOURCES
from .parsers import diag as diag_parser
from .parsers import stats as stats_parser
from .parsers import process_dump
from .parsers import rebalance_report
from .parsers import snapshot

_TS_RE = re.compile(
    r",(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:[+-]\d{2}:\d{2}|Z)),")
# Full build string, e.g. 8.0.1-1234-enterprise (patch distinguishes 7.6.8 vs
# 7.6.11). findings._version_tuple() parses the leading X.Y.Z for gating.
_VERSION_RE = re.compile(r"(\d+\.\d+\.\d+-\d+-(?:enterprise|community))")
# Fallback: the "Couchbase Server ... came up/started" line carries a version.
_CAMEUP_RE = re.compile(
    r"Couchbase Server.{0,40}?(\d+\.\d+\.\d+(?:-\d+)?)", re.I)
_BATCH = 5000
# When windowing with --end, keep reading this many seconds past --end before
# stopping a file. Log files are written in time order, so once we're well past
# the window the rest of the file is too; the slack absorbs minor boundary
# disorder (sub-second interleave, multi-line entries, mild clock skew).
_END_SLACK_S = 300

# Sources ingested for their FULL span even when --start/--end is given. These
# are bounded by construction -- event_log is a capped curated ring, babysitter
# rotates on a small budget, couchbase.log's OS section is a one-shot capture
# (incl. the dmesg ring), the diag snapshot is a single collection-time dump --
# so full ingest costs little and preserves whole-collection context (reboots,
# service restarts, failovers) that an incident window would hide. Unbounded
# sources (debug/http/syslog/journal/master_events) remain windowed.
_ALWAYS_FULL_SOURCES = {"event_log", "babysitter", "couchbase"}

# Completeness stacks: the same logical stream emitted to several files, where
# one sink is a strict superset of another over the time range it covers, so a
# line present in both is stored ONCE (from the superset). The only reason to
# read the less-complete file is reach: debug.log rotates fastest, the
# lower-volume files slowest, so for old ranges the smaller file is the surviving
# copy. Each entry is (source, capped_by): `source` is ingested only for the span
# BELOW the floor (earliest ts) of `capped_by` -- the superset that already
# carries these lines while it covers the range. capped_by=None => family root,
# ingested fully; an absent/excluded cap source also falls back to full ingest.
# Proven from ns_server.erl sink config:
#   MainFilesLoggers -> disk_debug(all) + disk_default/info.log(>=info)
#     + disk_error(>=error):                       debug > info > error
#   ?ERROR_LOGGER -> disk_debug + disk_reports (NOT info/error):  reports < debug
#   ?ACCESS_LOGGER -> disk_access_int(debug=all) + disk_access(info=external):
#                                      http_access_internal > http_access
# Severity is parsed from each line's own level token (ns_server.parse) / status
# code (http_access.parse), not the filename, so an error read out of debug.log
# still filters as an error.
_COMPLETENESS_STACKS = (
    (("debug", None), ("info", "debug"), ("error", "info"), ("reports", "debug")),
    (("http_access_internal", None), ("http_access", "http_access_internal")),
)


def _fallback_offset(node_logs):
    """TZ offset from the first ALE timestamp in debug/info, for resolving
    couchbase.log's abbreviated TZ."""
    p = node_logs.files.get("debug") or node_logs.files.get("info")
    if not p:
        return None
    m = _TS_RE.search(read_text(p, limit_bytes=100_000))
    if not m:
        return None
    _e, off = parse_iso_offset(m.group(1).replace("Z", "+00:00"))
    return off


def _detect_version(node_logs):
    for src in ("debug", "info", "diag", "couchbase"):
        p = node_logs.files.get(src)
        if not p:
            continue
        text = read_text(p, limit_bytes=300_000)
        m = _VERSION_RE.search(text)
        if m:
            return m.group(1)
        m = _CAMEUP_RE.search(text)
        if m:
            return m.group(1)
    return None


def _store(conn, events_iter, progress, label, default_offset=None,
           window=None, lean=False):
    """Persist events. Sources that don't log a per-line offset leave
    tz_offset_min unset; fill it with the node's collection offset so the UI can
    always render a local time (exact per-line offsets are kept as parsed).

    window=(lo, hi) UTC epochs: events with a timestamp outside [lo, hi] are
    dropped before storage (keeps the db small for a humongous cbcollect when
    you only care about an incident window). Events with NO timestamp
    (unanchored) are always kept — they can't be time-placed and are rare.

    lean=True drops `raw` for any event that carries a byte_off (the seekable
    ns_server/http_access sources) and isn't needed by a raw-parsing detector;
    the UI re-reads it on demand from the original file. Used on a full-bundle
    ingest where storing every raw line would balloon the db -- the originals
    stay on disk, so the pointer is enough."""
    lo, hi = window or (None, None)
    stop_at = hi + _END_SLACK_S if hi is not None else None
    batch, total, stopped, folded = [], 0, False, 0
    for ev in events_iter:
        e = ev.ts_utc_epoch
        if e is not None:
            if lo is not None and e < lo:
                continue
            if hi is not None and e > hi:
                # Past --end. The file is time-ordered, so once we're past the
                # slack the rest is too: stop reading it entirely.
                if e > stop_at:
                    stopped = True
                    break
                continue
        # timeout_diag_logger logs the "Got timeout ... Processes snapshot is:"
        # header AND one line per process (1000+), so each process would be its
        # own timeline event -- a flood. Keep only the header on the timeline
        # (the incident marker, counted by the _timeouts finding); the per-process
        # lines live in process_dump (via iter_timeout), shown like the diag
        # collection snapshot in the Processes explorer. Detect the header by its
        # explicit markers (NOT "parse_proc failed" -- a truncated process entry
        # can fail to parse yet must still be folded out, not kept on the timeline).
        if ev.subsystem == "timeout_diag_logger" and ev.raw \
                and not process_dump.is_timeout_header(ev.raw):
            folded += 1
            continue
        if ev.tz_offset_min is None:
            ev.tz_offset_min = default_offset
        if lean and ev.byte_off is not None \
                and ev.subsystem not in findings.RAW_REQUIRED_SUBSYSTEMS:
            ev.raw = ""    # re-read on demand from log_path:byte_off
        batch.append(ev)
        if len(batch) >= _BATCH:
            total += db.insert_events(conn, batch)
            batch = []
    if stopped and hasattr(events_iter, "close"):
        events_iter.close()   # release the file; we won't read the rest
    if batch:
        total += db.insert_events(conn, batch)
    if total or folded:
        progress(f"    {label}: {total} events"
                 + (f" ({folded} per-process timeout dump line(s) folded into "
                    "process_dump)" if folded else ""))
    return total


def _earliest_epoch(parser, node, source, path, ctx):
    """The oldest timestamped event in a file (its rotation floor). Reads from
    the top until the first event that carries a timestamp -- cheap (a handful of
    lines), since logs are written in ascending time order."""
    gen = parser(node, source, path, ctx)
    try:
        for ev in gen:
            if ev.ts_utc_epoch is not None:
                return ev.ts_utc_epoch
    finally:
        if hasattr(gen, "close"):
            gen.close()
    return None


def _parse(parser, node, source, path, ctx, start_epoch):
    """Parse a source, seeking past the head to start_epoch when supported."""
    if start_epoch and source in SEEKABLE_SOURCES:
        return parser(node, source, path, ctx, start_epoch=start_epoch)
    return parser(node, source, path, ctx)


def _ingest_stack(conn, nl, ctx, stack, exclude, window, progress, lean=False):
    """Ingest a completeness stack deduped by coverage: each member fills only the
    span below the floor of its superset (capped_by), so a line living in several
    files is stored once and the high-volume duplicate ranges are never even
    parsed."""
    lo, hi = window or (None, None)
    floors = {}       # source -> earliest ts seen, used to cap its subset members
    total = 0
    for source, capped_by in stack:
        path = nl.files.get(source)
        if not path or source in exclude:
            continue
        parser = get_parser(source)
        if not parser:
            continue
        cap = floors.get(capped_by)   # None for the root, or if the superset is
                                      # absent/excluded -> ingest fully
        eff_hi = cap if hi is None else (hi if cap is None else min(hi, cap))
        events = _parse(parser, nl.name, source, path, ctx, lo)
        label = source + (" (rotation-fill)" if cap is not None else "")
        total += _store(conn, events, progress, label, ctx.tz_offset_min,
                        (lo, eff_hi), lean=lean)
        floor = _earliest_epoch(parser, nl.name, source, path, ctx)
        if floor is not None:
            floors[source] = floor
    return total


def _in_window(ts, window):
    if ts is None or not window:
        return True
    lo, hi = window
    return not ((lo is not None and ts < lo) or (hi is not None and ts > hi))


def _dedup_event_logs(events, seen):
    """event_log is a cluster-wide ring replicated to every node, so each node's
    diag.log carries its own (ring-skewed) copy of the same events -- parsing all
    of them N-times overcounts. Dedup across nodes by the event's own `uuid`
    (event_log_server's identity, preserved in fields). This is UNION-by-identity,
    not skip-the-file: keep the first occurrence, skip repeats, so a later node
    still contributes the OLDER entries that had already rotated out of an
    earlier-collected node's ring (its ring covers a different slice of time).
    Fallback key when an event has no uuid: (epoch, subsystem, summary)."""
    for ev in events:
        uuid = ev.fields.get("uuid") if ev.fields else None
        key = uuid or (ev.ts_utc_epoch, ev.subsystem, ev.summary)
        if key in seen:
            continue
        seen.add(key)
        yield ev


def _pressure_key(r):
    """Cross-bundle identity of a pressure sample. ns_doctor gossips the WHOLE
    cluster's status into every node's stats.log on a 60s timer (ns_doctor.erl
    LOG_INTERVAL), so the same reported node's heartbeat is echoed by every
    bundle, each at that vantage's own ~minute-phased log time. last_heard is the
    RECEIVER's monotonic clock (not stable across vantages), so the only stable
    identity is (reported node, gossip minute): bucket ts_epoch to 60s. None-ts
    rows (no offset in the log line) fall back to their minute-truncated local
    string so they still dedup across re-reads."""
    e = r.get("ts_epoch")
    bucket = int(e // 60) if e is not None else (r.get("ts_local") or "")[:16]
    return (r["node"], bucket)


def _ingest_pressure(conn, node_name, stats_path, progress, window, seen):
    """Parse stats.log pressure rows, drop those outside the window, dedup across
    bundles (gossip echoes the same sample N times -- see _pressure_key), store
    them. A malformed dump must not abort the ingest -- it's a sidecar series."""
    try:
        rows = stats_parser.pressure_rows(stats_path)
    except Exception as e:
        progress(f"    stats(pressure): skipped ({e})")
        return
    lo, hi = window or (None, None)
    kept = []
    dups = 0
    for r in rows:
        e = r["ts_epoch"]
        if e is None:
            continue          # can't place an un-timestamped sample in a window
        if lo is not None and e < lo:
            continue
        if hi is not None and e > hi:
            continue
        key = _pressure_key(r)
        if key in seen:        # same gossip minute already taken from a bundle
            dups += 1
            continue
        seen.add(key)
        kept.append(r)
    n = db.insert_pressure(conn, kept)
    if n or dups:
        observed = sorted({r["node"] for r in kept})
        progress(f"    stats(pressure): {n} samples, "
                 f"{len(observed)} node(s) observed"
                 + (f" ({dups} gossip dup(s) skipped)" if dups else ""))


# events columns in insert order, for the ATTACH-based merge (mirrors the column
# list in db.insert_events).
_EVENT_COLS = (
    "node", "source", "ts_epoch", "ts_local", "tz_offset_min", "severity",
    "category", "subsystem", "pid", "service", "summary", "raw", "fields",
    "clock", "log_path", "line_no", "byte_off")


def _ingest_node_into(conn, nl, window, exclude, lean,
                      seen_uuids, seen_pressure, progress):
    """Parse ONE node's sources into `conn` and return
    (version, profile_text, cb_text, events_total).

    `seen_uuids`/`seen_pressure` are the cross-source dedup sets: shared across
    nodes on the serial path; fresh-per-node in a parallel worker, where the
    cross-NODE dedup (event_log ring, pressure gossip) is instead applied once at
    merge time -- within a single node these repeats don't occur, so a fresh set
    is equivalent. `conn` is the final db (serial) or this node's temp db
    (parallel); either way the per-node work is identical."""
    cb = nl.files.get("couchbase")
    cb_text = read_text(cb, limit_bytes=500_000) if cb else ""
    ctx = build_clock_context(nl.name, cb_text, _fallback_offset(nl),
                              find_uptime_secs(cb) if cb else None)
    v = _detect_version(nl)        # per-node (mixed-version clusters)
    db.insert_node(conn, ctx, nl.root, nl.redacted, version=v)

    profile_text = ""
    pp = nl.files.get("debug") or nl.files.get("babysitter")
    if pp:
        profile_text = read_text(pp, limit_bytes=200_000)

    total = 0
    start_epoch = window[0] if window else None
    # Completeness stacks (debug>info>error, http_access internal>external)
    # are ingested with coverage-stitched dedup; track their sources so the
    # plain loop below doesn't ingest them a second time.
    stacked = set()
    for stack in _COMPLETENESS_STACKS:
        members = {s for s, _ in stack}
        if members & nl.files.keys():
            total += _ingest_stack(conn, nl, ctx, stack, exclude, window,
                                   progress, lean=lean)
            stacked.update(members)

    for source, path in nl.files.items():
        if (source in stacked or source in SKIP_SOURCES
                or source in exclude):
            continue
        parser = get_parser(source)
        if not parser:
            continue
        # Seekable single-file sources skip the file's head straight to
        # --start instead of reading it; the rest read from the top (the
        # window filter in _store still drops out-of-window events).
        # _ALWAYS_FULL_SOURCES bypass both: full span, no seek, no filter.
        full = source in _ALWAYS_FULL_SOURCES
        events = _parse(parser, nl.name, source, path, ctx,
                        None if full else start_epoch)
        total += _store(conn, events, progress,
                        source + (" (full span)" if full and window else ""),
                        ctx.tz_offset_min, None if full else window,
                        lean=lean)

    # Per-process dumps (grab_process_info) come from two places via one
    # parser: diag.log's collection-time snapshot, and timeout_diag_logger's
    # incident-time dumps in debug.log. Both populate process_dump. Only the
    # diag snapshot emits message_queue timeline events; timeout dumps list
    # EVERY process, so surfacing each as an event floods the timeline -- the
    # long (>= threshold) mailboxes there are flagged by the message_queue
    # FINDING off process_dump instead (findings._message_queue).
    diag_path = nl.files.get("diag")
    if diag_path:
        diag_rows = list(process_dump.iter_diag(nl.name, diag_path, ctx))
        db.insert_process_dump(conn, diag_rows)   # the snapshot, kept whole
        # Both are _ALWAYS_FULL_SOURCES in spirit: the mq snapshot is stamped
        # with COLLECTION time (a window on the incident would drop it
        # entirely), and event_log is the capped curated ring. No window.
        total += _store(
            conn, process_dump.mq_events(diag_rows),
            progress, "diag(message_queue)", ctx.tz_offset_min, None)
        # event_log: the standalone file is zlib+ETF (unparseable here), but
        # diag.log embeds the same ring as JSON -- ingest it from there.
        total += _store(
            conn,
            _dedup_event_logs(
                diag_parser.parse_event_logs(nl.name, diag_path, ctx),
                seen_uuids),
            progress, "event_log (full span)" if window else "event_log",
            ctx.tz_offset_min, None)

    debug_path = nl.files.get("debug")
    if debug_path:
        to_rows = [r for r in process_dump.iter_timeout(
                       nl.name, debug_path, ctx, start_epoch)
                   if _in_window(r["capture_ts"], window)]
        if to_rows:
            db.insert_process_dump(conn, to_rows)

    # Coarse resource-pressure heartbeat (PSI/allocstall/CPU-steal) from
    # stats.log -> pressure_samples (not events). The dump reports every
    # node the orchestrator heard from, so a single cbcollect yields the
    # whole cluster's pressure as this node observed it -- which means every
    # bundle echoes the same samples, so _ingest_pressure dedups across them.
    stats_path = nl.files.get("stats")
    if stats_path and "stats" not in exclude:
        _ingest_pressure(conn, nl.name, stats_path, progress, window,
                         seen_pressure)

    # Collection-time snapshot facts (vmstat reclaim + cgroup PSI/memory) from
    # couchbase.log one-shots. Single-stamp readings -> snapshot table, never
    # windowed: a window on the incident would drop them (they carry only the
    # collection timestamp), and they belong in the Snapshot view regardless.
    if cb:
        snap_rows = list(snapshot.iter_snapshot(nl.name, cb, ctx))
        db.insert_snapshot(conn, snap_rows)
        if snap_rows:
            progress(f"  snapshot: {len(snap_rows)} collection-time facts")

    return v, profile_text, cb_text, total


def _worker(packed):
    """Parallel entry point: parse one node into its OWN temp db (own connection,
    own PRAGMAs, bare tables) so N nodes parse concurrently with no shared writer.
    Cross-node dedup is deferred to _merge_node_dbs. Returns the metadata the
    parent needs to merge + finalize. Progress is silenced -- the parent prints a
    line as each node completes."""
    nl, tmp_path, window, exclude, lean = packed
    conn = db.connect(tmp_path)
    db.init_schema(conn)
    db.drop_indexes(conn)
    v, profile_text, cb_text, total = _ingest_node_into(
        conn, nl, window, exclude, lean, set(), set(), lambda *_a: None)
    conn.commit()
    conn.close()
    return {"tmp": tmp_path, "name": nl.name, "version": v,
            "profile_text": profile_text, "cb_text": cb_text,
            "redacted": nl.redacted, "events": total}


def _merge_node_dbs(conn, results, seen_uuids, seen_pressure, progress):
    """Merge each node's temp db into the final `conn`, one ATTACH at a time.

    The high-volume tables (events except event_log, process_dump, nodes) are
    bulk-copied in C with INSERT..SELECT -- no Python, no row pickling. The two
    tables that need CROSS-node dedup are small (thousands of rows) and are
    deduped in Python against running seen-sets, reusing the exact keys the serial
    path uses (_dedup_event_logs by uuid, _pressure_key by node+gossip-minute), so
    the merged db is row-for-row identical to a serial ingest. Temp dbs are
    removed as they're consumed."""
    import json
    ecols = ",".join(_EVENT_COLS)
    pcols = ",".join(db._PROCDUMP_COLS)
    scols = ",".join(db._SNAPSHOT_COLS)
    prcols = ",".join(db._PRESSURE_COLS)
    eph = ",".join("?" * len(_EVENT_COLS))
    prph = ",".join("?" * len(db._PRESSURE_COLS))
    for r in results:
        tmp = r["tmp"]
        conn.execute("ATTACH DATABASE ? AS nd", (tmp,))
        conn.execute(f"INSERT INTO events ({ecols}) "
                     f"SELECT {ecols} FROM nd.events WHERE source != 'event_log'")
        conn.execute(f"INSERT INTO process_dump ({pcols}) "
                     f"SELECT {pcols} FROM nd.process_dump")
        # Snapshot facts are per-node (each node's own couchbase.log one-shots),
        # so no cross-node dedup -- straight bulk copy like process_dump.
        conn.execute(f"INSERT INTO snapshot ({scols}) "
                     f"SELECT {scols} FROM nd.snapshot")
        conn.execute("INSERT OR IGNORE INTO nodes SELECT * FROM nd.nodes")
        # event_log: cross-node dedup by uuid (fallback (epoch, subsystem,
        # summary)) -- the union-by-identity that _dedup_event_logs does.
        elog = []
        for row in conn.execute(
                f"SELECT {ecols} FROM nd.events WHERE source = 'event_log'"):
            d = dict(row)
            f = json.loads(d["fields"]) if d["fields"] else {}
            key = f.get("uuid") or (d["ts_epoch"], d["subsystem"], d["summary"])
            if key in seen_uuids:
                continue
            seen_uuids.add(key)
            elog.append(tuple(d[c] for c in _EVENT_COLS))
        if elog:
            conn.executemany(
                f"INSERT INTO events ({ecols}) VALUES ({eph})", elog)
        # pressure: cross-node dedup by (node, gossip minute) -- _pressure_key.
        prows = []
        for row in conn.execute(f"SELECT {prcols} FROM nd.pressure_samples"):
            d = dict(row)
            e = d["ts_epoch"]
            bucket = int(e // 60) if e is not None else (d["ts_local"] or "")[:16]
            key = (d["node"], bucket)
            if key in seen_pressure:
                continue
            seen_pressure.add(key)
            prows.append(tuple(d[c] for c in db._PRESSURE_COLS))
        if prows:
            conn.executemany(
                f"INSERT INTO pressure_samples ({prcols}) VALUES ({prph})",
                prows)
        conn.commit()
        conn.execute("DETACH DATABASE nd")
        try:
            os.remove(tmp)
        except OSError:
            pass
        progress(f"  merged {r['name']}: running total "
                 f"{conn.execute('SELECT COUNT(*) FROM events').fetchone()[0]} "
                 "events")


def _ingest_rebalance_reports(conn, nodes, progress):
    """Load rebalance_report*.json from every node dir, deduped by rebalanceId.

    Done ONCE in the parent rather than inside the per-node workers, because
    these are the only cluster-scoped source in a bundle: ns_server writes each
    report to the first keep node, not the orchestrator, so the same report
    appears in several node dirs and a per-node path would need cross-node
    dedup in the merge. Sweeping serially here makes the primary-key
    INSERT OR IGNORE the whole dedup, and it costs nothing -- at most six small
    JSON files per node, versus the multi-GB logs the workers are parsing.

    NEVER windowed. The reports are a bounded set (?NUM_REBALANCE_REPORTS = 5
    retained plus current) and an operation is exactly the context a window on
    an incident would hide.
    """
    reports = moves = files = 0
    for nl in nodes:
        for path in nl.reports:
            files += 1
            report, mv = rebalance_report.parse(path, node=nl.name)
            r, m = db.insert_rebalance_report(conn, report, mv)
            reports += r
            moves += m
    conn.commit()
    if files:
        progress(f"  rebalance reports: {reports} operation(s), {moves} move(s)"
                 f" from {files} file(s)")


def ingest(root, db_path, reset=True, progress=print, window=None,
           exclude=None, lean=None, jobs=None):
    exclude = set(exclude or ())
    # Lazy raw by default (windowed OR full-bundle): the db is an index into the
    # originals you keep on disk, so raw is re-read on demand instead of stored.
    # A window already shrinks the row COUNT; lazy also shrinks each kept row, and
    # the two compound -- a windowed db of a big cluster is still large. Pass
    # lean=False (CLI --embed-raw) only for a portable, originals-free db to share.
    #
    # When root is a .zip the "originals" are the files extracted beside it,
    # so those have to outlive the db for lazy raw to resolve; --embed-raw is
    # the way to cut that tie.
    if lean is None:
        lean = True
    nodes = discover(root, progress)
    if not nodes:
        raise ValueError(f"no node logs found under {root}")

    if reset:
        # Fresh ingest -> start from an empty file. reset() only DELETEs rows,
        # which leaves SQLite's file at its previous high-water mark (it never
        # hands free pages back to the OS without a VACUUM). Re-ingesting fewer
        # events into an existing db would then keep the OLD file size and look
        # like nothing changed -- so drop the file (and any journal) first.
        for p in (db_path, db_path + "-journal",
                  db_path + "-wal", db_path + "-shm"):
            try:
                os.remove(p)
            except OSError:
                pass
    conn = db.connect(db_path)
    db.init_schema(conn)
    if reset:
        db.reset(conn)
    # Load into bare tables: drop the query indexes now and rebuild them in one
    # pass after all rows are in (build_indexes, below). A fresh ingest has none
    # to drop; an --append db does, and this gives that path the same speedup.
    db.drop_indexes(conn)

    version = None       # cluster-wide (first seen), for meta + fallback
    total = 0
    node_names, profile_text, cb_for_plat = [], "", ""
    # event_log is replicated to every node's diag.log; dedup across the whole
    # ingest by uuid so the same event isn't stored once per node.
    seen_event_uuids = set()
    # ns_doctor gossips the whole cluster's pressure into every node's stats.log
    # every 60s; dedup across bundles by (node, gossip minute) -- see
    # _pressure_key -- so a sample isn't stored once per observing node.
    seen_pressure = set()

    # Parsing is ~85% of an ingest and each node is independent, so parse nodes
    # concurrently. Default to one worker per core, capped at the node count
    # (more workers than nodes is idle). jobs=1 (or a single-node bundle) keeps
    # the in-process serial path -- no temp dbs, no merge.
    if jobs is None:
        jobs = min(os.cpu_count() or 1, len(nodes))
    jobs = max(1, min(jobs, len(nodes)))

    if jobs == 1:
        for nl in nodes:
            progress(f"  node {nl.name}"
                     f"{' [REDACTED]' if nl.redacted else ''}")
            node_names.append(nl.name)
            v, ptext, cbtext, t = _ingest_node_into(
                conn, nl, window, exclude, lean,
                seen_event_uuids, seen_pressure, progress)
            total += t
            if v and not version:
                version = v
            if not profile_text and ptext:
                profile_text = ptext
            if not cb_for_plat and cbtext:
                cb_for_plat = cbtext
    else:
        progress(f"  parsing {len(nodes)} nodes with {jobs} workers")
        packed = [(nl, f"{db_path}.node{i}.tmp", window, exclude, lean)
                  for i, nl in enumerate(nodes)]
        done = {}
        with mp.Pool(jobs) as pool:
            for res in pool.imap_unordered(_worker, packed):
                # Key by temp-db path, not node name: the path carries the
                # node's index so it is unique by construction, whereas two
                # captures can resolve to the SAME name (the same node
                # collected twice). Keying by name dropped one of them and
                # then handed the survivor's db to the merge twice -- which
                # fails, because the merge deletes each db as it consumes it.
                done[res["tmp"]] = res
                progress(f"  parsed {res['name']}: {res['events']} events")
        # Merge in discovery order so "first seen" (version/profile/platform)
        # is deterministic regardless of which worker finished first.
        ordered = [done[tmp] for (_nl, tmp, *_rest) in packed]
        for res in ordered:
            node_names.append(res["name"])
            if res["version"] and not version:
                version = res["version"]
            if not profile_text and res["profile_text"]:
                profile_text = res["profile_text"]
            if not cb_for_plat and res["cb_text"]:
                cb_for_plat = res["cb_text"]
        _merge_node_dbs(conn, ordered, seen_event_uuids, seen_pressure,
                        progress)

    _ingest_rebalance_reports(conn, nodes, progress)

    # All rows are in -> build the indexes in one sorted pass and ANALYZE, so the
    # findings queries below (and later the server) hit indexes, not table scans.
    db.build_indexes(conn)
    # Exact post-dedup count (the parallel path's per-node tallies double-count
    # the event_log ring before the merge dedups it; recompute from the db).
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    plat = platform.detect(profile_text, cb_for_plat, node_names)
    db.set_meta(conn, "root", str(root))
    # Heavy-source coverage bounds. _ALWAYS_FULL_SOURCES span the whole
    # collection regardless, so outside these bounds the timeline is
    # context-only -- sparse there means "not ingested", not "quiet".
    if window:
        db.set_meta(conn, "window_lo", window[0])
        db.set_meta(conn, "window_hi", window[1])
    db.set_meta(conn, "version", version)
    db.set_meta(conn, "platform", plat)
    db.set_meta(conn, "redacted", any(n.redacted for n in nodes))

    fs = findings.run(conn, version)
    db.insert_findings(conn, fs)
    db.set_meta(conn, "num_findings", len(fs))
    conn.close()

    return {"nodes": [n.name for n in nodes], "events": total,
            "findings": len(fs), "version": version}


def ingest_snapshot_only(root, db_path, reset=True, progress=print):
    """Fast path: ingest ONLY the collection-time snapshot facts (vmstat reclaim
    + cgroup PSI/memory/throttle from each node's couchbase.log one-shots) and
    skip every rotating log. Reads just couchbase.log per node -- head for the
    clock, full for the sections that sit past it -- so it finishes in seconds
    instead of the multi-GB parse a full ingest pays for. Findings still run:
    the snapshot-only rules (dying cgroups, OOM) fire, the rest see empty event
    tables and yield nothing."""
    nodes = discover(root, progress)
    if not nodes:
        raise ValueError(f"no node logs found under {root}")

    if reset:
        for p in (db_path, db_path + "-journal",
                  db_path + "-wal", db_path + "-shm"):
            try:
                os.remove(p)
            except OSError:
                pass
    conn = db.connect(db_path)
    db.init_schema(conn)
    if reset:
        db.reset(conn)

    version = None
    node_names, cb_for_plat = [], ""
    total = 0
    for nl in nodes:
        progress(f"  node {nl.name}"
                 f"{' [REDACTED]' if nl.redacted else ''}")
        node_names.append(nl.name)
        cb = nl.files.get("couchbase")
        cb_text = read_text(cb, limit_bytes=500_000) if cb else ""
        if not cb_for_plat:
            cb_for_plat = cb_text
        ctx = build_clock_context(nl.name, cb_text, _fallback_offset(nl),
                                  find_uptime_secs(cb) if cb else None)
        v = _detect_version(nl)
        if v and not version:
            version = v
        db.insert_node(conn, ctx, nl.root, nl.redacted, version=v)
        if cb:
            snap_rows = list(snapshot.iter_snapshot(nl.name, cb, ctx))
            db.insert_snapshot(conn, snap_rows)
            total += len(snap_rows)
            progress(f"  snapshot: {len(snap_rows)} collection-time facts")

    plat = platform.detect("", cb_for_plat, node_names)
    db.set_meta(conn, "root", str(root))
    db.set_meta(conn, "version", version)
    db.set_meta(conn, "platform", plat)
    db.set_meta(conn, "redacted", any(n.redacted for n in nodes))
    db.set_meta(conn, "snapshot_only", True)

    fs = findings.run(conn, version)
    db.insert_findings(conn, fs)
    db.set_meta(conn, "num_findings", len(fs))
    conn.close()

    return {"nodes": node_names, "facts": total,
            "findings": len(fs), "version": version}
