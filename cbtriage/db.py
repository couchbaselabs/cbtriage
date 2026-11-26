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
"""SQLite storage for the normalized event stream + node/clock/findings meta.

SQLite (stdlib) keeps the tool zero-install so it runs on any machine with a
bare Python 3. Indexes on (ts_epoch, node, category, severity, source) make the
timeline's range+facet queries fast into the millions of rows. If the stats
explorer later needs heavy aggregation, the events table can be mirrored to
DuckDB/Parquet without changing the parsers.
"""
import json
import os
import sqlite3

from .parsers import service_lifecycle

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY,
    node      TEXT,
    source    TEXT,
    ts_epoch  REAL,
    ts_local  TEXT,
    tz_offset_min INTEGER,
    severity  TEXT,
    category  TEXT,
    subsystem TEXT,
    pid       TEXT,
    service   TEXT,
    summary   TEXT,
    raw       TEXT,
    fields    TEXT,
    clock     TEXT,
    log_path  TEXT,
    line_no   INTEGER,
    byte_off  INTEGER
);

CREATE TABLE IF NOT EXISTS nodes (
    name             TEXT PRIMARY KEY,
    version          TEXT,
    root             TEXT,
    redacted         INTEGER,
    tz_offset_min    INTEGER,
    tz_name          TEXT,
    boot_epoch       REAL,
    collection_epoch REAL,
    year             INTEGER,
    notes            TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id        INTEGER PRIMARY KEY,
    ts_epoch  REAL,
    node      TEXT,
    severity  TEXT,
    kind      TEXT,
    title     TEXT,
    detail    TEXT,
    handoff   TEXT,
    related   TEXT
);

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

-- Coarse (~1/min) resource-pressure heartbeat from ns_doctor in stats.log,
-- parsed by parsers/stats.py. Kept in its own table (these are metric samples,
-- not timeline events) and used for the per-window pressure verdict. Not a
-- backfill of the Prometheus snapshot -- a read-only sidecar series.
CREATE TABLE IF NOT EXISTS pressure_samples (
    node          TEXT,
    ts_epoch      REAL,
    ts_local      TEXT,
    tz_offset_min INTEGER,
    cpu_some_avg60  REAL,    -- % time SOME task stalled on CPU (avg over 60s)
    cpu_some_total  INTEGER, -- cumulative CPU stall time (usec)
    mem_full_avg60  REAL,    -- % time ALL work stalled on memory (avg over 60s)
    mem_full_total  INTEGER,
    io_full_avg60   REAL,    -- % time ALL work stalled on IO (avg over 60s)
    io_full_total   INTEGER,
    allocstall      REAL,    -- cumulative memory allocation stalls
    cpu_stolen_rate REAL,    -- % CPU stolen by the hypervisor (VM contention)
    cpu_util_rate   REAL,
    disk_usage_pct   REAL,   -- % used on the fullest mount (disksup)
    disk_usage_mount TEXT,   -- which mount that was
    mem_worst_pid    TEXT,   -- OS pid of the largest process (memsup)
    mem_worst_bytes  INTEGER -- its resident memory, bytes
);

-- Per-process Erlang dumps from diag_handler:grab_process_info, parsed by
-- parsers/process_dump.py. A "dump" = the rows sharing (node, capture_ts,
-- source). source='diag' is a collection-time snapshot; source='timeout' is an
-- incident-time dump logged by timeout_diag_logger. Sidecar (state, not a
-- timeline event); the high-message_queue rows ALSO emit message_queue events.
CREATE TABLE IF NOT EXISTS process_dump (
    id               INTEGER PRIMARY KEY,
    node             TEXT,
    source           TEXT,    -- 'diag' (collection snapshot) | 'timeout' (incident)
    capture_ts       REAL,
    capture_local    TEXT,
    tz_offset_min    INTEGER,
    clock            TEXT,
    pid              TEXT,
    name             TEXT,    -- registered_name, else initial_call, else pid
    status           TEXT,
    current_location TEXT,
    initial_call     TEXT,
    message_queue_len INTEGER,
    memory           INTEGER, -- bytes
    reductions       INTEGER,
    trap_exit        TEXT,
    raw              TEXT,
    log_path         TEXT,
    line_no          INTEGER
);

-- Collection-time snapshot facts from couchbase.log one-shots (vmstat reclaim,
-- cgroup PSI + memory accounting), parsed by parsers/snapshot.py. Single-stamp,
-- since-boot readings -- NOT a time series, so kept out of `events` (where they
-- would collapse to one bar at collection_epoch). A tall (metric,value) shape
-- so new one-shots add rows, not columns. scope_path records the exact cgroup
-- dir / file a fact came from (facts, not inference -- see the module docstring
-- on host-rooted vs namespaced cgroup views).
CREATE TABLE IF NOT EXISTS snapshot (
    id            INTEGER PRIMARY KEY,
    node          TEXT,
    capture_ts    REAL,
    capture_local TEXT,
    tz_offset_min INTEGER,
    clock         TEXT,
    category      TEXT,    -- reclaim|cgroup_pressure|cgroup_mem|
                           -- cgroup_census|cgroup_meta
    scope         TEXT,    -- host|root|container-root|couchbase
    scope_path    TEXT,    -- exact source (/proc/vmstat or the cgroup dir)
    metric        TEXT,
    value         REAL,
    text_value    TEXT,
    unit          TEXT,
    log_path      TEXT,
    line_no       INTEGER
);

-- One row per operation (rebalance or failover) from rebalance_report*.json,
-- parsed by parsers/rebalance_report.py. A document, not a timeline event, so
-- it is a sidecar like snapshot/process_dump -- but unlike those it is
-- CLUSTER-scoped, not node-scoped: ns_server writes the report to the first
-- keep node rather than the orchestrator, so the same report appears in several
-- node dirs. rebalance_id is therefore UNIQUE and the load dedups on it; `node`
-- records which node dir the surviving copy was read from, for provenance only.
-- Joins to the ops band by rebalance_id = the span's operation_id attribute.
CREATE TABLE IF NOT EXISTS rebalance_report (
    rebalance_id     TEXT PRIMARY KEY,
    node             TEXT,    -- node dir the copy was read from (provenance)
    master_node      TEXT,
    start_ts         REAL,
    start_local      TEXT,
    tz_offset_min    INTEGER,
    completed_ts     REAL,
    completed_local  TEXT,
    time_taken_ms    INTEGER,
    outcome          TEXT,    -- success|failure|interrupted|unknown
    completion_message TEXT,  -- verbatim; `outcome` is derived from it
    in_progress      INTEGER, -- still running when the report was written
    rebalance_type   TEXT,    -- master-only (MB-70003), NULL on released builds
    nodes_added      TEXT,    -- json; master-only, see rebalance_type
    nodes_removed    TEXT,    -- json; master-only
    has_delta_fields INTEGER, -- whether this build records the real delta
    keep_nodes       TEXT,    -- json; real start_rebalance inputs
    eject_nodes      TEXT,    -- json
    delta_nodes      TEXT,    -- json
    failed_nodes     TEXT,    -- json
    failover_nodes   TEXT,    -- json; present on failover reports only
    is_failover      INTEGER, -- discriminated on KEY presence, not emptiness
    services         TEXT,    -- json: per-service stageInfo timings
    buckets          TEXT,    -- json: per-bucket timings + phase roll-ups
    move_count       INTEGER,
    log_path         TEXT
);

-- One row per vbucket move within a report. `state` and `stuck_phases` come
-- straight from ns_server's three-state phase encoding (startTime set +
-- completedTime false = entered and never left), so "where did it stop" is a
-- filter over recorded facts rather than an inference. Full per-phase detail is
-- kept in `phases` for the drawer.
CREATE TABLE IF NOT EXISTS rebalance_move (
    id               INTEGER PRIMARY KEY,
    rebalance_id     TEXT,
    bucket           TEXT,
    service          TEXT,
    vbucket          INTEGER,
    state            TEXT,    -- done|in_flight|not_started
    stuck_phases     TEXT,    -- json list of phases entered but never completed
    stuck_since_ts   REAL,    -- when the earliest stuck phase was entered
    first_activity_ts REAL,
    before_chain     TEXT,    -- json
    after_chain      TEXT,    -- json
    target_nodes     TEXT,    -- json: after -- before
    docs_left        INTEGER,
    docs_total       INTEGER,
    vb_size          INTEGER,
    phases           TEXT     -- json: name -> {state,start_ts,completed_ts,...}
);
"""

# Indexes are built AFTER the bulk load, not before (see build_indexes). Keeping
# them out of the load path means each INSERT touches only the table heap instead
# of maintaining 7+ B-trees per row; the indexes are then built in one sorted pass
# at the end. On a full-range bundle (millions of rows) this is the difference
# between an index maintained incrementally row-by-row and one built once.
_INDEXES = """
CREATE INDEX IF NOT EXISTS ix_events_ts       ON events(ts_epoch);
CREATE INDEX IF NOT EXISTS ix_events_node     ON events(node);
CREATE INDEX IF NOT EXISTS ix_events_cat      ON events(category);
CREATE INDEX IF NOT EXISTS ix_events_sev      ON events(severity);
CREATE INDEX IF NOT EXISTS ix_events_source   ON events(source);
CREATE INDEX IF NOT EXISTS ix_events_sub      ON events(subsystem);
CREATE INDEX IF NOT EXISTS ix_events_service  ON events(service);
CREATE INDEX IF NOT EXISTS ix_pressure_ts     ON pressure_samples(ts_epoch);
CREATE INDEX IF NOT EXISTS ix_pressure_node   ON pressure_samples(node);
CREATE INDEX IF NOT EXISTS ix_pdump_dump      ON process_dump(node, source, capture_ts);
CREATE INDEX IF NOT EXISTS ix_pdump_name      ON process_dump(name);
CREATE INDEX IF NOT EXISTS ix_snapshot_node   ON snapshot(node, category);
CREATE INDEX IF NOT EXISTS ix_rbmove_reb      ON rebalance_move(rebalance_id, state);
CREATE INDEX IF NOT EXISTS ix_rbreport_start  ON rebalance_report(start_ts);
"""

# Names of every index in _INDEXES, for dropping before an --append load so that
# path gets the build-once treatment too (a fresh ingest starts from an empty
# file, so it has nothing to drop).
_INDEX_NAMES = (
    "ix_events_ts", "ix_events_node", "ix_events_cat", "ix_events_sev",
    "ix_events_source", "ix_events_sub", "ix_events_service",
    "ix_pressure_ts", "ix_pressure_node", "ix_pdump_dump", "ix_pdump_name",
    "ix_snapshot_node")

# Columns of pressure_samples in insert order (node + ts + the metric set).
_PRESSURE_COLS = (
    "node", "ts_epoch", "ts_local", "tz_offset_min",
    "cpu_some_avg60", "cpu_some_total", "mem_full_avg60", "mem_full_total",
    "io_full_avg60", "io_full_total", "allocstall", "cpu_stolen_rate",
    "cpu_util_rate", "disk_usage_pct", "disk_usage_mount",
    "mem_worst_pid", "mem_worst_bytes")


def connect(db_path):
    # sqlite3 reports any of "parent dir missing", "path is a directory" and
    # "no write permission" as the same bare "unable to open database file",
    # which says nothing about which one you hit. Create the parent dir (the
    # common case: -d out/run.db with no out/) and name the rest.
    parent = os.path.dirname(os.path.abspath(db_path))
    if not os.path.isdir(parent):
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            raise SystemExit(
                f"cannot create {parent}/ for the db {db_path}: {exc}")
    if os.path.isdir(db_path):
        raise SystemExit(f"{db_path} is a directory, not a db file")
    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.OperationalError as exc:
        raise SystemExit(f"cannot open the db {db_path}: {exc} "
                         f"(is {parent}/ writable?)")
    conn.row_factory = sqlite3.Row
    # Bulk-load / read-mostly tuning. The db is a disposable index rebuilt from
    # the originals on disk (ingest with reset=True drops the file first), so we
    # trade crash durability we don't need for speed: synchronous=OFF removes the
    # per-commit fsync (the dominant cost of a multi-million-row load) and
    # journal_mode=OFF skips the rollback journal entirely -- if a load dies you
    # re-run it. The big page cache + in-memory temp store also speed up the
    # server's range/sort queries, so this connection is shared by both paths.
    for pragma in (
            "PRAGMA journal_mode = OFF",
            "PRAGMA synchronous = OFF",
            "PRAGMA temp_store = MEMORY",
            "PRAGMA cache_size = -262144",   # ~256 MB (negative = KiB)
            "PRAGMA mmap_size = 268435456"):
        conn.execute(pragma)
    return conn


def init_schema(conn):
    """Create tables only -- indexes are built after the load (build_indexes)."""
    conn.executescript(_SCHEMA)
    conn.commit()


def build_indexes(conn):
    """Build the query indexes in one pass after the bulk load, then ANALYZE so
    the planner has stats for the timeline's range+facet queries. Idempotent
    (CREATE INDEX IF NOT EXISTS), so it's safe on an --append db whose indexes
    already exist."""
    conn.executescript(_INDEXES)
    conn.execute("ANALYZE")
    conn.commit()


def drop_indexes(conn):
    """Drop the query indexes so a load (incl. --append) inserts into bare tables;
    rebuilt by build_indexes at the end. A fresh ingest has none to drop."""
    for name in _INDEX_NAMES:
        conn.execute(f"DROP INDEX IF EXISTS {name}")
    conn.commit()


def reset(conn):
    for t in ("events", "nodes", "findings", "meta", "pressure_samples",
              "process_dump", "snapshot"):
        conn.execute(f"DELETE FROM {t}")
    conn.commit()


_PROCDUMP_COLS = (
    "node", "source", "capture_ts", "capture_local", "tz_offset_min", "clock",
    "pid", "name", "status", "current_location", "initial_call",
    "message_queue_len", "memory", "reductions", "trap_exit", "raw",
    "log_path", "line_no")


def insert_process_dump(conn, rows):
    if not rows:
        return 0
    data = [tuple(r.get(c) for c in _PROCDUMP_COLS) for r in rows]
    conn.executemany(
        f"INSERT INTO process_dump ({','.join(_PROCDUMP_COLS)}) "
        f"VALUES ({','.join('?' * len(_PROCDUMP_COLS))})", data)
    # No commit here: hot-path insert. Flushed at the per-node boundary
    # (insert_node) and finally by set_meta before findings run -- see ingest().
    return len(data)


def list_process_dumps(conn):
    """One entry per dump (node, source, capture_ts) with its process count, for
    the explorer's dump picker. No 'hot'/overload flag -- the explorer shows the
    raw grab_process_info numbers (sortable); the message_queue FINDING is where
    a backed-up mailbox is stated as a fact."""
    rows = conn.execute(
        "SELECT node, source, capture_ts, MAX(capture_local) capture_local, "
        "MAX(tz_offset_min) tz_offset_min, COUNT(*) n "
        "FROM process_dump GROUP BY node, source, capture_ts "
        "ORDER BY capture_ts IS NULL, capture_ts").fetchall()
    return [dict(r) for r in rows]


def _like_escape(s):
    """Neutralise LIKE wildcards so a typed _ or % matches itself. Erlang
    process names and locations are full of underscores (ns_doctor,
    gen_server:call), which LIKE would otherwise treat as 'any character'."""
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def query_process_dump(conn, node=None, source=None, capture_ts=None,
                       name=None, location=None, min_mq=None, order=None,
                       limit=5000):
    """Rows for one dump (node+source+capture_ts), narrowed and ordered.

    name/location are SUBSTRING matches, case-insensitive: a dump is thousands
    of processes, and the useful question is 'everything under ns_doctor' or
    'everything parked in prim_file:sync_nif', never one exact registered name.
    min_mq keeps only processes with a queue at/above N -- usually the fastest
    first cut. The chosen order always applies, whatever is filtered."""
    where, params = [], []
    if node:
        where.append("node = ?"); params.append(node)
    if source:
        where.append("source = ?"); params.append(source)
    if capture_ts is not None:
        where.append("capture_ts IS ?"); params.append(capture_ts)
    if name:
        where.append("name LIKE ? ESCAPE '\\'")
        params.append(f"%{_like_escape(name)}%")
    if location:
        where.append("current_location LIKE ? ESCAPE '\\'")
        params.append(f"%{_like_escape(location)}%")
    if min_mq is not None:
        where.append("message_queue_len >= ?"); params.append(min_mq)
    cols = {"mq": "message_queue_len", "memory": "memory",
            "reductions": "reductions"}
    if order == "location":
        # Cluster processes hanging at the same stack top, biggest cluster
        # first: a pile-up (e.g. dozens blocked in prim_file:sync_nif) reads
        # as one block at the top instead of being scattered alphabetically.
        order_by = ("current_location IS NULL, "
                    "COUNT(*) OVER (PARTITION BY current_location) DESC, "
                    "current_location, message_queue_len DESC")
    else:
        order_by = f"{cols.get(order, 'message_queue_len')} DESC"
    sql = "SELECT * FROM process_dump"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {order_by} LIMIT ?"
    params.append(limit)
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


_SNAPSHOT_COLS = (
    "node", "capture_ts", "capture_local", "tz_offset_min", "clock",
    "category", "scope", "scope_path", "metric", "value", "text_value",
    "unit", "log_path", "line_no")


def insert_snapshot(conn, rows):
    if not rows:
        return 0
    data = [tuple(r.get(c) for c in _SNAPSHOT_COLS) for r in rows]
    conn.executemany(
        f"INSERT INTO snapshot ({','.join(_SNAPSHOT_COLS)}) "
        f"VALUES ({','.join('?' * len(_SNAPSHOT_COLS))})", data)
    # No commit here: flushed at the per-node boundary like the other sidecars.
    return len(data)


def query_snapshot(conn):
    """All collection-time snapshot facts, grouped by node then category, for the
    Snapshot view. Ordered so a node's cards render in a stable, readable order."""
    rows = conn.execute(
        "SELECT node, capture_ts, capture_local, tz_offset_min, category, "
        "scope, scope_path, metric, value, text_value, unit "
        "FROM snapshot ORDER BY node, category, scope, metric").fetchall()
    return [dict(r) for r in rows]


_RBREPORT_COLS = (
    "rebalance_id", "node", "master_node", "start_ts", "start_local",
    "tz_offset_min", "completed_ts", "completed_local", "time_taken_ms",
    "outcome", "completion_message", "in_progress", "rebalance_type",
    "nodes_added", "nodes_removed", "has_delta_fields", "keep_nodes",
    "eject_nodes", "delta_nodes", "failed_nodes", "failover_nodes",
    "is_failover", "services", "buckets", "move_count", "log_path")

_RBMOVE_COLS = (
    "rebalance_id", "bucket", "service", "vbucket", "state", "stuck_phases",
    "stuck_since_ts", "first_activity_ts", "before_chain", "after_chain",
    "target_nodes", "docs_left", "docs_total", "vb_size", "phases")


def insert_rebalance_report(conn, report, moves):
    """Store one report, ignoring it if that rebalance_id is already loaded.

    The same report is written to every keep node, so a multi-node bundle offers
    several byte-identical copies; INSERT OR IGNORE on the rebalance_id primary
    key makes the first copy win and the rest no-ops. The moves are only stored
    when the report row was actually new -- otherwise a second copy would
    duplicate every move row behind an unchanged report."""
    if not report:
        return 0, 0
    cur = conn.execute(
        f"INSERT OR IGNORE INTO rebalance_report ({','.join(_RBREPORT_COLS)}) "
        f"VALUES ({','.join('?' * len(_RBREPORT_COLS))})",
        tuple(report.get(c) for c in _RBREPORT_COLS))
    if not cur.rowcount:
        return 0, 0
    if moves:
        conn.executemany(
            f"INSERT INTO rebalance_move ({','.join(_RBMOVE_COLS)}) "
            f"VALUES ({','.join('?' * len(_RBMOVE_COLS))})",
            [tuple(m.get(c) for c in _RBMOVE_COLS) for m in moves])
    return 1, len(moves)


def _json(text, default):
    try:
        v = json.loads(text) if text else default
    except (ValueError, TypeError):
        return default
    return v if isinstance(v, type(default)) else default


# Stalled moves listed individually in the drawer before the rest become a
# count. High enough that a real stall is shown whole, low enough that a
# rebalance that died with every move open doesn't render 1024 rows -- the
# thing that makes the upstream plot unusable.
_STALL_LIMIT = 200


def query_operation(conn, rebalance_id):
    """The rebalance report for one operation, shaped for the drawer.

    Joined from the ops band by operation_id = rebalanceId, an exact key both
    sides record (ns_orchestrator stamps it on the span, the report carries it
    at top level), so this is never a time correlation.

    `found` false is a real answer, not an error: only the 5 most recent
    reports are retained, so an older span legitimately has none and the drawer
    says so instead of rendering blank.

    Counts are per phase and per state straight from the stored three-state
    encoding -- no thresholds, no derived judgement about whether a duration was
    acceptable."""
    row = conn.execute("SELECT * FROM rebalance_report WHERE rebalance_id = ?",
                       (rebalance_id,)).fetchone()
    if not row:
        return {"found": False, "rebalance_id": rebalance_id}
    rep = dict(row)
    for key, default in (("services", {}), ("buckets", {}), ("keep_nodes", []),
                         ("eject_nodes", []), ("delta_nodes", []),
                         ("failed_nodes", []), ("failover_nodes", []),
                         ("nodes_added", []), ("nodes_removed", [])):
        rep[key] = _json(rep.get(key), default)

    moves = [dict(r) for r in conn.execute(
        "SELECT * FROM rebalance_move WHERE rebalance_id = ? "
        "ORDER BY state, stuck_since_ts, vbucket", (rebalance_id,))]
    totals = {"done": 0, "in_flight": 0, "not_started": 0}
    # phase -> state -> count. Built from each move's own phase map rather than
    # a fixed list of phase names, so a phase ns_server adds later appears here
    # without a code change (see parsers/rebalance_report.py).
    phases = {}
    stalled, never = [], []
    for m in moves:
        totals[m["state"]] = totals.get(m["state"], 0) + 1
        for name, ph in _json(m.get("phases"), {}).items():
            if not isinstance(ph, dict):
                continue
            bucket = phases.setdefault(name, {"done": 0, "in_flight": 0,
                                              "not_started": 0})
            state = ph.get("state")
            if state in bucket:
                bucket[state] += 1
        if m["state"] == "in_flight" and len(stalled) < _STALL_LIMIT:
            m["stuck_phases"] = _json(m.get("stuck_phases"), [])
            m["target_nodes"] = _json(m.get("target_nodes"), [])
            m["before_chain"] = _json(m.get("before_chain"), [])
            m["after_chain"] = _json(m.get("after_chain"), [])
            m["phases"] = _json(m.get("phases"), {})
            stalled.append(m)
        elif m["state"] == "not_started" and len(never) < _STALL_LIMIT:
            never.append(m["vbucket"])
    return {
        "found": True,
        "report": rep,
        "moves": totals,
        "phases": phases,
        "stalled": stalled,
        "stalled_shown": len(stalled),
        "not_started_sample": never,
    }


def insert_events(conn, events):
    rows = [
        (e.node, e.source, e.ts_utc_epoch, e.ts_local, e.tz_offset_min,
         e.severity, e.category, e.subsystem, e.pid,
         (e.fields or {}).get("service"), e.summary, e.raw,
         json.dumps(e.fields or {}), e.clock_confidence, e.log_path, e.line_no,
         e.byte_off)
        for e in events
    ]
    conn.executemany(
        "INSERT INTO events (node, source, ts_epoch, ts_local, tz_offset_min, "
        "severity, category, subsystem, pid, service, summary, raw, fields, "
        "clock, log_path, line_no, byte_off) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    # No commit here: hot-path insert (called once per 5000-row batch). Flushed
    # at the per-node boundary (insert_node) and by set_meta before findings run.
    return len(rows)


def insert_node(conn, ctx, root, redacted, version=None):
    conn.execute(
        "INSERT OR REPLACE INTO nodes (name, version, root, redacted, "
        "tz_offset_min, tz_name, boot_epoch, collection_epoch, year, notes) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (ctx.node, version, str(root), int(redacted), ctx.tz_offset_min,
         ctx.tz_name, ctx.boot_epoch, ctx.collection_epoch, ctx.year,
         "; ".join(ctx.notes)))
    conn.commit()


def insert_findings(conn, findings):
    conn.executemany(
        "INSERT INTO findings (ts_epoch, node, severity, kind, title, detail, "
        "handoff, related) VALUES (?,?,?,?,?,?,?,?)",
        [(f["ts_epoch"], f["node"], f["severity"], f["kind"], f["title"],
          f["detail"], f.get("handoff"), json.dumps(f.get("related", [])))
         for f in findings])
    conn.commit()


def insert_pressure(conn, rows):
    """rows: list of dicts keyed by _PRESSURE_COLS (parsers.stats.pressure_rows)."""
    if not rows:
        return 0
    placeholders = ",".join("?" * len(_PRESSURE_COLS))
    conn.executemany(
        f"INSERT INTO pressure_samples ({','.join(_PRESSURE_COLS)}) "
        f"VALUES ({placeholders})",
        [tuple(r.get(c) for c in _PRESSURE_COLS) for r in rows])
    # No commit here: flushed at the per-node boundary / by set_meta. See ingest().
    return len(rows)


# Pressure metrics surfaced in the verdict: (column, label, kind). 'avg' metrics
# are a % of time stalled (peak + mean matter); 'counter' metrics only grow
# (the delta across the window matters).
_PRESSURE_METRICS = [
    ("io_full_avg60", "io", "avg"),
    ("mem_full_avg60", "memory", "avg"),
    ("cpu_some_avg60", "cpu", "avg"),
    ("cpu_stolen_rate", "cpu_stolen", "avg"),
    ("allocstall", "allocstall", "counter"),
]


def query_pressure(conn, filters):
    """Per-node pressure summary over the filter window (start/end/nodes).

    Returns availability + per-node peak/mean for the %-stalled metrics and the
    window delta for the cumulative counters. Sample volume is ~1/min/node, so
    we aggregate in Python rather than in SQL -- trivially small, and it keeps
    the peak-timestamp lookup simple."""
    clauses, params = ["ts_epoch IS NOT NULL"], []
    nodes = filters.get("nodes")
    if nodes:
        clauses.append(f"node IN ({','.join('?' * len(nodes))})")
        params.extend(nodes)
    if filters.get("start") is not None:
        clauses.append("ts_epoch >= ?")
        params.append(filters["start"])
    if filters.get("end") is not None:
        clauses.append("ts_epoch <= ?")
        params.append(filters["end"])
    where = " WHERE " + " AND ".join(clauses)
    rows = [dict(r) for r in conn.execute(
        f"SELECT * FROM pressure_samples{where} ORDER BY node, ts_epoch",
        params).fetchall()]

    total = conn.execute(
        "SELECT COUNT(*) FROM pressure_samples").fetchone()[0]

    by_node = {}
    for r in rows:
        by_node.setdefault(r["node"], []).append(r)

    nodes_out = []
    for node, samples in sorted(by_node.items()):
        entry = {"node": node, "n": len(samples),
                 "lo": samples[0]["ts_epoch"], "hi": samples[-1]["ts_epoch"],
                 "metrics": {}}
        for col, label, kind in _PRESSURE_METRICS:
            vals = [(s["ts_epoch"], s[col]) for s in samples
                    if s[col] is not None]
            if not vals:
                continue
            if kind == "avg":
                peak_ts, peak = max(vals, key=lambda x: x[1])
                mean = sum(v for _, v in vals) / len(vals)
                entry["metrics"][label] = {
                    "peak": round(peak, 2), "peak_ts": peak_ts,
                    "mean": round(mean, 2)}
            else:  # counter: report the rise across the window
                first, last = vals[0][1], vals[-1][1]
                entry["metrics"][label] = {
                    "delta": round(last - first, 2),
                    "first": first, "last": last,
                    "last_ts": vals[-1][0]}
        nodes_out.append(entry)

    # PSI (io/mem/cpu) comes from the kernel's /proc/pressure and is frequently
    # absent (old kernel, non-Linux, not exported); CPU steal and allocstall come
    # from system_stats and show up on nearly every capture. Flag PSI presence so
    # callers can say "quiet" vs "never measured" -- it qualifies the whole strip.
    psi_available = any(k in n["metrics"]
                        for n in nodes_out for k in ("io", "memory", "cpu"))

    return {"available": total > 0, "in_window": len(rows),
            "total_samples": total, "psi_available": psi_available,
            "nodes": nodes_out}


def set_meta(conn, key, value):
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
                 (key, json.dumps(value)))
    conn.commit()


# ---------------------------------------------------------------------------
# Query helpers used by the server API
# ---------------------------------------------------------------------------

_FILTERABLE = {
    "nodes": "node", "sources": "source", "categories": "category",
    "severities": "severity", "subsystems": "subsystem", "services": "service",
}


def _where(filters):
    clauses, params = [], []
    for key, col in _FILTERABLE.items():
        vals = filters.get(key)
        if vals:
            clauses.append(f"{col} IN ({','.join('?' * len(vals))})")
            params.extend(vals)
    if filters.get("start") is not None:
        clauses.append("ts_epoch >= ?")
        params.append(filters["start"])
    if filters.get("end") is not None:
        clauses.append("ts_epoch <= ?")
        params.append(filters["end"])
    if filters.get("q"):
        clauses.append("(summary LIKE ? OR raw LIKE ?)")
        like = f"%{filters['q']}%"
        params.extend([like, like])
    # HTTP-only numeric/exact filters, read straight out of the fields JSON
    # (only http_access* rows carry these keys; other rows are NULL -> excluded
    # whenever one of these is set). Unindexed, but the timeline is always
    # narrowed to a window first, so the scan is small.
    if filters.get("min_resp_ms") is not None:
        clauses.append("json_extract(fields,'$.resp_ms') >= ?")
        params.append(filters["min_resp_ms"])
    if filters.get("status"):
        lo, hi = filters["status"]
        clauses.append("json_extract(fields,'$.status') >= ? "
                       "AND json_extract(fields,'$.status') < ?")
        params.extend([lo, hi])
    if filters.get("path"):
        clauses.append("json_extract(fields,'$.path_base') = ?")
        params.append(filters["path"])
    if filters.get("anchored_only"):
        clauses.append("ts_epoch IS NOT NULL")
    ids = filters.get("ids")
    if ids:
        clauses.append(f"id IN ({','.join('?' * len(ids))})")
        params.extend(ids)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def query_events(conn, filters, limit=2000, offset=0, order=None):
    where, params = _where(filters)
    # Default is chronological oldest-first; 'ts_desc' is newest-first (so the
    # tail of a busy window is reachable without paging through all of it);
    # 'resp_ms' floats the slowest HTTP requests to the top (rows without a
    # resp_ms sort last).
    if order == "resp_ms":
        order_by = ("json_extract(fields,'$.resp_ms') IS NULL, "
                    "json_extract(fields,'$.resp_ms') DESC")
    elif order == "ts_desc":
        order_by = "ts_epoch IS NULL, ts_epoch DESC"
    else:
        order_by = "ts_epoch IS NULL, ts_epoch"
    sql = f"SELECT * FROM events{where} ORDER BY {order_by} LIMIT ? OFFSET ?"
    rows = conn.execute(sql, params + [limit, offset]).fetchall()
    total = conn.execute(f"SELECT COUNT(*) FROM events{where}",
                         params).fetchone()[0]
    return [dict(r) for r in rows], total


def query_histogram(conn, filters, buckets=240):
    """Counts per time bucket per category for the overview strip."""
    where, params = _where(filters)
    rng = conn.execute(
        f"SELECT MIN(ts_epoch), MAX(ts_epoch) FROM events{where}",
        params).fetchone()
    lo, hi = rng[0], rng[1]
    if lo is None or hi is None or hi <= lo:
        return {"lo": lo, "hi": hi, "width": 0, "bins": []}
    width = (hi - lo) / buckets
    sql = (f"SELECT CAST((ts_epoch - ?) / ? AS INT) AS b, category, "
           f"COUNT(*) c FROM events{where} AND ts_epoch IS NOT NULL "
           f"GROUP BY b, category" if where else
           f"SELECT CAST((ts_epoch - ?) / ? AS INT) AS b, category, "
           f"COUNT(*) c FROM events WHERE ts_epoch IS NOT NULL "
           f"GROUP BY b, category")
    rows = conn.execute(sql, [lo, width] + params).fetchall()
    return {"lo": lo, "hi": hi, "width": width,
            "bins": [dict(r) for r in rows]}


def _distinct(conn, col):
    return [r[0] for r in conn.execute(
        f"SELECT DISTINCT {col} FROM events WHERE {col} IS NOT NULL "
        f"ORDER BY {col}").fetchall()]


def _offset_timeline(conn):
    """Offset (minutes) in effect over time, as transition points
    [{ts, off}, ...] ordered by UTC start. For a single-zone cluster with DST
    this is the 1-3 step changes across the collection — exactly what the UI
    needs to convert a typed local time back to UTC across a DST boundary.

    If the change list is large (e.g. nodes in genuinely different zones, whose
    events interleave by time), there is no clean step function, so collapse to
    the single most-common offset — per-event display is still exact; only the
    search box's local->UTC guess uses this."""
    rows = conn.execute(
        "SELECT ts, off FROM ("
        "  SELECT ts_epoch ts, tz_offset_min off, "
        "  LAG(tz_offset_min) OVER (ORDER BY ts_epoch) prev "
        "  FROM events WHERE ts_epoch IS NOT NULL AND tz_offset_min IS NOT NULL) "
        "WHERE prev IS NULL OR prev != off ORDER BY ts").fetchall()
    tl = [{"ts": r["ts"], "off": r["off"]} for r in rows]
    if len(tl) > 24:
        dom = conn.execute(
            "SELECT tz_offset_min off FROM events WHERE tz_offset_min IS NOT "
            "NULL GROUP BY tz_offset_min ORDER BY COUNT(*) DESC LIMIT 1"
        ).fetchone()
        return [{"ts": 0, "off": dom["off"]}] if dom else []
    return tl


def query_meta(conn):
    rng = conn.execute(
        "SELECT MIN(ts_epoch), MAX(ts_epoch) FROM events").fetchone()
    meta = {r["key"]: json.loads(r["value"])
            for r in conn.execute("SELECT key, value FROM meta").fetchall()}
    # Header range = the ingest window, not the raw event extent: always-full
    # sources (dmesg, diag, event_log) span the whole collection, so the raw
    # MIN/MAX would advertise a range the windowed sources don't cover.
    lo, hi = rng
    if lo is not None and meta.get("window_lo") is not None:
        lo = max(lo, meta["window_lo"])
    if hi is not None and meta.get("window_hi") is not None:
        hi = min(hi, meta["window_hi"])
    return {
        "nodes": [dict(r) for r in conn.execute(
            "SELECT * FROM nodes ORDER BY name").fetchall()],
        "sources": _distinct(conn, "source"),
        "categories": _distinct(conn, "category"),
        "severities": _distinct(conn, "severity"),
        "subsystems": _distinct(conn, "subsystem"),
        "services": _distinct(conn, "service"),
        "offset_timeline": _offset_timeline(conn),
        "time_range": {"lo": lo, "hi": hi},
        "total_events": conn.execute(
            "SELECT COUNT(*) FROM events").fetchone()[0],
        "info": meta,
    }


def query_service(conn, name, node=None):
    """One service's history: its lifecycle (babysitter start/stop/exit) and its
    ServiceAPI traffic (json_rpc), kept as two lists rather than one merged
    stream because they answer different questions -- "was it running" versus
    "was it answering rebalance calls". Both are tagged with the same `service`
    key, which is what makes the join possible.

    NOT limited to the ingest window: a service that exited before the window
    opened is exactly what explains the window's symptoms, so the whole capture
    is in scope here (the same reasoning as the Snapshots panel).
    """
    # A service answers to its babysitter port name AND its ServiceAPI name
    # (cont_backup/cbcontbk, n1ql/cbq-engine, saslauthd_port/saslauthd), so
    # match every alias or half its history goes missing.
    names = service_lifecycle.aliases_of(name)
    where = ["service IN (%s)" % ",".join("?" * len(names))]
    params = list(names)
    if node:
        where.append("node = ?")
        params.append(node)
    rows = [dict(r) for r in conn.execute(
        "SELECT id, node, ts_epoch, ts_local, tz_offset_min, source, severity, "
        "subsystem, summary, fields FROM events WHERE " + " AND ".join(where) +
        " ORDER BY ts_epoch IS NULL, ts_epoch", params).fetchall()]

    raw_life, outstanding, topology = [], [], []
    other = 0
    for r in rows:
        try:
            f = json.loads(r.get("fields") or "{}")
        except (ValueError, TypeError):
            f = {}
        r["fields"] = f
        if f.get("lifecycle"):
            raw_life.append(r)
            continue
        if r["source"] != "json_rpc":
            continue
        # An unanswered call is the answer to "why is the rebalance stalled",
        # so it is pulled out whatever channel it came in on.
        if f.get("phase") == "no_response":
            outstanding.append(r)
        elif f.get("channel") == "service_api":
            topology.append(r)
        else:
            # cbauth and other per-service channels: real traffic, but nothing
            # to do with rebalance. Counted, not listed -- in a 4-node capture
            # this is over 40% of json_rpc events and listing it buries the
            # ServiceAPI calls entirely.
            other += 1

    # Longest-outstanding first: that is the one to point the service team at.
    outstanding.sort(key=lambda r: -(r["fields"].get("outstanding_s") or 0))

    lifecycle = _collapse_lifecycle(raw_life)
    exits = [t for t in lifecycle if t["lifecycle"] == "exited"]
    return {
        "service": name,
        "node": node,
        "lifecycle": lifecycle,
        "outstanding": outstanding,
        "topology": topology,
        "other_rpc_count": other,
        "exit_count": len(exits),
        "nodes": sorted({r["node"] for r in rows if r["node"]}),
    }


# One real transition is reported by up to four modules within milliseconds --
# a non-zero exit shows up as ns_log's "Service 'x' exited with status N",
# goport's "Port exited with status N", and supervisor_cushion's
# "{abnormal,N}". Showing all of them reads as a crash loop that isn't one.
_COLLAPSE_WINDOW_S = 2.0


def _collapse_lifecycle(rows):
    """Fold same-(node, state) rows within a couple of seconds into one
    transition, keeping every contributing row's id so nothing is hidden and
    the reader can still open the raw text of any of them."""
    out = []
    last = {}   # node -> its most recent transition, so interleaved nodes in
                # the all-nodes view still collapse against their own history
    for r in rows:
        f = r["fields"]
        state = f.get("lifecycle")
        prev = last.get(r["node"])
        near = (prev and prev["lifecycle"] == state
                and prev["ts_epoch"] is not None and r["ts_epoch"] is not None
                and abs(r["ts_epoch"] - prev["ts_epoch"]) <= _COLLAPSE_WINDOW_S)
        if not near:
            t = {
                "ts_epoch": r["ts_epoch"], "ts_local": r["ts_local"],
                "tz_offset_min": r["tz_offset_min"], "node": r["node"],
                "lifecycle": state, "exit_status": f.get("exit_status"),
                "death_output": bool(f.get("death_output")),
                "id": r["id"], "summary": r["summary"],
                "subsystem": r["subsystem"], "ids": [r["id"]],
            }
            out.append(t)
            last[r["node"]] = t
            continue
        prev["ids"].append(r["id"])
        # Keep the most informative row as the one shown: the entry carrying the
        # service's own dying output beats a bare status line.
        if f.get("death_output") and not prev["death_output"]:
            prev.update({"id": r["id"], "summary": r["summary"],
                         "subsystem": r["subsystem"], "death_output": True})
        if prev["exit_status"] is None and f.get("exit_status") is not None:
            prev["exit_status"] = f["exit_status"]
    return out


def query_findings(conn):
    return [dict(r) for r in conn.execute(
        "SELECT * FROM findings ORDER BY "
        "CASE severity WHEN 'critical' THEN 0 WHEN 'error' THEN 1 "
        "WHEN 'warn' THEN 2 ELSE 3 END, ts_epoch IS NULL, ts_epoch"
    ).fetchall()]
