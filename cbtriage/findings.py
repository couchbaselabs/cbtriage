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
"""Findings engine: flags noteworthy facts in a cbcollect for first-line triage.

Runs after ingest and writes the findings table. Findings state FACTS, not
interpretations: what happened, which node(s), the reason string straight from
the logs, and timestamps. They deliberately do NOT guess root cause (e.g.
resource pressure vs connectivity) or route hand-offs ("punt to X") — that
misleads more than it helps; the engineer correlates from the facts. The one
exception is the /pools/default known-issue detector, whose value IS the
matched conclusion (a specific Erlang VM bug + MB ticket).

Covers: OOM, service-not-responding, high message_queue_len, failover,
auto-failover progression, net_kernel node membership, orchestrator/master
election, stale-task cleanup, crash/restart volume, and the /pools/default
Erlang VM stall fingerprint.
"""
import json
import re
from datetime import datetime, timezone

from . import db
from . import nodes

# Subsystems whose detectors parse the full raw entry (not just summary), so
# their raw must always be stored even when the lazy index omits raw elsewhere.
RAW_REQUIRED_SUBSYSTEMS = frozenset({
    "auto_failover_logic", "auto_failover", "ns_node_disco",
})

# Correlation window around a failover, seconds.
_WINDOW = 120
# message_queue_len that warrants a finding.
_MQ_THRESHOLD = 1000
# How many vbucket ids to name before summarising the rest as a count. A failed
# rebalance can leave hundreds of moves unfinished, and the finding is a
# headline, not the list -- the full set is in the rebalance_move table.
_REPORT_VB_SAMPLE = 6
# A /pools/default request slower than this (ms) is treated as "stalled".
_POOLS_STALL_MS = 60_000
# Stalled requests completing within this window (s) "woke up together".
_WAKE_WINDOW = 5
# Spread of stall durations (s) within a wake cluster proving the requests
# started at different times but recovered together (the VM-bug fingerprint).
_WAKE_DURATION_SPREAD = 10
# The upstream Erlang/OTP bug behind the /pools/default tasks-outstanding stall.
_OTP_ISSUE = "https://github.com/erlang/otp/issues/10651"


def _version_tuple(version):
    """'8.1.0-0000-enterprise' -> (8, 1, 0); None if unparseable."""
    if not version:
        return None
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    return tuple(int(x) for x in m.groups()) if m else None


def _pools_default_affected(version):
    """Heuristic: release trains with the Erlang VM /pools/default tasks-
    outstanding bug — roughly 7.6.8-7.6.11 and 8.0.0-8.0.2. Version numbering is
    messy (e.g. 8.0.2 shipped as 8.0.1-MP3), so this is corroboration only; the
    fingerprint is the primary signal. See _pools_tickets for the authority."""
    v = _version_tuple(version)
    if not v:
        return None  # unknown
    if v[:2] == (7, 6) and 8 <= v[2] <= 11:
        return True
    if v[:2] == (8, 0) and v[2] in (0, 1, 2):
        return True
    return False


def _pools_tickets(version):
    """The Erlang-build MB tickets that explain the fix per release train."""
    v = _version_tuple(version)
    if v and v[:2] == (7, 6):
        return "MB-71824 (7.6.x train)"
    if v and v[:2] == (8, 0):
        return "MB-71825 (8.0; fixed in 8.0.1-MP3), MB-71907 (8.0.3)"
    return ("MB-71824 (7.6.x) / MB-71825 (8.0, fixed 8.0.1-MP3) / "
            "MB-71907 (8.0.3)")


def _rows(conn, sql, params=()):
    return conn.execute(sql, params).fetchall()


# Peak % time stalled (60s avg) above which a node's pressure is worth a
# finding. CPU "some" runs high under normal load, so it gets the high bar;
# memory/IO "full" (everything stalled) are alarming at lower levels. CPU steal
# (hypervisor stealing the VM's cycles) is a noisy-neighbour signal.
_PRESSURE_WARN = {"io": 20.0, "memory": 10.0, "cpu": 50.0, "cpu_stolen": 5.0}
_PRESSURE_LABEL = {"io": "host IO", "memory": "host memory", "cpu": "host CPU",
                   "cpu_stolen": "CPU steal (VM contention)"}


def _pressure(conn):
    """Surface elevated HOST resource pressure (PSI/allocstall/CPU-steal) from
    the coarse stats.log heartbeat, and -- when the capture has no pressure data
    at all but DOES show failovers -- an honesty flag that the failover cause
    can't be checked against pressure. Facts only: which node, which resource,
    the peak %, and when.

    HOST, not slice: the heartbeat is ns_heart reading /proc/pressure/* (whole
    node). The couchbase cgroup slice's own PSI is a separate signal shown in the
    Snapshots view (from couchbase.log). Detail lives in promtimer."""
    out = []
    summary = db.query_pressure(conn, {})
    if not summary["available"]:
        fo = _rows(conn, "SELECT COUNT(*) c FROM events "
                         "WHERE category='failover'")
        if fo and fo[0]["c"]:
            out.append({
                "ts_epoch": None, "node": "(cluster)", "severity": "info",
                "kind": "pressure_unavailable",
                "title": "Host pressure data unavailable",
                "detail": ("No host PSI/allocstall samples in stats.log, so a "
                           "failover's 'node unresponsive' cause can't be "
                           "ruled in or out against host CPU/memory/IO "
                           "pressure. (Slice-level PSI, if any, is in the "
                           "Snapshots view.)"),
                "handoff": None, "related": [],
            })
        return out

    # One finding per (node, metric) so every crossed pressure is individually
    # navigable. Two shapes, two click behaviours:
    #   * PSI / CPU-steal are %-stall averages with a real peak instant -- we
    #     anchor ts_epoch on peak_ts (click windows +/-5min there) and name it.
    #   * allocstall is a cumulative kernel counter; its delta spans the whole
    #     capture, so there is NO instant -- ts_epoch stays None (the click then
    #     filters by node across the full interval) and we print no time.
    _SRC = ("Coarse ~1/min stats.log heartbeat -- open promtimer for the "
            "full-resolution series.")
    for n in summary["nodes"]:
        node = n["node"]
        for key, thr in _PRESSURE_WARN.items():
            m = n["metrics"].get(key)
            if not (m and m["peak"] >= thr):
                continue
            label = _PRESSURE_LABEL[key]
            ts = m["peak_ts"]
            _al = _rows(conn,
                        "SELECT ts_local FROM pressure_samples WHERE node=? "
                        "AND ts_epoch=? LIMIT 1", [node, ts])
            at = (f" at {_al[0]['ts_local'][:19]}"
                  if _al and _al[0]["ts_local"] else "")
            out.append({
                "ts_epoch": ts, "node": node, "severity": "warn",
                "kind": "pressure",
                "title": f"{label} {m['peak']:.1f}% on {node}",
                "detail": f"{label} peaked at {m['peak']:.1f}%{at}. {_SRC}",
                "handoff": None, "related": [],
            })
        a = n["metrics"].get("allocstall")
        if a and a["delta"] > 0:
            d = int(a["delta"])
            out.append({
                "ts_epoch": None, "node": node, "severity": "warn",
                "kind": "pressure",
                "title": f"Host allocation stalls +{d} on {node}",
                "detail": (f"host allocation stalls rose +{d} across the capture "
                           f"on {node} (cumulative whole-node kernel counter; "
                           f"whole-interval, no single instant). {_SRC}"),
                "handoff": None, "related": [],
            })
    return out


# --- collection-time snapshot facts (couchbase.log one-shots) ---
# couchbase slice memory this close to its limit reads as "at the ceiling".
_MEM_AT_LIMIT_PCT = 90.0
# Dying (zombie) cgroups this numerous is only reached when reclaim effectively
# never runs to reap them. General calibration -- not tied to any one report.
_DYING_CGROUP_EXCESSIVE = 1000
# CPU CFS throttling share of periods that warrants a warn (below it, info): a
# slice throttled this often is materially starved of CPU against its limit.
_THROTTLE_WARN_PCT = 25.0


def _gib(n):
    """Bytes -> 'N.NG'."""
    return f"{n / 1024 ** 3:.1f}G" if n is not None else "?"


def _fmt_ts(epoch):
    """UTC epoch -> 'YYYY-MM-DD HH:MM:SS', the format the timeline's time column
    uses by default. Findings that span sources quote this rather than a raw
    ts_local, because ts_local's shape is per-source: ns_server logs carry an
    ISO stamp that survives a [:19] slice, but dmesg carries '[Tue Feb  3
    20:56:34 2026]', which that same slice cuts mid-second."""
    if epoch is None:
        return "?"
    return datetime.fromtimestamp(epoch, timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")


def _snapshot_by_node(conn):
    """Snapshot facts as {node: {metric: row}}. Metric names are unique within a
    node (reclaim/couchbase-slice/census namespaces don't collide)."""
    by = {}
    for r in _rows(conn,
                   "SELECT node, category, scope, scope_path, metric, value, "
                   "text_value, unit FROM snapshot"):
        by.setdefault(r["node"], {})[r["metric"]] = dict(r)
    return by


def _snapshot(conn):
    """Facts from the collection-time snapshot: the couchbase slice hitting its
    own memory ceiling / getting OOM-killed, and whether host reclaim ran at all.
    Single-stamp since-boot readings, so ts_epoch stays None (no instant to
    window on -- the click filters the timeline to the node, like the allocstall
    pressure finding). Full detail lives in the Snapshot view."""
    out = []
    for node, m in _snapshot_by_node(conn).items():
        def val(metric):
            r = m.get(metric)
            return r["value"] if r else None

        oom = val("memory.events.oom_kill")
        if oom and oom > 0:
            out.append({
                "ts_epoch": None, "node": node, "severity": "critical",
                "kind": "snapshot_mem",
                "title": f"couchbase cgroup OOM-killed {int(oom)}x on {node}",
                "detail": (f"memory.events.oom_kill={int(oom)} on the couchbase "
                           f"slice: it reached its memory.max limit and the "
                           f"kernel OOM-killed a process in it (since-boot "
                           f"counter, read at collection time)."),
                "handoff": None, "related": [],
            })
        high = val("memory.events.high")
        if high and high > 0:
            out.append({
                "ts_epoch": None, "node": node, "severity": "warn",
                "kind": "snapshot_mem",
                "title": (f"couchbase cgroup memory-throttled {int(high)}x "
                          f"(memory.high) on {node}"),
                "detail": (f"memory.events.high={int(high)}: allocations were "
                           f"throttled and force-reclaimed at the memory.high "
                           f"soft limit (since-boot counter). PSI-independent "
                           f"memory-pressure signal -- the slice was squeezed "
                           f"without being OOM-killed."),
                "handoff": None, "related": [],
            })
        cur, mx = val("memory.current"), val("memory.max")
        if cur and mx and mx not in (0, float("inf")):
            pct = cur / mx * 100
            if pct >= _MEM_AT_LIMIT_PCT:
                out.append({
                    "ts_epoch": None, "node": node, "severity": "warn",
                    "kind": "snapshot_mem",
                    "title": (f"couchbase cgroup at {pct:.0f}% of its memory "
                              f"limit on {node}"),
                    "detail": (f"memory.current {_gib(cur)} of memory.max "
                               f"{_gib(mx)} ({pct:.0f}%) on the couchbase slice "
                               f"at collection time."),
                    "handoff": None, "related": [],
                })
        # CPU CFS throttling -- the PSI-independent stall signal (present even
        # when kernel PSI is disabled, the RHEL default). "Are WE being
        # throttled against our own cpu limit."
        thr = val("cpu.stat.throttled_period_pct")
        if thr is not None and thr > 0:
            nt, npd = val("cpu.stat.nr_throttled"), val("cpu.stat.nr_periods")
            vs = val("cpu.stat.throttled_vs_usage_pct")
            vs_s = f", throttled_usec {vs:.0f}% of run time" if vs is not None \
                else ""
            out.append({
                "ts_epoch": None, "node": node,
                "severity": "warn" if thr >= _THROTTLE_WARN_PCT else "info",
                "kind": "snapshot_cpu",
                "title": (f"couchbase cgroup CPU-throttled {thr:.0f}% of periods "
                          f"on {node}"),
                "detail": (f"cpu.stat: throttled in {int(nt)} of {int(npd)} CFS "
                           f"periods ({thr:.1f}%){vs_s} against its own cpu "
                           f"limit. PSI-independent; a heavily throttled slice "
                           f"misses heartbeats even with no memory pressure."),
                "handoff": None, "related": [],
            })

        # An ENCLOSING slice throttled = node/group-wide CPU throttling from
        # OUTSIDE our own limit (the whole pod budget is saturated).
        enc = val("encl.throttled_period_pct")
        if enc is not None and enc > 0:
            enct = val("encl.nr_throttled")
            out.append({
                "ts_epoch": None, "node": node, "severity": "info",
                "kind": "snapshot_cpu",
                "title": (f"enclosing cgroup CPU-throttled {enc:.0f}% of periods "
                          f"on {node}"),
                "detail": (f"a parent slice (the pod's enclosing group) was "
                           f"throttled in {int(enct)} periods ({enc:.1f}%) "
                           f"against ITS cpu limit -- node/group-wide CPU "
                           f"throttling from outside the couchbase slice."),
                "handoff": None, "related": [],
            })
    return out


def _dying_cgroups(conn):
    """Fingerprint (interpretive, like the /pools/default detector): an excessive
    dying-cgroup census. Dying cgroups are directories already rmdir'd but still
    pinned by residual page cache the kernel has not reclaimed; they pile up this
    high only when reclaim effectively never evicts that cache, and the pinned
    cgroups inflate kernel memory accounting and slow cgroup-wide walks. When the
    host reclaim counters are also zero, nothing is reaping them and the census
    only grows."""
    out = []
    for node, m in _snapshot_by_node(conn).items():
        r = m.get("cgroup.stat.nr_dying_descendants")
        if not r or (r["value"] or 0) < _DYING_CGROUP_EXCESSIVE:
            continue
        dying = int(r["value"])
        pgsteal = (m.get("pgsteal_total") or {}).get("value")
        allocstall = (m.get("allocstall_total") or {}).get("value")
        no_reclaim = not pgsteal and not allocstall
        where = ("host root" if r["scope"] == "root"
                 else "couchbase container root")
        detail = (f"cgroup.stat.nr_dying_descendants={dying} at the {where} "
                  f"cgroup. Dying cgroups are already removed but still pinned "
                  f"by residual page cache the kernel has not reclaimed.")
        if no_reclaim:
            detail += (" Host reclaim counters (pgsteal/allocstall) are zero, so "
                       "nothing is reaping them and the census only grows; this "
                       "inflates kernel memory accounting.")
        out.append({
            "ts_epoch": None, "node": node,
            "severity": "warn" if no_reclaim else "info",
            "kind": "dying_cgroups",
            "title": f"{dying} dying (zombie) cgroups on {node}",
            "detail": detail, "handoff": None, "related": [],
        })
    return out


# Disk-usage bars match ns_server's own guardrail defaults (menelaus_web_
# guardrails.erl): the data-service disk_usage maximum is 85, and the index
# guardrail splits serious=80 / critical=85. So warn at 80, error at 85.
_DISK_WARN = 80.0
_DISK_ERROR = 85.0


def _disk(conn):
    """Fullest-mount disk usage per node, from the coarse stats.log heartbeat
    (disksup). One finding per node whose peak crossed the bar -- ns_server's
    own guardrail treats 80/85% as serious/critical, so we use the same.

    Fact only: which node, the peak %, which mount, when. A near-full data/index
    mount stalls writes and aborts rebalances, so it's worth surfacing even on an
    otherwise-idle box. Coarse ~1/min source; open promtimer for the series."""
    rows = _rows(conn,
                 "SELECT p.node, p.disk_usage_pct pct, p.disk_usage_mount mount, "
                 "p.ts_epoch, p.ts_local FROM pressure_samples p WHERE "
                 "p.disk_usage_pct IS NOT NULL AND p.disk_usage_pct = "
                 "(SELECT MAX(disk_usage_pct) FROM pressure_samples p2 "
                 "WHERE p2.node = p.node) GROUP BY p.node")
    out = []
    for r in rows:
        pct = r["pct"]
        if pct < _DISK_WARN:
            continue
        mount = f" ({r['mount']})" if r["mount"] else ""
        out.append({
            "ts_epoch": r["ts_epoch"], "node": r["node"],
            "severity": "error" if pct >= _DISK_ERROR else "warn",
            "kind": "disk_usage",
            "title": f"Disk {pct:.0f}% full{mount} on {r['node']}",
            "detail": (f"peak disk usage {pct:.0f}%{mount} at "
                       f"{(r['ts_local'] or '')[:19]}. Coarse ~1/min stats.log "
                       "heartbeat (disksup); ns_server guardrails treat 80/85% "
                       "as serious/critical. Open promtimer for the series."),
            "handoff": None, "related": [],
        })
    return out


def _mem_worst_in_window(conn, node, lo, hi):
    """(pid, bytes) of the largest OS process (memsup) at its peak in [lo, hi]
    for `node`, or (None, None). Used only to annotate the pressure clause when
    memory pressure already crossed -- it explains WHAT held the memory."""
    if lo is None or hi is None:
        return None, None
    r = conn.execute(
        "SELECT mem_worst_pid pid, mem_worst_bytes b FROM pressure_samples "
        "WHERE node=? AND ts_epoch BETWEEN ? AND ? AND mem_worst_bytes IS NOT "
        "NULL ORDER BY mem_worst_bytes DESC LIMIT 1", [node, lo, hi]).fetchone()
    return (r["pid"], r["b"]) if r else (None, None)


def _pressure_in_window(conn, node, ts, timeout, available):
    """Factual resource-pressure clause for the lead-up window around an
    auto-failover of `node`, from the coarse stats.log heartbeat.

    Window is [ts - max(configured_timeout, _WINDOW), ts + _WINDOW]: pressure
    that drives a failover precedes it, so we look back over the down-progression
    (the authoritative timeout when known) plus a small trailing margin for the
    sample logged just after. Reports the %-stall metrics that crossed the same
    warn bars as _pressure, plus any allocstall rise; says so plainly when
    nothing crossed. When the node has NO heartbeat samples in the window, the
    orchestrator had stopped hearing its stats -- usually the very condition the
    failover reason states ("cluster manager did not respond") -- so we surface
    that as a fact too. Returns '' when unanchored or when stats.log carried no
    pressure data at all (the separate _pressure finding owns that case)."""
    if ts is None or not available:
        return ""
    lead = max(timeout or _WINDOW, _WINDOW)
    lo, hi = ts - lead, ts + _WINDOW
    summary = db.query_pressure(conn, {"nodes": [node], "start": lo, "end": hi})
    nodes = summary["nodes"]
    if not nodes or not nodes[0]["n"]:
        return "no stats.log heartbeat samples in window"
    metrics = nodes[0]["metrics"]
    parts, mem_crossed = [], False
    for key, thr in _PRESSURE_WARN.items():
        m = metrics.get(key)
        if m and m["peak"] >= thr:
            parts.append(f"{_PRESSURE_LABEL[key]} {m['peak']:.1f}%")
            if key == "memory":
                mem_crossed = True
    a = metrics.get("allocstall")
    if a and a["delta"] > 0:
        parts.append(f"allocation stalls +{int(a['delta'])}")
    if not parts:
        return "no elevated CPU/memory/IO pressure in window"
    # Worst memory consumer rides along only when memory pressure crossed -- it
    # explains what held the memory, and would be noise otherwise.
    if mem_crossed:
        pid, b = _mem_worst_in_window(conn, node, lo, hi)
        if b:
            parts.append(f"worst proc pid {pid} {b / 1024 ** 3:.1f} GB")
    return "pressure in window: " + ", ".join(parts)


# One OOM episode writes several kernel lines that all match the OOM filter:
# the allocating task ("<comm> invoked oom-killer"), stack frames
# (oom_kill_process...), the decision ("Out of memory: Kill process <pid>
# (<comm>)") and the victim ("Killed process <pid> (<comm>) ... anon-rss:<N>kB").
# Only the last of those is a kill, so it is what gets counted -- 50 matched
# lines on one real node were 13 kills.
_OOM_VICTIM_RE = re.compile(
    r"Killed process (\d+) \(([^)]+)\)(?:.*?anon-rss:(\d+)kB)?", re.I)
_OOM_INVOKER_RE = re.compile(r"(\S+) invoked oom-killer", re.I)


def _oom(conn):
    """OOM kills, rolled up to ONE finding per node.

    Still critical and still always surfaced -- the playbook rule is unchanged.
    What changes is the shape: a node that OOM-killed the same process every
    few minutes for an hour used to emit one identical finding per matched
    kernel line, burying every other finding on the page. The roll-up answers
    the three questions that actually get asked -- how many, over what span,
    and what died -- and keeps every contributing event id in `related`, so
    clicking the finding still pins the whole set on the timeline."""
    rows = _rows(conn,
                 "SELECT id, node, ts_epoch, summary FROM events "
                 "WHERE subsystem='oom' OR (category='os_kernel' AND "
                 "severity='critical') ORDER BY ts_epoch")
    by_node = {}
    for r in rows:
        by_node.setdefault(r["node"], []).append(r)

    out = []
    for node, evs in by_node.items():
        ids = [e["id"] for e in evs]
        stamps = [e["ts_epoch"] for e in evs if e["ts_epoch"] is not None]
        victims, invokers = {}, {}
        for e in evs:
            m = _OOM_VICTIM_RE.search(e["summary"] or "")
            if m:
                comm, rss = m.group(2), m.group(3)
                v = victims.setdefault(comm, {"n": 0, "peak_kb": 0})
                v["n"] += 1
                if rss:
                    v["peak_kb"] = max(v["peak_kb"], int(rss))
            mi = _OOM_INVOKER_RE.search(e["summary"] or "")
            if mi:
                invokers[mi.group(1)] = invokers.get(mi.group(1), 0) + 1

        kills = sum(v["n"] for v in victims.values())
        # No "Killed process" line means the filter matched an OOM episode whose
        # victim line fell outside the capture; report the matched lines instead
        # of claiming zero kills.
        shown = kills or len(evs)
        unit = "kill" if kills else "OOM kernel line"
        title = (f"OOM killer fired {shown}x on {node}" if shown > 1
                 else f"OOM killer fired on {node}")

        parts = []
        if stamps:
            lo, hi = min(stamps), max(stamps)
            # A span only means something for more than one; a single kill
            # still writes several lines a second apart, and "1 kill between
            # 03:56:34 and 03:56:35" reads as though something recurred.
            parts.append(
                f"{shown} {unit}s between {_fmt_ts(lo)} and {_fmt_ts(hi)}"
                if shown > 1 and hi > lo else f"{shown} {unit} at {_fmt_ts(lo)}")
        if victims:
            top = sorted(victims.items(), key=lambda kv: -kv[1]["n"])
            parts.append("victims: " + ", ".join(
                f"{c} x{v['n']}" + (f" (peak {v['peak_kb'] / 1024 ** 2:.1f} GB rss)"
                                    if v["peak_kb"] else "")
                for c, v in top[:4]))
        if invokers:
            parts.append("allocation requested by: " + ", ".join(
                sorted(invokers, key=lambda k: -invokers[k])[:4]))
        parts.append("Click to pin every OOM line on the timeline.")

        out.append({
            "ts_epoch": min(stamps) if stamps else None,
            "node": node, "severity": "critical", "kind": "oom",
            "title": title,
            "detail": ". ".join(parts),
            "handoff": None,
            "related": ids,
        })
    return out


# RPCs issued only during a topology change — no response here is a real
# rebalance hand-off failure. GetCurrentTopology/GetTaskList, by contrast, are
# routine polls ns_server runs continuously, so a lone unanswered poll is a
# health hint, not a rebalance failure.
_REBALANCE_CRITICAL = {"PrepareTopologyChange", "StartTopologyChange",
                       "CancelTask"}


def _timeouts(conn):
    """One rollup noting that process-timeout diagnostics were dumped.

    timeout_diag_logger fires only when a gen_server call blocked past its
    timeout (>=15s for the common ns_config path) -- never in a healthy node,
    so its mere presence is a fact worth surfacing. Each incident logs one
    'Got timeout ...' header followed by a per-process snapshot; we count
    ONLY the headers. The snapshot is parsed into process_dump and shown in
    the Snapshots view's Processes tab, not as timeline events. Facts only:
    how many, which nodes, the span. The reader drills into Snapshots ->
    Processes from there."""
    rows = _rows(conn,
                 "SELECT id, node, ts_epoch, ts_local FROM events "
                 "WHERE subsystem='timeout_diag_logger' "
                 "AND summary LIKE 'Got timeout%' ORDER BY ts_epoch")
    if not rows:
        return []
    nodes = sorted({r["node"] for r in rows if r["node"]})
    nodelist = ", ".join(nodes) if nodes else "?"
    span = (f" between {rows[0]['ts_local']} and {rows[-1]['ts_local']}"
            if len(rows) > 1 else f" at {rows[0]['ts_local']}")
    return [{
        "ts_epoch": rows[0]["ts_epoch"], "node": rows[0]["node"],
        "severity": "warn", "kind": "timeouts",
        "title": "Process timeouts logged",
        "detail": (f"{len(rows)} process-timeout diagnostic(s) on {nodelist}"
                   f"{span}. Each marks a gen_server call that blocked past its "
                   "timeout (>=15s on the common ns_config path). Dumps are "
                   "rate-limited to <=1 per 5s per node, so the count is a "
                   "floor on how many processes stalled. The timeline events "
                   "carry only the 'Got timeout' headers; the per-process "
                   "snapshot for each dump is in the Snapshots view, "
                   "Processes tab (timeout_diag_logger source)."),
        "handoff": None, "related": [r["id"] for r in rows],
    }]


def _service_not_responding(conn):
    out = []
    rows = _rows(conn,
                 "SELECT id, node, ts_epoch, summary, fields FROM events "
                 "WHERE source='json_rpc' AND json_extract(fields,'$.phase')="
                 "'no_response' ORDER BY ts_epoch")
    for r in rows:
        f = json.loads(r["fields"] or "{}")
        # A call still outstanding when the snapshot was taken was truncated,
        # not unanswered — skip it (set by the json_rpc parser).
        if f.get("at_capture_boundary"):
            continue
        svc = f.get("service") or "?"
        method = f.get("method")
        if method in _REBALANCE_CRITICAL:
            out.append({
                "ts_epoch": r["ts_epoch"], "node": r["node"],
                "severity": "error", "kind": "service_no_response",
                "title": f"{svc} did not respond to rebalance call {method}",
                "detail": r["summary"],
                "handoff": None,
                "related": [r["id"]],
            })
        else:
            out.append({
                "ts_epoch": r["ts_epoch"], "node": r["node"],
                "severity": "warn", "kind": "service_poll_no_response",
                "title": f"{svc} did not answer a {method} poll",
                "detail": r["summary"],
                "handoff": None,
                "related": [r["id"]],
            })
    return out


def _message_queue(conn):
    """Backed-up process mailboxes (message_queue_len >= _MQ_THRESHOLD).

    Two sources, both threshold-gated (we flag the LONG mailboxes, never every
    process): the diag.log collection-time snapshot (message_queue timeline
    events, with drill-down IDs) and timeout_diag_logger's incident-time dumps
    (read straight off process_dump -- those list every process, so they're not
    surfaced as per-process timeline events)."""
    out = []
    rows = _rows(conn,
                 "SELECT id, node, ts_epoch, summary, fields FROM events "
                 "WHERE subsystem='message_queue' AND CAST(json_extract("
                 "fields,'$.message_queue_len') AS INT) >= ? ORDER BY CAST("
                 "json_extract(fields,'$.message_queue_len') AS INT) DESC",
                 [_MQ_THRESHOLD])
    for r in rows:
        f = json.loads(r["fields"] or "{}")
        out.append({
            "ts_epoch": r["ts_epoch"], "node": r["node"], "severity": "error",
            "kind": "message_queue",
            "title": f"{f.get('process')} had message_queue_len="
                     f"{f.get('message_queue_len')} on {r['node']}",
            "detail": r["summary"] + "  (diag.log process_info dump)",
            "handoff": None,
            "related": [r["id"]],
        })
    # Incident-time: long mailboxes captured by timeout_diag_logger.
    to_rows = _rows(conn,
                    "SELECT node, capture_ts, name, pid, message_queue_len "
                    "FROM process_dump WHERE source='timeout' "
                    "AND message_queue_len >= ? "
                    "ORDER BY message_queue_len DESC", [_MQ_THRESHOLD])
    for r in to_rows:
        who = r["name"] or r["pid"] or "?"
        q = r["message_queue_len"]
        out.append({
            "ts_epoch": r["capture_ts"], "node": r["node"], "severity": "error",
            "kind": "message_queue",
            "title": f"{who} had message_queue_len={q} on {r['node']}",
            "detail": f"message_queue_len={q} on {who}  "
                      "(timeout_diag_logger dump at timeout time)",
            "handoff": None,
            "related": [],
        })
    return out


def _stale_tasks(conn):
    out = []
    rows = _rows(conn,
                 "SELECT id, node, ts_epoch, summary, fields FROM events "
                 "WHERE summary LIKE '%Cleaning up stale tasks%' "
                 "ORDER BY ts_epoch")
    for r in rows:
        f = json.loads(r["fields"] or "{}")
        svc = f.get("service") or "?"
        out.append({
            "ts_epoch": r["ts_epoch"], "node": r["node"], "severity": "warn",
            "kind": "stale_tasks",
            "title": f"Stale service tasks cleaned up ({svc})",
            "detail": r["summary"],
            "handoff": None,
            "related": [r["id"]],
        })
    return out


_FAILOVER_ACTIONS = (
    "%Starting failover%", "%Failed over%", "%Failing over%",
    "%Failover completed%", "%Failover exited%", "%automatically fail%over%",
    "%Could not automatically%", "%Starting graceful failover%")


def _failover(conn):
    out = []
    like = " OR ".join("summary LIKE ?" for _ in _FAILOVER_ACTIONS)
    rows = _rows(conn,
                 f"SELECT id, node, ts_epoch, summary FROM events "
                 f"WHERE category='failover' AND ({like}) ORDER BY ts_epoch",
                 list(_FAILOVER_ACTIONS))
    # Collapse bursts on the same node within _WINDOW into one finding.
    clustered = []
    for r in rows:
        if (clustered and clustered[-1]["node"] == r["node"]
                and r["ts_epoch"] is not None
                and clustered[-1]["ts_epoch"] is not None
                and r["ts_epoch"] - clustered[-1]["ts_epoch"] <= _WINDOW):
            clustered[-1]["ids"].append(r["id"])
            continue
        clustered.append({"node": r["node"], "ts_epoch": r["ts_epoch"],
                          "summary": r["summary"], "id": r["id"],
                          "ids": [r["id"]]})
    for r in clustered:
        ts, node = r["ts_epoch"], r["node"]
        out.append({
            "ts_epoch": ts, "node": node, "severity": "error", "kind": "failover",
            "title": f"Failover involving {node}",
            "detail": r["summary"],
            "handoff": None,
            "related": r["ids"],
        })
    return out


def _crashes(conn):
    """Surface crash/SUPERVISOR/CRASH REPORT volume as context only.

    Every real cluster carries crash + recovery reports as background noise —
    even repeated crashes cluster-wide are routine — so this is deliberately an
    info-level note (sorts to the bottom, no 'investigate' framing), not a
    warning. It's a count to orient with, not a problem to chase."""
    rows = _rows(conn,
                 "SELECT node, COUNT(*) c FROM events WHERE category='crash' "
                 "AND severity IN ('error','critical') GROUP BY node "
                 "HAVING c > 0")
    out = []
    for r in rows:
        out.append({
            "ts_epoch": None, "node": r["node"], "severity": "info",
            "kind": "crashes",
            "title": f"{r['c']} crash/recovery reports on {r['node']}",
            "detail": "Background context — crash + recovery reports are normal "
                      "in any cluster. Browse them with category=crash.",
            "handoff": None,
            "related": [],
        })
    return out


def _clock_sync(conn):
    """Node clock out of sync (NTP). ns_tick_agent compares each node's time to
    the master and, past the threshold (default 1s offset / 0.5s RTT),
    menelaus_web_alerts_srv raises the time_out_of_sync alert -- so ns_server has
    ALREADY decided the clocks disagree; we just surface its verdict. The alert
    text literally tells the operator to check NTP, so this is the NTP finding
    too. One finding per node carrying the alert, with the count and span.

    Matters doubly for this tool: cross-node correlation assumes comparable
    clocks, so a flagged node's events may be mis-placed on the timeline."""
    rows = _rows(conn,
                 "SELECT id, node, ts_epoch, ts_local FROM events "
                 "WHERE summary LIKE '%is not synchronized%' ORDER BY ts_epoch")
    by_node = {}
    for r in rows:
        g = by_node.setdefault(r["node"], {"ids": [], "lo": None, "hi": None,
                                           "lo_l": None, "hi_l": None})
        g["ids"].append(r["id"])
        if r["ts_epoch"] is not None:
            if g["lo"] is None:
                g["lo"], g["lo_l"] = r["ts_epoch"], r["ts_local"]
            g["hi"], g["hi_l"] = r["ts_epoch"], r["ts_local"]
    out = []
    for node, g in by_node.items():
        n = len(g["ids"])
        span = (f" between {(g['lo_l'] or '')[:19]} and {(g['hi_l'] or '')[:19]}"
                if n > 1 and g["lo_l"] else
                (f" at {(g['lo_l'] or '')[:19]}" if g["lo_l"] else ""))
        out.append({
            "ts_epoch": g["hi"], "node": node, "severity": "warn",
            "kind": "clock_sync",
            "title": f"Clock not synchronized on {node}",
            "detail": (f"{n} time_out_of_sync alert(s){span}. ns_tick_agent "
                       "found this node's clock too far from the master; check "
                       "NTP. Cross-node timeline correlation for this node may "
                       "be skewed."),
            "handoff": None, "related": g["ids"][:40],
        })
    return out


# Reason-ish keys an event_log payload may carry; first present wins.
_REASON_KEYS = ("reason", "error", "message", "completion_message",
                "exit_reason", "errorMessage")


def _event_reason(fields_json):
    try:
        f = json.loads(fields_json or "{}")
    except (ValueError, TypeError):
        return None
    for k in _REASON_KEYS:
        v = f.get(k)
        if v:
            return str(v)[:300]
    return None


def _operation_id(fields_json):
    """The rebalance/failover id stamped on an event_log span, or None.

    ns_orchestrator stamps {operation_id, RebalanceId} on rebalance_initiated
    and ns_rebalance_observer stamps the same on the terminator; both land in
    extra_attributes. It equals the report's top-level rebalanceId, so this is
    an exact join, not a time correlation."""
    try:
        f = json.loads(fields_json or "{}")
    except (ValueError, TypeError):
        return None
    attrs = f.get("extra_attributes")
    oid = attrs.get("operation_id") if isinstance(attrs, dict) else None
    return oid if isinstance(oid, str) and oid else None


def _vb_list(vbs):
    """'48, 64, 80' -- capped, and explicit about what was dropped. A silent
    truncation would read as 'that was all of them'."""
    shown = ", ".join(str(v) for v in vbs[:_REPORT_VB_SAMPLE])
    extra = len(vbs) - _REPORT_VB_SAMPLE
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def _stall_detail(conn, oid):
    """Where an operation stopped, from its rebalance report. None if no report.

    Every clause is a recorded field: `state` and `stuck_phases` come from
    ns_server's own three-state phase encoding (a phase with startTime set and
    completedTime false was entered and never left), target nodes are
    afterChain -- beforeChain, and docs left/total are replicationInfo. No
    statement of cause is made or implied -- the reader draws that from the
    facts, per the module docstring.

    The absence of a report is itself worth stating: only ?NUM_REBALANCE_REPORTS
    (5) are retained, so an older operation legitimately has none, and saying so
    stops someone hunting for a file that was rotated away."""
    rep = _rows(conn, "SELECT services, move_count FROM rebalance_report "
                      "WHERE rebalance_id = ?", (oid,))
    if not rep:
        return "no rebalance report retained for this operation " \
               "(only the 5 most recent are kept)"
    total_moves = rep[0]["move_count"] or 0
    moves = _rows(conn,
                  "SELECT vbucket, bucket, stuck_phases, stuck_since_ts, "
                  "target_nodes, docs_left, docs_total, state "
                  "FROM rebalance_move WHERE rebalance_id = ? "
                  "AND state != 'done' ORDER BY stuck_since_ts, vbucket", (oid,))
    parts = []
    stuck = [m for m in moves if m["state"] == "in_flight"]
    never = [m for m in moves if m["state"] == "not_started"]
    if stuck:
        # Group by the phase set a move is sitting in: moves wedged in the same
        # phase are one fact, not N.
        groups = {}
        for m in stuck:
            groups.setdefault(m["stuck_phases"] or "[]", []).append(m)
        for phases_json, group in sorted(groups.items(),
                                         key=lambda kv: -len(kv[1])):
            try:
                phases = "+".join(json.loads(phases_json))
            except (ValueError, TypeError):
                phases = "?"
            vbs = [m["vbucket"] for m in group]
            targets = sorted({n for m in group
                              for n in json.loads(m["target_nodes"] or "[]")})
            since = min((m["stuck_since_ts"] for m in group
                         if m["stuck_since_ts"] is not None), default=None)
            left = sum(m["docs_left"] or 0 for m in group)
            tot = sum(m["docs_total"] or 0 for m in group)
            seg = f"{len(group)} move(s) entered {phases} and never completed" \
                  f" (vb {_vb_list(vbs)}"
            if since:
                seg += f", since {_fmt_ts(since)}"
            if targets:
                seg += f", to {', '.join(targets)}"
            seg += ")"
            if tot:
                seg += f", {left} of {tot} docs still to replicate"
            parts.append(seg)
    if never:
        parts.append(f"{len(never)} move(s) never started "
                     f"(vb {_vb_list([m['vbucket'] for m in never])})")
    if not parts:
        return f"report retained: all {total_moves} recorded move(s) completed"
    try:
        services = json.loads(rep[0]["services"] or "{}")
    except (ValueError, TypeError):
        services = {}
    timings = ", ".join(
        f"{name} {info['time_taken_ms'] / 1000:.1f}s"
        for name, info in sorted(services.items())
        if isinstance(info, dict) and isinstance(info.get("time_taken_ms"),
                                                 (int, float)))
    detail = f"Report: {'; '.join(parts)}, of {total_moves} recorded move(s)"
    return detail + (f". Per service: {timings}" if timings else "")


def _rebalance(conn):
    """Rebalance failed / interrupted, from the trusted curated event_log
    (rebalance_failed=error id 4, rebalance_interrupted=info id 5). Directly
    answers 'why did rebalance fail?' with ns_server's own recorded reason.

    event_log is cluster-replicated, so the same event appears in every node's
    capture -- dedup by (ts_epoch, summary) and report once as a cluster event.
    A failure is error severity; an interruption (often a user-initiated stop)
    is warn. Fact only: that it ended abnormally, when, and the recorded
    reason.

    Where available, the operation's rebalance report is joined in by
    operation_id to add WHERE it stopped -- see _stall_detail. That join is
    gated to failed/interrupted here by construction: a successful rebalance
    never reaches this rule, and slowness is deliberately not a trigger (there
    is no threshold defensible from the data, whereas 'entered a phase and
    never left it' is a recorded fact)."""
    rows = _rows(conn,
                 "SELECT id, node, ts_epoch, ts_local, summary, fields FROM "
                 "events WHERE source='event_log' AND (summary LIKE "
                 "'%Rebalance failed%' OR summary LIKE '%Rebalance interrupted%')"
                 " ORDER BY ts_epoch")
    seen, out = set(), []
    for r in rows:
        key = (r["ts_epoch"], r["summary"])
        if key in seen:
            continue
        seen.add(key)
        failed = "failed" in (r["summary"] or "").lower()
        reason = _event_reason(r["fields"])
        when = (r["ts_local"] or "")[:19]
        detail = r["summary"]
        if reason:
            detail += f" — {reason}"
        oid = _operation_id(r["fields"])
        if oid:
            stall = _stall_detail(conn, oid)
            if stall:
                detail += f". {stall}"
        out.append({
            "ts_epoch": r["ts_epoch"], "node": "(cluster)",
            "severity": "error" if failed else "warn",
            "kind": "rebalance",
            "title": ("Rebalance failed" if failed else "Rebalance interrupted")
                     + (f" @ {when}" if when else ""),
            "detail": detail,
            "handoff": None, "related": [r["id"]],
        })
    return out


def _node_versions(conn):
    return {r["name"]: r["version"]
            for r in _rows(conn, "SELECT name, version FROM nodes")}


def _pools_isolated(conn, node, lo, hi):
    """True if NO non-/pools/default request was stalled/active during the
    [lo, hi] stall window on this node. Isolation is part of the VM-bug
    fingerprint; broad stalls point at general overload instead."""
    if lo is None or hi is None:
        return True
    others = _rows(
        conn,
        "SELECT json_extract(fields,'$.start_epoch') s, ts_epoch e "
        "FROM events WHERE node=? AND source IN "
        "('http_access','http_access_internal') AND json_extract(fields,"
        "'$.path_base') != '/pools/default' AND CAST(json_extract(fields,"
        "'$.resp_ms') AS INT) >= ? AND ts_epoch IS NOT NULL",
        [node, _POOLS_STALL_MS])
    for r in others:
        s = r["s"] if r["s"] is not None else r["e"]
        if s <= hi and r["e"] >= lo:   # overlaps the window
            return False
    return True


def _quiet_window(conn, node, lo, hi):
    """True if there's NO connectivity / OS-kernel / timeout activity on the
    node during [lo, hi]. The VM bug shows no obvious resource-pressure or
    connectivity cause — the process is simply suspended. (PSI/allocstall
    pressure lives in stats.log; confirm that separately in the stats view.)"""
    if lo is None or hi is None:
        return True
    # "timeout" only counts from non-http logs — http_access URLs carry benign
    # '?timeout=' query params (e.g. /_prometheusMetrics?timeout=10000).
    n = conn.execute(
        "SELECT COUNT(*) FROM events WHERE node=? AND ts_epoch BETWEEN ? AND ? "
        "AND (category IN ('connectivity','os_kernel') OR (summary LIKE "
        "'%timeout%' AND source NOT IN ('http_access','http_access_internal')))",
        [node, lo, hi]).fetchone()[0]
    return n == 0


def _wake_clusters(rows):
    """Group stalled requests whose COMPLETION times fall within _WAKE_WINDOW
    of each other (they recovered together)."""
    clusters, cur = [], []
    for r in sorted(rows, key=lambda r: r["ts_epoch"] or 0):
        if cur and r["ts_epoch"] - cur[-1]["ts_epoch"] > _WAKE_WINDOW:
            clusters.append(cur)
            cur = []
        cur.append(r)
    if cur:
        clusters.append(cur)
    return clusters


def _is_spontaneous_wake(cluster):
    """The fingerprint: >=2 requests that COMPLETED together but had been
    stalled for DIFFERENT durations (i.e. started at different times and all
    woke at once), not a burst that started and finished together."""
    if len(cluster) < 2:
        return False
    comp_span = cluster[-1]["ts_epoch"] - cluster[0]["ts_epoch"]
    durs = [r["resp_ms"] for r in cluster if r["resp_ms"] is not None]
    if not durs:
        return False
    dur_spread = (max(durs) - min(durs)) / 1000.0
    return comp_span <= _WAKE_WINDOW and dur_spread >= _WAKE_DURATION_SPREAD


def _pools_default_stall(conn, version):
    """Known recurring issue: /pools/default tasks outstanding due to an Erlang
    VM bug (otp#10651) on 7.6.8-7.6.11 / 8.0.0-8.0.2. Saves a 24-hour hunt.

    Fingerprint: stalled /pools/default requests that all recover SIMULTANEOUSLY
    (a tight completion cluster despite varying stall durations) while NO other
    request is stalled — on an affected release."""
    rows = _rows(conn,
                 "SELECT id, node, ts_epoch, summary, "
                 "CAST(json_extract(fields,'$.resp_ms') AS INT) resp_ms, "
                 "json_extract(fields,'$.start_epoch') start_epoch "
                 "FROM events WHERE source IN ('http_access',"
                 "'http_access_internal') AND json_extract(fields,"
                 "'$.path_base')='/pools/default' AND resp_ms >= ? "
                 "AND ts_epoch IS NOT NULL ORDER BY ts_epoch",
                 [_POOLS_STALL_MS])
    if not rows:
        return []
    versions = _node_versions(conn)
    by_node = {}
    for r in rows:
        by_node.setdefault(r["node"], []).append(dict(r))
    out = []
    for node, rs in by_node.items():
        nver = versions.get(node) or version
        affected = _pools_default_affected(nver)
        # Strongest spontaneous-wake cluster on this node.
        clusters = _wake_clusters(rs)
        wake = next((c for c in sorted(clusters, key=len, reverse=True)
                     if _is_spontaneous_wake(c)), None)
        focus = wake or max(clusters, key=len)
        starts = [c["start_epoch"] for c in focus if c["start_epoch"]]
        lo = min(starts) if starts else None
        hi = max(c["ts_epoch"] for c in focus)
        isolated = _pools_isolated(conn, node, lo, hi)
        quiet = _quiet_window(conn, node, lo, hi)
        spontaneous = wake is not None

        fp = ["node-local /pools/default stall"]
        if spontaneous:
            fp.append(f"{len(wake)} requests woke up simultaneously")
        if isolated:
            fp.append("no other requests stalled")
        fp_str = "; ".join(fp)

        # Fingerprint is primary; version + tickets are corroboration. Full
        # fingerprint = only /pools/default, isolated, simultaneous wake, and no
        # connectivity cause (the process is suspended by the VM). `quiet` (no
        # connectivity/kernel/timeout activity) still gates `strong` but is not
        # asserted in the fingerprint -- pressure (PSI/allocstall) is NOT checked
        # here, so the handoff tells the reader to check it rather than claiming
        # it was clear.
        strong = spontaneous and isolated and quiet
        ref = f"See {_pools_tickets(nver)}; upstream {_OTP_ISSUE}."
        if strong and affected is False:
            sev = "error"
            handoff = (f"{fp_str}. Matches the Erlang VM /pools/default stall "
                       f"fingerprint, but {nver} is believed fixed — verify / "
                       f"possible regression. {ref}")
        elif strong:
            sev = "critical"
            vtag = f"on {nver} " if affected else f"({nver or 'version?'}) "
            handoff = (f"Matches the known Erlang VM bug {vtag}— {fp_str}. The "
                       "process is suspended by the VM and /pools/default "
                       "recovers on its own; likely this. Check pressure "
                       f"statistics. {ref} In observed cases, the simultaneous "
                       "wake-up coincided with a cb_creds_rotation.")
        elif affected is True:
            sev = "error"
            handoff = (f"{fp_str} on affected release {nver}. Partial "
                       f"fingerprint — likely the Erlang VM stall. {ref}")
        else:
            sev = "warn"
            handoff = (f"{fp_str}. Partial /pools/default stall fingerprint; if "
                       f"this is the VM bug it recovers on its own. {ref}")
        out.append({
            "ts_epoch": hi, "node": node, "severity": sev,
            "kind": "known_pools_default_stall",
            "title": f"{len(rs)} stalled /pools/default request(s) on {node}"
                     f"{', woke up together' if spontaneous else ''}"
                     f" [{nver or 'version?'}]",
            "detail": ("fingerprint: " + fp_str + " | slowest: " +
                       "; ".join(r["summary"] for r in rs[:3])),
            "handoff": handoff, "related": [r["id"] for r in rs],
        })
    return out


# nodedown reasons that mean a real distribution/network drop rather than a
# planned stop. net_kernel monitor_nodes delivers these via nodedown_reason.
_NODEDOWN_WORRISOME = {"net_tick_timeout", "connection_closed", "etimedout",
                       "ehostunreach", "enetunreach", "econnrefused",
                       "disconnect"}
_NODE_UP_RE = re.compile(r"saw that node '?(" + nodes.NODE + r")'? came up")
_NODE_DOWN_RE = re.compile(r"saw that node '?(" + nodes.NODE + r")'? went down")
_NODEDOWN_REASON_RE = re.compile(r"nodedown_reason,\s*([a-z_]+)")


def _net_kernel(conn):
    """net_kernel node-membership transitions (ns_node_disco monitor_nodes):
    nodeup / nodedown, tagged with the nodedown_reason. Grouped per
    (node, type, reason). Routine transitions are info-level context; a
    nodedown with a connectivity-failure reason is flagged warn (severity is a
    factual calibration on the reason atom, not a root-cause guess).

    Scoped to source='debug' (a superset of info.log) so the user-log line that
    lands in both files is not double-counted."""
    rows = _rows(conn,
                 "SELECT id, node, ts_epoch, summary, raw FROM events "
                 "WHERE source='debug' AND subsystem='ns_node_disco' AND "
                 "(summary LIKE '%came up%' OR summary LIKE '%went down%') "
                 "ORDER BY ts_epoch")
    groups = {}
    for r in rows:
        s = r["summary"] or ""
        if "went down" in s:
            etype = "nodedown"
            m = _NODE_DOWN_RE.search(s)
            rm = _NODEDOWN_REASON_RE.search(r["raw"] or "")
            reason = rm.group(1) if rm else "unknown"
        elif "came up" in s:
            etype, m, reason = "nodeup", _NODE_UP_RE.search(s), None
        else:
            continue
        peer = m.group(1) if m else "?"
        g = groups.setdefault((r["node"], etype, reason),
                              {"ids": [], "peers": set(), "hi": None})
        g["ids"].append(r["id"])
        g["peers"].add(peer)
        if r["ts_epoch"] is not None:
            g["hi"] = (r["ts_epoch"] if g["hi"] is None
                       else max(g["hi"], r["ts_epoch"]))
    out = []
    for (node, etype, reason), g in groups.items():
        n = len(g["ids"])
        peers = ", ".join(sorted(g["peers"])[:5])
        if etype == "nodedown":
            worrisome = reason in _NODEDOWN_WORRISOME
            out.append({
                "ts_epoch": g["hi"], "node": node,
                "severity": "warn" if worrisome else "info",
                "kind": "net_kernel",
                "title": f"{n} nodedown (reason={reason}) seen by {node}",
                "detail": f"peers: {peers} | net_kernel monitor_nodes",
                "handoff": None,
                "related": g["ids"][:20],
            })
        else:
            out.append({
                "ts_epoch": g["hi"], "node": node, "severity": "info",
                "kind": "net_kernel",
                "title": f"{n} nodeup seen by {node}",
                "detail": f"peers: {peers} | net_kernel monitor_nodes",
                "handoff": None,
                "related": g["ids"][:20],
            })
    return out


# --- auto-failover progression -------------------------------------------
#
# The auto-failover monitor runs on the ORCHESTRATOR; these lines are in the
# orchestrator's debug.log. auto_failover_logic dumps the #node_state{} record
# via ~p, which WRAPS across lines, so we match the folded `raw`, not `summary`.
# A node walks up -> half_down -> nearly_down -> failover (down_counter rises
# each tick); it returns to `up` if it recovers.
#
# Real captured forms (validated against AutoFailoverTriggerTest -k):
#   Incremented down state:
#   {node_state,{'n_11@127.0.0.1',<<"f463...">>},
#               0,up,undefined}
#   ->{node_state,{'n_11@127.0.0.1',<<"f463...">>},
#                 0,half_down,undefined}
#   Transitioned node {'n_11@127.0.0.1',<<"f463...">>} state half_down -> up
#   Node 'n_11@127.0.0.1' is considered down. Reason:"The cluster manager did
#       not respond. "
#   Node ('n_11@127.0.0.1') was automatically failed over. Reason: The cluster
#       manager did not respond.
_AF_STATE_RANK = {"up": 0, "new": 0, "half_down": 1, "nearly_down": 2,
                  "failover": 3}
# New state = the record AFTER the `->` in an "Incremented down state" dump.
_AF_INCREMENT_RE = re.compile(
    r"->\{node_state,\{'?([\w@.\-]+)'?,\s*<<[^>]*>>\},\s*\d+,(\w+),")
_AF_RECOVER_RE = re.compile(
    r"Transitioned node \{'?([\w@.\-]+)'?,\s*<<[^>]*>>\} state (\w+) -> up")
_AF_REASON_RE = re.compile(
    r"Node '?([\w@.\-]+)'? is considered down\. Reason:\"(.*?)\"", re.S)
_AF_FAILED_RE = re.compile(
    r"Node \('?([\w@.\-]+)'?\) was automatically failed over\. Reason:\s*(.+)")


def _af_norm_reason(reason):
    """Trim trailing punctuation/space so the same reason logged by different
    code paths (e.g. 'respond. ' vs 'respond') dedups to one."""
    return (reason or "").strip().rstrip(". ").strip()


# The configured auto-failover timeout is stated authoritatively by ns_server
# itself on a ?USER_LOGGER line (auto_failover.erl:505/510 on enable,
# :521 on change) -- so we read it rather than inferring it from the
# down_counter ladder span. Both forms ("Enabled ... with timeout N",
# "Updating ... timeout to N") carry the value in seconds.
_AF_TIMEOUT_RE = re.compile(
    r"auto-failover (?:with timeout|timeout to)\s+(\d+)", re.I)


def _af_configured_timeout(conn, before_ts):
    """The auto-failover timeout (seconds) AUTHORITATIVELY in effect at
    `before_ts` -- the latest enable/update user-log line at or before the
    failover. Returns None when the capture has no such line at/before the
    failover, i.e. the timeout is INCONCLUSIVE (the enable line predates a
    windowed capture, or rotated out). We deliberately do NOT fall back to a
    line logged AFTER the failover: a value set afterwards may not be what was
    in effect during it, so reporting it would be a guess. Skip it instead."""
    rows = _rows(conn,
                 "SELECT ts_epoch, summary FROM events WHERE summary LIKE "
                 "'%auto-failover%timeout%' AND ts_epoch IS NOT NULL "
                 "ORDER BY ts_epoch")
    at = None
    for r in rows:
        if before_ts is not None and r["ts_epoch"] > before_ts:
            break                        # rows sorted; nothing more at/before
        m = _AF_TIMEOUT_RE.search(r["summary"] or "")
        if m:
            at = int(m.group(1))         # latest at/before wins
    return at


# A down-progression is a contiguous run of ticks; a gap larger than this (the
# monitor ticks every ~1s) means a separate episode, not the same one. The
# bootstrap blip and the real failover are tens of seconds apart, so segmenting
# on this gap keeps each episode's ladder and time-span honest.
_AF_EPISODE_GAP = 15
# >= this many recovered (non-failover) episodes for one (observer, target)
# within _AF_FLAP_WINDOW collapses into a single "flapping" finding.
_AF_FLAP_COUNT = 3
_AF_FLAP_WINDOW = 300


def _af_new_episode():
    return {"ids": [], "max_state": "up", "t0": None, "ts": None,
            "ladder": [], "reasons": [], "failed": False, "fail_reason": None}


def _af_step(ep, state, ts, eid):
    if eid is not None:
        ep["ids"].append(eid)
    if state is not None:
        if not ep["ladder"] or ep["ladder"][-1] != state:
            ep["ladder"].append(state)
        if _AF_STATE_RANK.get(state, 0) > _AF_STATE_RANK.get(ep["max_state"], 0):
            ep["max_state"] = state
    if ts is not None:
        ep["t0"] = ts if ep["t0"] is None else min(ep["t0"], ts)
        ep["ts"] = ts if ep["ts"] is None else max(ep["ts"], ts)


def _auto_failover_progression(conn):
    """Answer 'why was this node auto-failed-over?' by reconstructing each
    auto-failover down-state EPISODE from the orchestrator's log.

    The observer is the node whose log carried the progression (the
    orchestrator); the target is the node that went down. The event stream per
    (observer, target) is segmented into episodes (separated by a recovery, a
    failover, or a tick gap), so a bootstrap blip and a real failover are
    distinct findings rather than one merged ladder.

    Severity is calibrated to how far an episode got: half_down then recovered
    is info-level noise (bootstrap/transient blips look like this); reaching
    nearly_down or an actual failover is warn; many recovered episodes collapse
    into one warn 'flapping' finding. Each finding surfaces WHICH node, the
    progression ladder, and the REASON (the user's 'why')."""
    # Build a time-ordered step stream per (observer, target).
    streams = {}  # (observer, target) -> list[ (ts, kind, state, reason, id) ]

    def _add(observer, target, ts, kind, state, reason, eid):
        streams.setdefault((observer, target), []).append(
            (ts, kind, state, reason, eid))

    for r in _rows(conn,
                   "SELECT id, node, ts_epoch, raw FROM events WHERE "
                   "source='debug' AND subsystem IN ('auto_failover_logic',"
                   "'auto_failover') AND ts_epoch IS NOT NULL ORDER BY ts_epoch"):
        raw = r["raw"] or ""
        obs = r["node"]
        for m in _AF_INCREMENT_RE.finditer(raw):
            _add(obs, m.group(1), r["ts_epoch"], "inc", m.group(2), None,
                 r["id"])
        m = _AF_RECOVER_RE.search(raw)
        if m:
            _add(obs, m.group(1), r["ts_epoch"], "rec", None, None, r["id"])
        m = _AF_REASON_RE.search(raw)
        if m:
            _add(obs, m.group(1), r["ts_epoch"], "reason", None,
                 _af_norm_reason(m.group(2)), r["id"])

    # The terminal alert is logged to both debug.log and info.log (same node,
    # same ts), so dedup by (observer, target, ts) to avoid a phantom episode.
    seen_fail = set()
    for r in _rows(conn,
                   "SELECT id, node, ts_epoch, summary, raw FROM events WHERE "
                   "summary LIKE '%was automatically failed over%' "
                   "ORDER BY ts_epoch"):
        m = _AF_FAILED_RE.search(r["summary"] or r["raw"] or "")
        if not m:
            continue
        dedup = (r["node"], m.group(1), r["ts_epoch"])
        if dedup in seen_fail:
            continue
        seen_fail.add(dedup)
        _add(r["node"], m.group(1), r["ts_epoch"], "fail", None,
             _af_norm_reason(m.group(2)), r["id"])

    # Segment each stream into episodes.
    episodes = {}  # (observer, target) -> list[episode]
    for key, steps in streams.items():
        steps.sort(key=lambda s: (s[0] if s[0] is not None else 0))
        eps, cur = [], None
        for ts, kind, state, reason, eid in steps:
            # A tick gap ends the current episode.
            if (cur is not None and cur["ts"] is not None and ts is not None
                    and ts - cur["ts"] > _AF_EPISODE_GAP):
                eps.append(cur)
                cur = None
            if cur is None:
                cur = _af_new_episode()
            if kind == "inc":
                _af_step(cur, state, ts, eid)
            elif kind == "reason":
                _af_step(cur, None, ts, eid)
                if reason and reason not in cur["reasons"]:
                    cur["reasons"].append(reason)
            elif kind == "rec":
                _af_step(cur, "up", ts, eid)
                eps.append(cur)       # recovery closes the episode
                cur = None
            elif kind == "fail":
                _af_step(cur, "failover", ts, eid)
                cur["failed"] = True
                cur["fail_reason"] = reason
                eps.append(cur)       # failover closes the episode
                cur = None
        if cur is not None:
            eps.append(cur)
        # Keep only episodes that actually went down.
        episodes[key] = [e for e in eps
                         if e["failed"] or _AF_STATE_RANK.get(e["max_state"]) >= 1]

    out = []
    for (observer, target), eps in episodes.items():
        # Flap rollup: many recovered episodes clustered in time -> one warn.
        recovered = [e for e in eps if not e["failed"]]
        if len(recovered) >= _AF_FLAP_COUNT:
            t0 = min(e["t0"] for e in recovered if e["t0"] is not None)
            tn = max(e["ts"] for e in recovered if e["ts"] is not None)
            if tn - t0 <= _AF_FLAP_WINDOW:
                ids = [i for e in recovered for i in e["ids"]][:40]
                reasons = []
                for e in recovered:
                    for rs in e["reasons"]:
                        if rs not in reasons:
                            reasons.append(rs)
                rstr = (" | reasons: " + "; ".join(reasons)) if reasons else ""
                out.append({
                    "ts_epoch": tn, "node": target, "severity": "warn",
                    "kind": "auto_failover_progression",
                    "title": f"{target} flapped down/up "
                             f"{len(recovered)}x, seen by {observer}",
                    "detail": (f"orchestrator {observer} saw {target} go down "
                               f"and recover {len(recovered)} times in "
                               f"~{round(tn - t0)}s{rstr}"),
                    "handoff": None,
                    "related": ids,
                })
                eps = [e for e in eps if e["failed"]]  # emit only failures below

        for e in eps:
            reasons = list(e["reasons"])
            if e["fail_reason"] and e["fail_reason"] not in reasons:
                reasons.insert(0, e["fail_reason"])
            rank = _AF_STATE_RANK.get(e["max_state"], 0)
            ladder = "->".join(e["ladder"]) if e["ladder"] else e["max_state"]
            span = (f" over ~{round(e['ts'] - e['t0'])}s"
                    if e["t0"] is not None and e["ts"] is not None
                    and e["ts"] > e["t0"] else "")
            if e["failed"]:
                sev, title = "warn", f"{target} was auto-failed-over by {observer}"
            elif rank >= 2:  # nearly_down — imminent auto-failover
                sev = "warn"
                title = f"{target} nearly auto-failed-over by {observer} (recovered)"
            else:            # half_down then recovered — transient blip
                sev = "info"
                title = f"{target} briefly seen down by {observer} (recovered)"
            rstr = (" | reasons: " + "; ".join(reasons)) if reasons else ""
            out.append({
                "ts_epoch": e["ts"], "node": target, "severity": sev,
                "kind": "auto_failover_progression",
                "title": title,
                "detail": (f"orchestrator {observer} tracked {target}: "
                           f"{ladder}{span}{rstr}"),
                "handoff": None,
                "related": e["ids"][:40],
            })
    return out


def auto_failover_episodes(conn):
    """The auto-failover down-state episodes, for callers outside this module.

    Same matcher the auto-failover rollup uses for its related IDs, returned as
    is: one entry per (observer, target) episode with its ladder, its reason
    strings and the IDs of every log line that built it. The orchestration
    drawer attaches these to a failover span so a click reaches the whole
    lead-up rather than the two event_log entries that bracket it."""
    return _auto_failover_progression(conn)


def _auto_failover_summary(conn):
    """ONE red finding rolling up every COMPLETED auto-failover (the terminal
    'was automatically failed over' alert). A long-lived cluster can rack up
    many auto-failovers since the beginning of time; collapsing them into a
    single finding marks 'nodes were auto-failed-over here' without cluttering
    the panel with one-per-event. Pure fact: which node, when, the reason
    string, and the coarse resource pressure on that node in the lead-up window
    (so "was it pressure or connectivity?" is answered inline, including the
    telling case where the node had stopped reporting stats). The down-state
    lead-up lives in _auto_failover_progression (demoted to timeline-only) and
    the timeline (category=failover)."""
    seen, evs = set(), []
    for r in _rows(conn,
                   "SELECT id, node, ts_epoch, ts_local, summary, raw FROM "
                   "events WHERE summary LIKE '%was automatically failed over%' "
                   "ORDER BY ts_epoch"):
        m = _AF_FAILED_RE.search(r["summary"] or r["raw"] or "")
        if not m:
            continue
        # Same alert lands in debug.log and info.log — dedup by (target, ts).
        key = (m.group(1), r["ts_epoch"])
        if key in seen:
            continue
        seen.add(key)
        evs.append((r["ts_epoch"], r["ts_local"], m.group(1),
                    _af_norm_reason(m.group(2)), r["id"]))
    if not evs:
        return []
    targets = []
    for _ts, _tl, t, _rs, _id in evs:
        if t not in targets:
            targets.append(t)
    # Configured timeout (authoritative, from the user-log line) is computed up
    # front: it both leads the detail and sizes the per-failover pressure-lookup
    # window. None = inconclusive (no enable/update line at/before the failover).
    timeout = _af_configured_timeout(conn, evs[-1][0])
    # Whether stats.log carried ANY pressure data; gates the per-line window
    # lookup so we don't tag every line "no samples" when the source is simply
    # absent (the _pressure / pressure_unavailable finding owns that case).
    pressure_available = db.query_pressure(conn, {})["available"]
    lines = []
    for ts_e, tl, t, rs, _id in evs:
        when = (tl or "")[:19] or "?"
        line = f"{t} @ {when}" + (f" — {rs}" if rs else "")
        pc = _pressure_in_window(conn, t, ts_e, timeout, pressure_available)
        if pc:
            line += f"  [{pc}]"
        lines.append(line)
    shown = "; ".join(lines[:20])
    if len(lines) > 20:
        shown += f"  (+{len(lines) - 20} more)"
    tlist = ", ".join(targets[:6]) + ("…" if len(targets) > 6 else "")
    noun = "auto-failover" if len(evs) == 1 else "auto-failovers"
    if timeout is not None:
        shown = f"auto-failover timeout: {timeout}s | " + shown
    # Carry the full down-state lead-up (not just the terminal alerts) so that
    # clicking the rollup surfaces the whole story — Incremented down state,
    # half_down/nearly_down ticks, the reason line, then the failover. The
    # progression matcher (demoted from the panel) already reconstructs those
    # episodes per target; union its related IDs for the failed-over targets.
    related = [e[4] for e in evs]
    tset = set(targets)
    for f in _auto_failover_progression(conn):
        if f["node"] in tset:
            related.extend(f.get("related", []))
    # Preserve order, drop dups, cap.
    related = list(dict.fromkeys(related))[:200]
    return [{
        "ts_epoch": evs[-1][0],
        "node": targets[0] if len(targets) == 1 else "(multiple)",
        "severity": "critical",
        "kind": "auto_failover",
        "title": (f"{len(evs)} {noun}: {tlist}"),
        "detail": shown,
        "handoff": None,
        "related": related,
    }]


def run(conn, version=None):
    """Compute all findings (does not write). Returns list[dict].

    The findings panel is reserved for rare, actionable "something is wrong"
    signals — NOT the cluster's normal lifecycle. Over a long-lived customer
    cluster, failovers / node membership changes / orchestrator handoffs /
    crashes accumulate since the beginning of time and are pure clutter on top;
    they remain fully browsable in the timeline (category/subsystem/node/range
    facets), they just don't surface as findings.

    Active findings (high-signal only):
      _oom                  — OOM killer fired (rare, critical, infra).
      _message_queue        — a process mailbox >= _MQ_THRESHOLD (overload).
      _auto_failover_summary— ONE red rollup of all completed auto-failovers.
      _rebalance            — rebalance failed / interrupted (curated event_log;
                              answers "why did rebalance fail?").
      _clock_sync           — node clock out of sync / NTP (ns_server's own
                              time_out_of_sync alert; also skews correlation).
      _disk                 — fullest-mount disk usage past ns_server's 80/85%
                              guardrail bars (coarse stats.log heartbeat).
      _timeouts             — ONE rollup that timeout_diag_logger dumps exist
                              (a gen_server call blocked past its timeout).
      _pools_default_stall  — the known Erlang VM /pools/default >60s stall
                              (the one detector whose matched conclusion IS the
                              deliverable).
      _snapshot             — collection-time facts (couchbase.log one-shots):
                              couchbase slice OOM-killed / at its memory ceiling,
                              and whether host reclaim ran. Detail in Snapshot view.
      _dying_cgroups        — fingerprint: an excessive dying-cgroup census (the
                              second detector whose matched conclusion is the
                              deliverable).

    Intentionally NOT surfaced (defined above, browsable in the timeline):
      _failover, _auto_failover_progression, _net_kernel,
      _service_not_responding, _stale_tasks, _crashes. Kept in code (the
      auto-failover progression matcher in particular was validated against
      real logs) so they are trivial to revive — add them back to `rules`.

    Removed rather than kept: _orchestrator, which inferred the leader from
    ns_orchestrator op lines and flagged competing mb_master heartbeats. Both
    questions are answered directly and over time by leadership.py -- the op
    lines are now an overlay on the leadership lanes, and its election-conflict
    matcher found 1 line on a capture where the leadership rules found 72.
    """
    findings = []
    rules = [_oom, _message_queue, _auto_failover_summary, _rebalance,
             _clock_sync, _pressure, _snapshot, _dying_cgroups, _disk,
             _timeouts, lambda c: _pools_default_stall(c, version)]
    for fn in rules:
        name = getattr(fn, "__name__", "known_issue")
        try:
            findings.extend(fn(conn))
        except Exception as e:  # a bad finding must not abort ingest
            findings.append({
                "ts_epoch": None, "node": "?", "severity": "info",
                "kind": "engine_error",
                "title": f"finding rule {name} failed",
                "detail": str(e), "handoff": None, "related": [],
            })
    return findings
