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
"""Cluster operations as time spans: rebalance and failover, who drove each one,
and how it ended.

This is a separate axis from mastership, deliberately. Being the master (see
leadership.py) is a state every node holds an opinion about; driving a rebalance
is a single cluster-scoped operation with a start, an end, an owner and an
outcome. Orchestration sits over and above the election: the master is the node
that MAY act, and these spans are what it actually did.

Source: the curated event_log, the same one promtimer annotates from, so the two
tools tell the same story about the same capture. The typed ids are stable and
come from apps/ns_server/src/event_log.erl:

    rebalance          2 initiated, 3 completed, 4 failed, 5 interrupted
    graceful failover  6 initiated, 7 completed, 8 failed, 9 interrupted
    hard failover     10 initiated, 11 completed, 12 failed, 13 interrupted
    auto failover     14 initiated, 15 completed, 16 failed
    master selected   18

Why event_log rather than the ns_orchestrator debug lines this used to be built
from:

  * it states the outcome explicitly, instead of leaving it to be inferred from
    which phrase happened to appear in a log line;
  * it separates the four operation types, so a graceful failover is never
    reported as a hard one;
  * it is cluster-replicated, so an operation survives the rotation of the one
    node's debug.log that drove it -- the exact case where the old approach went
    blind;
  * every entry carries otp_node, stamped with node() at add_log time
    (event_log.erl:267). The rebalance and failover calls come from
    ns_orchestrator, which runs only under mb_master_sup on the elected master,
    so that field IS the orchestrating node rather than a guess at it.

The one thing event_log cannot do is date an operation that began before the
capture's ring buffer starts; such a span is reported with start_unknown set
rather than back-dated.
"""
import json
from bisect import bisect_left, bisect_right

from . import leadership


# event_id -> (operation kind, role). Only spans belong here; one-shot events
# (node down, service crashed) are timeline events, not operations.
_OPS = {
    2: ("rebalance", "initiated"),
    3: ("rebalance", "completed"),
    4: ("rebalance", "failed"),
    5: ("rebalance", "interrupted"),
    6: ("graceful_failover", "initiated"),
    7: ("graceful_failover", "completed"),
    8: ("graceful_failover", "failed"),
    9: ("graceful_failover", "interrupted"),
    10: ("hard_failover", "initiated"),
    11: ("hard_failover", "completed"),
    12: ("hard_failover", "failed"),
    13: ("hard_failover", "interrupted"),
    14: ("auto_failover", "initiated"),
    15: ("auto_failover", "completed"),
    16: ("auto_failover", "failed"),
}

# Curated record of a promotion, written by mb_master's start_master. Not an
# operation, but the same event_log pass may as well pick it up: it corroborates
# the leadership lanes from a cluster-replicated source, which is what is left
# when the debug.log that carried the announcements has rotated away.
_MASTER_SELECTED = 18

# Outcomes that mean the operation did not do what it set out to do.
BAD_OUTCOMES = ("failed", "interrupted", "unfinished")


def _fields(raw):
    try:
        return json.loads(raw or "{}")
    except (ValueError, TypeError):
        return {}


# Where ns_server records why an operation ended the way it did. Same keys the
# findings engine reads, so both report the same reason for the same event.
_REASON_KEYS = ("reason", "error", "message", "completion_message",
                "exit_reason", "errorMessage")


def _attrs(fields):
    """extra_attributes as a mapping when it is one.

    It is not always. diag.log's event dump renders some entries with erlang
    term syntax rather than JSON, so the value arrives as text like
    "{'section': 'security', ...}". That is kept as text for display rather than
    guessed at with a term parser: an operation's recorded detail is worth
    showing verbatim, and half-parsing it would be worse than not parsing it.
    """
    a = fields.get("extra_attributes")
    if isinstance(a, dict):
        return a
    if isinstance(a, str):
        try:
            parsed = json.loads(a)
            return parsed if isinstance(parsed, dict) else {}
        except ValueError:
            return {}
    return {}


def _attrs_text(fields):
    """extra_attributes as displayable text, whichever way it was stored."""
    a = fields.get("extra_attributes")
    if isinstance(a, dict):
        return ", ".join(f"{k}={v}" for k, v in a.items())[:400]
    return str(a)[:400] if a else ""


def _reason(fields):
    """The recorded reason for an outcome, from the event's top-level fields or
    from extra_attributes when it parsed as a mapping."""
    attrs = _attrs(fields)
    for k in _REASON_KEYS:
        v = fields.get(k) or attrs.get(k)
        if v:
            return str(v)[:300]
    return None


def _nodes_info(fields):
    """The nodes_info object every rebalance/failover event carries:
    {active_nodes, failover_nodes, master_node} (ns_orchestrator.erl:2230)."""
    ni = _attrs(fields).get("nodes_info")
    return ni if isinstance(ni, dict) else {}


def _node_list(v):
    """A nodes_info list field as a list of names, whatever it arrived as."""
    if isinstance(v, list):
        return [str(x) for x in v if x]
    return [str(v)] if v else []


def _failover_detail(fields):
    """Which nodes a failover acted on and, per node, the reason recorded for it.

    Both come off the failover_initiated event's own attributes, added at
    ns_orchestrator.erl:2259:

        nodes_info.failover_nodes  the nodes passed to failover:start/2
        failover_reason            an OBJECT KEYED BY NODE, built from
                                   auto_failover:failover_reasons/3 -- so an
                                   auto-failover of two nodes carries a separate
                                   reason for each
        allow_unsafe               the modifier, not a failover type: a hard
                                   failover run with it set is the quorum-loss
                                   case, and that is worth reading off the span
                                   rather than out of a log line

    Kept as recorded, one reason per node. The old single `reason` field cannot
    hold this: it takes the first of several generic keys and stringifies it, so
    a per-node map arrived flattened into one clipped blob.

    A span whose start fell off the event_log ring has no failover_reason at all
    -- only the initiated event carries it. The terminator still carries
    nodes_info, so the nodes survive and the reasons are simply absent, which is
    the honest outcome rather than a reason attributed to the wrong node."""
    attrs = _attrs(fields)
    raw = attrs.get("failover_reason")
    reasons = {}
    if isinstance(raw, dict):
        reasons = {str(k): str(v) for k, v in raw.items() if v}
    out = {"failover_nodes": _node_list(_nodes_info(fields).get(
        "failover_nodes"))}
    if reasons:
        out["failover_reasons"] = reasons
    if "allow_unsafe" in attrs:
        out["allow_unsafe"] = bool(attrs.get("allow_unsafe"))
    return out


# ---- what a span's log evidence is -------------------------------------------
#
# event_log records only that an operation started and how it ended. The lines
# that say what it DID are in the ns_server logs, written by the modules that
# implement the operation -- so the evidence for a span is: those modules, over
# that span's time. Both halves are recorded facts (the module name is the ALE
# header's, the window is the event_log's own start and end), so nothing here is
# a judgement about which lines matter.
#
# Modules per kind, from the ns_server source tree. A rebalance and a failover
# share the orchestrator and the janitor and diverge after that.
_REBALANCE_MODULES = (
    "ns_orchestrator", "ns_rebalancer", "ns_rebalance_observer",
    "ns_vbucket_mover", "ns_single_vbucket_mover", "janitor_agent",
    "ns_janitor", "service_rebalancer", "service_manager", "rebalance_agent",
    "dcp_replicator", "leader_activities",
)
_FAILOVER_MODULES = (
    "ns_orchestrator", "failover", "auto_failover", "auto_failover_logic",
    "ns_rebalance_observer", "janitor_agent", "ns_janitor", "chronicle_master",
    "leader_activities",
)
_OP_MODULES = {
    "rebalance": _REBALANCE_MODULES,
    "graceful_failover": _FAILOVER_MODULES,
    "hard_failover": _FAILOVER_MODULES,
    "auto_failover": _FAILOVER_MODULES,
}

# How far either side of the recorded span to read. The lead-in exists because
# the decision to act is logged before the operation is declared: a failover is
# preceded by the down-state ladder that triggered it, a rebalance by the call
# that asked for it. Kept small and symmetric rather than tuned per kind; the
# auto-failover ladder itself comes from the episode matcher, which is not
# window-bound.
_EV_LEAD = 60
_EV_TAIL = 30
# Ceiling on the IDs carried per span, so an unfinished operation (no end
# recorded, evidence therefore running to the end of the capture) cannot pull
# the whole log into the payload. A truncated set says so.
_EV_MAX_IDS = 400


def _ev_window(span):
    """[lo, hi] to read a span's evidence over; hi None = to end of capture.

    An unfinished operation has no end, and its lines genuinely run to wherever
    the log stops, so the window is left open rather than closed at a guessed
    duration. A span dated only by its terminator (start fell off the event_log
    ring) is read backwards from that terminator by the same lead-in.
    """
    at = span["start"] if span["start"] is not None else span["end"]
    if at is None:
        return None, None
    if span["end"] is None:
        return at - _EV_LEAD, None
    return at - _EV_LEAD, span["end"] + _EV_TAIL


def _ev_rows(conn, lo, hi):
    """Every log line from an operation-implementing module in [lo, hi]."""
    mods = sorted({m for ms in _OP_MODULES.values() for m in ms})
    # Selected on the module alone, not on the log file it landed in: the same
    # module writes to debug.log, info.log and error.log by level, and which
    # file a line ended up in says nothing about whether it belongs to the
    # operation.
    q = ("SELECT id, node, ts_epoch, subsystem FROM events WHERE "
         "subsystem IN (%s) AND ts_epoch IS NOT NULL AND ts_epoch >= ?"
         % ",".join("?" * len(mods)))
    args = list(mods) + [lo]
    if hi is not None:
        q += " AND ts_epoch <= ?"
        args.append(hi)
    return conn.execute(q + " ORDER BY ts_epoch, id", args).fetchall()


def attach_evidence(conn, spans):
    """Give every span the log lines behind it, grouped by the module that wrote
    them, plus -- for a failover -- the auto-failover down-state episodes that
    led to it.

    The episodes come from findings.auto_failover_episodes, the same matcher the
    auto-failover finding uses for its related IDs, reused unchanged: it already
    reconstructs 'orchestrator O tracked node N: up->half_down->failover, reason
    R' with the IDs of every line that built the ladder. A failover span keeps
    the episodes for the nodes IT failed over, matched on the target node and
    the episode ending inside the span's window, so a span never inherits a
    different failover's lead-up.
    """
    windows = [(s, ) + _ev_window(s) for s in spans]
    dated = [(s, lo, hi) for s, lo, hi in windows if lo is not None]
    for s in spans:
        s["evidence"] = {"total": 0, "ids": [], "modules": [], "episodes": [],
                         "truncated": False}
    if not dated:
        return spans
    lo = min(lo for _s, lo, _hi in dated)
    hi = None if any(h is None for _s, _lo, h in dated) else max(
        h for _s, _lo, h in dated)
    rows = _ev_rows(conn, lo, hi)
    # One read for every span, then each span takes its own slice of it. The rows
    # come back in time order, so a window is a bisect rather than a scan: a
    # capture with a hundred operations in it would otherwise walk the whole
    # module log once per operation.
    times = [r["ts_epoch"] for r in rows]

    for s, s_lo, s_hi in dated:
        mods = _OP_MODULES.get(s["kind"], ())
        by_mod, seq = {}, []
        i = bisect_left(times, s_lo)
        j = len(rows) if s_hi is None else bisect_right(times, s_hi)
        for r in rows[i:j]:
            if r["subsystem"] not in mods:
                continue
            seq.append(r["id"])          # time-ordered, all modules together
            by_mod.setdefault(r["subsystem"], []).append(r["id"])
        ev = s["evidence"]
        ev["total"] = len(seq)
        # Biggest groups first: that is where the operation spent its logging,
        # and it keeps the module a reader wants (ns_rebalancer on a rebalance,
        # failover on a failover) out of a long tail of one-liners.
        ev["modules"] = [{"module": m, "count": len(ids),
                          "ids": ids[:_EV_MAX_IDS]}
                         for m, ids in sorted(by_mod.items(),
                                              key=lambda kv: (-len(kv[1]),
                                                              kv[0]))]
        # The cap keeps the FIRST lines in time order, not the first module's:
        # a truncated set that still reads chronologically is a beginning, while
        # one grouped by module would be a single module's whole story and none
        # of the others'.
        ev["ids"] = seq[:_EV_MAX_IDS]
        ev["truncated"] = len(seq) > _EV_MAX_IDS

    fo_spans = [(s, lo_, hi_) for s, lo_, hi_ in dated
                if s["kind"].endswith("failover")]
    if not fo_spans:
        return spans
    from . import findings          # local: findings imports nothing from here
    episodes = findings.auto_failover_episodes(conn)
    for s, s_lo, s_hi in fo_spans:
        targets = set(s.get("failover_nodes") or [])
        for e in episodes:
            t = e.get("ts_epoch")
            if t is None or t < s_lo or (s_hi is not None and t > s_hi):
                continue
            # No failover_nodes recorded (a span dated from its terminator on an
            # older build) -> keep every episode that ended in the window, which
            # is all the span itself can vouch for.
            if targets and e.get("node") not in targets:
                continue
            ids = (e.get("related") or [])[:_EV_MAX_IDS]
            ev = s["evidence"]
            ev["episodes"].append({
                "node": e.get("node"), "title": e.get("title"),
                "detail": e.get("detail"), "ids": ids,
            })
            # The ladder lines come from auto_failover_logic ticks that the
            # module window may not have reached (the ladder can run for the
            # whole configured timeout), so fold them into the span's own set
            # rather than leaving "everything for this operation" short of them.
            merged = list(dict.fromkeys(ev["ids"] + ids))
            ev["truncated"] = ev["truncated"] or len(merged) > _EV_MAX_IDS
            ev["ids"] = merged[:_EV_MAX_IDS]
            ev["total"] = max(ev["total"], len(merged))
    return spans


def _rows(conn):
    """event_log entries that are operation or master-selection records.

    event_log is a cluster-wide ring replicated to every node, so the same entry
    sits in every capture. Ingest already dedups it by the event's own uuid; the
    uuid check here is belt and braces for a db built before that, and costs one
    set lookup per row.
    """
    out, seen = [], set()
    for r in conn.execute(
            "SELECT id, node, ts_epoch, ts_local, tz_offset_min, severity, "
            "summary, fields FROM events WHERE source='event_log' AND "
            "ts_epoch IS NOT NULL ORDER BY ts_epoch, id").fetchall():
        f = _fields(r["fields"])
        try:
            eid = int(f.get("event_id"))
        except (TypeError, ValueError):
            continue
        if eid not in _OPS and eid != _MASTER_SELECTED:
            continue
        uuid = f.get("uuid")
        if uuid:
            if uuid in seen:
                continue
            seen.add(uuid)
        out.append((eid, r, f))
    return out


def _span(kind, start_row, start_fields):
    a = _attrs(start_fields)
    return {
        # Which nodes were failed over and why, promoted out of
        # extra_attributes: on a failover span that is the whole question, and
        # digging it out of a flattened attribute blob per read is what made it
        # hard to answer.
        **_failover_detail(start_fields),
        "master_node": str(_nodes_info(start_fields).get("master_node") or ""),
        "kind": kind,
        "start": start_row["ts_epoch"],
        "start_local": start_row["ts_local"],
        "tz_offset_min": start_row["tz_offset_min"],
        "end": None,
        # The node that ran ns_orchestrator for this operation.
        "owner": start_fields.get("otp_node"),
        "outcome": "unfinished",
        "start_unknown": False,
        "start_event_id": start_row["id"],
        "end_event_id": None,
        "detail": start_row["summary"] or "",
        # Whatever the event recorded about scope: nodes involved, delta
        # recovery, the failover reason. Kept verbatim; not interpreted.
        "attrs": a,
        "start_text": _attrs_text(start_fields),
        "end_text": "",
        "reason": None,
    }


def _close(span, role, row, fields):
    span["end"] = row["ts_epoch"]
    span["outcome"] = role
    span["end_event_id"] = row["id"]
    span["end_text"] = _attrs_text(fields)
    # Only a bad ending has a reason worth carrying: "why did it fail" is the
    # question, and a completion message on a clean run is noise.
    if role in BAD_OUTCOMES:
        span["reason"] = _reason(fields)
    span["duration_s"] = (span["end"] - span["start"]
                          if span["start"] is not None else None)
    return span


def query_orchestration(conn):
    """Rebalance and failover spans, newest information first for the caller to
    lay out on the same x-axis as the leadership lanes.

    Pairing follows the same rule promtimer uses -- hold an initiated event per
    operation kind, close it on the next terminator of that kind -- with two
    honesty cases it does not distinguish:

      unfinished     an initiated event with no terminator. Either the operation
                     was still running when the capture was taken, or it died
                     with the node. NOT drawn as a completed span.
      start_unknown  a terminator with no initiated event, because the start
                     fell off the front of the event_log ring. The span is
                     reported at its end, not back-dated to the ring's start.

    """
    rows = _rows(conn)
    spans, open_by_kind, master_selected = [], {}, []
    for eid, r, f in rows:
        if eid == _MASTER_SELECTED:
            a = _attrs(f)
            master_selected.append({
                "ts_epoch": r["ts_epoch"], "ts_local": r["ts_local"],
                "tz_offset_min": r["tz_offset_min"],
                # mb_master records new_master/old_master in the event's
                # attributes; the parser may flatten them to the top level, so
                # both are read. otp_node is the last resort and is still right:
                # start_master runs on the winner, so the node that logged the
                # promotion IS the new master.
                "new_master": (f.get("new_master") or a.get("new_master")
                               or f.get("otp_node")),
                "old_master": f.get("old_master") or a.get("old_master"),
                "event_id": r["id"],
                "summary": r["summary"] or "",
            })
            continue
        kind, role = _OPS[eid]
        if role == "initiated":
            # Two initiated events with no terminator between them: the first
            # one's outcome was never recorded, so it stays unfinished rather
            # than being silently closed by the second one's start.
            if kind in open_by_kind:
                spans.append(open_by_kind.pop(kind))
            open_by_kind[kind] = _span(kind, r, f)
            continue
        span = open_by_kind.pop(kind, None)
        if span is None:
            span = _span(kind, r, f)
            span["start_unknown"] = True
        spans.append(_close(span, role, r, f))
    spans.extend(open_by_kind.values())
    for s in spans:
        s.setdefault("duration_s",
                     None if s["end"] is None else s["end"] - s["start"])
    spans.sort(key=lambda s: (s["start"] is None, s["start"]))
    attach_evidence(conn, spans)

    bad = [s for s in spans if s["outcome"] in BAD_OUTCOMES]
    return {
        "spans": spans,
        "master_selected": master_selected,
        "kinds": sorted({s["kind"] for s in spans}),
        "verdict": {
            "total": len(spans),
            "bad": len(bad),
            "by_outcome": {o: sum(1 for s in spans if s["outcome"] == o)
                           for o in sorted({s["outcome"] for s in spans})},
            "owners": sorted({s["owner"] for s in spans if s["owner"]}),
            # Per kind and outcome, which is what "what ran, how did it end, is
            # it re-running" asks for. Counts of recorded outcomes, nothing else.
            "by_kind": {k: {o: sum(1 for s in spans
                                   if s["kind"] == k and s["outcome"] == o)
                            for o in sorted({s["outcome"] for s in spans
                                             if s["kind"] == k})}
                        for k in sorted({s["kind"] for s in spans})},
        },
    }


def overview(conn):
    """The cluster overview payload: both axes on one shared x-axis.

    The axes are derived independently and then given a common span, because
    each one alone would draw a misleading picture of the other. Mastership
    evidence can cover an hour of a three-week capture while the only rebalance
    in it ran on a different day; scaling either band to the other's extent
    hides one of them. The span is the union of what both axes have evidence
    for, and each axis keeps its own extent so the header can say which of them
    the covered time came from.
    """
    lead = leadership.query_leadership(conn)
    orch = query_orchestration(conn)

    ts = [t for s in orch["spans"]
          for t in (s["start"], s["end"]) if t is not None]
    ts += [m["ts_epoch"] for m in orch["master_selected"]
           if m["ts_epoch"] is not None]
    orch_lo, orch_hi = (min(ts), max(ts)) if ts else (None, None)
    bounds = [v for v in (lead["span"]["lo"], lead["span"]["hi"],
                          orch_lo, orch_hi) if v is not None]
    span = ({"lo": min(bounds), "hi": max(bounds)} if bounds
            else {"lo": None, "hi": None})
    return {
        "span": span,
        "capture_span": lead["capture_span"],
        "leadership": lead,
        "orchestration": dict(orch, span={"lo": orch_lo, "hi": orch_hi}),
    }


