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
"""rebalance_report*.json -- the orchestrator's own record of one operation.

Not a log stream: each file is a single document describing one rebalance (or
failover -- the same observer serves all of them), so it lands in its own
sidecar tables rather than in `events`, like process_dump and snapshot.

WHY THIS SOURCE EXISTS HERE. Two facts are recorded nowhere else in a cbcollect:

  * Where an operation STOPPED. Every phase of every vbucket move carries its
    own start/complete stamps, so a move that entered a phase and never left it
    is a recorded fact, not an inference (see the three-state encoding below).
  * How long each SERVICE took. stageInfo is per service (a real capture shows
    `search` and `data` as siblings), so "which service ate the time" is
    answerable before opening a single vbucket.

Reports exist for every outcome, not just successes: ns_orchestrator's
handle_rebalance_completion is the single completion path for all exit reasons
and always records a report, with the failure text in completionMessage.

THE THREE-STATE PHASE ENCODING is the whole trick, and it comes from
ns_rebalance_observer:construct_stat_info_json/1 having two clauses:

    never entered   {"startTime": false}                  <- no completedTime key
    still running   {"startTime": "...", "completedTime": false, ...}
    completed       {"startTime": "...", "completedTime": "...", ...}

So `startTime` set with `completedTime` false IS the hang, and startTime is when
it hung. `false` therefore means three different things depending on where it
appears (key absent / never entered / never finished), which is the main way to
get this format wrong.

PHASES ARE DETECTED GENERICALLY, not enumerated. ns_server currently emits
move / backfill / takeover / persistence and, for file-based backfills,
snapshot_download / snapshot_deks_import / snapshot_waiting -- but any key whose
value looks like a stat_info object is treated as a phase. A phase added
upstream then shows up on its own instead of being silently dropped, which
matters because this feeds a finding, and a finding that quietly stops firing is
worse than a drawer that renders one row short.

VERSION GATE. rebalanceType / nodesAdded / nodesRemoved (the real membership
delta, computed by ns_rebalancer:determine_rebalance_type/1 from an actual
before/after active_nodes() snapshot) arrived with MB-70003 and are on master
only -- no release branch has them. They are parsed opportunistically and are
absent from every released-build capture. nodesInfo.active_nodes is NOT a
substitute: ns_orchestrator builds it as `KeepNodes ++ EjectNodes`, a synthetic
union of the inputs, so node ADDITIONS are invisible in it. keep/eject/delta/
failed come straight from the start_rebalance params and are real.

Format quirks below follow ns_server's own consumer,
scripts/jq/rebalance_report/parser.py -- the browser-download `data` wrapper,
the `is_rebalancing` guard, the trailing-Z timestamp form, and phases that are
the bare literal `false` when that phase never applied to the move at all.
"""
import json

from ..clock import parse_iso_offset
from ..discovery import open_text

# completionMessage format strings from ns_orchestrator:get_log_msg/3, which
# types every completion as success | failure | interrupted. The report JSON
# carries only the rendered text, not the type, so the type is recovered by
# matching the fixed prefixes those formats produce. Anything unrecognised stays
# 'unknown' rather than being guessed into a bucket -- and the verbatim message
# is always kept, so the reader never depends on this mapping being right.
_OUTCOME_MARKERS = (
    ("completed successfully", "success"),
    ("exited with reason", "failure"),
    ("interrupted due to auto-failover", "interrupted"),
    ("stopped by user", "interrupted"),
)

# Keys under a vbucket entry that are structural, not phases. Everything else
# whose value looks like a stat_info object is a phase (see module docstring).
_VB_NON_PHASE = frozenset(("id", "beforeChain", "afterChain", "size",
                           "replicationInfo"))

# Phase states, mirroring construct_stat_info_json/1's clauses.
NOT_STARTED = "not_started"
IN_FLIGHT = "in_flight"
DONE = "done"


def _ts(value):
    """One report timestamp -> (epoch, offset_min, verbatim).

    binarify_timestamp/1 renders misc:timestamp_iso8601(T, local), which carries
    an explicit offset (2026-01-15T03:34:43.113-08:00), so these are unambiguous
    instants and need no per-node clock reconstruction. The trailing-Z form is
    accepted because ns_server's own parser accepts it. `false` (never happened)
    and absent both come back as all-None."""
    if not isinstance(value, str):
        return None, None, None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    epoch, off = parse_iso_offset(text)
    return epoch, off, value


def _phase(value):
    """A stat_info object -> a phase dict, or None if this key is not a phase.

    Returns state per the three-state encoding. A phase can also be the bare
    literal `false` (takeover reports that when the move involved no takeover at
    all); that is 'never applied', which we report as not_started with no
    timestamps rather than inventing a distinct state for it."""
    if value is False:
        return {"state": NOT_STARTED, "start_ts": None, "start_local": None,
                "completed_ts": None, "completed_local": None,
                "time_taken_ms": None}
    if not isinstance(value, dict) or "startTime" not in value:
        return None
    start_ts, _off, start_local = _ts(value.get("startTime"))
    if start_ts is None:
        # startTime: false -- the phase was never entered. There is no
        # completedTime key at all in this clause.
        return {"state": NOT_STARTED, "start_ts": None, "start_local": None,
                "completed_ts": None, "completed_local": None,
                "time_taken_ms": None}
    done_ts, _off2, done_local = _ts(value.get("completedTime"))
    return {
        "state": DONE if done_ts is not None else IN_FLIGHT,
        "start_ts": start_ts,
        "start_local": start_local,
        "completed_ts": done_ts,
        "completed_local": done_local,
        # timeTaken is only meaningful once completed; ns_server computes it
        # against a `false` end time for in-flight phases, so it is dropped
        # there rather than stored as a number that means nothing.
        "time_taken_ms": value.get("timeTaken") if done_ts is not None else None,
    }


def _phases(vb):
    """Every phase on a vbucket entry, keyed by phase name."""
    out = {}
    for key, value in vb.items():
        if key in _VB_NON_PHASE:
            continue
        phase = _phase(value)
        if phase is not None:
            out[key] = phase
    return out


def _docs_left(vb):
    """(docs_left, docs_total) summed over the move's replication targets.

    replicationInfo is per destination node; a move usually has one, but a
    replica-count change can have several. Summing keeps the row a single
    'is it still draining' number -- the per-node detail stays in the raw
    payload for the drawer."""
    info = vb.get("replicationInfo")
    if not isinstance(info, dict):
        return None, None
    left = total = None
    for entry in info.values():
        if not isinstance(entry, dict):
            continue
        if isinstance(entry.get("inDocsLeft"), (int, float)):
            left = (left or 0) + entry["inDocsLeft"]
        if isinstance(entry.get("inDocsTotal"), (int, float)):
            total = (total or 0) + entry["inDocsTotal"]
    return left, total


def _move_state(phases):
    """Roll a move's phases up to one state.

    A move is in_flight if ANY phase was entered and never left -- that is the
    stall, whichever phase it happened in. Otherwise done if its own `move`
    phase completed, else not_started. Deliberately no notion of 'slow': the
    only claims made here are ones the JSON records."""
    stuck = sorted(name for name, p in phases.items()
                   if p["state"] == IN_FLIGHT)
    if stuck:
        return IN_FLIGHT, stuck
    move = phases.get("move")
    if move and move["state"] == DONE:
        return DONE, []
    return NOT_STARTED, []


def _outcome(message):
    if not isinstance(message, str):
        return "unknown"
    low = message.lower()
    for marker, outcome in _OUTCOME_MARKERS:
        if marker in low:
            return outcome
    return "unknown"


def _nodes(value):
    return [n for n in value if isinstance(n, str)] \
        if isinstance(value, list) else []


def parse(path, node=None):
    """Parse one rebalance_report*.json.

    Returns (report, moves). report is None when the file holds no operation --
    an idle rebalance_report_current.json is 24 bytes of
    {"is_rebalancing": false} -- or when the file is unreadable, so a corrupt
    report never aborts an ingest.
    """
    try:
        with open_text(path) as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None, []
    if not isinstance(doc, dict):
        return None, []
    # A report downloaded from the UI's rebalance pop-up is wrapped in "data".
    if isinstance(doc.get("data"), dict):
        doc = doc["data"]
    # current.json when nothing is running. Absent on the retained reports,
    # which is why the default is True rather than False.
    if not doc.get("is_rebalancing", True):
        return None, []
    rebalance_id = doc.get("rebalanceId")
    if not isinstance(rebalance_id, str) or not rebalance_id:
        return None, []

    start_ts, tz_off, start_local = _ts(doc.get("startTime"))
    done_ts, done_off, done_local = _ts(doc.get("completedTime"))
    message = doc.get("completionMessage")
    nodes_info = doc.get("nodesInfo")
    nodes_info = nodes_info if isinstance(nodes_info, dict) else {}
    stage_info = doc.get("stageInfo")
    stage_info = stage_info if isinstance(stage_info, dict) else {}

    services = {}
    for name, stage in stage_info.items():
        if not isinstance(stage, dict):
            continue
        phase = _phase(stage)
        if phase is None:
            continue
        services[name] = {
            "state": phase["state"],
            "start_ts": phase["start_ts"],
            "completed_ts": phase["completed_ts"],
            "time_taken_ms": phase["time_taken_ms"],
            "total_progress": stage.get("totalProgress"),
            "per_node_progress": stage.get("perNodeProgress"),
        }

    moves = []
    buckets = {}
    for service, stage in stage_info.items():
        details = stage.get("details") if isinstance(stage, dict) else None
        if not isinstance(details, dict):
            continue
        for bucket, info in details.items():
            if not isinstance(info, dict):
                continue
            b_start, _o, _l = _ts(info.get("startTime"))
            b_done, _o2, _l2 = _ts(info.get("completedTime"))
            level = info.get("vbucketLevelInfo")
            level = level if isinstance(level, dict) else {}
            vbs = level.get("vbucketInfo")
            vbs = vbs if isinstance(vbs, list) else []
            buckets[bucket] = {
                "service": service,
                "start_ts": b_start,
                "completed_ts": b_done,
                "time_taken_ms": info.get("timeTaken"),
                # vbucketLevelInfo carries ns_server's own per-phase roll-ups
                # alongside the per-vb detail, so totals come free.
                "phase_totals": {k: v for k, v in level.items()
                                 if k != "vbucketInfo"},
                "vbucket_count": len(vbs),
            }
            for vb in vbs:
                if not isinstance(vb, dict):
                    continue
                phases = _phases(vb)
                state, stuck = _move_state(phases)
                before = _nodes(vb.get("beforeChain"))
                after = _nodes(vb.get("afterChain"))
                left, total = _docs_left(vb)
                entered = [p["start_ts"] for p in phases.values()
                           if p["start_ts"] is not None]
                moves.append({
                    "rebalance_id": rebalance_id,
                    "bucket": bucket,
                    "service": service,
                    "vbucket": vb.get("id"),
                    "state": state,
                    # The phases a stall is sitting in, and when it entered the
                    # earliest of them -- both recorded facts, no judgement.
                    "stuck_phases": json.dumps(stuck) if stuck else None,
                    "stuck_since_ts": min(
                        (phases[p]["start_ts"] for p in stuck
                         if phases[p]["start_ts"] is not None), default=None),
                    "first_activity_ts": min(entered) if entered else None,
                    "before_chain": json.dumps(before),
                    "after_chain": json.dumps(after),
                    # Destinations of the move, the same subtraction
                    # ns_rebalance_observer uses for per-node inbound size.
                    "target_nodes": json.dumps([n for n in after
                                                if n not in before]),
                    "docs_left": left,
                    "docs_total": total,
                    "vb_size": vb.get("size"),
                    "phases": json.dumps(phases),
                })

    report = {
        "rebalance_id": rebalance_id,
        "node": node,
        "master_node": doc.get("masterNode"),
        "start_ts": start_ts,
        "start_local": start_local,
        "tz_offset_min": tz_off if tz_off is not None else done_off,
        "completed_ts": done_ts,
        "completed_local": done_local,
        "time_taken_ms": doc.get("timeTaken"),
        "outcome": _outcome(message),
        "completion_message": message,
        # completedTime false on the top-level document means the operation was
        # still running when the report was written (current.json), as opposed
        # to a terminal report where it is always stamped.
        "in_progress": done_ts is None,
        # Master-only (MB-70003); absent on every released build.
        "rebalance_type": doc.get("rebalanceType"),
        "nodes_added": json.dumps(_nodes(doc.get("nodesAdded"))),
        "nodes_removed": json.dumps(_nodes(doc.get("nodesRemoved"))),
        "has_delta_fields": "rebalanceType" in doc,
        # Real inputs from start_rebalance. active_nodes is deliberately NOT
        # promoted to a column: it is the synthetic KeepNodes ++ EjectNodes
        # union, so presenting it as pre-operation membership would be wrong.
        "keep_nodes": json.dumps(_nodes(nodes_info.get("keep_nodes"))),
        "eject_nodes": json.dumps(_nodes(nodes_info.get("eject_nodes"))),
        "delta_nodes": json.dumps(_nodes(nodes_info.get("delta_nodes"))),
        "failed_nodes": json.dumps(_nodes(nodes_info.get("failed_nodes"))),
        # Failover reports carry failover_nodes and no keep_nodes; the operation
        # kind is discriminated on which KEYS are present, never on whether a
        # list is empty (a rebalance ejecting everything has empty keep_nodes).
        "failover_nodes": json.dumps(_nodes(nodes_info.get("failover_nodes"))),
        "is_failover": "failover_nodes" in nodes_info,
        "services": json.dumps(services),
        "buckets": json.dumps(buckets),
        "move_count": len(moves),
        "log_path": str(path),
    }
    return report, moves
