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
"""Leadership over time: which node each node BELIEVED held mastership, and when
that belief changed.

Read the word "believed" literally. There is no cluster-wide fact to report
here. mb_master is a gen_statem running on every node, and a candidate promotes
itself once it has not heard from a higher priority node or a master for
TIMEOUT_INTERVAL_COUNT heartbeats (5 x 2s = 10s by default,
apps/ns_server/src/mb_master.erl). Under a partition both sides of the split can
therefore hold a node in the master state at the same time, each correctly by
its own evidence. So this module derives one lane per observer and treats
disagreement between lanes as the signal, not as an error to reconcile away.
The same relational reading as a per-node connectivity matrix: mastership is the
SET of opinions the nodes hold, not a scalar.

What the concepts actually are, since they get used interchangeably:

  mb_master           the election. Runs everywhere. Answers WHO.
  mb_master_sup       started only on the winner; its children are what being
                      the master consists of.
  leader_lease_*      NOT a second election. leader_lease_acquirer is a child of
                      mb_master_sup, so it only runs on the node mb_master
                      already elected; it collects leases from peers and
                      leader_activities requires a quorum of them before an
                      activity may run. Answers whether that mastership is
                      still valid enough to ACT.
  ns_orchestrator     under ns_orchestrator_sup under mb_master_sup. Answers
                      what the master is DOING (rebalance, failover, janitor).
  chronicle_leader    chronicle's own per-term leadership, in the chronicle dep.
                      Related but separately elected.
  chronicle_master    an ns_server module, child of mb_master_sup, that funnels
                      topology changes into chronicle. Needs mastership.

Only the mb_master axis is derived here. The lease and chronicle axes are
separate tracks with different fidelity and belong in their own pass.

Where the belief lines come from
--------------------------------
mb_master announces every transition through announce_leader/1, which is a
SYNCHRONOUS gen_event notify on leader_events, from exactly three places:
start_master (becoming master), the surrender path, and shutdown_master_sup
(which announces the undefined holder). leader_registry subscribes on every
node and logs

    New leader is <node>. Invalidating name cache.

at debug. That makes the registry line a complete per-observer trace of the
believed holder rather than a sample of it, which is why it is the spine of this
view. mb_master's own lines carry the REASON a belief changed (took over on
timeout, surrendered, demoted) and are folded in as evidence for the same
change; where the registry line is missing (debug.log rotated away under a busy
window) they stand in as the belief source on their own.

Two mb_master lines are deliberately NOT treated as belief changes. "Got master
heartbeat from X when I'm master" and the "not in peers" warnings do not move
this node's belief; they record that the observer SAW a competing claim, which
is the direct split-brain tell. They are returned as conflicts.
"""
import json
import re

from . import nodes


# Erlang prints a node atom quoted, since it contains @ and dots. The host half
# comes from nodes.NODE so an IPv6 cluster's names survive whole: a host class
# that stopped at the first colon captured 'ns_1@fd63' out of ns_1@fd63:...:1,
# and the lane then said one node believed a node that does not exist.
_NODE = r"'?(" + nodes.NODE + r")'?"

# Sentinel holder meaning "the observer itself". The self-promotion lines name
# no node (there is nothing to name -- it is node()), so the holder is only
# knowable from which node logged the line.
_SELF = "\x00self"

# The host part every node carries before it is renamed to its real name
# (misc:localhost_alias/0 in misc.erl; leader_lease_agent.erl notes that "the
# node rename transitions the node from cb.local to the real node name"). A
# holder with this host is a node still bootstrapping, so the early flurry of
# transitions through it is initialisation rather than an election worth reading.
# Naming it matters because it has no lane of its own and would otherwise be
# reported as a node whose capture is missing from the bundle.
LOCALHOST_ALIAS = "cb.local"

# Beyond one mb_master heartbeat interval, disagreement between two observers is
# no longer explainable as the announcement not having reached them yet. Used to
# mark a divergence transient rather than to hide it.
PROPAGATION_S = 2.0

# (regex, holder source, reason, expected-holder source). Holder source is a
# group number, _SELF, or None for "no master". Matched against the entry's
# header line only.
#
# The surrender line is the one place where the log text and the announcement
# order disagree, and the announcement wins. mb_master logs "Surrendering
# mastership to X" and THEN calls shutdown_master_sup, which announces
# the undefined holder before announce_leader(X) runs (mb_master.erl lines
# 497-500 and 636). The state this node announces then is therefore no-master,
# and X is only where it expects mastership to go -- recorded as the segment's
# expected holder rather than as a belief, so a surrender never fabricates a
# belief the node had not announced.
_BELIEF_RULES = [
    # leader_registry, every node, every transition (the spine).
    (re.compile(r"^New leader is undefined\. Invalidating name cache"),
     None, "announced", None),
    (re.compile(r"^New leader is " + _NODE + r"\. Invalidating name cache"),
     1, "announced", None),

    # mb_master's own view, which carries the reason.
    (re.compile(r"^Changing master from \S+ to undefined\b"),
     None, "lost_master", None),
    (re.compile(r"^Changing master from \S+ to " + _NODE),
     1, "heartbeat", None),
    (re.compile(r"^Surrendering mastership to " + _NODE),
     None, "surrendered", 1),
    (re.compile(r"^Master has been demoted"), None, "demoted", None),
    (re.compile(r"^I'm (?:now )?the only node, so I'm the master"),
     _SELF, "only_node", None),
    (re.compile(r"^Master has been removed from cluster\. "
                r"I'm taking over as the master"), _SELF, "master_removed",
     None),
    (re.compile(r"^Haven't heard from a higher priority node or a master, "
                r"so I'm taking over"), _SELF, "timeout_takeover", None),
]

# (regex, kind, peer group or None). A competing claim this observer saw, which
# does not itself move the observer's belief.
_CONFLICT_RULES = [
    (re.compile(r"^Got master heartbeat from " + _NODE + r" when I'm master"),
     "two_masters_seen", 1),
    (re.compile(r"^(?:Master|Candidate) got master heartbeat from node " +
                _NODE + r" which is not in peers"), "master_not_in_peers", 1),
    (re.compile(r"^(?:Master|Candidate) got candidate heartbeat from node " +
                _NODE + r" which is not in peers"),
     "candidate_not_in_peers", 1),
    (re.compile(r"^Candidate got master heartbeat from node .*"
                r"which has lower priority"), "lower_priority_master", None),
    (re.compile(r"^Somebody thinks we're master"), "forced_takeover", None),
    (re.compile(r"^Failed to resolve name .* is not a leader"),
     "stale_leader_belief", None),
]

# Reasons that state WHY mastership moved, as opposed to merely recording that
# this node learned of a move the cluster had already made.
_REASONS_WITH_CAUSE = ("only_node", "master_removed", "timeout_takeover",
                       "surrendered", "demoted")


def _match(summary):
    """(holder, reason, expected) if this line is a belief change, else None.
    holder is a node name, _SELF, or None for "no master"; expected is the node
    the line names as the incoming holder, where it names one."""
    text = (summary or "").strip()
    if not text:
        return None
    for rx, src, reason, exp_src in _BELIEF_RULES:
        m = rx.match(text)
        if not m:
            continue
        expected = m.group(exp_src) if exp_src else None
        if src is None:
            return None, reason, expected
        if src is _SELF:
            return _SELF, reason, expected
        return m.group(src), reason, expected
    return None


def _conflict(summary):
    text = (summary or "").strip()
    for rx, kind, grp in _CONFLICT_RULES:
        m = rx.match(text)
        if m:
            return kind, (m.group(grp) if grp else None)
    return None


def _rows(conn):
    """Candidate lines: the two modules that carry mastership belief.

    Not limited to the ingest window, for the same reason the service and
    snapshot panels are not: the promotion that explains the window frequently
    happened just before it opened, and a lane whose first evidence is inside
    the window cannot say what was believed at the start of it.
    """
    return conn.execute(
        "SELECT id, node, ts_epoch, ts_local, tz_offset_min, source, severity, "
        "subsystem, summary FROM events WHERE subsystem IN "
        "('leader_registry', 'mb_master') AND ts_epoch IS NOT NULL "
        "ORDER BY ts_epoch, id").fetchall()


def _collect(conn):
    """Per-observer belief changes and conflicts, both time-ordered.

    Several of these lines go through ale's USER_LOGGER or ?log_info, which write
    to info.log as well as debug.log. Ingest's completeness stack already stores
    info.log only below debug.log's floor, so the overlap is confined to the
    boundary timestamp -- but that boundary is exactly where an election tends to
    sit in a windowed ingest. Deduped on (node, ts, summary), keeping the first,
    rather than by source, so it stays correct whichever of the two files a
    given collection happens to include.
    """
    beliefs, conflicts, seen = {}, [], set()
    for r in _rows(conn):
        summary = r["summary"] or ""
        key = (r["node"], r["ts_epoch"], summary)
        if key in seen:
            continue
        seen.add(key)

        hit = _match(summary)
        if hit is not None:
            holder, reason, expected = hit
            if holder is _SELF:
                holder = r["node"]
            beliefs.setdefault(r["node"], []).append({
                "observer": r["node"],
                "ts_epoch": r["ts_epoch"],
                "ts_local": r["ts_local"],
                "tz_offset_min": r["tz_offset_min"],
                "holder": holder,
                "reason": reason,
                "expected_holder": expected,
                "event_id": r["id"],
                "subsystem": r["subsystem"],
                "summary": summary,
            })
            continue

        hit = _conflict(summary)
        if hit is not None:
            kind, peer = hit
            conflicts.append({
                "observer": r["node"],
                "ts_epoch": r["ts_epoch"],
                "ts_local": r["ts_local"],
                "tz_offset_min": r["tz_offset_min"],
                "kind": kind,
                "peer": peer,
                "severity": r["severity"],
                "event_id": r["id"],
                "summary": summary,
            })
    return beliefs, conflicts


def _segments(changes, span_hi):
    """Collapse an observer's belief changes into held-until segments.

    Consecutive changes naming the same holder are one segment: a promotion is
    announced by mb_master AND logged by leader_registry within milliseconds, so
    a real transition produces two or three lines. Their event ids are all kept
    as evidence, which is also how the view shows corroboration -- a segment
    attested by both modules is on firmer ground than one seen by only one.
    """
    segs = []
    for c in changes:
        if segs and segs[-1]["holder"] == c["holder"]:
            seg = segs[-1]
            seg["evidence"].append(c["event_id"])
            seg["subsystems"].append(c["subsystem"])
            # A promotion or surrender line is a stronger statement about why
            # this node holds (or has stopped holding) mastership than the
            # announcement beside it, so it wins the segment's reason no matter
            # which of the two was logged first.
            if c["reason"] in _REASONS_WITH_CAUSE:
                seg["reason"] = c["reason"]
            if c["expected_holder"]:
                seg["expected_holder"] = c["expected_holder"]
            continue
        if segs:
            segs[-1]["end"] = c["ts_epoch"]
        segs.append({
            "holder": c["holder"],
            "expected_holder": c["expected_holder"],
            "start": c["ts_epoch"],
            "start_local": c["ts_local"],
            "tz_offset_min": c["tz_offset_min"],
            "end": None,
            "reason": c["reason"],
            "evidence": [c["event_id"]],
            "subsystems": [c["subsystem"]],
            "summary": c["summary"],
        })
    for seg in segs:
        if seg["end"] is None:
            seg["end"] = span_hi
        seg["subsystems"] = sorted(set(seg["subsystems"]))
    return segs


def _belief_at(segs, ts):
    """What this observer believed at ts: (holder, known). known is False before
    the observer's first evidence -- an unlit lane is unknown, never consensus.
    """
    if not segs or ts < segs[0]["start"]:
        return None, False
    holder = None
    for seg in segs:
        if seg["start"] <= ts:
            holder = seg["holder"]
        else:
            break
    return holder, True


def _consensus(lanes, span_lo, span_hi):
    """The whole span sliced into intervals, each labelled with how much the
    observers agreed. This is the bird's-eye answer -- one strip that says, at
    every instant, whether the cluster had one master, two, or none.

    Built on the merged set of change points across all lanes, so every interval
    has one belief per observer by construction. Observers with no evidence yet
    are excluded from the comparison rather than counted as believing "no
    master".

      agreed        every observer with an opinion named the same node.
      two_masters   two or more observers named DIFFERENT nodes. The partition
                    case, and the one worth an escalation.
      no_master     every observer with an opinion believed there was none.
                    Expected briefly at a handover; a long one means nothing was
                    orchestrating, so no rebalance and no auto-failover.
      partial       some named a node, others believed none. Ordinary
                    propagation if short.
      unknown       fewer than two observers had said anything yet. Not
                    agreement, and must not be drawn as any of the above.

    Intervals shorter than one heartbeat interval are marked transient rather
    than dropped: they are the expected shape of a clean handover, and hiding
    them would make a storm of them invisible.
    """
    points = sorted({seg["start"] for segs in lanes.values() for seg in segs})
    if span_lo is not None and (not points or points[0] > span_lo):
        points.insert(0, span_lo)
    out = []
    for i, ts in enumerate(points):
        end = points[i + 1] if i + 1 < len(points) else span_hi
        views = {}
        for observer, segs in lanes.items():
            holder, known = _belief_at(segs, ts)
            if known:
                views[observer] = holder
        holders = set(views.values())
        named = {h for h in holders if h}
        if len(views) < 2:
            kind = "unknown"
        elif len(named) > 1:
            kind = "two_masters"
        elif not named:
            kind = "no_master"
        elif None in holders:
            kind = "partial"
        else:
            kind = "agreed"
        rec = {
            "kind": kind, "start": ts, "end": end,
            "duration_s": (end - ts) if end is not None else None,
            "views": views,
            "holder": sorted(named)[0] if len(named) == 1 else None,
            "self_claimants": sorted(o for o, h in views.items() if h == o),
        }
        rec["transient"] = (rec["duration_s"] is not None
                            and rec["duration_s"] <= PROPAGATION_S)
        out.append(rec)

    # Adjacent identical intervals come from a change point in some OTHER lane
    # that did not alter the picture; merge them so a 40s two-masters window
    # reads as one 40s window and not as nine slices of it.
    merged = []
    for rec in out:
        prev = merged[-1] if merged else None
        if (prev and prev["kind"] == rec["kind"] and prev["end"] == rec["start"]
                and prev["views"] == rec["views"]):
            prev["end"] = rec["end"]
            if prev["end"] is not None:
                prev["duration_s"] = prev["end"] - prev["start"]
                prev["transient"] = prev["duration_s"] <= PROPAGATION_S
            continue
        merged.append(rec)
    return merged


def _episodes(divergences):
    """Contiguous same-kind divergence intervals rolled up into one episode each.

    _divergences slices at every change point in every lane, so one partition
    produces a row per node that changed its mind during it -- four rows for one
    60s event. The slices are what the lane view draws; an episode is what the
    verdict quotes and what an escalation is argued from.

    Only slices of the SAME kind are merged, even though a real incident runs
    straight from partial into no-master into partial with no gap. Merging across
    kinds and labelling the result with the worst one produces a false duration:
    a 10s window where nobody held mastership, followed by three minutes of one
    node holding a stale belief, is not "no master for 200s". Each episode is one
    condition and its duration is a claim that survives being checked.
    """
    out = []
    for rec in divergences:
        prev = out[-1] if out else None
        if prev and prev["kind"] == rec["kind"] and prev["end"] == rec["start"]:
            prev["end"] = rec["end"]
            prev["slices"] += 1
            prev["holders"].update(h for h in rec["views"].values() if h)
            prev["self_claimants"].update(rec["self_claimants"])
        else:
            out.append({
                "kind": rec["kind"], "start": rec["start"], "end": rec["end"],
                "slices": 1,
                "holders": {h for h in rec["views"].values() if h},
                "self_claimants": set(rec["self_claimants"]),
            })
    for ep in out:
        ep["duration_s"] = ((ep["end"] - ep["start"])
                            if ep["end"] is not None else None)
        ep["transient"] = (ep["duration_s"] is not None
                           and ep["duration_s"] <= PROPAGATION_S)
        ep["holders"] = sorted(ep["holders"])
        ep["self_claimants"] = sorted(ep["self_claimants"])
    return out


def _capture_span(conn):
    """The whole capture's extent, for context only -- never the chart's x-axis.
    See _span for why."""
    lo, hi = conn.execute(
        "SELECT MIN(ts_epoch), MAX(ts_epoch) FROM events "
        "WHERE ts_epoch IS NOT NULL").fetchone()
    meta = {}
    for r in conn.execute("SELECT key, value FROM meta").fetchall():
        try:
            meta[r["key"]] = json.loads(r["value"])
        except (ValueError, TypeError):
            pass
    if lo is not None and meta.get("window_lo") is not None:
        lo = max(lo, meta["window_lo"])
    if hi is not None and meta.get("window_hi") is not None:
        hi = min(hi, meta["window_hi"])
    return lo, hi


def _span(evidence_ts, capture_lo, capture_hi):
    """The chart's x-axis: the extent of the mastership evidence itself.

    Emphatically NOT the capture's extent. The always-full sources (event_log,
    diag, dmesg) span the entire retention of a cbcollect, so on a real 4-node
    bundle MIN(ts_epoch) can sit weeks before the first mb_master line -- one
    measured capture spanned 18,000 hours while every election in it happened
    inside a single hour. Scaled to the capture, that hour is a third of a pixel
    and the whole view reads as empty. The evidence's own extent is also the only
    span this view can speak to: outside it, nothing is known about who held
    mastership, so drawing it would be drawing an assumption.

    A margin of 2% of the span (at least a second) keeps the first and last
    transitions off the edges where they are easy to miss.
    """
    if not evidence_ts:
        return capture_lo, capture_hi
    lo, hi = min(evidence_ts), max(evidence_ts)
    pad = max((hi - lo) * 0.02, 1.0)
    return lo - pad, hi + pad


def query_leadership(conn):
    """The mb_master leadership view: one lane per observer, plus the intervals
    where the lanes disagreed and the competing claims nodes reported seeing."""
    beliefs, conflicts = _collect(conn)
    cap_lo, cap_hi = _capture_span(conn)
    evidence_ts = [c["ts_epoch"] for chs in beliefs.values() for c in chs]
    evidence_ts += [c["ts_epoch"] for c in conflicts]
    lo, hi = _span(evidence_ts, cap_lo, cap_hi)

    lanes = {obs: _segments(chs, hi) for obs, chs in beliefs.items()}
    consensus = _consensus(lanes, lo, hi)
    divergences = [c for c in consensus
                   if c["kind"] not in ("agreed", "unknown")]
    episodes = _episodes(divergences)

    # Every node in the capture, not just the ones with belief lines: a node
    # that logged nothing about mastership is itself worth seeing as an empty
    # lane, since the usual reason is that its debug.log does not reach back
    # this far.
    nodes = [r["name"] for r in conn.execute(
        "SELECT name FROM nodes ORDER BY name").fetchall()]
    observers = sorted(set(nodes) | set(lanes))

    holders = [seg["holder"] for segs in lanes.values() for seg in segs
               if seg["holder"]]
    # Headline numbers count only episodes longer than one heartbeat interval.
    # A cluster where nodes come and go has brief disagreement constantly -- that
    # is what the propagation of an announcement looks like, not an incident --
    # and counting it would put a number in the header that is never zero and so
    # never means anything.
    solid = [e for e in episodes if not e["transient"]]
    longest = {}
    for kind in ("two_masters", "no_master"):
        longest[kind] = max((e for e in solid if e["kind"] == kind),
                            key=lambda e: e["duration_s"] or 0, default=None)
    worst = longest["two_masters"]
    gap = longest["no_master"]
    # A node named as the holder that has no lane of its own: its cbcollect was
    # not in the bundle. Worth saying, because its lane is the one that would
    # settle whether it agreed it was the master. A pre-rename name is excluded:
    # it has no lane because it is not a separate node at all, and calling it a
    # missing capture would send someone looking for a cbcollect that cannot
    # exist.
    def _is_bootstrap(node):
        return (node or "").endswith("@" + LOCALHOST_ALIAS)

    bootstrap = sorted({h for h in holders if _is_bootstrap(h)})
    uncollected = sorted({h for h in holders
                          if h not in lanes and not _is_bootstrap(h)})
    return {
        "axis": "mb_master",
        # The evidence's span, which is what the chart is drawn on, and the
        # capture's, which is usually far wider. Both are reported so the header
        # can say the view covers an hour of a three-week bundle.
        "span": {"lo": lo, "hi": hi},
        "capture_span": {"lo": cap_lo, "hi": cap_hi},
        "propagation_s": PROPAGATION_S,
        "observers": observers,
        "uncollected_holders": uncollected,
        "bootstrap_holders": bootstrap,
        "consensus": consensus,
        "lanes": [{"observer": o,
                   "segments": lanes.get(o, []),
                   # Transitions this observer announced, and how many log lines
                   # attested them. The two differ because one transition is
                   # logged by both modules.
                   "changes": len(lanes.get(o, [])),
                   "lines": len(beliefs.get(o, [])),
                   # Where the lane's evidence came from, so a lane resting on
                   # mb_master alone is not read as strongly as one the registry
                   # also attests.
                   "subsystems": sorted({c["subsystem"]
                                         for c in beliefs.get(o, [])})}
                  for o in observers],
        "divergences": divergences,
        "episodes": episodes,
        "conflicts": conflicts,
        "verdict": {
            "holders": sorted(set(holders)),
            "changes": sum(len(v) for v in lanes.values()),
            # How much of the covered span the cluster spent agreeing. The
            # headline number for "were they in sync".
            "agreed_s": sum(c["duration_s"] or 0 for c in consensus
                            if c["kind"] == "agreed"),
            "diverged_s": sum(c["duration_s"] or 0 for c in divergences),
            "silent_observers": [o for o in observers if o not in lanes],
            "two_masters_episodes": sum(1 for e in solid
                                        if e["kind"] == "two_masters"),
            "longest_two_masters_s": (worst or {}).get("duration_s"),
            "longest_two_masters_at": (worst or {}).get("start"),
            # A stretch where no observer believed anyone held it: nothing was
            # orchestrating, so no rebalance and no auto-failover could have run
            # however healthy the nodes looked.
            "longest_no_master_s": (gap or {}).get("duration_s"),
            "longest_no_master_at": (gap or {}).get("start"),
            "conflicts_seen": len(conflicts),
        },
    }
