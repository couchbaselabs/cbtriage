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
"""ServiceAPI call/response analysis over json_rpc.log.

Ported from scripts/service_tasks.py (the user's proven logic): pair each
ServiceAPI call with its response by request id, compute round-trip time, and
decode topology-change (rebalance/failover) payloads. Calls with no response
are surfaced as warnings — that is the "service not responding to a service
rebalance task" signal that drives the punt-to-service-team decision.

Handles both JSON and Erlang-binary term encodings of the payload.
"""
import re

from ..events import Event, CLOCK_EXACT, CLOCK_UNANCHORED
from ..clock import parse_iso_offset
from ..discovery import open_text
from .service_lifecycle import split_rpc_label

_SERVICE_RE = re.compile(r"json_rpc_connection-([a-z0-9_-]+)", re.I)

_ID = (re.compile(r'"id"\s*:\s*(\d+)'), re.compile(r'<<"id">>,\s*(\d+)'),
       re.compile(r"\bid,(\d+)"))
_METHOD = (re.compile(r'"method"\s*:\s*"([^"]+)"'),
           re.compile(r'<<"method">>,<<"([^"]+)"'),
           re.compile(r'\{method,<<"([^"]+)"'))
_TC_TYPE = (re.compile(r'"type"\s*:\s*"(topology-change-[^"]+)"'),
            re.compile(r'<<"type">>,<<"(topology-change-[^"]+)"'))
_KEEP = (re.compile(r'"keepNodes"\s*:\s*\[(.*?)\]', re.S),
         re.compile(r'<<"keepNodes">>,\s*\[(.*?)\]', re.S))
_EJECT = (re.compile(r'"ejectNodes"\s*:\s*\[(.*?)\]', re.S),
          re.compile(r'<<"ejectNodes">>,\s*\[(.*?)\]', re.S))
_TASKS = (re.compile(r'"tasks"\s*:\s*\[(.*?)\]', re.S),
          re.compile(r'<<"tasks">>,\s*\[(.*?)\]', re.S))
_TC_ID = (re.compile(r'"id"\s*:\s*"([0-9a-fA-F-]+)"'),
          re.compile(r'<<"id">>,<<"([0-9a-fA-F-]+)"'))
# Whether a GetTaskList response still carries a running rebalance task, and
# whether GetCurrentTopology reports the service as balanced -- the two answers
# that say if the service thinks it is still mid-rebalance.
_HAS_REBAL = re.compile(r'"type"\s*:\s*"task-rebalance"|'
                        r'<<"type">>,<<"task-rebalance"')
_ISBAL = (re.compile(r'"isBalanced"\s*:\s*(true|false)'),
          re.compile(r'<<"isBalanced">>,(true|false)'))

_METHODS = {
    "ServiceAPI.GetTaskList": "GetTaskList",
    "ServiceAPI.GetCurrentTopology": "GetCurrentTopology",
    "ServiceAPI.PrepareTopologyChange": "PrepareTopologyChange",
    "ServiceAPI.StartTopologyChange": "StartTopologyChange",
    "ServiceAPI.CancelTask": "CancelTask",
}
# Topology-change methods are the rebalance-critical ones.
_REBALANCE_METHODS = {"PrepareTopologyChange", "StartTopologyChange",
                      "GetTaskList", "CancelTask"}

# A call still unanswered within this many seconds of the log's last activity
# was almost certainly cut off by the cbcollect snapshot (the response would
# have landed after capture), not a service that failed to respond.
_CAPTURE_BOUNDARY_S = 30


def _first(block, regexes):
    for r in regexes:
        m = r.search(block)
        if m:
            return m.group(1)
    return None


def _count_items(block):
    s = (block or "").strip()
    return s.count("},{") + 1 if s else 0


def _hdr(line):
    """(ts, service, channel) from an ALE header line. The channel says whether
    this connection is the ServiceAPI one (rebalance) or background traffic."""
    i = line.find(",")
    j = line.find("Z", i) if i != -1 else -1
    ts = line[i + 1:j + 1].strip() if i != -1 and j != -1 else ""
    if not ts:  # offset form (...-07:00]) rather than Z
        m = re.search(r",(\d{4}-\d{2}-\d{2}T[\d:.]+[+-]\d{2}:\d{2}),", line)
        ts = m.group(1) if m else ""
    sm = _SERVICE_RE.search(line)
    svc, chan = split_rpc_label(sm.group(1)) if sm else (None, None)
    return ts, svc, chan


def _is_call(line):
    return ("json_rpc_connection:start_call" in line
            and "sending jsonrpc call" in line)


def _is_resp(line):
    return ("json_rpc_connection:handle_info" in line
            and "got response" in line)


def _category(method):
    return "rebalance" if method in _REBALANCE_METHODS else "other"


def parse(node_name, source, path, ctx):
    pending = {}          # id -> call dict
    buf, mode, hdr = [], None, ""
    last = {"epoch": None}   # latest activity epoch seen (the log's tail)

    def epoch_of(ts):
        e, _ = parse_iso_offset(ts) if ts else (None, None)
        return e

    def off_of(ts):
        _, o = parse_iso_offset(ts) if ts else (None, None)
        return o

    def saw(e):
        if e is not None and (last["epoch"] is None or e > last["epoch"]):
            last["epoch"] = e

    def on_call(block, header):
        ts, svc, chan = _hdr(header)
        method = _METHODS.get(_first(block, _METHOD) or "")
        rid = _first(block, _ID)
        saw(epoch_of(ts))
        if not method or not rid:
            return
        extras = {}
        if method in ("PrepareTopologyChange", "StartTopologyChange"):
            extras["tc_type"] = _first(block, _TC_TYPE)
            extras["tc_id"] = _first(block, _TC_ID)
            extras["keep_n"] = _count_items(_first(block, _KEEP))
            extras["eject_n"] = _count_items(_first(block, _EJECT))
        pending[rid] = {"ts": ts, "svc": svc, "chan": chan, "method": method,
                        "extras": extras, "header": header}

    def on_resp(block, header):
        ts, svc, chan = _hdr(header)
        rid = _first(block, _ID)
        call = pending.pop(rid, None) if rid else None
        method = call["method"] if call else None
        details = {}
        if method == "GetTaskList" or _first(block, _TASKS):
            method = method or "GetTaskList"
            details["tasks_count"] = _count_items(_first(block, _TASKS))
            # Does the service still believe it has a rebalance task running?
            # This is the field that separates "the service is done and
            # ns_server missed it" from "the service really is still working".
            details["has_task_rebalance"] = bool(_HAS_REBAL.search(block))
        if method == "GetCurrentTopology" or _first(block, _ISBAL):
            method = method or "GetCurrentTopology"
            isbal = _first(block, _ISBAL)
            if isbal is not None:
                details["is_balanced"] = (isbal == "true")
        rt_ms = None
        e1 = epoch_of(ts)
        saw(e1)
        if call:
            e0 = epoch_of(call["ts"])
            if e0 and e1:
                rt_ms = round((e1 - e0) * 1000, 1)
            svc = call["svc"] or svc
            chan = call["chan"] or chan
            details.update({k: v for k, v in call["extras"].items()
                            if v is not None})
        fields = {"service": svc, "channel": chan, "method": method,
                  "phase": "response", "request_id": rid, "rt_ms": rt_ms,
                  **details}
        summary = f"{method or 'response'} on {svc}"
        if rt_ms is not None:
            summary += f" rt={rt_ms}ms"
        return Event(
            node=node_name, source="json_rpc", ts_utc_epoch=e1, ts_local=ts,
            tz_offset_min=off_of(ts),
            severity="info", category=_category(method), subsystem=method,
            summary=summary[:300],
            raw=(call["header"] + "\n" + header).strip() if call else header,
            fields=fields,
            clock_confidence=CLOCK_EXACT if e1 else CLOCK_UNANCHORED,
            log_path=str(path))

    with open_text(path) as f:
        for line in f:
            if _is_call(line):
                if buf and mode == "resp":
                    ev = on_resp("".join(buf), hdr)
                    if ev:
                        yield ev
                elif buf and mode == "call":
                    on_call("".join(buf), hdr)
                buf, mode, hdr = [line], "call", line
            elif _is_resp(line):
                if buf and mode == "resp":
                    ev = on_resp("".join(buf), hdr)
                    if ev:
                        yield ev
                elif buf and mode == "call":
                    on_call("".join(buf), hdr)
                buf, mode, hdr = [line], "resp", line
            elif buf and line.startswith("[") and not (
                    _is_call(line) or _is_resp(line)):
                if mode == "call":
                    on_call("".join(buf), hdr)
                elif mode == "resp":
                    ev = on_resp("".join(buf), hdr)
                    if ev:
                        yield ev
                buf, mode, hdr = [], None, ""
            elif buf:
                buf.append(line)
    if buf and mode == "call":
        on_call("".join(buf), hdr)
    elif buf and mode == "resp":
        ev = on_resp("".join(buf), hdr)
        if ev:
            yield ev

    # Calls with no response: the service-not-responding signal. Calls still
    # outstanding within _CAPTURE_BOUNDARY_S of the log's tail were cut off by
    # the snapshot, not unanswered — flag them so the finding can skip them.
    for rid, c in pending.items():
        e = epoch_of(c["ts"])
        boundary = (last["epoch"] is not None and e is not None
                    and (last["epoch"] - e) <= _CAPTURE_BOUNDARY_S)
        # How long the call had been outstanding when the log ran out. This is
        # the number that answers "the rebalance is stalled -- on what, and for
        # how long"; a call outstanding for minutes is the stall, one
        # outstanding for a second was merely cut off by the snapshot.
        outstanding = (round(last["epoch"] - e, 1)
                       if last["epoch"] is not None and e is not None else None)
        fields = {"service": c["svc"], "channel": c["chan"],
                  "method": c["method"],
                  "phase": "no_response", "request_id": rid,
                  "at_capture_boundary": boundary,
                  "outstanding_s": outstanding,
                  **{k: v for k, v in c["extras"].items() if v is not None}}
        prefix = "IN-FLIGHT AT CAPTURE" if boundary else "NO RESPONSE"
        yield Event(
            node=node_name, source="json_rpc", ts_utc_epoch=e, ts_local=c["ts"],
            tz_offset_min=off_of(c["ts"]),
            severity="info" if boundary else "warn",
            category=_category(c["method"]),
            subsystem=c["method"],
            summary=f"{prefix}: {c['method']} on {c['svc']}"[:300],
            raw=c["header"].strip(),
            fields=fields,
            clock_confidence=CLOCK_EXACT if e else CLOCK_UNANCHORED,
            log_path=str(path))
