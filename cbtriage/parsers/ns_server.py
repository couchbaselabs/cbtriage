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
"""Parser for ns_server ALE-format logs.

Shared by debug/info/error/reports/babysitter/json_rpc — all use the same
header:
    [<logger>:<level>,<ts±offset>,<node>:<pid>:<module>:<function>:<line>]<msg>

Entries are multi-line: any line not matching the header is a continuation of
the current entry (config dumps, stacktraces, term dumps) and is folded in.
"""
import re

from ..events import Event, categorize, normalize_severity, CLOCK_EXACT
from ..clock import parse_iso_offset
from .. import nodes
from ..discovery import open_text
from ..seek import seek_start
from . import service_lifecycle

_HEADER_RE = re.compile(
    r"^\[(?P<logger>[\w]+):(?P<level>[a-z]+),"
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:[+-]\d{2}:\d{2}|Z)),"
    r"(?P<rest>[^\]]*)\](?P<msg>.*)$")

# Service rebalance / service-agent process names embed the service:
#   service_manager-eventing-worker, service_agent-index-..., service_rebalancer
# The trailing part is a channel/worker suffix, not the service, so the capture
# is normalized against the known ServiceAPI names (see service_lifecycle).
_SERVICE_RE = re.compile(
    r"(?:service_manager|service_agent|service_rebalancer|"
    r"json_rpc_connection)-([a-z0-9_-]+)")

_NODE_HEAD_RE = re.compile(r"^(" + nodes.NODE + r")")

MAX_RAW = 32_768  # cap a single folded entry; term dumps can be huge


def _split_node_pid(rest):
    """rest = node:pid:... -> (node, everything after it), where the NODE may
    itself contain colons.

    On an IPv6 cluster the node is n_10@::1 or ns_1@fd63:...:1, so splitting
    this on the first colon truncates it to 'n_10@' -- and the truncated form
    still looks like a node name, so it propagates as a second identity for the
    same node instead of failing. It also shifts every field after it by one,
    which is how a pid ended up in the module column.

    The pid field is the anchor: it is either <0.146.0> or a registered name
    carrying one (net_kernel<0.123.0>), and neither a node name nor a module or
    function name contains '<'. So the node ends at the last colon before the
    first '<'. Without a pid shape there is nothing to anchor on and the node
    pattern decides where the name ends."""
    cut = rest.find("<")
    if cut != -1:
        colon = rest.rfind(":", 0, cut)
        if colon != -1:
            return rest[:colon], rest[colon + 1:]
        return None, rest
    m = _NODE_HEAD_RE.match(rest)
    if m:
        return m.group(1), rest[m.end():].lstrip(":")
    node, _, tail = rest.partition(":")
    return node or None, tail


def _split_rest(rest):
    """rest = node:pid:module:function:line -> tuple, defensively."""
    node, tail = _split_node_pid(rest)
    parts = tail.split(":") if tail else []
    pid = mod = fn = line = None
    if len(parts) >= 4 and parts[-1].isdigit():
        line, fn, mod = parts[-1], parts[-2], parts[-3]
        pid = ":".join(parts[:-3])
    elif len(parts) >= 3 and parts[-1].isdigit():
        line, mod = parts[-1], parts[-2]
        pid = ":".join(parts[:-2])
    elif parts:
        pid = ":".join(parts)
    return node, pid or None, mod, fn, line


def _build(node_name, source, cur):
    head = cur["header"]
    raw = "\n".join(cur["raw"])
    if len(raw) > MAX_RAW:
        raw = raw[:MAX_RAW] + "\n... [truncated]"
    log_node, pid, mod, fn, line = _split_rest(head["rest"])
    msg = head["msg"]
    summary = msg.strip()[:300] if msg.strip() else (
        cur["raw"][1].strip()[:300] if len(cur["raw"]) > 1 else "")
    epoch, off = parse_iso_offset(head["ts"])

    fields = {"logger": head["logger"], "function": fn, "line": line}
    if log_node and log_node != node_name:
        fields["log_node"] = log_node
    svc = _SERVICE_RE.search(head["rest"])
    if svc:
        fields["service"] = service_lifecycle.normalize_rpc_service(svc.group(1))
    # Babysitter start/stop/exit lines. Tags `service` (from the message text or
    # the goport process label) + `lifecycle`, so a service's whole history can
    # be pulled by name alongside its json_rpc traffic.
    service_lifecycle.annotate(msg, head["rest"], fields)

    return Event(
        node=node_name,
        source=source,
        ts_utc_epoch=epoch,
        ts_local=head["ts"],
        tz_offset_min=off,
        severity=normalize_severity(head["level"]),
        category=categorize(source, mod, msg or summary),
        subsystem=mod,
        pid=pid,
        summary=summary,
        raw=raw,
        fields=fields,
        clock_confidence=CLOCK_EXACT,
        log_path=cur["path"],
        line_no=cur["line_no"],
        byte_off=cur["byte_off"],
    )


def _line_epoch(line):
    """UTC epoch of an ALE line, or None for a continuation line (used by the
    --start byte-seek)."""
    m = _HEADER_RE.match(line)
    if not m:
        return None
    return parse_iso_offset(m.group("ts"))[0]


def parse(node_name, source, path, ctx, start_epoch=None):
    """Yield Event per folded ALE entry. With start_epoch set, byte-seek past
    the head of the file to the first entry at/after it (line_no is then unknown
    and left None; it's only a display hint). Each entry records the byte offset
    (tell() cookie) of its header line so the raw text can be re-read on demand
    when it isn't stored -- read via readline()+tell() (not a for-loop, whose
    read-ahead makes tell() meaningless)."""
    cur = None
    off = seek_start(path, start_epoch, _line_epoch)
    seeked = off > 0
    with open_text(path) as f:
        if off:
            f.seek(off)
        i = 0
        while True:
            pos = f.tell()
            line = f.readline()
            if not line:
                break
            i += 1
            line = line.rstrip("\n")
            m = _HEADER_RE.match(line)
            if m:
                if cur is not None:
                    yield _build(node_name, source, cur)
                cur = {
                    "header": m.groupdict(),
                    "raw": [line],
                    "path": str(path),
                    "line_no": None if seeked else i,
                    "byte_off": pos,
                }
            elif cur is not None:
                cur["raw"].append(line)
            # lines before the first header (rare, or the partial entry left of
            # a seek landing) are ignored
    if cur is not None:
        yield _build(node_name, source, cur)
