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
"""Normalized event record and category/severity classification.

Every parser emits Event records with a common shape so the timeline can
filter and correlate uniformly across logs and nodes.
"""
from dataclasses import dataclass, field
import re


# Severity levels, ordered weakest -> strongest. The UI filters on these.
SEVERITIES = ["debug", "info", "warn", "error", "critical", "unknown"]

# Categories used as timeline "lanes". Keep this list stable; the UI keys off
# it. "other" is the catch-all.
CATEGORIES = [
    "connectivity",   # node up/down, disconnects, net partitions
    "failover",       # auto/hard/graceful failover
    "rebalance",      # rebalance + topology changes
    "orchestrator",   # mb_master / chronicle leader / orchestrator moves
    "crash",          # supervisor/crash reports, port crashes, restarts
    "config",         # ns_config / chronicle / bucket / settings changes
    "os_kernel",      # OOM, disk errors, link down, hung tasks (dmesg/syslog)
    "boot",           # OS boot (kernel banner) / ns_server start banner
    "http",           # http_access(_internal)
    "other",
]

# Clock confidence for a resolved timestamp:
#   exact      - timestamp carried an explicit offset (ns_server, http_access)
#   inferred   - reconstructed (dmesg monotonic via boot time; syslog + year)
#   unanchored - could not resolve to wallclock (kept, but excluded from axis)
CLOCK_EXACT = "exact"
CLOCK_INFERRED = "inferred"
CLOCK_UNANCHORED = "unanchored"


@dataclass
class Event:
    node: str
    source: str                 # logical source: debug, http_access, ...
    ts_utc_epoch: float | None  # seconds since unix epoch (UTC), None if N/A
    ts_local: str               # original timestamp text as it appeared
    # Local UTC offset (minutes) in effect on this line. Exact sources
    # (ns_server, http_access) carry it per line, so it is DST-correct across a
    # months-long collection; None is filled at ingest with the node's
    # collection offset for sources that don't log an offset (dmesg/diag).
    tz_offset_min: int | None = None
    severity: str = "unknown"
    category: str = "other"
    subsystem: str | None = None
    pid: str | None = None
    summary: str = ""
    raw: str = ""
    fields: dict = field(default_factory=dict)
    clock_confidence: str = CLOCK_EXACT
    log_path: str | None = None
    line_no: int | None = None
    # Byte offset (a tell() cookie) of this entry's start in log_path, so the
    # full raw text can be re-read on demand when it isn't stored (lazy index).
    # Set only by the seekable single-file parsers (ns_server, http_access).
    byte_off: int | None = None


# (compiled regex, category) ordered by priority. First match wins. Matched
# against a lowercased blob of "subsystem + summary/first line".
_CATEGORY_RULES = [
    # Boot markers. THREE nesting levels, deliberately in one lane:
    # "Linux version" (dmesg first line) = OS boot; "Brought up <vm> logging"
    # (ns_babysitter/ns_couchdb/config_remap init) = that Erlang VM starting,
    # babysitter's being the whole-service start; "Started & configured
    # logging" (ns_server:init_logging) = ns_server start, which also fires on
    # an inner restart under a running babysitter. A banner with no
    # outer-level banner nearby reads as restart-without-reboot.
    (r"started & configured logging|brought up \w+ logging|"
     r"\blinux version \d", "boot"),

    # OS / kernel first: these signatures are unambiguous and high value.
    (r"out of memory|oom-killer|killed process \d|oom_kill", "os_kernel"),
    (r"hung task|blocked for more than \d+ seconds|soft lockup", "os_kernel"),
    (r"link is down|link down|nic link|carrier lost", "os_kernel"),
    (r"i/o error|ext4-fs error|xfs.*(error|corrupt)|md/raid|ata\d.*error",
     "os_kernel"),
    (r"segfault|general protection|kernel panic|call trace:", "os_kernel"),

    (r"auto[_ ]?failover|failover|failing over|failed[_ ]over|"
     r"orchestrate_failover|failover_safeness", "failover"),
    (r"rebalance|topology|recovery_(start|end)|janitor.*(stale|bad)|"
     r"\bvbucket move", "rebalance"),
    (r"node_down|nodedown|node_up|nodeup|ns_node_disco|nodes_wanted|"
     r"net_kernel|heart|lost connection|connection (refused|closed)|"
     r"disconnect|could not connect|econnrefused|\bdown\b.*node|"
     r"did(n't| not) respond|nodes? failed to respond|no response from",
     "connectivity"),
    (r"ns_orchestrator|mb_master|became (the )?master|took over mastership|"
     r"new leader|not_leader|leader_(activities|registry)|chronicle_leader|"
     r"compat_mode", "orchestrator"),
    (r"crash report|supervisor report|terminating|\*\* generic server|"
     r"\*\* state machine|exited with reason|port server.*(crash|exit|died)|"
     r"respawning|child terminated|reached_max_restart|killed by signal",
     "crash"),
    (r"ns_config|chronicle|bucket.*(created|deleted|updated)|set_bucket|"
     r"config change|settings.*(changed|updated)|memcached_config|"
     r"collections manifest", "config"),
]
_CATEGORY_RULES = [(re.compile(p, re.I), c) for p, c in _CATEGORY_RULES]


def categorize(source, subsystem, text):
    """Best-effort category from source + subsystem + leading text."""
    if source in ("http_access", "http_access_internal"):
        return "http"
    blob = " ".join(x for x in (subsystem or "", (text or "")[:400]) if x)
    for rx, cat in _CATEGORY_RULES:
        if rx.search(blob):
            return cat
    return "other"


# ns_server / OTP log-level token -> normalized severity.
_LEVEL_MAP = {
    "debug": "debug",
    "info": "info",
    "warn": "warn",
    "warning": "warn",
    "error": "error",
    "critical": "critical",
    "crit": "critical",
    "emergency": "critical",
    "alert": "critical",
}


def normalize_severity(level_token):
    if not level_token:
        return "unknown"
    return _LEVEL_MAP.get(level_token.strip().lower(), "unknown")
