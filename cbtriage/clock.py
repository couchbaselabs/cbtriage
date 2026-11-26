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
"""Per-node clock context and timestamp normalization to UTC.

The hard part of correlating cbcollect logs: every source stamps time
differently, and dmesg/syslog don't carry a usable wallclock at all.

Strategy: build one ClockContext per node from couchbase.log (the node's
`date`, `uptime`, and timezone), then normalize every parsed timestamp to a
UTC epoch through it. Sources with an explicit offset (ns_server, http_access)
don't need the context and resolve exactly; dmesg-monotonic and syslog do.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
import re


@dataclass
class ClockContext:
    node: str
    tz_offset_min: int | None = None   # node local TZ offset from UTC, minutes
    tz_name: str | None = None         # e.g. "PDT", from `date`
    boot_epoch: float | None = None    # for dmesg/journal monotonic anchoring
    collection_epoch: float | None = None  # node's `date` at collection time
    year: int | None = None            # for syslog (no year in its stamps)
    notes: list = field(default_factory=list)

    def offset(self):
        return timedelta(minutes=self.tz_offset_min or 0)


# ---------------------------------------------------------------------------
# Explicit-offset timestamps (the easy, exact case)
# ---------------------------------------------------------------------------

def parse_iso_offset(ts):
    """ns_server style: 2026-01-15T15:02:24.656-08:00 -> (epoch, offset_min)."""
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        return None, None
    if dt.tzinfo is None:
        return None, None
    off = int(dt.utcoffset().total_seconds() // 60)
    return dt.timestamp(), off


_CLF_RE = re.compile(r"^(\d{2})/(\w{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*"
                     r"([+-]\d{4})$")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def parse_clf(ts):
    """http_access style: 21/May/2026:15:02:48 -0700 -> (epoch, offset_min)."""
    m = _CLF_RE.match(ts.strip())
    if not m:
        return None, None
    day, mon, year, hh, mm, ss, off = m.groups()
    month = _MONTHS.get(mon)
    if not month:
        return None, None
    sign = 1 if off[0] == "+" else -1
    off_min = sign * (int(off[1:3]) * 60 + int(off[3:5]))
    tz = timezone(timedelta(minutes=off_min))
    dt = datetime(int(year), month, int(day), int(hh), int(mm), int(ss),
                  tzinfo=tz)
    return dt.timestamp(), off_min


# ---------------------------------------------------------------------------
# Building the per-node clock context from couchbase.log
# ---------------------------------------------------------------------------

# `date` output e.g. "Wed Jun 19 10:00:00 PDT 2024" or with numeric offset.
#
# Anchored to a WHOLE LINE. couchbase.log dumps `uname -a` before `date`, and
# the kernel build stamp inside it is the same shape:
#   Linux host 6.8.0-71-generic #71-Ubuntu SMP ... Tue Jul 22 16:52:38 UTC 2025 ...
# An unanchored search matched that first and took the kernel's build date as
# the node's collection time -- out by however old the OS image is (11 months
# on the capture this was found with). `date` prints the timestamp alone on
# its own line, so requiring a full-line match separates them.
_DATE_RE = re.compile(
    r"^(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+"
    r"([A-Z]{2,5}|[+-]\d{4})\s+(\d{4})\s*$", re.M)
_UPTIME_SECS_RE = re.compile(r"^\s*([\d.]+)\s")  # /proc/uptime first field


def _named_tz_offset_min(name, sample_epoch):
    """Best-effort offset for a TZ abbreviation. Abbreviations are ambiguous
    globally, so we only resolve via the explicit numeric offset path; here we
    just record the name and leave offset to be inferred from log offsets."""
    return None


def find_uptime_secs(path):
    """Host uptime (seconds) from couchbase.log's raw /proc/uptime one-shot.

    Streams the file and stops at the hit. This is a separate pass because the
    section sits deep in couchbase.log -- byte ~2.1M on a real capture, far
    past the head that build_clock_context is handed -- so the caller cannot
    supply it from that text. Without it boot_epoch stays None, and the dmesg
    lines that carry only a monotonic timestamp (journalctl -ko
    short-monotonic) cannot be resolved to wallclock at all -- 1837 of 3670 on
    the capture this was found with."""
    seen_header = False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if "/proc/uptime" in line:
                    seen_header = True
                    continue
                if seen_header:
                    # "<up_secs> <idle_secs>" -- the first such line after the
                    # header. Section banners (====) are skipped over.
                    m = re.match(r"^\s*(\d+\.\d+)\s+\d+\.\d+\s*$", line)
                    if m:
                        return float(m.group(1))
    except OSError:
        return None
    return None


def build_clock_context(node, couchbase_log_text, fallback_offset_min=None,
                        uptime_secs=None):
    """Construct a ClockContext from couchbase.log text (may be empty).

    uptime_secs: host uptime from find_uptime_secs(), when the caller has read
    far enough into couchbase.log to have it; falls back to scanning the text.

    fallback_offset_min: offset learned from ns_server/http_access log lines,
    used when couchbase.log gives a TZ abbreviation we can't resolve.
    """
    ctx = ClockContext(node=node)
    text = couchbase_log_text or ""

    # collection wallclock from `date`
    dm = _DATE_RE.search(text)
    coll_dt = None
    if dm:
        _, mon, day, hh, mm, ss, tz, year = dm.groups()
        ctx.tz_name = tz if tz[0] not in "+-" else None
        ctx.year = int(year)
        month = _MONTHS.get(mon)
        if tz[0] in "+-":
            sign = 1 if tz[0] == "+" else -1
            ctx.tz_offset_min = sign * (int(tz[1:3]) * 60 + int(tz[3:5]))
        elif fallback_offset_min is not None:
            ctx.tz_offset_min = fallback_offset_min
            ctx.notes.append(
                f"TZ abbreviation {tz!r} resolved via log offset")
        if month:
            off = timedelta(minutes=ctx.tz_offset_min or 0)
            coll_dt = datetime(int(year), month, int(day), int(hh), int(mm),
                               int(ss), tzinfo=timezone(off))
            ctx.collection_epoch = coll_dt.timestamp()

    if ctx.tz_offset_min is None and fallback_offset_min is not None:
        ctx.tz_offset_min = fallback_offset_min

    # uptime -> boot epoch (prefer raw /proc/uptime seconds when present)
    if uptime_secs is None:
        for line in text.splitlines():
            m = re.match(r"^\s*(\d+\.\d+)\s+\d+\.\d+\s*$", line)  # /proc/uptime
            if m:
                uptime_secs = float(m.group(1))
                break
    if uptime_secs is not None and ctx.collection_epoch is not None:
        ctx.boot_epoch = ctx.collection_epoch - uptime_secs
        ctx.notes.append("boot time = date - /proc/uptime")

    if ctx.year is None:
        ctx.notes.append("no `date` found; syslog year may be wrong")
    return ctx


# ---------------------------------------------------------------------------
# dmesg / syslog / journal normalization (the inferred cases)
# ---------------------------------------------------------------------------

# dmesg raw / journalctl short-monotonic: "[ 1234.567]" seconds since boot.
_MONO_RE = re.compile(r"^\[\s*(\d+\.\d+)\]")
# dmesg -T: "[Wed Jun 19 10:00:00 2024]"
_DMESG_T_RE = re.compile(
    r"^\[(\w{3})\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})\]")
# syslog / journalctl short: "Jun 19 10:00:00" (no year)
_SYSLOG_RE = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")


def resolve_dmesg(line, ctx):
    """Return (epoch, confidence) for a dmesg/journal-monotonic line."""
    m = _DMESG_T_RE.match(line)
    if m:
        _, mon, day, hh, mm, ss, year = m.groups()
        month = _MONTHS.get(mon)
        if month:
            off = timedelta(minutes=ctx.tz_offset_min or 0)
            dt = datetime(int(year), month, int(day), int(hh), int(mm),
                          int(ss), tzinfo=timezone(off))
            return dt.timestamp(), "inferred"
    m = _MONO_RE.match(line)
    if m and ctx.boot_epoch is not None:
        return ctx.boot_epoch + float(m.group(1)), "inferred"
    return None, "unanchored"


def resolve_syslog(line, ctx):
    """Return (epoch, confidence) for a syslog-style line (no year)."""
    m = _SYSLOG_RE.match(line)
    if not m:
        return None, "unanchored"
    mon, day, hh, mm, ss = m.groups()
    month = _MONTHS.get(mon)
    if not month:
        return None, "unanchored"
    year = ctx.year or datetime.now(timezone.utc).year
    off = timedelta(minutes=ctx.tz_offset_min or 0)
    try:
        dt = datetime(year, month, int(day), int(hh), int(mm), int(ss),
                      tzinfo=timezone(off))
    except ValueError:
        return None, "unanchored"
    epoch = dt.timestamp()
    # Guard against year rollover: syslog spanning Dec->Jan with one `date`.
    if ctx.collection_epoch and epoch - ctx.collection_epoch > 86400 * 2:
        dt = dt.replace(year=year - 1)
        epoch = dt.timestamp()
    return epoch, "inferred"


# ---------------------------------------------------------------------------
# Capture-wide time zone (what a bare CLI --start/--end means)
# ---------------------------------------------------------------------------
#
# A cbcollect's own timestamps are in the node's local zone, and that is the
# zone the person reading the logs is thinking in -- the incident was reported
# as "around 03:40", not "around 10:40Z". So bare CLI times default to the
# capture's zone rather than UTC, and this resolves what that zone is.
#
# Source order is by precision, not convenience:
#   1. /etc/timezone (or /etc/sysconfig/clock) -- an IANA NAME, which is the
#      only answer that stays right across a DST change inside the capture.
#   2. `date; date -u` -- the two lines differ by exactly the offset, so this
#      works whatever abbreviation `date` prints. Fixed offset, taken at
#      COLLECTION time, so a window on the far side of a DST boundary is out
#      by an hour.
#   3. the explicit offset ns_server stamps on every line -- same caveat.
_BANNER = "=========="
# Area/City, plus the multi-segment forms (America/Argentina/Salta).
_IANA_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+-]+)+$")
_ZONE_EQ_RE = re.compile(r'^\s*ZONE\s*=\s*"?([^"\s]+)"?')
_DATE_LINE_RE = re.compile(
    r"^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+"
    r"([A-Za-z]{2,5}|[+-]\d{4})\s+(\d{4})$")
_ISO_OFFSET_RE = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?([+-]\d{2}:?\d{2}|Z)")


def _section_body(text, title):
    """Lines of a couchbase.log section, by its title line.

    Shape is: a banner, the title, the command(s) it ran, a banner, the output,
    a banner. An empty body means the command FAILED (its stderr went to the
    collection log) -- a header proves only that cbcollect tried."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() != title:
            continue
        j = i + 1
        while j < len(lines) and not lines[j].startswith(_BANNER):
            j += 1                     # past the echoed command line(s)
        j += 1                         # past the banner closing the header
        body = []
        while j < len(lines) and not lines[j].startswith(_BANNER):
            body.append(lines[j])
            j += 1
        return body
    return []


def tz_name_from_couchbase_log(text):
    """IANA zone name from the /etc/timezone (Debian) or /etc/sysconfig/clock
    (RHEL) dump, or None when neither section produced output."""
    for line in _section_body(text, "raw /etc/timezone"):
        s = line.strip()
        if _IANA_RE.match(s):
            return s
    for line in _section_body(text, "raw /etc/sysconfig/clock"):
        m = _ZONE_EQ_RE.match(line)
        if m and _IANA_RE.match(m.group(1)):
            return m.group(1)
    return None


def _naive_from_date_line(s):
    m = _DATE_LINE_RE.match(s.strip())
    if not m:
        return None, None
    mon, day, hh, mm, ss, tz, year = m.groups()
    month = _MONTHS.get(mon)
    if not month:
        return None, None
    return datetime(int(year), month, int(day), int(hh), int(mm),
                    int(ss)), tz


def tz_offset_from_couchbase_log(text):
    """Offset (minutes east of UTC) from the `date; date -u` section.

    Subtracting the two printed wallclocks gives the offset directly, so no
    abbreviation has to be resolved -- PDT, IST and a numeric +0530 all work,
    and the pair straddling midnight is handled because both lines carry a
    full date."""
    rows = [r for r in (_naive_from_date_line(l)
                        for l in _section_body(text, "time and TZ"))
            if r[0] is not None]
    if len(rows) >= 2:
        # cbcollect runs `date; date -u`, so local is first, UTC second.
        return int(round((rows[0][0] - rows[1][0]).total_seconds() / 60))
    if rows and rows[0][1][0] in "+-":
        tz = rows[0][1]
        sign = 1 if tz[0] == "+" else -1
        return sign * (int(tz[1:3]) * 60 + int(tz[3:5]))
    return None


def _offset_from_log_head(path):
    """Offset from the first ns_server line that carries one."""
    from .discovery import read_text
    try:
        text = read_text(path, limit_bytes=64_000)
    except OSError:
        return None
    m = _ISO_OFFSET_RE.search(text)
    if not m:
        return None
    off = m.group(1)
    if off == "Z":
        return 0
    off = off.replace(":", "")
    sign = 1 if off[0] == "+" else -1
    return sign * (int(off[1:3]) * 60 + int(off[3:5]))


def detect_node_tz(nl):
    """(tz_name, offset_min, source) for one discovered node; Nones if unknown."""
    from .discovery import read_text
    cb = nl.files.get("couchbase")
    if cb:
        try:
            # The time/TZ sections are the first few hundred lines of the file.
            text = read_text(cb, limit_bytes=256_000)
        except OSError:
            text = ""
        name = tz_name_from_couchbase_log(text)
        if name:
            return name, tz_offset_from_couchbase_log(text), "/etc/timezone"
        off = tz_offset_from_couchbase_log(text)
        if off is not None:
            return None, off, "`date` vs `date -u`"
    for source in ("info", "debug", "error"):
        p = nl.files.get(source)
        if p:
            off = _offset_from_log_head(p)
            if off is not None:
                return None, off, "log timestamps"
    return None, None, None


def detect_capture_tz(nodes):
    """The capture's own time zone, as (tzinfo, label, source, note).

    Returns (None, None, None, note) when no node gave an answer. Nodes are
    normally one cluster in one zone; when they disagree the most common answer
    wins and the note says so, because the alternative -- refusing to pick --
    just pushes the same guess onto the caller."""
    names, offsets, sources = {}, {}, {}
    for nl in nodes:
        name, off, src = detect_node_tz(nl)
        key = name or (off if off is not None else None)
        if key is None:
            continue
        (names if name else offsets)[key] = \
            (names if name else offsets).get(key, 0) + 1
        sources.setdefault(key, src)
    pool = names or offsets
    if not pool:
        return None, None, None, "no time zone found in the capture"
    ranked = sorted(pool.items(), key=lambda kv: (-kv[1], str(kv[0])))
    best = ranked[0][0]
    note = None
    if len(ranked) > 1:
        others = ", ".join(_tz_label(k) for k, _ in ranked[1:])
        note = (f"nodes disagree on the time zone (also saw {others}); "
                f"using {_tz_label(best)}")
    if isinstance(best, str):
        try:
            from zoneinfo import ZoneInfo
            return ZoneInfo(best), best, sources[best], note
        except Exception:
            # tzdata missing: fall back to the offset if we have one.
            off = next((o for o in offsets), None)
            if off is None:
                return None, None, None, f"unknown time zone {best!r}"
            return (timezone(timedelta(minutes=off)), _tz_label(off),
                    sources.get(off) or sources[best],
                    f"zone {best!r} not installed; using its collection-time "
                    f"offset")
    return (timezone(timedelta(minutes=best)), _tz_label(best),
            sources[best], note)


def _tz_label(key):
    if isinstance(key, str):
        return key
    sign = "-" if key < 0 else "+"
    key = abs(key)
    return f"{sign}{key // 60:02d}:{key % 60:02d}"
