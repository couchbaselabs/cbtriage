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
"""Parser for the ns_doctor heartbeat dump in stats.log.

This is the single source of truth for turning a `stats.log` (ns_doctor:debug
dumps) into structured per-(timestamp, node) entries. The ingest path reads
PSI / allocstall / CPU-steal out of the entries into the pressure_samples
table for the timeline's pressure verdict.

Each entry is a dict with at least:
    node           node name from the dump (ns_1@host / n_N@ip)
    timestamp      naive datetime at the node's LOCAL wall clock, used to
                   render ts_local
    ts_epoch       UTC epoch (float) when the line carried an ISO offset, else
                   None
    tz_offset_min  local UTC offset in minutes when known, else None
plus every stat key parsed below (system_*, memory_*, <proc>_*, disk_*).

This is a COARSE source, suitable for a "was there pressure in this window"
verdict, not fine-grained correlation:
  * ns_doctor timestamps mark when the orchestrator logged the cluster status,
    not the exact per-node collection time;
  * granularity is ~1 minute, but intervals vary with system load and with
    network delay propagating stats between nodes;
  * stale data (an unchanged last_heard) is omitted, so it reads as a gap --
    as does a real collection gap or an unresponsive node.
Promtimer's "NS Server log-derived" dashboard plots the full-resolution series
from the same log.
"""
from collections import defaultdict
from datetime import datetime
import re

from ..clock import parse_iso_offset

# ns_doctor stamps an ISO time, normally with sub-seconds + a UTC offset
# (2026-01-15T08:52:14.085-08:00); older logs may omit the offset. The previous
# standalone parser captured only YYYY-MM-DDThh:mm:ss and discarded the rest --
# we keep the offset so cbtriage can place samples on the UTC timeline.
_TS_RE = re.compile(
    r"ns_doctor:\w+,("
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?"
    r"(?:[+-]\d{2}:\d{2}|Z)?)")


def _parse_doctor_ts(ts_str):
    """(naive_local_datetime, utc_epoch|None, offset_min|None) from the dump's
    ISO timestamp."""
    iso = ts_str.replace("Z", "+00:00")
    epoch, off = parse_iso_offset(iso)          # (None, None) when naive
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        # Last resort: seconds precision, no tz (matches the old behaviour).
        return datetime.strptime(ts_str[:19], "%Y-%m-%dT%H:%M:%S"), None, None
    return dt.replace(tzinfo=None), epoch, off


def parse_entries(log_file):
    """Parse a stats.log (ns_doctor dump) into a list[dict] of entries.

    Raises ValueError on a malformed dump (the plotting tool relies on this);
    callers that must not abort (the cbtriage ingest) should guard the call.
    """
    entries = []
    heard = defaultdict(str)
    current_entries = {}        # (timestamp, node) -> entry, for dedup asserts

    with open(log_file, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    current_entry = None
    mode = None
    current_process = None
    current_timestamp = None
    current_ts_epoch = None
    current_off = None

    try:
        for i, line in enumerate(lines):
            # Parse timestamp (start of a new cluster-wide dump).
            if "ns_doctor:debug," in line:
                m = _TS_RE.search(line)
                if not m:
                    raise ValueError(f"Invalid timestamp format at line {i}")
                (current_timestamp, current_ts_epoch,
                 current_off) = _parse_doctor_ts(m.group(1))
                current_entries.clear()

            # Parse node (ns_1@node1, n_1@192.168.1.1, ...)
            elif re.match(r"[\[ ]{'(?:ns_1@|n_\d+@)", line):
                if not current_timestamp:
                    raise ValueError(f"Node entry without timestamp at line {i}")

                node_match = re.search(r"{'([^']+)'", line)
                if not node_match:
                    raise ValueError(f"Invalid node format at line {i}")

                if current_entry:
                    entries.append(current_entry)

                node = node_match.group(1)
                assert (current_timestamp, node) not in current_entries, (
                    f"Duplicate entry for node {node} at {current_timestamp}")

                current_entry = {
                    "node": node,
                    "timestamp": current_timestamp,
                    "ts_epoch": current_ts_epoch,
                    "tz_offset_min": current_off,
                }
                current_entries[(current_timestamp, node)] = current_entry

            # Check if stats are stale (same last_heard as the prior dump).
            elif "last_heard" in line and current_entry:
                last_heard_match = re.search(r"{last_heard,([-]*[0-9]+)", line)
                last_heard = last_heard_match.group(1)
                if heard[current_entry["node"]] == last_heard:
                    current_entry = None        # discard stale entry
                else:
                    heard[current_entry["node"]] = last_heard

            # Parse system stats (allocstall + CPU rates).
            elif current_entry and "{system_stats," in line:
                assert mode is None, f"mode {mode} entering system_stats"
                mode = "system_stats"
            elif mode == "system_stats":
                stat_match = re.search(r"\{([^,]+),([0-9.]+)\}", line)
                if stat_match:
                    stat_name = stat_match.group(1)
                    if (stat_name == "allocstall"
                            or "cpu" in stat_name.lower()
                            or "cores" in stat_name.lower()):
                        current_entry[f"system_{stat_name}"] = float(
                            stat_match.group(2))
                if "]}" in line:
                    mode = None

            # Parse memory data (memsup:get_memory_data()).
            elif current_entry and "{memory_data," in line:
                assert mode is None, f"mode {mode} entering memory_data"
                mem_match = re.search(
                    r"\{memory_data,\{(\d+),(\d+),\{([^,]+),(\d+)\}\}\}", line)
                if mem_match:
                    current_entry["memory_worst_pid"] = mem_match.group(3)
                    current_entry["memory_worst_used"] = int(mem_match.group(4))

            # Parse /proc/meminfo blob (Linux only). The anon/file LRU split
            # (Active/Inactive (anon) vs (file)) is not reported to Prometheus.
            elif current_entry and "{meminfo," in line:
                blob = line
                if i + 1 < len(lines):
                    blob += lines[i + 1]
                for key, field in [
                    ("active_anon", r"Active\(anon\)"),
                    ("inactive_anon", r"Inactive\(anon\)"),
                    ("active_file", r"Active\(file\)"),
                    ("inactive_file", r"Inactive\(file\)"),
                    ("dirty", "Dirty"),
                    ("writeback", "Writeback"),
                ]:
                    m = re.search(field + r":\s*(\d+)\s*kB", blob)
                    if m:
                        current_entry[f"meminfo_{key}"] = int(m.group(1)) * 1024

            elif current_entry and "{disk_data," in line:
                assert mode is None, f"mode {mode} entering disk_data"
                mode = "disk_data"
            elif mode == "disk_data":
                disk_match = re.search(r"(\"\/[a-z]*\"),([0-9]*),([0-9]*)", line)
                if disk_match:
                    disk = disk_match.group(1)
                    current_entry[f"disk_{disk}_usage"] = int(disk_match.group(3))
                    current_entry[f"disk_{disk}_capacity"] = int(
                        disk_match.group(2))
                if "}]}]}" in line:
                    mode = None

            # Parse system memory data (memsup:get_system_memory_data()).
            elif current_entry and "{system_memory_data," in line:
                assert mode is None, f"mode {mode} entering system_memory_data"
                mode = "system_memory_data"
            elif mode == "system_memory_data":
                mem_match = re.search(r"\{([^,]+),(\d+)\}", line)
                if mem_match:
                    current_entry[f"system_{mem_match.group(1)}"] = int(
                        mem_match.group(2))
                if "]}" in line:
                    mode = None

            # Parse Erlang memory breakdown (erlang:memory()).
            elif current_entry and "{memory," in line:
                assert mode is None, f"mode {mode} entering memory"
                mode = "memory"
            elif mode == "memory":
                mem_match = re.search(r"\{([^,]+),(\d+)\}", line)
                if mem_match:
                    current_entry[f"memory_{mem_match.group(1)}"] = int(
                        mem_match.group(2))
                if "]}" in line:
                    mode = None

            # Parse process stats (per-process cpu/mem/faults).
            elif (current_entry and "{processes_stats," in line
                    and "{processes_stats,[]}," not in line):
                assert mode is None, f"mode {mode} entering processes_stats"
                next_line = lines[i + 1].strip()
                if "<<" in next_line:
                    mode = "processes_stats_before_7_2_4"
                else:
                    mode = "processes_stats_7_2_4_onwards"

            elif mode == "processes_stats_before_7_2_4":
                binary_match = re.search(
                    r"{<<\"([\S]+)/([\S]+)\">>,(\d*\.*\d+)}", line)
                if binary_match:
                    process, stat, value = binary_match.groups()
                    try:
                        value = int(value)
                    except ValueError:
                        value = float(value)
                    current_entry[f"{process}_{stat}"] = value
                if "}]}," in line:
                    mode = None

            elif mode == "processes_stats_7_2_4_onwards":
                process_match = re.search(r"\{([^,]+),$", line)
                if process_match:
                    current_process = process_match.group(1).strip("'")
                stat_match = re.search(r"\{([^,]+),([0-9.]+)\}", line)
                if stat_match and current_process:
                    stat_name = stat_match.group(1).strip("'")
                    current_entry[f"{current_process}_{stat_name}"] = float(
                        stat_match.group(2))
                if "}]}]}" in line:
                    mode = None

            # Parse pressure stats (PSI). The {<resource>_pressure, key is on
            # one line; the <<"some .. \nfull .. ">> binary is on the NEXT line.
            elif current_entry and "_pressure" in line:
                try:
                    pressure_match = re.search(r"\{([\w]+)_pressure", line)
                    if pressure_match:
                        ptype = pressure_match.group(1)     # cpu/memory/io
                        some_match = re.search(
                            r'<<"some avg10=([0-9]+.[0-9]+) '
                            "avg60=([0-9]+.[0-9]+) "
                            "avg300=([0-9]+.[0-9]+) "
                            "total=([0-9]+)",
                            lines[i + 1])
                        if some_match:
                            pfx = f"system_{ptype}_pressure_some"
                            current_entry[f"{pfx}_avg60"] = float(
                                some_match.group(2))
                            current_entry[f"{pfx}_total"] = int(
                                some_match.group(4))
                        full_match = re.search(
                            r"full avg10=([0-9]+.[0-9]+) "
                            "avg60=([0-9]+.[0-9]+) "
                            "avg300=([0-9]+.[0-9]+) "
                            "total=([0-9]+)",
                            lines[i + 1])
                        if full_match:
                            pfx = f"system_{ptype}_pressure_full"
                            current_entry[f"{pfx}_avg60"] = float(
                                full_match.group(2))
                            current_entry[f"{pfx}_total"] = int(
                                full_match.group(4))
                except Exception as e:
                    raise ValueError(
                        f"Failed to parse pressure stats at line {i+1}: {e}")
    except Exception as e:
        raise ValueError(f"Failed to parse {log_file} at line {i}: {e}")

    if current_entry:
        entries.append(current_entry)
    return entries


# Pressure-verdict columns cbtriage stores, mapped from entry keys. CPU PSI
# has no meaningful "full" (a single task can't stall the whole CPU), so we use
# "some"; memory/IO use "full" (everything stalled) -- the same choice the
# plotting tool makes.
_ROW_MAP = {
    "cpu_some_avg60": "system_cpu_pressure_some_avg60",
    "cpu_some_total": "system_cpu_pressure_some_total",
    "mem_full_avg60": "system_memory_pressure_full_avg60",
    "mem_full_total": "system_memory_pressure_full_total",
    "io_full_avg60": "system_io_pressure_full_avg60",
    "io_full_total": "system_io_pressure_full_total",
    "allocstall": "system_allocstall",
    "cpu_stolen_rate": "system_cpu_stolen_rate",
    "cpu_util_rate": "system_cpu_utilization_rate",
}
# A row is worth storing only if it carries at least one of these (cpu_util is
# always present even on an idle box, so it doesn't count as signal on its own).
_SIGNAL_COLS = ("cpu_some_avg60", "mem_full_avg60", "io_full_avg60",
                "allocstall", "cpu_stolen_rate")


def _worst_disk(entry):
    """(usage_pct, mount) of the fullest mount in this heartbeat, from the
    disksup `disk_<"/mount">_usage` keys (usage is already a percentage). None
    when the dump carried no disk_data."""
    worst_pct, worst_mount = None, None
    for k, v in entry.items():
        if k.startswith("disk_") and k.endswith("_usage") and v is not None:
            if worst_pct is None or v > worst_pct:
                worst_pct = v
                # k == 'disk_"/data"_usage' -> '/data'
                worst_mount = k[len("disk_"):-len("_usage")].strip('"')
    return worst_pct, worst_mount


def pressure_rows(path):
    """Parse stats.log into pressure_samples rows (dicts keyed by the table's
    columns), one per (dump timestamp, node) that carries any PSI / allocstall /
    CPU-steal signal. Rows without a UTC epoch (no offset in the log line) keep
    ts_epoch=None; the ingest window filter drops those only when windowing.

    Disk usage (fullest mount) and the worst memory consumer ride along on these
    rows -- they are not in _SIGNAL_COLS, so they do NOT change which rows are
    stored (that stays PSI/alloc/steal-gated, preserving the pressure-available
    honesty flag). On real Linux captures allocstall is in system_stats on nearly
    every heartbeat, so a row exists to carry them; they're simply absent on the
    rare capture with no pressure signal at all."""
    out = []
    for e in parse_entries(path):
        ts = e.get("timestamp")
        row = {
            "node": e["node"],
            "ts_epoch": e.get("ts_epoch"),
            "ts_local": ts.isoformat(sep=" ") if ts else None,
            "tz_offset_min": e.get("tz_offset_min"),
        }
        for col, key in _ROW_MAP.items():
            row[col] = e.get(key)
        if any(row[c] is not None for c in _SIGNAL_COLS):
            disk_pct, disk_mount = _worst_disk(e)
            row["disk_usage_pct"] = disk_pct
            row["disk_usage_mount"] = disk_mount
            row["mem_worst_pid"] = e.get("memory_worst_pid")
            row["mem_worst_bytes"] = e.get("memory_worst_used")
            out.append(row)
    return out

