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
"""Collection-time snapshot facts parsed from couchbase.log one-shot commands.

These are single-stamp, since-boot kernel readings -- NOT a time series. They
belong in their own sidecar table (like process_dump), stamped at the node's
collection time, and are shown in the Snapshot view rather than on the incident
timeline (where they would pile up as one meaningless bar at collection_epoch).

Two sources, two different visibility rules -- both matter for "why did the
node fail over under memory pressure with no pressure stats recorded":

  * `/proc/vmstat` ("Raw /proc/vmstat") is NOT cgroup-namespaced, so its
    pgscan/pgsteal/allocstall counters are whole-node (root) reclaim figures
    even when couchbase runs in a pod. This answers "is reclaim happening at
    all, and is it finding anything" at the host level.

  * `/sys/fs/cgroup` ("SysFs Control Group data") visibility depends on the
    container's cgroup namespace. A host-rooted capture (paths under
    kubepods.slice / system.slice) exposes every slice; a namespaced capture
    (rooted at 0::/) exposes only couchbase's own subtree. We record which view
    we got (scope_path) so the reader can see exactly which slice each fact came
    from -- facts, not inference.

  * `/proc/meminfo`, `/proc/zoneinfo` and `sysctl -a` are host-wide too, and
    they carry the one thing a time series cannot: the THRESHOLDS. Promtimer
    already plots memory, swap usage and the allocstall rate over time, but
    nothing in those series says where the reclaim watermarks sit, whether swap
    is configured at all, or how the vm.* knobs were tuned -- so a dip in the
    free-memory line cannot be read as "this crossed the point where kswapd
    wakes" without them. That is what these sections add, and why counters
    already covered by a series are not duplicated here.

v1 scope: root reclaim + reclaim thresholds/knobs + root dying-cgroup census
(from the top cgroup dir) + the couchbase slice's own PSI / memory accounting.
Comparing couchbase's slice against sibling slices (full attribution) needs a
host-rooted view and is left for a later pass.
"""
import re

from ..discovery import open_text
from . import cbsections

# Section headers ("<desc> <cmd>") of the couchbase.log one-shots we read.
_VMSTAT_RE = re.compile(r"/proc/vmstat", re.I)
_CGROUP_RE = re.compile(r"cgroup", re.I)
_UPTIME_RE = re.compile(r"/proc/uptime", re.I)
_MEMINFO_RE = re.compile(r"/proc/meminfo", re.I)
_ZONEINFO_RE = re.compile(r"/proc/zoneinfo", re.I)
_SYSCTL_RE = re.compile(r"\bsysctl\b", re.I)
# Raw /proc/uptime body: "<seconds up> <seconds idle>". First field = host uptime.
_UPTIME_VAL_RE = re.compile(r"^\s*(\d+\.\d+)\s+\d+\.\d+\s*$", re.M)

# vmstat reclaim counters we keep. Direct-reclaim invocations (allocstall_*) and
# pages scanned/reclaimed by kswapd vs direct reclaim; kept per path AND summed
# into totals below. Anchored at the end so pgscan_direct_throttle -- a count of
# throttle events, not pages -- is not folded into the direct-reclaim page count.
_ALLOCSTALL_RE = re.compile(r"^allocstall_")
_PGSCAN_RE = re.compile(r"^pgscan_(kswapd|direct)$")
_PGSTEAL_RE = re.compile(r"^pgsteal_(kswapd|direct)$")

# One PSI line: "some avg10=0.00 avg60=0.00 avg300=0.00 total=12345".
_PSI_KV_RE = re.compile(r"(avg10|avg60|avg300|total)=([\d.]+)")


def _snap(ctx, category, scope, scope_path, metric, value=None,
          text_value=None, unit=None, path=None):
    """Shape one snapshot fact into a table row. capture_ts is collection time
    (the whole capture shares it), mirroring the diag process snapshot."""
    return {
        "node": None,  # filled by iter_snapshot (it knows the node)
        "capture_ts": ctx.collection_epoch,
        "capture_local": "(collection snapshot)",
        "tz_offset_min": ctx.tz_offset_min,
        "clock": "collection",
        "category": category,
        "scope": scope,
        "scope_path": scope_path,
        "metric": metric,
        "value": value,
        "text_value": text_value,
        "unit": unit,
        "log_path": str(path) if path else None,
        "line_no": None,
    }


def _parse_vmstat(body):
    """Return {key: int} for the vmstat lines we care about."""
    out = {}
    for line in body.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        k, v = parts
        if (_ALLOCSTALL_RE.match(k) or _PGSCAN_RE.match(k)
                or _PGSTEAL_RE.match(k)):
            try:
                out[k] = int(v)
            except ValueError:
                pass
    return out


def _vmstat_facts(ctx, vm, path):
    """Root/host reclaim facts: is reclaim running, and is it finding anything.

    allocstall_* summed = direct-reclaim invocations (0 across a long uptime =
    the node has never had to reclaim under pressure). pgscan/pgsteal summed =
    pages scanned vs actually reclaimed; efficiency = reclaimed/scanned. NaN
    efficiency (nothing scanned) means that reclaim path never ran this boot.

    The two reclaim paths are also kept separately, because they mean different
    things for the workload: kswapd runs in the background and costs the
    allocator nothing, while direct reclaim happens inline in an allocating
    task's context -- those pages were scanned while couchbase was stalled
    waiting for memory. A node whose scanning is all kswapd is keeping up;
    direct-reclaim pages climbing means it is not."""
    def total(rx):
        return sum(v for k, v in vm.items() if rx.match(k))

    allocstall = total(_ALLOCSTALL_RE)
    pgscan = total(_PGSCAN_RE)
    pgsteal = total(_PGSTEAL_RE)

    rows = [
        _snap(ctx, "reclaim", "host", "/proc/vmstat", "allocstall_total",
              value=allocstall, unit="count", path=path),
        _snap(ctx, "reclaim", "host", "/proc/vmstat", "pgscan_total",
              value=pgscan, unit="pages", path=path),
        _snap(ctx, "reclaim", "host", "/proc/vmstat", "pgsteal_total",
              value=pgsteal, unit="pages", path=path),
    ]
    if pgscan > 0:
        rows.append(_snap(
            ctx, "reclaim", "host", "/proc/vmstat", "scan_efficiency_pct",
            value=round(pgsteal / pgscan * 100, 2), unit="percent", path=path))

    # Per-path split. Emitted only for keys the kernel actually reported, so a
    # missing counter stays absent rather than being reported as a zero we
    # never read.
    for which in ("kswapd", "direct"):
        scan = vm.get("pgscan_" + which)
        steal = vm.get("pgsteal_" + which)
        if scan is not None:
            rows.append(_snap(ctx, "reclaim", "host", "/proc/vmstat",
                              "pgscan_" + which, value=scan, unit="pages",
                              path=path))
        if steal is not None:
            rows.append(_snap(ctx, "reclaim", "host", "/proc/vmstat",
                              "pgsteal_" + which, value=steal, unit="pages",
                              path=path))
        if scan:
            rows.append(_snap(
                ctx, "reclaim", "host", "/proc/vmstat",
                "scan_efficiency_%s_pct" % which,
                value=round((steal or 0) / scan * 100, 2), unit="percent",
                path=path))
    # What share of all scanning happened inline in an allocating task.
    if pgscan > 0:
        rows.append(_snap(
            ctx, "reclaim", "host", "/proc/vmstat", "pgscan_direct_share_pct",
            value=round(vm.get("pgscan_direct", 0) / pgscan * 100, 2),
            unit="percent", path=path))
    return rows


def _uptime_facts(ctx, body, path):
    """Host uptime from raw /proc/uptime ("<up_secs> <idle_secs>"). Host-wide
    (NOT cgroup-namespaced), so this is the VM/host uptime even in a pod. The
    clock context can't see it (it reads only couchbase.log's head, and this
    section sits past it), so we parse it here off the full-file read.

    Only the elapsed duration is emitted, not a derived boot instant: turning
    it into a wallclock needs ctx.collection_epoch, which has been observed
    disagreeing with the events it was collected alongside (a capture whose
    events were a year newer than its collection_epoch). A duration
    is read straight off /proc and needs no such anchor."""
    m = _UPTIME_VAL_RE.search(body)
    if not m:
        return []
    return [_snap(ctx, "boot", "host", "/proc/uptime", "uptime_secs",
                  value=float(m.group(1)), unit="secs", path=path)]


# /proc/meminfo lines: "MemTotal:       12314260 kB". Values are kB except a few
# count fields we do not read.
_MEMINFO_RE_LINE = re.compile(r"^(\w+):\s+(\d+) kB\s*$")
# "Node 0, zone   Normal" -> one zone block. Watermarks and sizes inside it are
# indented "<key> <pages>" lines; the leading "per-node stats" block only carries
# nr_* keys, so it cannot collide with min/low/high/managed.
_ZONE_HEAD_RE = re.compile(r"^Node\s+(\d+),\s+zone\s+(\S+)\s*$")
_ZONE_KV_RE = re.compile(r"^\s+(pages free|min|low|high|managed|present)\s+(\d+)\s*$")
# Every one of these must be present in every populated zone before any summed
# watermark is emitted (see _zoneinfo_facts).
_ZONE_REQUIRED = ("min", "low", "high", "pages free")
# "sysctl -a" lines: "vm.swappiness = 60".
_SYSCTL_LINE_RE = re.compile(r"^(vm\.[\w.]+)\s*=\s*(-?\d+)\s*$")

# The vm.* knobs that decide when reclaim starts, how hard it swaps, and what
# happens when reclaim fails. Nothing here is a time series -- promtimer plots
# the memory/swap/allocstall SERIES, but carries no record of where the
# thresholds those series must be read against actually sit.
_SYSCTL_KEYS = (
    "vm.swappiness",
    "vm.min_free_kbytes",
    "vm.watermark_scale_factor",
    "vm.zone_reclaim_mode",
    "vm.extfrag_threshold",
    "vm.overcommit_memory",
    "vm.overcommit_ratio",
    "vm.panic_on_oom",
    "vm.oom_kill_allocating_task",
)
# Page sizes a Linux kernel we might see actually uses. The derivation below
# snaps to one of these, so a rounding wobble in MemTotal vs managed pages
# cannot invent a bogus size (the candidates are 4x apart).
_PAGE_SIZES = (4096, 16384, 65536)


def _parse_meminfo(body):
    """{key: kB} for the /proc/meminfo fields we read."""
    out = {}
    for line in body.splitlines():
        m = _MEMINFO_RE_LINE.match(line)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def _meminfo_facts(ctx, mi, path):
    """Host memory total/free plus whether swap exists at all.

    SwapTotal is the fact no time series carries: the swap-usage series reads 0
    both on a host with no swap configured and on a host with swap configured
    and untouched, and those two are different incidents. A recorded zero is
    emitted, because "no swap configured" is the answer as much as a size is --
    but a field the capture never recorded stays absent rather than becoming a
    zero we did not read (a cbcollect taken without the privileges to read a
    source can leave the section empty, and empty is not the same as zero)."""
    rows = []
    for key, metric in (("MemTotal", "mem_total_bytes"),
                        ("MemFree", "mem_free_bytes"),
                        ("MemAvailable", "mem_available_bytes"),
                        ("SwapTotal", "swap_total_bytes"),
                        ("SwapFree", "swap_free_bytes")):
        if key in mi:
            rows.append(_snap(ctx, "reclaim_config", "host", "/proc/meminfo",
                              metric, value=mi[key] * 1024, unit="bytes",
                              path=path))
    total, free = mi.get("SwapTotal"), mi.get("SwapFree")
    if total:
        rows.append(_snap(ctx, "reclaim_config", "host", "/proc/meminfo",
                          "swap_used_pct",
                          value=round((total - (free or 0)) / total * 100, 2),
                          unit="percent", path=path))
    return rows


def _parse_zoneinfo(body):
    """[(node, zone, {key: pages}), ...] for every zone block in the dump."""
    zones = []
    cur = None
    for line in body.splitlines():
        head = _ZONE_HEAD_RE.match(line)
        if head:
            cur = {}
            zones.append((int(head.group(1)), head.group(2), cur))
            continue
        if cur is None:
            continue
        kv = _ZONE_KV_RE.match(line)
        if kv:
            cur.setdefault(kv.group(1), int(kv.group(2)))
    return zones


def _page_size(mi, zones):
    """Bytes per page, derived from MemTotal against the managed page count.

    MemTotal is the sum of every zone's managed pages, so the ratio IS the page
    size; snapping to a real candidate absorbs the small skew from pages the
    kernel accounts outside MemTotal. Falls back to 4 KiB when meminfo is
    missing -- page_size_bytes is emitted either way, so whatever was used to
    scale the watermarks is visible rather than assumed."""
    managed = sum(z.get("managed", 0) for _, _, z in zones)
    if not managed or "MemTotal" not in mi:
        return 4096
    ratio = mi["MemTotal"] * 1024 / managed
    return min(_PAGE_SIZES, key=lambda p: abs(p - ratio))


def _zoneinfo_facts(ctx, mi, zones, path):
    """The watermarks that decide when each reclaim path starts, in bytes.

    Free memory below a zone's low watermark wakes kswapd (background reclaim);
    below min, an allocating task reclaims inline (direct reclaim) and stalls
    while it does; kswapd stops once free is back above high. min_free_kbytes
    sets min and watermark_scale_factor sets the gap up to low/high.

    Summed across every populated zone, because the free-memory series these
    read against is host-wide MemFree. Reclaim itself is decided PER ZONE, so a
    single zone can cross its own watermark while the host total still looks
    comfortable -- wmark_zones records which zones went into the sum, and the
    dominant zone is emitted separately so that case stays visible.

    Nothing is emitted unless EVERY populated zone reported every watermark: a
    sum taken over whatever subset happened to parse would understate the
    threshold, and a wrong threshold is worse than an absent one."""
    populated = [(n, name, z) for n, name, z in zones if z.get("managed")]
    if not populated or not all(
            all(k in z for k in _ZONE_REQUIRED) for _, _, z in populated):
        return []
    psize = _page_size(mi, populated)
    rows = [_snap(ctx, "reclaim_thresholds", "host", "/proc/zoneinfo",
                  "page_size_bytes", value=psize, unit="bytes", path=path)]

    def pages(key):
        return sum(z.get(key, 0) for _, _, z in populated)

    for key, metric in (("min", "wmark_min_bytes"), ("low", "wmark_low_bytes"),
                        ("high", "wmark_high_bytes"),
                        ("pages free", "zone_free_bytes")):
        rows.append(_snap(ctx, "reclaim_thresholds", "host", "/proc/zoneinfo",
                          metric, value=pages(key) * psize, unit="bytes",
                          path=path))
    rows.append(_snap(
        ctx, "reclaim_thresholds", "host", "/proc/zoneinfo", "wmark_zones",
        text_value=", ".join("node%d/%s" % (n, name)
                             for n, name, _ in populated), path=path))

    # The zone holding the most memory: the one whose watermarks a host-wide
    # free-memory reading is mostly tracking, and the one to compare against
    # when the summed view looks fine.
    n, name, big = max(populated, key=lambda t: t[2].get("managed", 0))
    rows.append(_snap(ctx, "reclaim_thresholds", "host", "/proc/zoneinfo",
                      "wmark_largest_zone",
                      text_value="node%d/%s" % (n, name), path=path))
    for key, metric in (("low", "largest_zone_wmark_low_bytes"),
                        ("pages free", "largest_zone_free_bytes")):
        if key in big:
            rows.append(_snap(ctx, "reclaim_thresholds", "host",
                              "/proc/zoneinfo", metric,
                              value=big[key] * psize, unit="bytes", path=path))

    # Headroom at collection: how far free sat above the point where kswapd
    # wakes. Negative means it was already below it and kswapd was running.
    free, low = pages("pages free"), pages("low")
    if free or low:
        rows.append(_snap(ctx, "reclaim_thresholds", "host", "/proc/zoneinfo",
                          "free_above_low_bytes", value=(free - low) * psize,
                          unit="bytes", path=path))
    return rows


def _sysctl_facts(ctx, body, path):
    """The vm.* reclaim knobs, as recorded. Values are kept verbatim (kbytes
    stay kbytes, ratios stay ratios) so each row is the sysctl reading itself
    and not something rescaled on the way in."""
    rows = []
    seen = set()
    for line in body.splitlines():
        m = _SYSCTL_LINE_RE.match(line)
        if not m or m.group(1) not in _SYSCTL_KEYS or m.group(1) in seen:
            continue
        seen.add(m.group(1))
        rows.append(_snap(ctx, "reclaim_config", "host", "sysctl -a",
                          m.group(1), value=int(m.group(2)), unit="count",
                          path=path))
    return rows


def _parse_sysfs(body):
    """Fold the flat "path:contents" grep dump into {cgroup_dir: {file: [lines]}}.

    grep -H prints one "PATH:LINE" per content line, so multi-line files
    (memory.pressure, memory.stat, cgroup.stat) accumulate into a list."""
    cgroups = {}
    for line in body.splitlines():
        path, sep, content = line.partition(":")
        if not sep or "/sys/fs/cgroup" not in path:
            continue
        slash = path.rfind("/")
        cgdir, fname = path[:slash], path[slash + 1:]
        cgroups.setdefault(cgdir, {}).setdefault(fname, []).append(content)
    return cgroups


def _num(cg, fname):
    """First numeric line of a single-value cgroup file, or None. The literal
    'max' (cgroup v2 'unlimited') is NOT a number, so it returns None too -- a
    real limit is one that parses to a value."""
    vals = cg.get(fname)
    if not vals:
        return None
    try:
        return float(vals[0].strip())
    except ValueError:
        return None


def _kv(cg, fname):
    """Flat "key value" cgroup file (memory.events, cgroup.stat) -> {key: int}."""
    out = {}
    for line in cg.get(fname, []):
        parts = line.split()
        if len(parts) == 2:
            try:
                out[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return out


def _find_couchbase_slice(cgroups):
    """Pick the cgroup dir that is couchbase, and say how we identified it.

    Returns (dir, how). Priority: the systemd unit path (on-prem) > the busiest
    real-limited kubepods leaf (k8s host-rooted view) > the capture root itself
    (a namespaced view, where /sys/fs/cgroup IS couchbase's own subtree)."""
    for cgdir in cgroups:
        if "couchbase-server.service" in cgdir:
            return cgdir, "systemd unit path"

    pods = [d for d in cgroups if "kubepods" in d]
    if pods:
        # The container's own leaf: has a real memory.max and the most memory
        # charged to it. Leaves (no child slice shares the same prefix + '/').
        leaves = [d for d in pods
                  if not any(o != d and o.startswith(d + "/") for o in pods)]
        limited = [(_num(cgroups[d], "memory.current") or 0, d) for d in leaves
                   if _num(cgroups[d], "memory.max") is not None]
        if limited:
            return max(limited)[1], "busiest limited kubepods leaf"

    root = _cgroup_root(cgroups)
    return root, "capture root (namespaced view)"


def _cgroup_root(cgroups):
    """The top cgroup dir in the capture (shortest path)."""
    return min(cgroups, key=len) if cgroups else None


def _psi_facts(ctx, cg, scope, scope_path, resource, path):
    """some/full avgN + total from one PSI file (memory/cpu/io.pressure)."""
    rows = []
    fname = f"{resource}.pressure"
    for line in cg.get(fname, []):
        share = line.split(None, 1)[0] if line.split() else ""
        if share not in ("some", "full"):
            continue
        for key, val in _PSI_KV_RE.findall(line):
            unit = "usec" if key == "total" else "percent"
            rows.append(_snap(
                ctx, "cgroup_pressure", scope, scope_path,
                f"{resource}.{share}.{key}", value=float(val), unit=unit,
                path=path))
    return rows


# memory.stat keys that signal in-slice memory strain without needing PSI:
# major faults (disk-backed) + workingset refaults (pages evicted under the
# limit then immediately faulted back = thrashing) + in-slice reclaim.
_MEM_STAT_KEYS = ("pgmajfault", "workingset_refault_file",
                  "workingset_refault_anon", "pgscan", "pgsteal")


def _io_totals(cg):
    """Sum io.stat counters across all devices. io.stat lines are
    'maj:min rbytes=.. wbytes=.. rios=.. wios=..'."""
    tot = {}
    for line in cg.get("io.stat", []):
        for tok in line.split()[1:]:            # skip the maj:min device token
            k, sep, v = tok.partition("=")
            if sep:
                try:
                    tot[k] = tot.get(k, 0) + int(v)
                except ValueError:
                    pass
    return tot


def _io_limited(cg):
    """Devices in io.max carrying any real (non-'max') limit -> ['maj:min', ...].
    Presence means the slice CAN be block-IO throttled."""
    out = []
    for line in cg.get("io.max", []):
        parts = line.split()
        if len(parts) >= 2 and any(
                "=" in p and not p.endswith("=max") for p in parts[1:]):
            out.append(parts[0])
    return out


def _cpu_throttle(cg):
    """cpu.stat CFS-throttling counters. cgroup v2 uses throttled_usec; v1 uses
    throttled_time (ns) -- normalise to usec. Returns {} when cpu.stat absent or
    has no throttling accounting (no CPU limit set)."""
    stat = _kv(cg, "cpu.stat")
    if "throttled_usec" not in stat and "throttled_time" in stat:
        stat["throttled_usec"] = stat["throttled_time"] // 1000
    return stat


def _throttle_facts(ctx, scope, scope_path, stat, path, prefix="cpu.stat"):
    """CFS throttling facts + derived percentages. throttled_period_pct answers
    'how often it stalled' (share of enforcement periods throttled);
    throttled_vs_usage_pct answers 'throttled time vs time actually run'. Both
    are PSI-independent -- present whenever a CPU limit is set, even on a kernel
    with PSI disabled (the RHEL default)."""
    rows = []
    for k in ("nr_periods", "nr_throttled", "throttled_usec", "usage_usec"):
        if k in stat:
            rows.append(_snap(ctx, "cgroup_cpu", scope, scope_path,
                              f"{prefix}.{k}", value=stat[k],
                              unit="usec" if k.endswith("usec") else "count",
                              path=path))
    np, nt = stat.get("nr_periods"), stat.get("nr_throttled")
    if np:
        rows.append(_snap(ctx, "cgroup_cpu", scope, scope_path,
                          f"{prefix}.throttled_period_pct",
                          value=round(nt / np * 100, 2), unit="percent",
                          path=path))
    tu, uu = stat.get("throttled_usec"), stat.get("usage_usec")
    if uu:
        rows.append(_snap(ctx, "cgroup_cpu", scope, scope_path,
                          f"{prefix}.throttled_vs_usage_pct",
                          value=round(tu / uu * 100, 2), unit="percent",
                          path=path))
    return rows


def _ancestors(cbdir, cgroups):
    """cgroup dirs that are strict ancestors of cbdir and present in the dump,
    nearest first (excludes the top /sys/fs/cgroup root, which is never
    CPU-throttled)."""
    parts = cbdir.split("/")
    out = []
    for i in range(len(parts) - 1, 0, -1):
        anc = "/".join(parts[:i])
        if anc and anc != cbdir and anc in cgroups and not anc.endswith(
                "/sys/fs/cgroup"):
            out.append(anc)
    return out


def _slice_facts(ctx, cgroups, cbdir, how, path):
    """PSI + memory accounting + dying-cgroup census for the couchbase slice,
    plus the root census. scope_path records exactly which dir each came from."""
    rows = []
    cg = cgroups.get(cbdir, {})

    # Record which slice we read and how we chose it -- auditable, not inferred.
    rows.append(_snap(ctx, "cgroup_meta", "couchbase", cbdir,
                      "identified_by", text_value=how, path=path))

    for res in ("memory", "cpu", "io"):
        rows += _psi_facts(ctx, cg, "couchbase", cbdir, res, path)

    for fname, unit in (("memory.current", "bytes"), ("memory.max", "bytes"),
                        ("memory.swap.current", "bytes")):
        v = _num(cg, fname)
        if v is not None:
            rows.append(_snap(ctx, "cgroup_mem", "couchbase", cbdir, fname,
                              value=v, unit=unit, path=path))
        elif (cg.get(fname) or [None])[0] == "max":
            # cgroup v2 'unlimited' -- a fact worth stating (no cgroup memory
            # cap; kernel OOM only fires on host pressure, not a slice limit).
            rows.append(_snap(ctx, "cgroup_mem", "couchbase", cbdir, fname,
                              text_value="max", unit=unit, path=path))

    for key, n in _kv(cg, "memory.events").items():
        rows.append(_snap(ctx, "cgroup_mem", "couchbase", cbdir,
                          f"memory.events.{key}", value=n, unit="count",
                          path=path))

    # CPU CFS throttling for the couchbase slice (PSI-independent: present
    # whenever a cpu limit is set, even on a PSI-disabled kernel). This is "are
    # WE being throttled against our own cpu limit".
    cbstat = _cpu_throttle(cg)
    if cbstat.get("nr_periods"):
        rows += _throttle_facts(ctx, "couchbase", cbdir, cbstat, path)

    # The most-throttled ENCLOSING group: an ancestor slice hitting its own cpu
    # limit (e.g. kubepods.slice = the node's whole pod budget) is system-wide
    # throttling, distinct from just us. Emitted under an encl.* prefix so it
    # never collides with the couchbase slice's cpu.stat metrics.
    throttled_anc = [(_cpu_throttle(cgroups[a]), a) for a in _ancestors(cbdir, cgroups)]
    throttled_anc = [(s, a) for s, a in throttled_anc if s.get("nr_throttled")]
    if throttled_anc:
        stat, anc = max(throttled_anc, key=lambda sa: sa[0]["nr_throttled"])
        rows += _throttle_facts(ctx, "ancestor", anc, stat, path, prefix="encl")

    # Memory reclaim / thrash within the slice (PSI-free): major faults +
    # workingset refaults = pages evicted under the limit then faulted back in
    # (thrashing); pgscan/pgsteal = the slice reclaiming its own memory.
    for k, n in _kv(cg, "memory.stat").items():
        if k in _MEM_STAT_KEYS:
            rows.append(_snap(ctx, "cgroup_mem", "couchbase", cbdir,
                              f"memory.stat.{k}", value=n, unit="count",
                              path=path))
    for k, n in _kv(cg, "memory.swap.events").items():
        rows.append(_snap(ctx, "cgroup_mem", "couchbase", cbdir,
                          f"memory.swap.events.{k}", value=n, unit="count",
                          path=path))

    # Block IO: whether the slice has IO limits set (can it be throttled at all)
    # and how much IO it did. NOTE: a snapshot has no throttle-TIME without PSI,
    # so this is "limits + volume", not an IO-throttle verdict.
    limited = _io_limited(cg)
    if limited:
        rows.append(_snap(ctx, "cgroup_io", "couchbase", cbdir,
                          "io.max.limited_devices", text_value=",".join(limited),
                          path=path))
    for k, n in _io_totals(cg).items():
        if k in ("rbytes", "wbytes", "rios", "wios"):
            rows.append(_snap(ctx, "cgroup_io", "couchbase", cbdir,
                              f"io.stat.{k}", value=n,
                              unit="bytes" if k.endswith("bytes") else "count",
                              path=path))

    # Dying-cgroup census from the capture root (the "root" the collection can
    # see: the true host root in a host-rooted view, else couchbase's container
    # root in a namespaced one -- scope_path makes which explicit).
    root = _cgroup_root(cgroups)
    if root is not None:
        host_rooted = any(("kubepods" in d or "/system.slice" in d)
                          for d in cgroups)
        scope = "root" if host_rooted else "container-root"
        stat = _kv(cgroups.get(root, {}), "cgroup.stat")
        for key in ("nr_descendants", "nr_dying_descendants"):
            if key in stat:
                rows.append(_snap(ctx, "cgroup_census", scope, root,
                                  f"cgroup.stat.{key}", value=stat[key],
                                  unit="count", path=path))
    return rows


# The sections this parser reads, for reporting which of them came back empty.
# Only these: a capture is full of empty sections for commands we never wanted
# (a SuSE release file on RHEL, numactl on a host without it), and listing those
# would bury the ones that actually cost us a card.
_OUR_SECTIONS = (_VMSTAT_RE, _UPTIME_RE, _MEMINFO_RE, _ZONEINFO_RE,
                 _SYSCTL_RE, _CGROUP_RE)


def _not_collected_facts(ctx, skipped, path):
    """One fact per source this parser wanted whose command produced no output.

    Without these, a card simply vanishes and reads identically to a healthy
    capture that had nothing to report. The whole point of tracking skipped
    sections is to be able to say "this was not collected" instead, which is a
    different statement from a value of zero -- and in the field the usual cause
    is cbcollect_info having been run without the privileges the command needed.
    """
    rows = []
    for desc, cmd in cbsections.matching(skipped, *_OUR_SECTIONS):
        rows.append(_snap(ctx, "not_collected", "host", cmd.strip(),
                          "no_output:" + desc.strip(),
                          text_value=cmd.strip(), path=path))
    return rows


def iter_snapshot(node, couchbase_log_path, ctx):
    """Yield snapshot-table rows from one node's couchbase.log. Reads the file
    directly (not the truncated cb_text) since the cgroup/vmstat sections can
    sit well past the head."""
    text = open_text(couchbase_log_path).read()
    rows = []
    # Held back rather than emitted in place: scaling the zoneinfo watermarks
    # from pages to bytes needs MemTotal, and the two sections' order in the
    # file is not ours to rely on.
    meminfo, zones = {}, []
    # Sections whose command produced nothing never reach the parsers below, so
    # no absent source can turn into a zero. The list is kept so the ones this
    # parser wanted can be reported as not collected.
    skipped = []
    for desc, cmd, body in cbsections.iter_output_sections(text, skipped):
        header = f"{desc} {cmd}"
        if _UPTIME_RE.search(header):
            rows += _uptime_facts(ctx, body, couchbase_log_path)
        elif _VMSTAT_RE.search(header):
            rows += _vmstat_facts(ctx, _parse_vmstat(body), couchbase_log_path)
        elif _MEMINFO_RE.search(header):
            meminfo = _parse_meminfo(body)
        elif _ZONEINFO_RE.search(header):
            zones = _parse_zoneinfo(body)
        elif _SYSCTL_RE.search(header):
            rows += _sysctl_facts(ctx, body, couchbase_log_path)
        elif _CGROUP_RE.search(header) and "SysFs" in desc:
            cgroups = _parse_sysfs(body)
            if not cgroups:
                continue
            cbdir, how = _find_couchbase_slice(cgroups)
            if cbdir is not None:
                rows += _slice_facts(ctx, cgroups, cbdir, how,
                                     couchbase_log_path)
    if meminfo:
        rows += _meminfo_facts(ctx, meminfo, couchbase_log_path)
    if zones:
        rows += _zoneinfo_facts(ctx, meminfo, zones, couchbase_log_path)
    rows += _not_collected_facts(ctx, skipped, couchbase_log_path)
    for r in rows:
        r["node"] = node
        yield r
