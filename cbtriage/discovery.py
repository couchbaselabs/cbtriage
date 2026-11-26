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
"""Discover nodes and log files in a cbcollect tree or cluster_run logs/ dir.

Handles two layouts:
  * cbcollect: one dir per node (cbcollect_info_<node>_<ts>/) containing
    ns_server/*.log, couchbase.log, syslog.tar.gz, systemd_journal.gz, ...
  * cluster_run: logs/n_0/, logs/n_1/, each a node with *.log at the top.

Files may be gzip'd (.gz) or bundled (syslog.tar.gz); openers transparently
decompress. Node identity is taken from log content where possible (the
ns_1@host token), falling back to the directory name.

A cbcollect .zip can be passed directly -- there is no need to unpack the
bundle by hand. Only the members that are actually parsed are extracted, into
the cbcollect_info_* dir beside the zip where unpacking it yourself would have
put them, and everything downstream then works on ordinary files. That last
part is the point: zip members are deflate streams and cannot be seeked, so
reading them in place would defeat seek.py's jump to --start -- the
optimisation that makes a narrow window at the tail of a months-long capture
cheap. Decompressing once, for a handful of files, keeps the seek and makes
re-ingesting at a different window instant.
"""
from dataclasses import dataclass, field
from pathlib import Path
import gzip
import io
import re
import shutil
import tarfile
import zipfile

from . import nodes


# Map of logical source name -> filename(s) we look for within a node dir.
# Order matters only for display. ns_server logs may live at the node-dir root
# (cluster_run) or under an ns_server/ subdir (cbcollect).
SOURCE_FILES = {
    "debug": ["debug.log"],
    "info": ["info.log"],
    "error": ["error.log"],
    "reports": ["reports.log"],
    "babysitter": ["babysitter.log"],
    "json_rpc": ["json_rpc.log"],
    "http_access": ["http_access.log"],
    "http_access_internal": ["http_access_internal.log"],
    "stats": ["stats.log"],
    "event_log": ["event_log"],
    "master_events": ["master_events.log"],
    "diag": ["diag.log"],
    "couchbase": ["couchbase.log"],
    "syslog_bundle": ["syslog.tar.gz"],
    "journal": ["systemd_journal.gz"],
}

# The rebalance reports are a FAMILY, not a single file, so they can't live in
# SOURCE_FILES (which maps one source to one resolved Path). ns_server retains
# ?NUM_REBALANCE_REPORTS (5) timestamped reports plus rebalance_report_current
# .json, and record_rebalance_report writes to the first KEEP node rather than
# the orchestrator -- so the same report appears in several node dirs and the
# caller dedups by rebalanceId. cbcollect pulls these over REST, so they are
# plaintext and carry no ns_server. prefix; .gz is tolerated anyway.
_REBALANCE_REPORT_RE = re.compile(r"^rebalance_report.*\.json(\.gz)?$")

_NS_SERVER_SUBDIR = "ns_server"
_NS_SERVER_PREFIX = "ns_server."
_NODE_TOKEN_RE = re.compile(r"\b((?:ns_1|n_\d+)@" + nodes.HOST + r")")
_CBCOLLECT_DIR_RE = re.compile(r"^cbcollect_info_(.+)_\d{8}-\d{6}$")


@dataclass
class NodeLogs:
    name: str               # resolved node name (ns_1@host or dir name)
    root: Path              # node directory
    files: dict = field(default_factory=dict)  # source -> Path
    redacted: bool = False
    reports: list = field(default_factory=list)  # rebalance_report*.json paths


def _find_file(node_root, names):
    """Look for any of names at node_root and node_root/ns_server, allowing a
    trailing .gz. Returns the Path or None.

    Real cbcollects prefix the ns_server logs with 'ns_server.' and keep them at
    the cbcollect-dir root (e.g. ns_server.debug.log, ns_server.http_access.log),
    whereas cluster_run logs/n_*/ keeps them bare (debug.log). We try the
    ns_server.-prefixed name FIRST, then the bare name, so a single map covers
    both layouts. Prefixed-first matters when both exist and differ: a real
    cbcollect ships both 'stats.log' (the raw stats-banner dump) and
    'ns_server.stats.log' (the ns_doctor heartbeat we actually want); bare-first
    would grab the wrong one. Bare-named, non-ns_server logs (master_events.log,
    couchbase.log, diag.log, event_log) simply never match the prefixed
    candidate and fall through to the bare name."""
    search_dirs = [node_root, node_root / _NS_SERVER_SUBDIR]
    for d in search_dirs:
        if not d.is_dir():
            continue
        for name in names:
            variants = (_NS_SERVER_PREFIX + name,
                        _NS_SERVER_PREFIX + name + ".gz",
                        name, name + ".gz")
            for cand in (d / v for v in variants):
                if cand.is_file():
                    return cand
    return None


def _find_reports(node_root):
    """Every rebalance_report*.json in a node dir, in name order.

    A list rather than a single Path because these are a family (see
    _REBALANCE_REPORT_RE): several retained reports plus the current one, and
    the same report duplicated across node dirs. Dedup by rebalanceId is the
    caller's job -- it needs the parsed content, which discovery does not read.
    """
    found = []
    for d in (node_root, node_root / _NS_SERVER_SUBDIR):
        if not d.is_dir():
            continue
        found.extend(sorted(p for p in d.iterdir()
                            if p.is_file() and _REBALANCE_REPORT_RE.match(p.name)))
    return found


def _is_wanted(basename):
    """Whether a zip member is worth extracting.

    Kept as one predicate so the extractor and the finders can never disagree
    about what is worth having: the fixed SOURCE_FILES names in any variant
    _find_file would accept -- bare, ns_server.-prefixed, either with a trailing
    .gz -- plus the rebalance-report family, which _find_reports globs."""
    return basename in _WANTED_BASENAMES \
        or _REBALANCE_REPORT_RE.match(basename) is not None


def _wanted_basenames():
    """Every fixed filename _find_file would accept, as a flat set."""
    wanted = set()
    for names in SOURCE_FILES.values():
        for n in names:
            wanted.update((n, n + ".gz",
                           _NS_SERVER_PREFIX + n, _NS_SERVER_PREFIX + n + ".gz"))
    return wanted


_WANTED_BASENAMES = _wanted_basenames()


# A member proving its directory really is a cbcollect node dir. couchbase.log
# and cbcollect_info.log are emitted by cbcollect_info itself and appear in
# every bundle; ns_server.debug.log covers the prefixed layout.
_CBCOLLECT_MARKERS = frozenset(
    ("couchbase.log", "cbcollect_info.log", "ns_server.debug.log"))


def _cbcollect_roots(z):
    """Top-level directory names inside the zip that hold a cbcollect.

    Reads the namelist only (central-directory metadata, no decompression).
    Returns an empty set for an archive that merely happens to contain files
    named like logs, so nothing is extracted from it."""
    roots = set()
    for name in z.namelist():
        parts = Path(name).parts
        if len(parts) >= 2 and parts[-1] in _CBCOLLECT_MARKERS:
            roots.add(parts[0])
    return roots


def materialize_zip(zip_path, progress=None):
    """Extract the parseable log members of a cbcollect zip; return its dir.

    Files land where unzipping the bundle by hand would have put them -- the
    cbcollect_info_* directory beside the zip -- so there is only ever ONE copy
    of a capture on disk and one rule to reason about: extract a file if it
    isn't already there, otherwise use what is. That makes the three cases
    identical in code and in behaviour --

      * already unzipped     -> every member present, nothing extracted;
      * promtimer ran first  -> it left couchbase.log and stats_snapshot/,
                                so the remaining members are filled in;
      * zip only             -> the directory is created and populated.

    -- and it converges with promtimer, which unpacks into the same place, so
    each tool benefits from what the other already pulled out.

    Only files cbtriage reads are written: a dozen or so per node, not the
    pprof dumps, cert bundles and JSON blobs that are most of a bundle's size.

    A member is considered present when a file of the same uncompressed size
    is already there, so a truncated or half-written extraction is redone."""
    zip_path = Path(zip_path)
    dest_root = zip_path.parent
    extracted = reused = 0
    written = 0
    with zipfile.ZipFile(zip_path) as z:
        roots = _cbcollect_roots(z)
        if not roots:
            if progress:
                progress(f"  {zip_path.name}: not a cbcollect, skipped")
            return dest_root
        for info in z.infolist():
            if info.is_dir():
                continue
            parts = Path(info.filename).parts
            # Basename alone is not enough: debug.log/info.log/error.log are
            # ordinary names, so an unrelated archive would match and get
            # partly unpacked. Require the member to sit under a directory
            # that actually looks like a cbcollect.
            if parts[0] not in roots or not _is_wanted(parts[-1]):
                continue
            out = dest_root.joinpath(*parts)
            if out.is_file() and out.stat().st_size == info.file_size:
                reused += 1
                continue
            out.parent.mkdir(parents=True, exist_ok=True)
            # Stream member -> file; a big debug.log should never be held whole.
            with z.open(info) as src, open(out, "wb") as dst:
                shutil.copyfileobj(src, dst)
            extracted += 1
            written += info.file_size
    if progress:
        if extracted:
            progress(f"  {zip_path.name}: {extracted} file(s) extracted"
                     f"{f', {reused} already unpacked' if reused else ''}"
                     f" ({written / 1024 ** 2:.0f} MiB)")
        else:
            progress(f"  {zip_path.name}: already unpacked ({reused} file(s))")
    return dest_root


def open_text(path):
    """Open a log file as text, transparently handling .gz. Returns a file
    object yielding str lines. Caller closes it."""
    if str(path).endswith(".gz"):
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8",
                                errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def read_text(path, limit_bytes=None):
    """Read a whole (possibly gzip'd) log file to a string. limit_bytes caps
    the read for large files like couchbase.log when we only need the head."""
    with open_text(path) as f:
        return f.read(limit_bytes) if limit_bytes else f.read()


def iter_tar_members(path, name_filter=None):
    """Yield (member_name, text) for files inside a .tar.gz (e.g. syslog.tar.gz).

    name_filter: optional predicate on member basename.
    """
    try:
        with tarfile.open(path, "r:*") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                base = Path(member.name).name
                if name_filter and not name_filter(base):
                    continue
                fobj = tar.extractfile(member)
                if fobj is None:
                    continue
                raw = fobj.read()
                if base.endswith(".gz") or member.name.endswith(".gz"):
                    try:
                        raw = gzip.decompress(raw)
                    except OSError:
                        pass
                yield base, raw.decode("utf-8", errors="replace")
    except (tarfile.TarError, OSError):
        return


def _looks_like_node_dir(d):
    return (_find_file(d, ["debug.log"]) is not None
            or _find_file(d, ["couchbase.log"]) is not None)


def _resolve_node_name(node_root, default):
    """Resolve node name. For cbcollect dirs, parse the directory name (same
    source as dump-guts: post-rename ns_config). Fall back to scanning the head
    of debug.log for cluster_run layouts, then to the raw directory name."""
    m = _CBCOLLECT_DIR_RE.match(node_root.name)
    if m:
        return m.group(1)
    dbg = _find_file(node_root, ["debug.log"])
    if dbg:
        try:
            head = read_text(dbg, limit_bytes=200_000)
        except OSError:
            head = ""
        m = _NODE_TOKEN_RE.search(head)
        if m and not m.group(1).startswith("nonode"):
            return m.group(1)
    return default


def _detect_redaction(node_root):
    """cbcollect redaction replaces names with <ud>hash</ud> tokens."""
    dbg = _find_file(node_root, ["debug.log"])
    if not dbg:
        return False
    try:
        return "<ud>" in read_text(dbg, limit_bytes=100_000)
    except OSError:
        return False


def discover(root, progress=None):
    """Discover all node log sets under root. Returns list[NodeLogs].

    root may be a cbcollect dir, a cluster_run logs/ dir, a cbcollect .zip, or
    a dir holding several .zips (one per node of a cluster) -- zips are
    extracted to a cache first, then walked like any other tree."""
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"path not found: {root}")

    # Unpack zips up front so the rest of discovery only ever sees plain dirs.
    search_roots = []
    if zipfile.is_zipfile(root):
        search_roots.append(materialize_zip(root, progress))
    else:
        search_roots.append(root)
        if root.is_dir():
            for child in sorted(root.iterdir()):
                if child.is_file() and zipfile.is_zipfile(child):
                    search_roots.append(
                        materialize_zip(child, progress))

    # Candidate node dirs: a root itself, its children, or grandchildren under
    # a logs/ wrapper. Keep it shallow and explicit.
    candidates = []
    for r in search_roots:
        if _looks_like_node_dir(r):
            candidates.append(r)
        for child in sorted(r.iterdir()) if r.is_dir() else []:
            if child.is_dir() and _looks_like_node_dir(child):
                candidates.append(child)
    # cluster_run wrapper: <root>/logs/n_*
    for r in search_roots:
        logs_dir = r / "logs"
        if logs_dir.is_dir():
            for child in sorted(logs_dir.iterdir()):
                if child.is_dir() and _looks_like_node_dir(child):
                    candidates.append(child)

    # De-dup while preserving order.
    seen = set()
    nodes = []
    for d in candidates:
        rp = d.resolve()
        if rp in seen:
            continue
        seen.add(rp)
        name = _resolve_node_name(d, default=d.name)
        files = {}
        for source, names in SOURCE_FILES.items():
            p = _find_file(d, names)
            if p:
                files[source] = p
        nodes.append(NodeLogs(name=name, root=d, files=files,
                              redacted=_detect_redaction(d),
                              reports=_find_reports(d)))
    return _dedupe_captures(nodes, progress)


def _dedupe_captures(nodes, progress=None):
    """Collapse the same capture appearing twice, keeping the richer copy.

    Running promtimer over a folder of zips leaves a cbcollect_info_* dir
    beside each zip holding only stats_snapshot/ and couchbase.log. That dir
    looks like a node (couchbase.log is one of the markers), so the same
    capture would be ingested twice -- once nearly empty -- and every event
    counted twice.

    Identity is the cbcollect directory name, which carries node AND collection
    timestamp, so two genuinely different captures of one node stay separate.
    Directories that don't match that pattern (cluster_run n_0/n_1) are never
    collapsed. Whichever copy discovered more sources wins; ordering is
    otherwise preserved."""
    best = {}
    for i, nl in enumerate(nodes):
        m = _CBCOLLECT_DIR_RE.match(nl.root.name)
        key = nl.root.name if m else f"\0{i}"    # unmatched: unique, never merged
        prev = best.get(key)
        if prev is None or len(nl.files) > len(prev[1].files):
            best[key] = (i if prev is None else prev[0], nl)
    kept = [nl for _, (_, nl) in sorted(best.items(), key=lambda kv: kv[1][0])]
    if progress and len(kept) < len(nodes):
        for nl in nodes:
            if nl not in kept:
                progress(f"  skipping duplicate capture {nl.root.name} at "
                         f"{nl.root} ({len(nl.files)} source(s)) -- another "
                         f"copy has at least as many")
    return kept
