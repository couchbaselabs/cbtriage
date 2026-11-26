#!/usr/bin/env python3
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
"""cbtriage: offline cross-log timeline + findings for cbcollect trees.

    # parse a cbcollect (or cluster_run logs/) tree into a local SQLite db
    python3 cbtriage.py ingest <cbcollect_dir> [-d analysis.db]

    # serve the timeline UI from an ingested db (browser, fully local)
    python3 cbtriage.py serve [-d analysis.db] [-p 8765]

    # parse + serve in one step
    python3 cbtriage.py <cbcollect_dir>

Nothing is ever uploaded; everything runs on localhost against local files.
"""
import argparse
import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cbtriage import ingest as ingest_mod  # noqa: E402

DEFAULT_DB = "analysis.db"
# Sources excluded from ingest unless re-added with --include. The heavy
# compressed OS bundles (systemd_journal.gz / syslog.tar.gz) aren't seekable
# and aren't windowable, so a narrow window can't trim them -- the whole file
# is decompressed and read. For the curated lines we actually keep (OOM /
# kernel / disk / net signal) they duplicate couchbase.log's dmesg section,
# which IS ingested. So they cost a multi-GB decompression to (almost always)
# add nothing. --include journal,syslog_bundle when chasing a kernel event
# older than the dmesg ring buffer. couchbase.log (dmesg/OOM, playbook #1) and
# every other source still ingest by default; narrow the rest with --window.
DEFAULT_EXCLUDE = {"journal", "syslog_bundle"}


def _parse_tz(s):
    """--tz value -> tzinfo. Accepts a fixed UTC offset ('-07:00', '+0530',
    '+05', 'Z'/'UTC') or an IANA name ('America/Los_Angeles', needs zoneinfo,
    stdlib on 3.9+). Returns None for an empty value."""
    if not s:
        return None
    s = s.strip()
    if s.upper() in ("Z", "UTC", "GMT"):
        return timezone.utc
    m = re.fullmatch(r"([+-])(\d{2}):?(\d{2})?", s)
    if m:
        sign = -1 if m.group(1) == "-" else 1
        return timezone(sign * timedelta(hours=int(m.group(2)),
                                         minutes=int(m.group(3) or 0)))
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(s)
    except Exception:
        raise SystemExit(
            f"bad --tz {s!r}: use an offset like -07:00 or an IANA name "
            f"like America/Los_Angeles")


def _parse_when(s, default_tz=None):
    """CLI time bound -> UTC epoch seconds. Accepts a bare epoch, or
    'YYYY-MM-DD[ HH:MM[:SS]]', or an ns_server log stamp pasted as-is
    (2026-01-15T03:47:57.942-08:00). A bare (offset-less) time is interpreted
    in default_tz (from _window_tz: --tz, else the capture's own zone, else
    UTC). An explicit offset in the string always wins."""
    if not s:
        return None
    s = s.strip()
    try:
        return float(s)
    except ValueError:
        pass
    iso = s.replace(" ", "T")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", iso):
        iso += "T00:00:00"
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        raise SystemExit(
            f"bad time {s!r}: use e.g. 2026-01-15T03:47, a log stamp like "
            f"2026-01-15T03:47:57.942-08:00, or an epoch")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=default_tz or timezone.utc)
    return dt.timestamp()


def _bare_time(s):
    """True if a --start/--end value needs a zone to be meaningful (i.e. it is
    not an epoch and carries no offset of its own)."""
    if not s:
        return False
    s = s.strip()
    try:
        float(s)
        return False
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(s.replace(" ", "T")).tzinfo is None
    except ValueError:
        return True            # let _parse_when report the syntax error


def _window_tz(args):
    """Zone for bare --start/--end: --tz if given, else the CAPTURE's own zone.

    The logs are stamped in the node's local time and that is the time the
    incident was reported in, so a bare "03:40" means 03:40 as the logs print
    it. Defaulting to UTC instead silently shifted the window by the offset --
    on a PDT capture, seven hours away from the incident, which looks exactly
    like "the window matched nothing". Detection needs the tree, so it only
    runs when a bare bound was actually given."""
    explicit = _parse_tz(getattr(args, "tz", None))
    if explicit is not None:
        return explicit, args.tz.strip(), None
    if not (_bare_time(getattr(args, "start", None))
            or _bare_time(getattr(args, "end", None))):
        return None, None, None
    from cbtriage import clock
    from cbtriage.discovery import discover
    try:
        nodes = discover(args.path, progress=None)
    except (OSError, ValueError) as exc:
        return timezone.utc, "UTC", f"cannot read {args.path}: {exc}"
    tz, label, source, note = clock.detect_capture_tz(nodes)
    if tz is None:
        return timezone.utc, "UTC", f"{note}; assuming UTC (--tz to set it)"
    return tz, label, f"cluster time zone from {source}" + (
        f"; {note}" if note else "")


def cmd_ingest(args):
    tz, tzlabel, tznote = _window_tz(args)
    lo = _parse_when(getattr(args, "start", None), tz)
    hi = _parse_when(getattr(args, "end", None), tz)
    if lo is not None and hi is not None and hi < lo:
        raise SystemExit(
            f"--end ({args.end}) is before --start ({args.start}); "
            "the window would match nothing")
    window = (lo, hi) if (lo is not None or hi is not None) else None
    print(f"Ingesting {args.path} -> {args.db}")
    if window:
        # No label means no bare bound was given (epoch, or the value carried
        # its own offset), so there is no zone assumption to report.
        zone = f"{tzlabel}, {tznote}; " if tznote else (
            f"{tzlabel}; " if tzlabel else "")
        print(f"Window:   {args.start or '-inf'} .. {args.end or '+inf'} "
              f"({zone}events outside are skipped)")
    def _split(v):
        return {s.strip() for s in (v or "").split(",") if s.strip()}
    # journal/syslog_bundle excluded by default (heavy, unwindowable, redundant
    # with couchbase.log dmesg -- see DEFAULT_EXCLUDE). --exclude adds more
    # (e.g. http_access, a subset of http_access_internal); --include re-adds.
    exclude = (DEFAULT_EXCLUDE | _split(getattr(args, "exclude", ""))) \
        - _split(getattr(args, "include", ""))
    if exclude:
        print(f"Excluding: {', '.join(sorted(exclude))}")
    # Lazy raw by default (db = index into the originals you keep on disk);
    # --embed-raw stores raw for a portable, originals-free db.
    embed = getattr(args, "embed_raw", False)
    lean = False if embed else None
    if not embed:
        print("Raw:      lazy (re-read from originals on disk; --embed-raw to "
              "store)")
    else:
        print("Raw:      embedded (self-contained db)")
    summary = ingest_mod.ingest(args.path, args.db, reset=not args.append,
                                window=window, exclude=exclude, lean=lean,
                                jobs=getattr(args, "jobs", None))
    print(f"\nNodes:    {', '.join(summary['nodes'])}")
    print(f"Version:  {summary['version']}")
    print(f"Events:   {summary['events']}")
    print(f"Findings: {summary['findings']}")
    return summary


def cmd_snapshot(args):
    """Ingest only the collection-time snapshot facts -- reads just each node's
    couchbase.log, skips every rotating log. Seconds instead of a full parse."""
    print(f"Snapshot-only ingest {args.path} -> {args.db}")
    summary = ingest_mod.ingest_snapshot_only(
        args.path, args.db, reset=not args.append)
    print(f"\nNodes:    {', '.join(summary['nodes'])}")
    print(f"Version:  {summary['version']}")
    print(f"Facts:    {summary['facts']}")
    print(f"Findings: {summary['findings']}")
    return summary


def cmd_findings(args):
    """(Re)compute findings on an already-ingested db — e.g. after an ingest
    was interrupted (findings run only at the end) or after editing rules."""
    from cbtriage import db, findings
    conn = db.connect(args.db)
    version = (db.query_meta(conn).get("info") or {}).get("version")
    fs = findings.run(conn, version)
    conn.execute("DELETE FROM findings")
    db.insert_findings(conn, fs)
    db.set_meta(conn, "num_findings", len(fs))
    conn.close()
    print(f"Findings: {len(fs)} (written to {args.db})")


def cmd_serve(args):
    from cbtriage import server
    server.serve(args.db, host=args.host, port=args.port)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd")

    p_ing = sub.add_parser("ingest", help="parse a cbcollect tree into SQLite")
    p_ing.add_argument("path", help="cbcollect .zip or dir, node dir, "
                                "logs/ dir, or a dir of cbcollect .zips")
    p_ing.add_argument("-d", "--db", default=DEFAULT_DB)
    p_ing.add_argument("--append", action="store_true",
                       help="add to an existing db instead of resetting it")
    p_ing.add_argument("--start", metavar="WHEN",
                       help="only ingest events at/after this time, e.g. "
                            "2026-01-15T03:47, read in the cluster's own time "
                            "zone (the one its logs print in). A full log "
                            "stamp with offset (2026-01-15T03:47:57.942-08:00) "
                            "or an epoch also works")
    p_ing.add_argument("--end", metavar="WHEN",
                       help="only ingest events at/before this time")
    p_ing.add_argument("--tz", metavar="ZONE",
                       help="override the time zone for bare --start/--end "
                            "values (offset like -07:00 or IANA name like "
                            "America/Los_Angeles); by default they are read "
                            "in the cluster's time zone, detected from the "
                            "capture. An explicit offset in the value itself "
                            "overrides both")
    p_ing.add_argument("--exclude", metavar="SOURCES", default="",
                       help="extra log sources to skip on top of the defaults "
                            "(journal, syslog_bundle); e.g. --exclude "
                            "http_access, a subset of http_access_internal")
    p_ing.add_argument("--include", metavar="SOURCES", default="",
                       help="re-add a default-excluded source, e.g. "
                            "--include journal,syslog_bundle for kernel logs "
                            "older than couchbase.log's dmesg")
    p_ing.add_argument("-j", "--jobs", type=int, metavar="N",
                       help="parse this many nodes in parallel (default: one "
                            "per core, capped at the node count; 1 = serial)")
    p_ing.add_argument("--embed-raw", action="store_true",
                       help="store full raw text instead of lazily re-reading "
                            "it from the originals (makes a full-bundle db "
                            "self-contained/portable, but much larger)")

    p_snap = sub.add_parser(
        "snapshot",
        help="ingest ONLY collection-time snapshot facts (couchbase.log "
             "one-shots); skips the rotating logs -- seconds, not a full parse")
    p_snap.add_argument("path", help="cbcollect .zip or dir, node dir, "
                                 "logs/ dir, or a dir of cbcollect .zips")
    p_snap.add_argument("-d", "--db", default=DEFAULT_DB)
    p_snap.add_argument("--append", action="store_true",
                        help="add to an existing db instead of resetting it")

    p_srv = sub.add_parser("serve", help="serve the timeline UI")
    p_srv.add_argument("-d", "--db", default=DEFAULT_DB)
    p_srv.add_argument("-p", "--port", type=int, default=8765)
    p_srv.add_argument("--host", default="127.0.0.1")

    p_fnd = sub.add_parser("findings",
                           help="(re)compute findings on an existing db")
    p_fnd.add_argument("-d", "--db", default=DEFAULT_DB)

    # Bare path: `cbtriage <dir>` ingests then serves. Detected before
    # argparse, because the subparsers would otherwise read the path as an
    # (invalid) subcommand name and error out.
    argv = sys.argv[1:]
    if argv and argv[0] not in ("ingest", "snapshot", "serve", "findings",
                                "-h", "--help"):
        path = argv[0]
        ing = argparse.Namespace(path=path, db=DEFAULT_DB, append=False)
        cmd_ingest(ing)
        from cbtriage import server
        server.serve(DEFAULT_DB, host="127.0.0.1", port=8765)
        return

    args = ap.parse_args()
    if args.cmd == "ingest":
        cmd_ingest(args)
    elif args.cmd == "snapshot":
        cmd_snapshot(args)
    elif args.cmd == "serve":
        cmd_serve(args)
    elif args.cmd == "findings":
        cmd_findings(args)
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
