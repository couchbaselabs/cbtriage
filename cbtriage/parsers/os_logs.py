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
"""Parsers for OS-level logs: couchbase.log (dmesg/uptime sections),
syslog.tar.gz, and systemd_journal.gz.

These are high-volume and mostly noise, so we keep only lines matching OS
signal patterns the ns_server triage flow cares about (OOM, link state, disk
errors, hung tasks, couchbase-server service transitions). OOM is always
emitted at critical severity.
"""
import re

from ..events import Event, CLOCK_INFERRED, CLOCK_UNANCHORED
from ..clock import resolve_dmesg, resolve_syslog, parse_iso_offset
from ..discovery import open_text, iter_tar_members
from . import cbsections

# Lines worth keeping from OS logs. Tuned for ns_server first-line triage.
_SIGNAL_RE = re.compile(
    r"out of memory|oom-?kill|killed process|memory cgroup|"
    r"link is (down|up)|link down|carrier|"
    r"\b(eth\d|bond\d|ens\d|eno\d|enp\d)\b|"
    r"blocked for more than|hung task|soft lockup|"
    r"i/o error|ext4-fs (error|warning)|xfs.*(error|corrupt)|"
    r"\b(nvme|scsi|ata\d|md/raid)\b.*(error|fail|reset)|"
    r"segfault|general protection|kernel panic|call trace|"
    r"couchbase-server|beam\.smp",
    re.I)
_OOM_RE = re.compile(r"out of memory|oom-?kill|killed process|oom_kill", re.I)

# Section descriptions/commands that carry timestamped OS log lines.
_DMESG_SECTION_RE = re.compile(r"dmesg|kernel log|journalctl", re.I)
_SYSLOG_SECTION_RE = re.compile(r"uptime|/var/(adm|log)|messages|syslog",
                                re.I)


def _emit(node_name, source, text, ctx, resolver, log_path, keep_all=False):
    """Yield Events, timestamped via resolver. By default only signal-matching
    lines are kept (syslog/journal are high-volume). keep_all=True emits every
    non-blank line -- used for dmesg, which is a small bounded ring buffer the
    triage flow wants in full (OOM/errors are still elevated by severity)."""
    for i, line in enumerate(text.splitlines(), 1):
        if not keep_all and not _SIGNAL_RE.search(line):
            continue
        if keep_all and not line.strip():
            continue
        epoch, conf = resolver(line, ctx)
        is_oom = bool(_OOM_RE.search(line))
        yield Event(
            node=node_name,
            source=source,
            ts_utc_epoch=epoch,
            ts_local=line[:32],
            severity="critical" if is_oom else (
                "error" if re.search(r"error|fail|panic|down", line, re.I)
                else "info"),
            category="os_kernel",
            subsystem="oom" if is_oom else "kernel",
            summary=line.strip()[:300],
            raw=line.rstrip(),
            fields={"oom": is_oom},
            clock_confidence=conf if epoch else CLOCK_UNANCHORED,
            log_path=log_path,
            line_no=i,
        )


def parse_couchbase_log(node_name, source, path, ctx):
    """dmesg / syslog lines out of couchbase.log's one-shot sections.

    iter_output_sections, not iter_sections: a section whose command could not
    run carries its header and an empty body (see cbsections), and an empty
    dmesg is not the same fact as a dmesg with no kernel events in it."""
    text = open_text(path).read()
    for desc, cmd, body in cbsections.iter_output_sections(text):
        header = f"{desc} {cmd}"
        if _DMESG_SECTION_RE.search(header):
            yield from _emit(node_name, "dmesg", body, ctx, resolve_dmesg,
                             str(path), keep_all=True)
        elif _SYSLOG_SECTION_RE.search(header):
            yield from _emit(node_name, "syslog", body, ctx, resolve_syslog,
                             str(path))


def parse_syslog_bundle(node_name, source, path, ctx):
    def keep(base):
        return bool(re.search(r"syslog|messages|kern|daemon|dmesg", base,
                              re.I))
    for member, text in iter_tar_members(path, keep):
        resolver = resolve_dmesg if "dmesg" in member.lower() else resolve_syslog
        yield from _emit(node_name, "syslog", text, ctx, resolver,
                         f"{path}:{member}")


def _journal_resolver(line, ctx):
    """journalctl output may be short-iso (leading ISO ts) or short (syslog)."""
    head = line.split(None, 1)[0] if line.split() else ""
    if re.match(r"\d{4}-\d{2}-\d{2}T", head):
        epoch, _off = parse_iso_offset(head.replace("Z", "+00:00"))
        if epoch:
            return epoch, CLOCK_INFERRED
    return resolve_syslog(line, ctx)


def parse_journal(node_name, source, path, ctx):
    text = open_text(path).read()
    yield from _emit(node_name, "journal", text, ctx, _journal_resolver,
                     str(path))
