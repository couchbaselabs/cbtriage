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
"""couchbase.log's one-shot command sections, and whether each one actually ran.

couchbase.log is a concatenation of command output, each block introduced by a
header cbcollect_info writes BEFORE running the command:

    ==============================================================================
    Raw /proc/zoneinfo
    cat /proc/zoneinfo
    ==============================================================================
    <stdout>

Every parser that reads couchbase.log has the same problem, so the handling
belongs here once rather than in each of them.

A HEADER IS NOT EVIDENCE THE COMMAND WORKED. cbcollect_info writes the header
unconditionally (cbcollect_info.in, Task.execute) and then feeds only the
command's STDOUT into the file -- stderr goes to the collection log instead
(Task._readerthread_stderr calls log(), not outstream.write). So a command that
could not run leaves its header followed by NOTHING. The body carries no
"Permission denied" text to notice, because that text was never written here.

An empty body has several causes and the file cannot tell them apart:

  * insufficient privileges. cbcollect_info is routinely run as a non-root user
    in the field, and much of what it asks for needs more than that
    (iptables-save, netstat -anp, some /proc and /sys reads).
  * the tool is not installed (numactl, ntpq) or the file does not exist on this
    distro (cat /etc/SuSE-release on RHEL).
  * a task declared privileged=True and was skipped by its precondition before
    the header was even written, so the section is ABSENT rather than empty.

In a normal healthy capture roughly a quarter of the sections are empty, so this
is the common case, not an anomaly. What matters is that none of them is parsed:
an unread source must stay absent, never become a recorded zero, because a zero
reads as a measurement and takes a triage the wrong way. Callers get the list of
sections that produced nothing so they can SAY the source was not collected,
which is a different statement from a value of none.
"""
import re

# The banner is 78 '=' characters. The 20-minimum keeps a body line that
# happens to be a short run of '=' from being read as a section boundary.
_SEP_RE = re.compile(r"^={20,}\s*$")

# What an empty section means, in one place, for anything that surfaces it. Kept
# short enough to sit in a UI card and honest about not knowing which cause it
# was -- the file does not record that.
NO_OUTPUT_NOTE = ("the command produced no output: it needs privileges the "
                  "collection did not have, or the tool/file is not on this "
                  "host. cbcollect_info writes the header before running the "
                  "command and sends errors elsewhere, so nothing here says "
                  "which")


def iter_sections(text):
    """Yield (description, command, body) for every section, empty ones too.

    Use this only when the emptiness itself is the subject. To parse values, use
    iter_output_sections so an unusable section cannot reach a parser at all."""
    lines = text.splitlines()
    i, n = 0, len(lines)
    while i < n:
        if _SEP_RE.match(lines[i]) and i + 3 < n and _SEP_RE.match(lines[i + 3]):
            desc, cmd = lines[i + 1], lines[i + 2]
            j = i + 4
            body = []
            while j < n and not (
                    _SEP_RE.match(lines[j]) and j + 3 < n
                    and _SEP_RE.match(lines[j + 3])):
                body.append(lines[j])
                j += 1
            yield desc, cmd, "\n".join(body)
            i = j
        else:
            i += 1


def iter_output_sections(text, skipped=None):
    """Yield (description, command, body) for sections that actually produced
    output, and record the ones that did not.

    This is the entry point every couchbase.log parser should use: a section with
    no output never reaches parsing code, so there is no path by which a missing
    source becomes a zero. Pass a list as `skipped` to collect
    (description, command) for each empty section -- the caller decides which of
    those are worth reporting, since most of a capture's empty sections are
    commands it never wanted.
    """
    for desc, cmd, body in iter_sections(text):
        if body.strip():
            yield desc, cmd, body
        elif skipped is not None:
            skipped.append((desc, cmd))


def matching(skipped, *patterns):
    """The skipped (desc, cmd) pairs whose header matches any given regex.

    Lets a parser report exactly the sources IT wanted and did not get, rather
    than the whole capture's empty sections."""
    out = []
    for desc, cmd in skipped:
        header = f"{desc} {cmd}"
        if any(rx.search(header) for rx in patterns):
            out.append((desc, cmd))
    return out
