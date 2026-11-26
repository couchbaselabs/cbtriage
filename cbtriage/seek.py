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
"""Binary-search a plain (seekable) log file to the byte offset of the first
line at/after a target time, so a windowed ingest can skip the file's head
without reading it.

This is the win for the common triage shape: the customer sends logs right
after an incident, so the incident sits near the END of a long capture and the
--start/--end window is a narrow slice at the tail. Reading from byte 0 to the
window wastes almost the whole file; seeking jumps straight to it.

Only for uncompressed files -- gzip isn't randomly seekable, so a .gz path
returns offset 0 (the caller reads it in full and drops out-of-window events as
before). Log lines are written in time order, which is what makes the search
valid; the result is never LATE (it may land a little early, costing a few
extra pre-window lines that the ingest filter drops anyway)."""
import os


def seek_start(path, start_epoch, line_epoch):
    """Return a byte offset into `path` at a line boundary such that no log
    entry at/after `start_epoch` begins before it.

    line_epoch(str) -> float | None extracts a line's UTC epoch, or None for a
    line that carries no timestamp (e.g. a multi-line entry's continuation).
    Returns 0 (read from the top) when there's no start bound, the file is
    gzipped, or anything goes wrong -- correctness never depends on the seek."""
    if not start_epoch or str(path).endswith(".gz"):
        return 0
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            # Leftmost-boundary bisection: maintain everything strictly left of
            # `lo` is < start_epoch. The probe value at an offset is the first
            # timestamped line at/after it (logs are time-ordered -> monotonic).
            lo, hi = 0, size
            while lo < hi:
                mid = (lo + hi) // 2
                f.seek(mid)
                if mid:
                    f.readline()        # discard the partial line at the cut
                t = None
                while True:
                    line = f.readline()
                    if not line:
                        break           # no timestamped line ahead
                    t = line_epoch(line.decode("utf-8", "replace"))
                    if t is not None:
                        break
                if t is not None and t < start_epoch:
                    lo = mid + 1
                else:
                    hi = mid
            # Align `lo` to the next full-line boundary (the entry we want).
            f.seek(lo)
            if lo:
                f.readline()
            return f.tell()
    except (OSError, ValueError):
        return 0
