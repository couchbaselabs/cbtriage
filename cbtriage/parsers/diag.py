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
"""Extract the event_log ring from diag.log's 'Event Logs:' section.

diag.log's bulk duplicates debug.log, so we don't ingest its log lines. Its two
unique payloads are mined elsewhere: the per-process dumps (registered_name /
message_queue_len / memory / backtrace ...) -> parsers/process_dump, and the
event_log ring -> here.
"""
import json

from . import structured
from ..discovery import open_text

_EVENT_LOGS_HDR = "Event Logs:"


def parse_event_logs(node_name, path, ctx):
    """Yield event_log Events from diag.log's 'Event Logs:' section.

    The standalone `event_log` file in a cbcollect is zlib-compressed Erlang ETF
    (no stdlib decoder), so we read event_log from here instead: diag.log embeds
    the SAME ring as clean JSON -- diag_handler dumps
    build_events_json(undefined, -1, []), and -1 = ALL events (event_log_server
    returns the full list, uncapped), so nothing is lost vs the binary file.

    Layout (diag_handler): a 'Event Logs:' header, a dashed rule, one JSON
    object per line, then a closing dashed rule. We skip the opening rule and
    stop at the closing one. Each object is converted by the shared
    structured.event_from_log_obj so these rows are identical to a real
    event_log source (source='event_log')."""
    in_section = False
    seen_json = False
    with open_text(path) as f:
        for line in f:
            s = line.strip()
            if not in_section:
                if s.startswith(_EVENT_LOGS_HDR):
                    in_section = True
                continue
            if s.startswith("{"):
                seen_json = True
                try:
                    obj = json.loads(s)
                except ValueError:
                    continue           # multi-line/edge JSON: skip, don't abort
                yield structured.event_from_log_obj(node_name, obj, str(path))
            elif s.startswith("---") and seen_json:
                break                  # closing rule -> section done
            # opening rule / blank lines before the first object: skip
