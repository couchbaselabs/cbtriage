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
"""Parser registry.

Each parser is a generator: parse(node_name, source, path, ctx) -> Event...
A source maps to exactly one parser. ns_server-family logs share one ALE-line
parser; OS bundles and structured JSON logs have dedicated ones.
"""
from . import ns_server, http_access, structured, os_logs, json_rpc

# source name -> parser callable
_REGISTRY = {
    "debug": ns_server.parse,
    "info": ns_server.parse,
    "error": ns_server.parse,
    "reports": ns_server.parse,
    "babysitter": ns_server.parse,
    "json_rpc": json_rpc.parse,
    "http_access": http_access.parse,
    "http_access_internal": http_access.parse,
    "event_log": structured.parse_event_log,
    "master_events": structured.parse_master_events,
    "couchbase": os_logs.parse_couchbase_log,
    "syslog_bundle": os_logs.parse_syslog_bundle,
    "journal": os_logs.parse_journal,
}

# Sources discovered but intentionally not ingested via the main parse loop.
#   stats     -> handled by the (separate) stats explorer view
#   diag      -> duplicates debug.log; mined separately (message_queue +
#                event_log JSON section, see ingest)
#   event_log -> the standalone file is zlib-compressed Erlang ETF (no stdlib
#                decoder); the same ring is read as JSON from diag.log's
#                'Event Logs:' section instead (diag.parse_event_logs)
SKIP_SOURCES = {"stats", "diag", "event_log"}

# Sources whose parser accepts start_epoch and reads a single time-ordered file,
# so a windowed ingest can byte-seek past the head to --start (ns_server.parse
# and http_access.parse). The rest read from the top.
SEEKABLE_SOURCES = {"debug", "info", "error", "reports", "babysitter",
                    "http_access", "http_access_internal"}


def get_parser(source):
    return _REGISTRY.get(source)
