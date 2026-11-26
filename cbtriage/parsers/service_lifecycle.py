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
"""Service lifecycle annotation: when did each managed service start, stop, or
exit, and with what status.

This is not a parser of its own -- it tags ALE entries the ns_server parser has
already folded, setting `service` plus a `lifecycle` field so a service's whole
history can be pulled out of the events table by name. The json_rpc parser
already tags ServiceAPI traffic with the same `service` key, so the two views
join on it: lifecycle (this module, from the babysitter) versus service
rebalance (json_rpc). They are deliberately kept distinct -- a service can be
answering rebalance RPCs perfectly while crash-looping, and vice versa.

Why content matching and not severity: every step of the babysitter's death
path logs at `info`. `goport` logs "Port exited with status ~b" at info
whatever the status; `ns_port_server` logs NOTHING on a non-zero exit (it hands
the crash record to ns_babysitter_log and stops with `{abnormal, Status}`);
`supervisor_cushion` reports the failure at info; and `ns_log:consume_log`
picks `debug` for status 0 and `info` for every non-zero one. There is no warn
or error anywhere in the chain, so a service in a crash loop is invisible to a
severity filter and can only be found by matching the text.

The lines, in the order the death path produces them (see
apps/ns_babysitter/src/ns_port_server.erl, apps/ns_server/src/goport.erl,
supervisor_cushion.erl, apps/ns_server/src/ns_log.erl):

  babysitter.log
    "Starting supervisor cushion for <svc> with delay of 5000"  -> started
    "supervising port: {<svc>,"                                 -> started
    "Shutting down port <svc>"                                  -> stopped
    "Got {exit_status,0} from port <svc>. Exiting normally"      -> stopped
    "<svc> has exited"                                          -> stopped
    "Port exited with status <N>."                              -> exited
        service comes from the process label (`projector-goport<0.221.0>`),
        NOT the message text
    "Cushion managed supervisor for <svc> failed:  {abnormal,<N>}" -> exited
        (two spaces after the colon, as in the source format string)
    "restarting port: {<svc>,"                                  -> restarting

  debug.log / info.log (?USER_LOGGER, consumed from the babysitter node)
    "Service '<svc>' exited with status <N>. Restarting. Messages:" -> exited
        The lines that follow are the service's last stdout/stderr before it
        died -- the actual Go panic and stack. They are already folded into the
        entry's raw text by the ALE parser, so `death_output` just flags that
        the raw is worth opening.
"""
import re

# The same service is named differently by the babysitter (the port name) and
# by json_rpc (the ServiceAPI name), so the two halves of its history land under
# two keys unless they are stitched. The mapping is explicit in ns_server:
# `goport_defs()` in apps/ns_server/src/ns_ports_setup.erl gives each port a
# `rpc = <name>` field. Only the ones that actually differ are listed; the rest
# (index, projector, goxdcr, fts, cbas, eventing, backup) use one name for both.
# saslauthd is not a goport def -- it is a plain erlang port, `saslauthd_port`
# to the babysitter and `saslauthd` over json_rpc.
SERVICE_ALIASES = [
    {"n1ql", "cbq-engine"},
    {"cont_backup", "cbcontbk"},
    {"saslauthd_port", "saslauthd"},
]


def aliases_of(name):
    """Every name this service is known by, including the one given."""
    for group in SERVICE_ALIASES:
        if name in group:
            return sorted(group)
    return [name] if name else []


# ServiceAPI names as they appear in a json_rpc connection label, longest first.
# A label is "json_rpc_connection-<service>-<channel>" -- e.g.
# `-cbcontbk-cbauth`, `-saslauthd-saslauthd-port` -- so the service cannot be
# read as "everything up to the first hyphen" (that breaks `cbq-engine`) nor as
# a greedy run (that swallows the channel). Matching a known name off the front
# is the only reading that gets both right.
_RPC_SERVICES = sorted(
    ["index", "projector", "goxdcr", "cbq-engine", "fts", "cbas", "eventing",
     "backup", "cbcontbk", "saslauthd", "kv"], key=len, reverse=True)


def split_rpc_label(captured):
    """(service, channel) from a json_rpc connection label's tail.

    A connection is per (service, purpose), and the purpose is the part that
    decides whether the traffic has anything to do with rebalance:

        json_rpc_connection-fts-service_api        ServiceAPI  (rebalance)
        json_rpc_connection-goxdcr-cbauth          cbauth      (auth db pushes)
        json_rpc_connection-saslauthd-saslauthd-port

    Only `service_api` carries topology changes. Everything else is ordinary
    background chatter, and counting it as rebalance traffic buries the calls
    that matter -- in one 4-node capture, 527 of 1224 json_rpc events were
    cbauth. The channel is stated in the label, so it never has to be guessed
    from which method happened to be decodable."""
    if not captured:
        return captured, None
    for known in _RPC_SERVICES:
        if captured == known:
            return known, None
        if captured.startswith(known + "-"):
            return known, captured[len(known) + 1:]
    svc, _, chan = captured.partition("-")
    return svc, (chan or None)


def normalize_rpc_service(captured):
    """Just the service half of split_rpc_label."""
    return split_rpc_label(captured)[0]


# (compiled regex, lifecycle, service-from) -- first match wins. "label" means
# the service name comes from the process label in the header, not the message.
_RULES = [
    (re.compile(r"^Service '([a-z0-9_]+)' exited with status (-?\d+)"),
     "exited", "msg2"),
    (re.compile(r"^Cushion managed supervisor for ([a-z0-9_]+) failed:\s+"
                r"\{abnormal,(-?\d+)\}"), "exited", "msg2"),
    (re.compile(r"^Port exited with status (-?\d+)\."), "exited", "label"),
    (re.compile(r"^Got \{exit_status,0\} from port ([a-z0-9_]+)\."),
     "stopped", "msg"),
    (re.compile(r"^Shutting down port ([a-z0-9_]+)"), "stopped", "msg"),
    (re.compile(r"^([a-z0-9_]+) has exited"), "stopped", "msg"),
    (re.compile(r"^Starting supervisor cushion for ([a-z0-9_]+) "), "started",
     "msg"),
    (re.compile(r"^supervising port: \{([a-z0-9_]+),"), "started", "msg"),
    (re.compile(r"^restarting port: \{([a-z0-9_]+),"), "restarting", "msg"),
]

# Service name in a goport process label: "projector-goport<0.221.0>".
_LABEL_RE = re.compile(r"\b([a-z0-9_]+)-goport\b")

# A clean shutdown reported through the cushion; not a crash.
_CUSHION_NORMAL = re.compile(r"^Cushion managed supervisor for ([a-z0-9_]+) "
                             r"failed:\s+normal\b")


def annotate(msg, rest, fields):
    """Tag one ALE entry in place if it is a service lifecycle line.

    msg    the entry's message text (header line only, not the folded body)
    rest   the header's "node:pid:module:function:line" chunk, which carries
           the goport process label
    fields the Event fields dict, mutated in place

    Returns True if this entry was a lifecycle line."""
    text = (msg or "").strip()
    if not text:
        return False

    m = _CUSHION_NORMAL.match(text)
    if m:
        fields["service"] = m.group(1)
        fields["lifecycle"] = "stopped"
        return True

    for rx, lifecycle, src in _RULES:
        m = rx.match(text)
        if not m:
            continue
        if src == "label":
            lm = _LABEL_RE.search(rest or "")
            if not lm:
                # Without the label there is no way to say which service this
                # was; leaving it untagged is better than guessing.
                return False
            svc, status = lm.group(1), m.group(1)
        elif src == "msg2":
            svc, status = m.group(1), m.group(2)
        else:
            svc, status = m.group(1), None

        fields["service"] = svc
        fields["lifecycle"] = lifecycle
        if status is not None:
            try:
                fields["exit_status"] = int(status)
            except ValueError:
                pass
            # Status 0 through the "exited" lines is an ordinary shutdown.
            if fields.get("exit_status") == 0:
                fields["lifecycle"] = "stopped"
        # The panic / last stderr follows this header line in the same entry.
        if text.endswith("Messages:"):
            fields["death_output"] = True
        return True
    return False
