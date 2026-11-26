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
"""One definition of what an Erlang node name looks like in a log line.

The host half is not always dot-separated: an IPv6 cluster names its nodes
ns_1@fd63:6f75:...:1 and a cluster_run one n_10@::1, so any pattern whose host
class is [\\w.-]+ stops at the first colon. That does not fail loudly -- it
yields a SHORTER name that still looks like a node ('ns_1@fd63'), which then
disagrees with the full name everywhere else and silently splits one node into
two identities.

So the host is: a bracketed literal, or a bare IPv6 address, or the ordinary
word-and-dot form -- tried in that order. The final IPv6 group is required to
be non-empty so the pattern cannot run past the address into the colon that
separates it from the next field (node:pid:module:...).
"""

# Bare IPv6 needs the leading branch to allow '::' at the start (n_10@::1).
_IPV6 = r"(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{1,4}"
HOST = r"(?:\[[0-9A-Fa-f:.]+\]|" + _IPV6 + r"|[\w.\-]+)"
# Full node atom, e.g. ns_1@10.0.0.1, n_10@::1, ns_1@[fe80::1], babysitter_of_...
NODE = r"[\w.\-]+@" + HOST
