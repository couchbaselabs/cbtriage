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
"""Detect the deployment platform: config profile (Capella vs on-prem),
Kubernetes/Operator, container, and cloud provider.

All signals come from logs ns_server already collects:
  * Capella    -> config profile 'provisioned' (ns_server-native, reliable)
  * Kubernetes -> couchbase.log cgroup/env/secret markers + '.svc' node names
"""
import re

# 'Using profile 'provisioned'' or {name,"provisioned"} in startup logs.
_PROFILE_RE = re.compile(r"(?:Using profile|\{name,)\s*['\"](\w+)['\"]")

_K8S_MARKERS = [
    ("kubepods", "kubepods cgroup"),
    ("KUBERNETES_SERVICE_HOST", "KUBERNETES_SERVICE_HOST env"),
    ("/var/run/secrets/kubernetes.io", "k8s serviceaccount mount"),
    ("/var/run/secrets/kubernetes", "k8s serviceaccount mount"),
]
_CONTAINER_MARKERS = [
    ("/.dockerenv", "/.dockerenv"),
    ("containerd", "containerd cgroup"),
    ("docker", "docker cgroup"),
]
_CLOUD_MARKERS = [
    (re.compile(r"amazon|aws|ec2", re.I), "aws"),
    (re.compile(r"google|gce|gcp", re.I), "gcp"),
    (re.compile(r"microsoft|azure", re.I), "azure"),
]


def detect(profile_text, couchbase_text, node_names):
    """Return a platform dict. profile_text: head of debug/babysitter;
    couchbase_text: couchbase.log; node_names: discovered node names."""
    evidence = []

    profile = None
    m = _PROFILE_RE.search(profile_text or "")
    if m:
        profile = m.group(1)
    is_capella = profile == "provisioned"
    if profile:
        evidence.append(f"config profile '{profile}'")

    cb = couchbase_text or ""
    k8s_hits = [why for marker, why in _K8S_MARKERS if marker in cb]
    svc_nodes = [n for n in (node_names or []) if ".svc" in n]
    if svc_nodes:
        k8s_hits.append(f"{len(svc_nodes)} node name(s) end in .svc")
    is_kubernetes = bool(k8s_hits)
    evidence.extend(k8s_hits)

    container_hits = [why for marker, why in _CONTAINER_MARKERS if marker in cb]
    is_container = is_kubernetes or bool(container_hits)
    evidence.extend(container_hits)

    cloud = None
    for rx, name in _CLOUD_MARKERS:
        if rx.search(cb):
            cloud = name
            break

    return {
        "profile": profile,
        "is_capella": is_capella,
        "is_kubernetes": is_kubernetes,
        "is_container": is_container,
        "cloud": cloud,
        "evidence": evidence,
    }
