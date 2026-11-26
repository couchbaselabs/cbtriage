# cbtriage

A local tool for reading the logs in a Couchbase Server cbcollect. Point it at
a cbcollect (the `.zip`, a folder of one zip per node, an unpacked tree, or
`cluster_run`'s `logs/`) and a time window around an incident. It parses every
node's logs for that window into a SQLite db and serves a browser UI with one
cross-node timeline, a set of findings, and panels for the things a timeline
shows badly.

It is the log-side companion to [promtimer](https://github.com/couchbaselabs/promtimer),
which shows the same cbcollect's **stats** over time. The two share one
unpacked copy of the capture and are meant to be used side by side.

**Nothing leaves your machine.** It binds to `localhost` and needs only
Python 3. No install step, no third-party packages.

## Built for an incident window, not a whole capture

A cbcollect routinely carries months, sometimes more than a year, of rotated
logs, and the incident is usually a few minutes of it near the end. cbtriage is
designed around that: you give it the window (`--start 2026-01-15T03:30
--end 2026-01-15T03:50`, read in the cluster's own time zone), it byte-seeks
into each log to the start of the window, and it ingests only those minutes.
A one-hour window on a large capture ingests in seconds and gives a small db
that is quick to browse.

Ingesting a whole capture works, but it is slow, the db is large, and every
view is scaled to the full retention, so it is not the intended use. A few
sources are read in full regardless of the window, because they are bounded in
size and their history matters (the curated event_log, the babysitter log,
rebalance reports, the diag.log process dump, and couchbase.log's one-shot
sections including the dmesg ring). Anything they
contribute outside the window is clipped from the views and the omission is
stated.

## Good for

- **Correlating events across logs and nodes for one time period.** Every
  node's debug, info, error, babysitter, http_access, json_rpc, event_log,
  dmesg, syslog and journal lines on one timeline, converted to a single UTC
  clock. Mixed timezones, dmesg monotonic timestamps and year-less syslog lines
  are all anchored, and clock skew between nodes is shown rather than hidden,
  so cross-node ordering can be trusted.
- **A bird's-eye view of the cluster over time.** The cluster overview puts
  three things on one time axis: which node each node believed was the
  orchestrator (one lane per node, so a partition shows up as lanes that
  disagree), a strip showing whether they agreed, and every rebalance and
  failover as a span coloured by how it ended. A rebalance is labelled with the
  node that drove it; a failover with the nodes it failed over, each with its
  recorded reason. Clicking an operation opens its rebalance report: the phase and vbucket it
  stopped in and how long each service took (ns_server keeps only the 5 most
  recent reports).
- **Navigating Erlang process dumps.** Both the diag.log dump taken at collect
  time and the dumps `timeout_diag_logger` writes when a call times out (that
  is, at the moment of the incident). Filter by process name or
  `current_location`, sort by message queue length, and long mailboxes are
  raised as a finding.
- **A service that is crash-looping or not answering.** Per-service start,
  stop and exit history with the exit status and the service's own dying output
  (for example a Go panic), next to the ServiceAPI calls it never answered and
  how long each was outstanding.
- **The host and container at collect time.** cgroup CPU, memory and IO
  throttling, memory-reclaim watermarks, vm settings, and uptime (a reboot shows
  as an uptime shorter than the capture). A source that could not be read is
  listed as missing, never shown as zero.
- **Known issues.** Findings fingerprint specific known problems, such as the
  `/pools/default` stall on 7.6.8–7.6.11 / 8.0.0–8.0.2, alongside OOM kills,
  clock out of sync and disks nearly full.

## Scope

The findings and dedicated panels cover the cluster manager (ns_server) and the
host it runs on. Logs from other services still appear on the timeline, but have
no findings of their own. Findings state recorded facts (what happened, on which
node, with the logged reason) and link to the log lines behind them; they do
not offer a root cause.

## Getting a cbcollect

A cbcollect is the per-node diagnostics bundle produced by `cbcollect_info` or
by **Logs > Collect Information** in the Couchbase Server UI. See
[Manage Logging](https://docs.couchbase.com/server/current/manage/manage-logging/manage-logging.html)
in the Couchbase docs. Collect from every node in the cluster; cbtriage lines
them up against each other.

## License

Apache License 2.0, the same as promtimer. See [`LICENSE`](LICENSE).

## Usage

### Recommended: one DB per incident, narrow the time window

cbcollect bundles can be large. Always scope with `--start`/`--end` to the
time range you care about — ingest skips everything outside the window, so the
DB stays small and ingest is fast. Without a window the tool reads every event
in every log file, which is slow and produces a very large DB.

```sh
# ingest a cbcollect .zip (or dir, or cluster_run logs/) into a per-incident DB
# -d names the output DB; there is no need to unpack the bundle first
# times are read in the cluster's own time zone, as its logs print them
python3 $CBTRIAGE/cbtriage.py ingest ~/Downloads/collectinfo-....zip \
    -d /tmp/incident.db \
    --start 2026-01-15T03:30 --end 2026-01-15T03:50

# ingest once, then re-open as many times as you like without re-ingesting
python3 $CBTRIAGE/cbtriage.py serve -d /tmp/incident.db
```

Each `ingest` run **overwrites** the named DB (use `--append` to accumulate).
Use an explicit `-d` path — the default `analysis.db` lands in the working
directory, which pollutes the script tree if you run from there.

`/tmp` is fine for short-lived work; the OS clears it on reboot. Use a
permanent path if you want the DB to survive a restart.

### Working straight from the .zip

Pass the `.zip` — or a directory holding one zip per node — and the log files
cbtriage parses are extracted into the `cbcollect_info_*` dir beside the zip:
exactly where unzipping the bundle yourself would have put them. On the
capture used here that is 57 MiB of a 141 MiB bundle; the rest (pprof dumps,
cert bundles, JSON blobs) is never touched.

There is one rule — **a file is extracted if it isn't already there**. So it
does not matter what state the folder is in:

| folder already contains | what happens |
|---|---|
| nothing but the zip | the dir is created and populated |
| a full manual unzip | every file is present, nothing is extracted |
| promtimer's partial unpack | the files it didn't extract are filled in |

That last row matters because promtimer unpacks `couchbase.log` and
`stats_snapshot/` into the same directory, so the two tools share one copy of
the capture and each benefits from what the other already pulled out. One
folder per incident serves both:

```sh
cd ~/cbcollects/incident
promtimer -p <path>/prometheus -g $(brew --prefix grafana)/share/grafana
python3 $CBTRIAGE/cbtriage.py ingest . -d /tmp/incident.db --start ... --end ...
```

cbtriage extracts rather than reading members in place because zip members are
deflate streams and can't be seeked, and the `--start` byte-seek is what makes
a narrow window at the tail of a long capture cheap.

With lazy raw (the default) the DB is an index into those files, so keep them
as long as the DB. `--embed-raw` cuts that tie.

### Quick parse + serve in one step

```sh
python3 cbtriage.py /path/to/cbcollect_dir
```

This combines ingest and serve. Useful for a quick look, but without
`--start`/`--end` the ingest reads everything. Add the window flags:

```sh
python3 cbtriage.py /path/to/cbcollect_dir \
    --start 2026-01-15T03:30 --end 2026-01-15T03:50
```

### Time format and time zone

The usual form is a date and time to the minute, `2026-01-15T03:47`, read in
**the cluster's own time zone**: the clock its logs print in, so a time read
off a log line needs no conversion.

| You pass | Read as |
|---|---|
| `2026-01-15T03:47` | the cluster's own time zone (the usual form) |
| `2026-01-15T03:47:57` or `'2026-01-15 03:47'` | the cluster's own time zone |
| `2026-01-15` | midnight, in the cluster's own time zone |
| `2026-01-15T03:47:57.942-08:00` | that exact instant: a full log stamp pasted as-is, offset included |
| `1768477677` | a Unix epoch (seconds) |

The full form is the timestamp exactly as ns_server writes it. A line in
`ns_server.debug.log` starts `[ns_server:debug,2026-01-15T03:47:57.942-08:00,...`,
and the part between the first two commas can be pasted whole. Its offset fixes
the time, so no zone setting applies to it.

A time with no offset is read in **the cluster's own time zone**, the one its
logs print in, detected from the capture (for example `/etc/timezone`). Ingest
prints the zone it used and where it found it:

```
Window:   2026-01-15T03:30 .. 2026-01-15T03:50 (America/Los_Angeles, cluster time zone from /etc/timezone; ...)
```

If the capture records no time zone, bare times are read as UTC and ingest says
so. To read bare times in some other zone, for instance when an incident was
reported in the reporter's local time, pass `--tz` with a fixed offset (`+01:00`,
`-0700`) or an IANA name (`Europe/London`).

Internally every event is stored as a UTC epoch. The UI shows UTC by default;
a "collection-local time" toggle shows each event in the offset its own log
line recorded.

## What it ingests

| Source | Parser | Notes |
|---|---|---|
| debug/info/error/reports/babysitter | ALE multi-line | folds continuation lines; `subsystem` = erlang module, with logger/fn/line |
| http_access(_internal) | CLF | response-time (ms), inferred start, 4xx/5xx severity; handles bare `-` UA |
| json_rpc | ServiceAPI pairing | ports `service_tasks.py`: call/response rt, topology-change decode, **no-response = service not responding** (with how long it stayed outstanding). The connection label's channel (`-service_api` vs `-cbauth`) separates rebalance traffic from background chatter |
| babysitter + `Service '…' exited` | service lifecycle | per-service start / stop / exit **with status code**, and the service's own dying output (the Go panic). Matched on content, not severity — the whole babysitter death path logs at `info` |
| event_log | JSON | trusted curated events |
| master_events.log | NDJSON (unix-epoch `ts`) | rebalance/failover state-machine |
| couchbase.log / syslog.tar.gz / systemd_journal.gz | dmesg/syslog/journal | OS signals only (OOM, link, disk, hung task); **OOM always critical** |
| couchbase.log one-shots | snapshot | collection-time state, not a timeline: cgroup memory / CPU throttling / block IO / PSI, host vmstat reclaim, dying-cgroup census, `/proc/uptime`. Shown in the Snapshots panel regardless of the window |
| diag.log | process dump | `message_queue_len` extraction only (log lines skipped — dup of debug.log) |

Per-node **clock context** normalizes everything to UTC: explicit-offset logs
resolve exactly; dmesg monotonic anchors via `date − uptime`; syslog gets year
inference; clock skew is surfaced, not hidden. Per-node **Couchbase version**
and **platform** (Capella = `provisioned` profile; Kubernetes = couchbase.log
markers + `.svc` node names) are detected and shown.

## Layout: what goes inline, what gets a window

One rule decides where a panel lives: **does it share the timeline's x-axis?**

- **Inline strips**, stacked in the order they get read: findings, cluster
  overview, host pressure, activity — then the search and time-range bar, then
  the table. The controls sit directly above the rows they filter, below
  everything that is global to the capture. All are time-aligned and
  clicking them drives the table, so a panel that covers the table defeats
  itself — the cluster overview was briefly a full-screen modal and every click
  appeared to do nothing until it was closed. None of them is behind a button:
  a strip that shares the timeline belongs in the stack, and its header caret is
  how it gets out of the way.
- **Docked drawer**, on the right: the service drawer. Entity-scoped but still
  time-anchored, and clicking a row moves the timeline, so it sits beside the
  table rather than over it.
- **Modal window**: Snapshots, the only button left in the toolbar.
  Collection-time state at a single stamp, with no counterpart on the timeline to
  stay visible beside it.

Every inline strip collapses to its header, with the caret showing the state and
the count or summary staying visible. That matters because all four expanded on a
laptop viewport leaves the table with no rows, and which ones are worth the space
is per-person and per-investigation rather than something to guess at. The choice
persists per strip in `localStorage`, so a layout is chosen once, not on every
reload. `activity` starts collapsed: its only unique function is the drag-to-zoom
gesture, which does not justify 110px permanently — the gesture belongs on the
cluster overview's own axis, and once it lives there the histogram can go.

## Service drawer

Click a service — in the `services` facet, or the service chip on any timeline
row — to open a drawer on the right with that service's whole history, not
limited to the time window (a service that died before the window opened is
usually what explains the window). Three sections, in the order the questions
get asked:

- **outstanding calls** — ServiceAPI calls that never got a response, longest
  first, with the request id, the topology-change id/type, and how long the
  call sat unanswered. This is the hand-off: the specific call to point the
  service team at. Clicking one moves the timeline to a ±2 min window around
  it, so the surrounding events come with it. Calls still in flight when the
  capture was taken are shown separately and labelled ambiguous rather than
  counted as a stall.
- **ServiceAPI — topology / rebalance** — the answered calls, with round-trip
  time, whether the response still carried a running rebalance task, and
  whether the service reported itself balanced.
- **lifecycle — babysitter** — started / stopped / exited with the status code,
  and an expander for the service's dying output. The four modules that report
  one exit within milliseconds of each other are collapsed into a single
  transition, so a crash loop looks like a crash loop and a clean restart does
  not.

Per-service json_rpc traffic on other channels (cbauth and similar) is counted
but not listed — it is real traffic with nothing to do with rebalance, and in a
4-node capture it was over 40% of all json_rpc events.

## Cluster overview

`◆ Cluster overview` puts what the cluster was *doing* and what it *believed* on
one shared x-axis, as a diagram rather than a list:

- an **operations band**, one row per operation kind: rebalance and failover
  spans, coloured by outcome and labelled with the node that drove each one;
- a **believed-master strip** saying whether the nodes agreed at each instant;
- **one lane per node**, coloured by which node that observer believed held
  mastership.

Read it top-down: find the red on the strip, then look down the column to see
which nodes were on which side of it, and which operation was running at the
time.

Colour carries one meaning each way. **Node identity** uses blues, purples,
cyans, pinks and greys; **outcomes and consensus states** own green, amber and
red (completed / interrupted / failed, no master / split). That separation is
load-bearing rather than cosmetic: the identity palette's fourth colour used to
be the exact amber of "interrupted" and "no master", so on a six-node cluster one
node was drawn in the colour of a broken operation.

Hovering any band fills a readout at the foot of the strip — wrapped, not
truncated, and sticky so it stays visible while the pointer is up on the chart.
It carries what the event recorded, including the node sets a rebalance was
given (`keep_nodes`, `eject_nodes`, `delta_nodes`).

The two axes are deliberately separate bands rather than one merged row. A
belief is per-node state at every instant; an operation is a single
cluster-scoped span with an owner and an outcome. Orchestration sits over and
above the election — the master is the node that *may* act, and the spans are
what it actually did — so the cross-read is the point: **was the node that drove
this rebalance the node the cluster believed was master, and did the operation
straddle a split?** Operations that ran while the nodes disagreed are outlined
and counted in the header.

Operations come from the curated `event_log`, the same source promtimer
annotates from, so the two tools tell the same story about one capture. Typed ids
from `event_log.erl` separate the four kinds (rebalance, graceful / hard / auto
failover) and state the outcome explicitly, and every entry carries `otp_node`,
stamped with `node()` at `add_log` time — since those calls come from
`ns_orchestrator`, which runs only under `mb_master_sup` on the elected master,
that field *is* the orchestrating node rather than a guess at it. Two cases get
said out loud rather than smoothed over: an operation with no terminating event
is drawn open-ended as **no end recorded** (it may still have been running when
the capture was taken), and one whose start fell off the front of the event_log
ring is reported at its end rather than back-dated.

The x-axis is the extent of the evidence, *not* the capture's. The
always-full sources (event_log, diag, dmesg) span a cbcollect's whole retention,
so scaling to the capture is what makes the view unreadable: in one 4-node
bundle the events table spanned 18,000 hours while every election in it happened
inside 40 minutes, which is a third of a pixel. Outside the evidence's own span
nothing is known about who held mastership anyway. The header states both spans
so the chart is never mistaken for the whole capture.

There is deliberately no single "the master" row. mb_master is a gen_statem on
every node, and a candidate promotes itself once it has not heard from a
higher-priority node or a master for 10s (5 heartbeat intervals), so a partition
legitimately puts two nodes in the master state at the same time, each correct
by its own evidence. Disagreement between lanes is the signal.

- **lanes** come from `announce_leader/1`, which fires on exactly three paths
  (promotion, surrender, teardown) and is logged on every node by
  leader_registry — so a lane is a complete trace of what that node announced,
  not a sample. mb_master's own lines supply the *reason* (took over on timeout,
  surrendered, demoted, only node left) and stand in as the belief source where
  the registry line is missing. A lane that rests on only one of the two modules
  is marked as such; a node with no belief lines at all is called out rather
  than drawn as agreeing.
- **the cluster strip** is one of *agreed* (with the holder named), *split*
  (nodes disagreed — the partition case), *no master* (nothing was
  orchestrating, so no rebalance and no auto-failover could have run), *partial*
  (some believed a master, others none), or *unknown* (too few nodes had said
  anything yet — never drawn as agreement). The header does **not** summarise
  this: no share of time in agreement, no count of splits, transitions or rival
  claims. Each of those is a statistic about churn a live cluster produces
  constantly — nodes joining and leaving, brief partitions, rolling restarts — so
  the number is never zero, never means much alone, and reads as a score. What
  the header does carry is what ran ("7 rebalances: 7 completed"), how much of
  the capture the chart covers, and any node that logged nothing.
- **nothing is listed or drawn to mark a divergence window.** In a cluster whose
  nodes come and go — added, failed over, taken down for a rolling upgrade and
  restarted — brief divergence is constant. Hard guides for it cry wolf, and a
  vertical line already means an event's start and end to anyone who reads
  promtimer. The strip carries it continuously, in colour, without a caption
  telling the reader what to make of it. Disagreement shorter than one 2s
  heartbeat interval is the propagation of an announcement, so it is excluded
  from the headline counts entirely: a number that is never zero never means
  anything.
- **rival claims** — "Got master heartbeat from X when I'm master" and the
  not-in-peers warnings — are counted in the header rather than listed, because
  they do *not* move the observer's own belief; they record that a node SAW a
  rival claim. Clicking the count pins them in the timeline.
- a node named as the holder that has no lane of its own is labelled **not
  collected**: its cbcollect was not in the bundle, and its lane is the one that
  would settle whether it agreed it was the master. A holder at the pre-rename
  name (`misc:localhost_alias()`, `cb.local`) is labelled **node initialising**
  instead — it is not a separate node, so the early flurry of transitions through
  it is bootstrap rather than an election, and calling it a missing capture would
  send someone hunting for a cbcollect that cannot exist.

- **spans are spans.** An operation's rectangle runs from its initiated event to
  its terminator, because the duration is the information. Below a readable floor
  the drawn width is that floor rather than the duration, so the right edge is
  hatched and the hover gives the real figure. Setting a time window (click a
  strip slice or an episode, or type into from/to) redraws the bands to that
  window, which is how a short operation gets a readable span; a chip in the
  header says the view is zoomed and clears it.
- **the only list is operations that did not complete**, with ns_server's own
  recorded outcome and reason. An operation that completed is not listed, and
  neither is one that merely overlapped a divergence window — selecting on that
  would be a judgement that a clean rebalance needs attention because the cluster
  briefly disagreed, which is the inevitable dressed up as an incident. The
  overlap is still marked on the block and counted in the header, where it is a
  count rather than a verdict.

Everything is hoverable for detail. Clicking a strip slice or an episode takes
the timeline to a ±2 min window around it; clicking a lane segment pins the log
lines that attest it, and clicking an operation pins its event_log start and end.

Only the mb_master axis of leadership is derived so far, and orchestration is
scoped to rebalance and failover. Per-node Couchbase version over time (from the
version banner each node logs at boot) is the next band: mb_master's election is
version-ordered, so a version change is frequently the *cause* of a mastership
move rather than an unrelated fact sitting beside it.

Not yet derived: the lease layer (`leader_lease_acquirer` is a child of
`mb_master_sup`, so it runs only on the elected master and gates whether that
mastership can still *act*) and chronicle's per-term leadership, which is
silent on observing a new leader and so has to be rebuilt from term events.

## Findings

Shown at the top of the UI. Each one states what was recorded, on which node
and when, and links to the log lines behind it. The active set
(`cbtriage/findings.py`, `run()`):

- **OOM kill**: the kernel OOM killer fired. Always critical.
- **Auto-failover**: one rollup of every completed auto-failover, giving the
  node, the time, ns_server's recorded reason, the configured timeout, and the
  coarse host pressure on that node in the lead-up window (or that the node had
  stopped reporting stats, or that the capture has no pressure data).
- **Rebalance failed or interrupted**: ns_server's own event_log entry with the
  recorded reason, deduplicated across nodes. Where the rebalance report is
  still retained, it adds the phase and vbuckets the operation stopped in.
- **Clock out of sync**: ns_server's `time_out_of_sync` alert. The node's
  events may be skewed on the cross-node timeline.
- **Host pressure**: elevated PSI, allocstall or CPU steal from the stats.log
  heartbeat, with the node, resource, peak and time. Promtimer has the series.
- **Disk nearly full**: the fullest mount per node past ns_server's own
  guardrail bars (warn 80%, error 85%).
- **Long process mailboxes**: any process with `message_queue_len` of 1000 or
  more, in either the diag.log dump taken at collect time or a
  `timeout_diag_logger` dump taken when a call timed out.
- **Timeout diagnostics present**: `timeout_diag_logger` only writes when a
  call blocked past its timeout, so its presence is reported, with the count,
  nodes and span. The dumps are browsable under Snapshots > Processes.
- **Collection-time facts**: the couchbase cgroup was OOM-killed or sat at its
  memory ceiling, and whether host reclaim ran.
- **Known-issue fingerprints**, the two findings whose conclusion is the point:
  - the `/pools/default` stall on 7.6.8–7.6.11 / 8.0.0–8.0.2
    ([otp#10651](https://github.com/erlang/otp/issues/10651)): only
    `/pools/default` requests stall, on one node, with no other stall and no
    pressure or connectivity cause, and they all complete at the same moment.
    Cites the MB for the node's release train.
  - an excessive dying-cgroup census: cgroups already removed but pinned by
    page cache that reclaim never evicts.

Failover, nodedown, service-not-responding, stale-task and crash detectors also
exist in the code but are not surfaced as findings: on a long-lived cluster
these are routine and would bury the list. Their events stay browsable on the
timeline, and failovers have their own band in the cluster overview.

## Limitations

- Findings cover ns_server and the host. Other services' logs are on the
  timeline only.
- Only the 5 most recent rebalance reports are kept by ns_server, so older
  operations have no report; the overview says so rather than showing an empty
  drawer.
- The time window has to be translated by hand from what you are looking at in
  promtimer (Grafana gives epoch milliseconds or local time).
- A window that starts before `debug.log`'s oldest rotation is filled from the
  thinner info and error logs without a warning.
