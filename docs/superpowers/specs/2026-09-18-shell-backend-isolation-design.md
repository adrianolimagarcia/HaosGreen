# Shell Backend Isolation Design

> **Revision 2.** Revision 1 was reviewed and rejected as ready-to-implement on
> eight points. Every correction below is backed by a measurement taken on this
> host (bubblewrap 0.12.0, CachyOS, kernel 7.2.4-3-cachyos, running as uid 0),
> not by assumption. Where a proposed correction turned out to be unnecessary,
> or insufficient, that is recorded too.

## Objective

Make the supervisor's `ShellBackend` containment **real**. Today it runs the
operator's task text as a shell command with no containment at all, behind a
three-substring check that `sh` semantics defeat. After this work a shell job
runs inside a bubblewrap sandbox that cannot see the host's home directory,
`/etc`, the host's network, or the supervisor's environment — and when that
sandbox is unavailable the operator is **asked**, not silently obeyed.

## The problem, with the evidence

`ShellBackend::run` (`src/supervisor/backend/shell.rs:50-90`) takes
`job.prompt`, passes it through `validate()`, and runs it as `sh -c <cmd>` with
`current_dir(sandbox)`.

`validate()` (`src/supervisor/backend/shell.rs:26-33`) rejects only a command
that starts with `cd /`, contains `cd ..`, or contains `../`. It is a heuristic,
and its own error string — `"sandbox-violation: cd outside sandbox"` — claims a
containment that does not exist. The code's TODO at `shell.rs:19` says the
replacement must happen "before exposing ShellBackend through any user-facing
entrypoint"; that precondition was already violated.

The reachability chain, each link verified by reading the named site:

| Step | Site | Fact |
|---|---|---|
| Registered in production | `src/main.rs:519-523` | `ShellBackend::new(sandbox)` is in the live registry |
| Raw text is classified | `src/supervisor/mod.rs:1275` | `classify(text)`, not the title |
| Text starting `"run "` ⇒ `required_capabilities: ["shell"]` | `src/supervisor/classifier.rs:50-56` | the `OpsAutomation` branch |
| A bundled skill declares it too | `skills/sup-ops/SKILL.md:6` | `required_capabilities: [shell, reasoning]` |
| Selection ignores `can_handle` | `src/supervisor/backend/mod.rs:115-117` | `select_by_name` matches on `name()` only |
| `validate()` passes the payload | `shell.rs:26-33` | no `cd /`, `cd ..` or `../` present |
| `sh -c` runs the second command | measured | `sh -c 'run x; cat /etc/hostname'` printed the hostname |
| The text reaches the prompt verbatim | `src/supervisor/intake.rs:6-11` | `normalize` keeps `user_request` whole |

So `/supervise run x; cat ~/.haos-green/config.toml` classifies as
`OpsAutomation` with backend `shell`, passes `validate()`, and executes — with
the config file (API key plus every A2A peer token) landing in the job output,
the `sup_jobs` row, and the dashboard.

A second leak nobody had recorded: `sh -c` **inherits the supervisor's
environment**, so anything exported into the process is readable by every shell
job. (The job's own stdin is already `Stdio::null()`, `shell.rs:86`.)

### Severity, stated honestly

This is **not** a privilege escalation today. The only two callers of
`Supervisor::submit` are `src/platform/telegram.rs:355` (the `/supervise`
command, restricted to `telegram.allowed_user_ids`) and
`src/web/routes/supervisor.rs:464` (an authenticated dashboard session). Both
already have arbitrary host shell by design — `execute_command` is in the chat
tool policy, and the dashboard documents "any authenticated user has host shell
execution" as an accepted risk. No registry tool submits supervisor tasks, and
`DEFAULT_PEER_TOOLS` contains nothing of the sort, so **an A2A peer cannot reach
this path**.

It is a real vulnerability for three other reasons:

1. the error message and the TODO both imply containment that does not exist;
2. `CLAUDE.md:208` states that "File and command operations are contained by
   `validate_sandbox_path()`" — **false** for this path, which never calls it;
3. the A2A anti-recursion and wildcard invariants exist precisely to stop this
   class of drift, and a future "let peers delegate to the supervisor" feature
   would turn this into a remote escape with no further code change.

## Verified environment facts

Measured, not assumed. `bwrap --version` on this host reports **0.12.0**, and
every flag below is present in `bwrap --help`:

| Fact | Measurement |
|---|---|
| bubblewrap version | `0.12.0` |
| `--new-session`, `--disable-userns`, `--assert-userns-disabled`, `--hostname`, `--die-with-parent`, `--clearenv`, `--share-net` | all present |
| `--unshare-all` composition | `man bwrap`: equivalent to `--unshare-user-try --unshare-ipc --unshare-pid --unshare-net --unshare-uts --unshare-cgroup-try` — **user namespace is `-try`**, i.e. silently skipped on failure |
| `--disable-userns` precondition | `man bwrap`: "This option requires `--unshare-user`" |
| Nested user namespace, hardened argv | **blocked** (`unshare --user` fails inside) |
| Nested user namespace, without `--disable-userns` | **permitted** — the gap is real, not theoretical |
| `--hostname haos-sandbox` | inside `haos-sandbox`; host is `cachyos-x8664` |
| Network, no `--share-net` | only `lo`; TCP to `127.0.0.1:8790` refused |
| Network, with `--share-net` | `lo enp2s0 wlan0 tailscale0 virbr0 dnsstub`, and `127.0.0.1:8790` **reachable** |
| `--die-with-parent` | killing bwrap leaves **0** of 3 sandboxed `sleep` processes |
| Same, without `--die-with-parent` | **3** survivors — the grandchild leak |
| `/etc/passwd` inside | invisible |
| `--clearenv` placed **after** `--setenv` | wipes them (`HOME=` empty) |
| `--symlink usr/lib64 /lib64` omitted | `execvp /bin/sh: No such file or directory` |

Two of these change the design rather than merely confirming it:

- **`--die-with-parent` closes the documented `kill_on_drop` gap.** `CLAUDE.md`
  records that "`kill_on_drop` kills only the **direct** child — a backgrounded
  grandchild of a compound `sh -c` can survive". With bwrap in front, killing
  bwrap kills the whole tree: 4 → 1 (the 1 being a pre-existing unrelated
  process), against 3 survivors without the flag. For sandboxed jobs this
  documented bound **stops being true**.
- **Argument order is load-bearing.** `--clearenv` must precede every
  `--setenv`; reversed, the environment is wiped and `HOME` comes back empty.
  This is exactly what the "smoke test with the production argv" requirement
  exists to catch, and it was caught by it.

## Constraints

- Must work unprivileged. Measured: unprivileged user namespaces work here
  (`max_user_namespaces = 125706`).
- Must not weaken the existing lease/cancellation semantics
  (`run_until_lease_loss`, `kill_on_drop`, `job.timeout_secs`).
- Must fail closed: no silent fallback to an unconfined shell, ever.
- `src/lib.rs` carries `#![deny(dead_code)]`, so nothing added may be unreachable.

## Architecture

### 1. `src/supervisor/backend/sandbox.rs` — one unit, one argv

A single module owns the probe and the argv construction, so the sandbox is
described in exactly one place and the tests assert against the real thing.

#### 1.1 Version floor: bubblewrap >= 0.12.0 (P0)

bubblewrap below **0.12.0** is affected by **CVE-2026-87766 /
GHSA-pxhw-h44j-8pfx** (CVSS 8.8): during setup, before any sandboxed process
starts, a symlink traversal through `/oldroot` lets bubblewrap create files and
directories **outside** the sandbox, on the host, with the launcher's
privileges. 0.12.0 resolves paths with `openat2()` and `RESOLVE_IN_ROOT`.

This is not generic hygiene for this design — it is directly reachable.
bubblewrap performs that path resolution during **setup**, and the one
attacker-writable path in our argv is the job's own sandbox directory, which a
shell job can write to. A job can therefore plant a symlink that the **next**
job's setup walks. The version floor is part of the boundary, not a
recommendation.

`probe()` therefore:

1. locate `bwrap`;
2. run `bwrap --version`;
3. parse and require **>= 0.12.0**;
4. treat an older version **exactly as if bubblewrap were absent** — same
   `IsolationUnavailable` outcome, same fail-closed path, no distinct "insecure
   but usable" state;
5. only then run the functional smoke test.

A version that cannot be parsed is a failure, not a pass.

#### 1.2 The argv, in order

Order is normative. `--clearenv` **before** `--setenv`; the `--symlink` entries
are required or `execvp` cannot find the loader.

```
bwrap
  --unshare-all
  --unshare-user                 # explicit: --unshare-all only does -try
  --disable-userns               # requires --unshare-user
  --assert-userns-disabled       # fail unless it actually took effect
  --new-session                  # detach the controlling terminal (TIOCSTI)
  --die-with-parent
  --hostname haos-sandbox        # --unshare-all gives us a UTS namespace
  --clearenv
  --setenv HOME  <job-sandbox>
  --setenv PATH  /usr/bin:/bin
  --ro-bind /usr /usr
  --symlink usr/bin   /bin
  --symlink usr/lib   /lib
  --symlink usr/lib64 /lib64
  --proc /proc
  --dev  /dev
  --ro-bind /etc/resolv.conf /etc/resolv.conf    # only if host_network
  --ro-bind /etc/nsswitch.conf /etc/nsswitch.conf
  --ro-bind /etc/hosts /etc/hosts
  --bind <job-sandbox> <job-sandbox>
  --chdir <job-sandbox>
  /bin/sh -c <command>
```

- **`--new-session`** (P0). Without it the sandboxed process keeps the
  controlling terminal, and `TIOCSTI` lets it inject input into the operator's
  terminal — which is execution outside the sandbox. Paired with
  `stdin(Stdio::null())`, already present at `shell.rs:86`.
- **`--unshare-user` + `--disable-userns` + `--assert-userns-disabled`** (P1).
  `--unshare-all` alone is `--unshare-user-try`: on a host where the user
  namespace cannot be created, it is **silently skipped** and the sandbox is
  weaker with no signal. `--disable-userns` requires `--unshare-user` and stops
  the sandbox creating further user namespaces (it sets
  `user.max_user_namespaces = 1` and enters a nested namespace). It *asks*;
  `--assert-userns-disabled` is what *verifies*, and it fails the run if the
  restriction did not take effect. Both, or the boundary is advisory.
- **`--hostname haos-sandbox`**. We already have a UTS namespace; leaving the
  host's hostname visible hands the sandbox a free identity signal for no
  benefit.

#### 1.3 The writable directory (P1)

The job sandbox is the **only** writable host path in the argv, which makes it
the critical part of the boundary. It is resolved as:

```
sandbox_root = canonicalize(configured sandbox root)?
job_sandbox  = sandbox_root / <task-id> / <job-id>
```

with these invariants, each a hard failure rather than a warning:

- the resolved path is absolute;
- it is **not** `/`;
- it is a strict descendant of `sandbox_root` (after canonicalisation, so
  `..` and symlink tricks are already resolved);
- `sandbox_root` is not `/`, not the home directory, and not inside
  `~/.haos-green`;
- the directory is created if absent, and re-canonicalised **after** creation
  (a pre-existing symlink at that path is caught here, which is also the
  CVE-2026-87766 precondition).

Per-job directories, not one shared sandbox: a shell job must not see a
sibling's artifacts, and a symlink planted by job A must not sit in job B's
setup path. This is the same reasoning as the version floor, applied to the
only path we hand out.

### 2. Fail-closed in two layers (unchanged from revision 1)

- **Layer 1 — route time.** The gate asks the *same* planning path the executor
  uses (plan the task, ask the registry) rather than duplicating a routing
  predicate, so the gate and the executor cannot disagree. If a task would
  select the shell backend and isolation is unavailable and no grant covers it,
  the task is parked in `Route` via `RequireApproval`.
- **Layer 2 — job time.** `ShellBackend::run` re-checks and **spawns nothing**
  when isolation is unavailable and no grant covers this job. Layer 1 is a UX
  affordance; Layer 2 is the boundary, because a task can move between the two
  (approval, resume, a config reload, a revoked grant).

### 3. Consent: two different decisions, two different commands (P0/P1)

Revision 1 let a single `/approve <id>` grant unconfined shell **for the rest of
the process**. That is a UX trap: the operator believes they are approving one
job, and has in fact authorised every future shell job until restart. The two
decisions are separated:

| Command | Scope |
|---|---|
| `/approve <task-id>` | **this task only.** Does not authorise any other job. |
| `/unsafe-shell on` | standing consent for the process, granted explicitly and named for what it is |
| `/unsafe-shell off` | revokes standing consent immediately |

```rust
enum UnsafeShellGrant {
    None,
    Job(TaskId),   // one-shot, consumed when that job runs
    Process,       // standing, until revoked or restart
}
```

- The grant is in-memory (`Arc<AtomicBool>` for `Process`, a set of task ids for
  `Job`) and **never persists across a restart**, matching the dashboard's
  session model.
- `Job` is consumed on use, so an approval cannot be replayed by a later run of
  the same task id.
- Every grant and every revocation writes a `sup_transitions` row naming the
  actor and the scope, so the audit log distinguishes "approved this job" from
  "enabled unsafe shell process-wide" — which revision 1's single row could not.

### 4. Configuration

```toml
[supervisor.shell]
sandbox      = "bwrap"   # "bwrap" | "none"
host_network = false     # default: share the HOST network namespace
```

**`host_network` defaults to `false`** (P0). The name is deliberate: `network =
true` reads as "allow internet access", but what `--share-net` actually does is
keep the **host's** network namespace. Measured exposure with it on: `lo enp2s0
wlan0 tailscale0 virbr0 dnsstub`, with `127.0.0.1:8790` (the operator's own LLM
gateway) reachable from inside the sandbox. That reaches loopback services, the
LAN, Tailscale peers, VM bridges and any cloud metadata endpoint the host can
reach. The config key now says so.

> **Open question, flagged rather than guessed.** The review that produced this
> revision stated the network default twice and the two statements contradict:
> the priority table and the section arguing the point both say change it to
> `false`, while the concluding line of the duplicated message says
> `network = TRUE padrao`. This revision implements **`false`**, on the weight of
> the reviewer's own reasoning, and treats the lone `TRUE` as a typo. If it was
> not a typo, this is a one-line change and the sandboxed job simply keeps the
> host namespace by default.

With `sandbox = "none"` nothing is gated: that mode **is** the operator's
consent, and Layer 1 does not apply. `host_network` is ignored under `"none"`.

An unknown value for `sandbox` is refused at load rather than defaulted.

### 5. Resource containment (P1)

bubblewrap is a **namespace** tool, not a resource sandbox. It does not bound
CPU, memory, process count or output. The review asked for this to be explicit;
here is exactly what exists today in `shell.rs` and what this change adds:

| Bound | Today | This change |
|---|---|---|
| Wall-clock timeout | **exists** — `tokio::time::timeout(job.timeout_secs, …)`, `shell.rs:91` | unchanged |
| stdin | **exists** — `Stdio::null()`, `shell.rs:86` | unchanged |
| Cancellation | **exists** — `kill_on_drop`, direct child only | **improved**: bwrap's `--die-with-parent` makes it the whole tree |
| stdout bytes | **missing** — `wait_with_output` buffers without limit | **added**: cap, and the job fails with a clear error |
| stderr bytes | **missing** | **added**: cap |
| Child process count | **missing** | **added**: `RLIMIT_NPROC` via `pre_exec`, best-effort, documented as such |
| CPU / memory | missing | **explicitly out of scope**; needs cgroups, deferred with a written reason |
| Sandbox filesystem fill | missing | bounded by the wall clock only; documented, not solved |

The caps are enforced by reading the child's pipes with a bounded reader rather
than `wait_with_output`, so a `yes` job is stopped by the byte cap and not only
by the deadline. The output cap is enforced **before** the text reaches the job
row or the artifact, so a runaway producer cannot inflate the database.

### 6. The probe's smoke test uses the production argv (P1)

`probe()` does not run `bwrap --unshare-all /bin/sh -c true`. It runs the
**same argv builder** the executor uses, against a scratch job directory, and
asserts the properties the boundary claims:

- the shell starts (proves `/usr`, `/bin`, `/lib`, `/lib64` and the loader);
- `$HOME` is the job sandbox and `$PATH` is the set value (proves the
  `--clearenv`/`--setenv` **ordering**);
- the sandbox directory is writable and `--chdir` took effect;
- `hostname` is `haos-sandbox`;
- `/etc/passwd` is not readable;
- a TCP connect to the host's loopback fails (unless `host_network`);
- creating a nested user namespace fails (proves `--disable-userns` and
  `--assert-userns-disabled` actually took effect on this kernel).

A failure at any step is `IsolationUnavailable`, with the failing step named in
the error. The probe runs once at startup and its result is cached.

## Error handling

- `IsolationUnavailable` is one variant carrying the failing step, so the
  operator sees *why* (no bwrap / version too old / nested userns still possible
  / network not isolated), not just "unavailable".
- Layer 2 returns a `JobStatus::Failed` with an error naming the command that
  would grant consent; it never falls back to `sh -c`.
- A sandbox-directory invariant failure is a hard error, never a warning, and
  never a fallback to the configured root.

## Testing and verification

### Mutation tests (each must be shown to fail)

From revision 1, kept:

- remove `--unshare-all` → escape test fails
- remove `--clearenv` → environment-leak test fails
- remove the `--bind` → sandbox-write test fails
- remove the Layer-2 refusal → unconfined-execution test fails

Added, one per correction in this revision:

- **stub `bwrap --version` at `0.11.x`** → `probe()` must refuse, and must
  refuse *as* `IsolationUnavailable`, not as a distinct "insecure" state
- remove `--new-session` → the PTY/TIOCSTI test must detect it
- remove `--disable-userns` (or `--assert-userns-disabled`) → nested-userns test
  must detect it
- remove `--unshare-user` while keeping `--disable-userns` → the run must fail,
  not silently downgrade
- move `--clearenv` after `--setenv` → `HOME` must come back empty
- `host_network = false` → loopback and LAN unreachable
- remove `--hostname` → the host's hostname must be visible
- set the sandbox root to `/` → config load must refuse
- revoke the grant between Layer 1 and Layer 2 → Layer 2 must still refuse
- kill the supervisor → no sandbox process or descendant survives
- infinite stdout → the byte cap ends the job before the wall clock

### Tests that run against real bubblewrap

Marked `#[ignore]`d and re-checked at runtime against an env gate, matching the
existing live-test convention (`HAOS_GREEN_A2A_LIVE`, `HAOS_GREEN_WEB_LIVE`), so
plain `cargo test` stays green on a host without bubblewrap:

- the original attack (`run x; cat /etc/hostname`) fails inside the sandbox;
- `~/.haos-green/config.toml` is unreachable;
- the environment leak is closed;
- the two-layer gate parks a task in `Route` and `/unsafe-shell on` releases it;
- `/approve <id>` does **not** release a *different* task.

Every await on spawned work goes through `supervisor::bounded("what", handle)`,
per the hang rule in `CLAUDE.md`.

## Documentation corrections

- `CLAUDE.md:208` claims file and command operations are contained by
  `validate_sandbox_path()`; true for the tools, **false** for this backend.
- `shell.rs:19-23`'s TODO is satisfied and must be replaced, not deleted
  silently.
- The `"sandbox-violation"` error string is replaced by a message that
  describes what was actually checked.
- `CLAUDE.md`'s `kill_on_drop` bound gains the exception: sandboxed shell jobs
  kill their whole tree via `--die-with-parent`.

## Non-goals

- seccomp, container runtimes, chroot — bubblewrap's namespace model is the
  boundary here.
- CPU and memory limits (cgroups); deferred explicitly, with the gap recorded in
  the table above rather than left implicit.
- Sandboxing `claude_code`, `codex`, or `script`. They spawn processes too, but
  none is registered in production (`main.rs` registers only reasoning and
  shell), so they are a follow-up rather than part of this change.
- Making natural-language-as-shell sensible. Isolation bounds the damage; it
  does not make the route a good idea. Removing it is a separate decision.

## Delivery sequence

1. `sandbox.rs`: version probe, argv builder, sandbox-directory invariants, plus
   unit tests for the argument construction and its **ordering**.
2. Wire into `ShellBackend`; real-bwrap tests; first mutation round.
3. Config keys (`sandbox`, `host_network`), startup probe and warning.
4. Output caps and `RLIMIT_NPROC`; runaway-producer tests.
5. Layer-1 gate and Layer-2 refusal.
6. Consent (`UnsafeShellGrant`), audit rows, `/approve` scoping,
   `/unsafe-shell on|off` and the dashboard equivalent.
7. Documentation corrections, then the full gates.
