# Shell Backend Isolation Design

> **Revision 3.** Revision 1 was reviewed and rejected as ready-to-implement on
> eight points; revision 2 corrected those. Every correction below is backed by a
> measurement taken on this host (bubblewrap 0.12.0, CachyOS, kernel
> 7.2.4-3-cachyos, running as uid 0), not by assumption. Where a proposed
> correction turned out to be unnecessary, or insufficient, that is recorded too.
>
> **Revision 3 changes the consent model.** Revision 2 asked one binary question
> — "may this job run outside the sandbox?" — and answered the network question
> in `config.toml`, defaulting `host_network` to `true` at the operator's
> explicit direction. Revision 3 replaces both with a boundary drawn at
> **capability**: reads are free, **writes and the host network require a named,
> revocable grant**. §3 records the model and §4 records why the config key is
> gone. The network default is therefore no longer `true`; it is "not granted
> until the operator says `/allow-net`".

## Objective

Make the supervisor's `ShellBackend` containment **real**. Today it runs the
operator's task text as a shell command with no containment at all, behind a
three-substring check that `sh` semantics defeat. After this work a shell job
runs inside a bubblewrap sandbox that cannot see the host's home directory,
`/etc`, or the supervisor's environment — and when that sandbox is unavailable
the operator is **asked**, not silently obeyed.

**What this promises, and what it does not.** A shell job runs inside a
bubblewrap sandbox that cannot see the host's home directory or `/etc` beyond a
small read-only base, and cannot modify the host at all: every host path it can
reach is bound `--ro-bind`, and the only writable location is its own job
directory.

The host's **network namespace is not shared by default** (revision 3; revision
2 defaulted it on). A job that needs the network asks, and the operator grants
it with `/allow-net` — see §3. The same is true of any host path the job needs
to **write**: it is refused until the operator names it with `/allow <path>`.
Reads of the base set are never gated, because a read-only bind cannot damage
the host.

So the isolation this design delivers is a **filesystem boundary that is
read-only by construction, plus a network and write boundary that is
grant-gated**. It does not promise that a granted job is harmless: once
`/allow-net` is granted, the dashboard escape route in §3 is live again.

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
  --ro-bind /etc/resolv.conf   /etc/resolv.conf
  --ro-bind /etc/nsswitch.conf /etc/nsswitch.conf
  --ro-bind /etc/hosts         /etc/hosts
  --ro-bind /etc/ssl/certs     /etc/ssl/certs        # if it exists
  --ro-bind /etc/ca-certificates /etc/ca-certificates # if it exists
  --bind <job-sandbox> <job-sandbox>
  --chdir <job-sandbox>
  /bin/sh -c <command>
```

and, **only when the operator has granted the network**, one more flag after the
`/etc` binds:

```
  --share-net
```

- **The certificate binds are what keep HTTPS working**, and they are not
  optional garnish. Measured from inside this argv: without them `curl
  https://example.com` fails with `curl: (77) error adding trust anchors from
  file: /etc/ssl/certs/ca-certificates.crt`; adding `/etc/ssl/certs` **alone**
  still fails, because on Arch/CachyOS the bundle is a symlink to
  `../../ca-certificates/extracted/tls-ca-bundle.pem` and binding the directory
  that holds the symlink without its target leaves it dangling; adding both
  returns **HTTP 200**, and `openssl s_client` reports `Verify return code: 0
  (ok)`. On Debian/Ubuntu the second path does not exist and is skipped. They are
  public CA certificates — read-only, and no secrets.
- **`--share-net` is not in the base argv.** It is appended only under a network
  grant, because it hands the job the host's namespace — measured as `lo enp2s0
  wlan0 tailscale0 virbr0 dnsstub`, with the operator's own LLM gateway on
  `127.0.0.1:8790` reachable from inside.
- **The three `/etc` files for name resolution are always bound.** Without them
  a job cannot resolve a hostname at all, and DNS resolution is a read; measured,
  `getent hosts example.com` resolves correctly with them and fails without.

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
  `..` and symlink tricks are already resolved) — strictly below it, never
  equal to it, so the job can never write at the root itself;
- `sandbox_root` is not `/`, and `sandbox_root` is **not an ancestor of
  `config.toml`**. The default root is `<home>/workspace` and the job directory
  is `<home>/workspace/<task-id>/<job-id>`, so the job can write only below
  `workspace/` and `config.toml` — a sibling, not a descendant — stays
  unreachable. An operator who points the root at `<home>` itself is refused,
  because then the job directory's parent *is* the directory holding the
  secrets;
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

### 3. The sandbox is the authorization boundary (P0/P1)

Revision 2 treated consent as a single binary decision — "may this job run
outside the sandbox at all?" — with a job-scoped `/approve` and a process-wide
`/unsafe-shell on`. That conflates two very different questions and gives the
operator only an all-or-nothing lever: a job that needs one extra read-only
path and a job that needs to write to `/etc` are answered identically.

Revision 3 replaces that with a boundary drawn at **capability**, not at the
binary:

| Capability | Default | Requires authorization |
|---|---|---|
| Read a host path that the base set already binds | **allowed** | no |
| Read any other host path | not bound — the sandbox simply has no such path | n/a |
| **Write** to a host path | **refused** | **yes** |
| **Host network namespace** (`--share-net`) | **refused** | **yes** |
| Write inside its own job directory | allowed | no |

Reads are free by construction: the base set is bound `--ro-bind`, so a job
cannot modify the host through it, and a path outside the base set does not
exist inside the sandbox at all. The two capabilities that can actually damage
the host are a **read-write bind** and **the host's network namespace**, and
those are the two that ask.

This is the operator's decision, stated plainly: reading is not dangerous,
writing and reaching the host's network are.

#### The base set, bound read-only and never gated

```
/usr  /bin  /lib  /lib64  /proc  /dev
/etc/resolv.conf  /etc/hosts  /etc/nsswitch.conf
/etc/ssl/certs  /etc/ca-certificates
```

The two certificate paths are not optional. Measured on this host: without them
`curl https://example.com` from inside the sandbox fails with
`curl: (77) error adding trust anchors from file:
/etc/ssl/certs/ca-certificates.crt`, and binding `/etc/ssl/certs` **alone** does
not fix it, because on Arch/CachyOS the bundle is a symlink to
`../../ca-certificates/extracted/tls-ca-bundle.pem`. Both are needed; on
Debian/Ubuntu the second is absent and is skipped. They are public CA
certificates — read-only, no secrets.

Binding them keeps a property that would otherwise silently regress: today
`ShellBackend` runs `sh -c` on the host with a complete `/etc`, so a job that
fetches a URL works. A sandbox that broke HTTPS would be a functional
regression, not a security win.

#### Authorization is declared before the run, not discovered during it

`bubblewrap` builds its argv before the process starts; a bind cannot be added
to a running sandbox. So authorization cannot be reactive — the supervisor
cannot watch a job fail and then widen its own sandbox. It is resolved **before**
the job runs:

1. The task declares the grants it needs (`Grants { write: Vec<PathBuf>, network:
   bool }`). In practice the planner derives this from the job's command; a
   declaration that is missing a grant fails closed and the job is refused, it
   does not fall back to a wider sandbox.
2. The supervisor subtracts the grants already held. If nothing is missing, the
   job runs.
3. Otherwise the task is parked and the operator is asked, by name, for each
   missing grant — the path, and why the task wants it.

```rust
struct Grants {
    /// Host paths the job may mount read-write. Absolute, canonicalised.
    write: BTreeSet<PathBuf>,
    /// Share the host network namespace.
    network: bool,
}
```

#### Grants are per path, standing until revoked

| Command | Effect |
|---|---|
| `/allow <path>` | grants read-write access to that host path, for every future job until revoked |
| `/deny <path>` | revokes it immediately |
| `/allow-net` | grants the host network namespace until revoked |
| `/deny-net` | revokes it immediately |
| `/approve <task-id>` | releases one task parked at Layer 1 (see §2) — job-scoped, consumed on use |

Standing rather than one-shot is deliberate: a job that fetches a URL needs the
network on every run, and asking again each time trains the operator to approve
without reading. `/deny` is the revocation, and it is immediate.

`write` grants are matched on the **canonicalised** path, so `/etc/../etc` and a
symlink pointing at `/etc` resolve to the same entry. A grant covers exactly the
path named and not its children: `/allow /var/lib/docker` does not grant
`/var/lib`. Widening is an explicit, separate decision.

The grant set is in-memory and **never persists across a restart**, matching the
dashboard's session model: a restart is a cheap, complete revocation. Every
grant and revocation writes a `sup_transitions` row naming the actor, the path
and whether it was granted or revoked, so the audit log answers "who allowed
writes to /etc, and when?" — which revision 2's single boolean could not.

#### What this closes

Revision 2 documented an escape path and accepted it: with `host_network = true`
by default, a sandboxed job could reach the dashboard on `127.0.0.1:8787`, log
in with the default `admin`/`admin`, and run `execute_command` on the host
outside the sandbox. Under revision 3 the host network namespace is **not
granted by default**, so that path requires the operator to type `/allow-net`
first — turning an implicit default into an explicit decision. The escape is
still possible once granted, and it is still worth knowing that the dashboard is
the weakest link; the difference is that it is now a decision rather than a
default.

#### `sandbox = "none"`

Unchanged in spirit: that mode **is** the operator's standing consent to run
shell jobs outside any sandbox, and nothing is gated. It is named for what it
is, it is refused unless set explicitly, and the operator is warned at startup.

### 4. Configuration

```toml
[supervisor.shell]
sandbox = "bwrap"   # "bwrap" | "none"
```

**There is no `host_network` config key in revision 3.** The host network
namespace became a *runtime grant* (`/allow-net`), not a startup setting, for one
reason: a config key is decided once, at rest, by whoever edits `config.toml`,
while the escape path it opens is exercised per job. Making it a grant means it
is named at the moment it is used, by the operator, and revocable without a
restart.

Revision 2 defaulted `host_network` to `true` at the operator's explicit
request, and documented the exposure it created: `--share-net` keeps the
**host's** namespace, so the sandbox saw `lo enp2s0 wlan0 tailscale0 virbr0
dnsstub`, with `127.0.0.1:8790` — the operator's own LLM gateway — reachable from
inside. That reached loopback services, the LAN, Tailscale peers and VM bridges.
Under revision 3 the default is the empty grant set: **no host network, no
writable host path**, and the operator grants each explicitly.

> The accepted-risk block from revision 2 is retained in §3, re-framed: the
> dashboard escape path still exists once `/allow-net` is granted, and the
> dashboard remains the weakest link in the chain. What changed is that reaching
> it is now a decision the operator takes by name rather than a default they
> inherit by omission.

With `sandbox = "none"` nothing is gated: that mode **is** the operator's
consent, and Layer 1 does not apply.

An unknown value for `sandbox` is refused at load rather than defaulted.

A grant of a path that does not exist, is not absolute, or is `/` is refused
when it is issued, not when a job later fails to start: `/allow /` would hand
back everything the sandbox exists to withhold, and a relative path has no
meaning once the sandbox has its own root. `--` handling matters here, because a
path is operator input: `/allow -- /etc` must not be read as a flag.

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
- `$HOME` is the job sandbox and `$PATH` is the set value;
- an **inherited canary variable is absent** inside — this is what proves
  `--clearenv` ran, and `$HOME`/`$PATH` do **not**. Measured: removing
  `--clearenv` leaves a probe that asserts only `$HOME`/`$PATH` passing 7/7,
  because `--setenv` sets exactly those two variables; with a canary set in the
  probe's own environment, removing `--clearenv` leaks it
  (`canary vazou=[SEGREDO]`) and the probe fails. The probe is therefore spawned
  with the canary present;
- the sandbox directory is writable, and `--chdir` took effect **when the probe
  spawns `bwrap` with its own cwd outside the job directory**. Measured: bwrap
  inherits the invoking process's cwd when `--chdir` is absent — with the parent
  at `/` the sandbox sees `/` (caught), with the parent already inside the job
  directory it sees the job directory (silently passes). The probe pins its own
  cwd so the check cannot pass by coincidence;
- `hostname` is `haos-sandbox`;
- `/etc/passwd` is not readable, and `/etc/shadow` does not exist;
- **HTTPS works**: a request to an HTTPS endpoint succeeds, proving the two
  certificate binds are present and resolvable. Measured as the difference
  between `curl: (77)` and `HTTP 200`, and `openssl s_client` reporting
  `Verify return code: 0 (ok)`;
- a TCP connect to the host's loopback **fails** unless the network grant is
  held, and **succeeds** when it is — the probe asserts the behaviour of the
  grant set actually in force, so both states are covered rather than assuming
  the default;
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
- move `--clearenv` after `--setenv` → the **canary** must leak. Not `$HOME`:
  measured, a probe asserting only `$HOME`/`$PATH` passes 7/7 with `--clearenv`
  removed, so that assertion has no teeth here
- remove `--share-net` while the network grant is held → the loopback check must
  fail, proving the flag is what carries reachability
- hold the network grant → loopback reachable; revoke it → loopback unreachable
- remove the two certificate binds → the HTTPS check must fail with `(77)`
- bind `/etc/ssl/certs` **without** `/etc/ca-certificates` → HTTPS must still
  fail, proving the second bind is load-bearing rather than redundant
- grant a path read-write, then `/deny` it → the write must be refused again
- grant `/var/lib` and attempt to write `/var/lib/docker/x` → refused, proving a
  grant covers exactly the named path and not its children
- spawn `bwrap` with its cwd already inside the job directory and remove
  `--chdir` → the cwd check must still catch it, proving the probe pins its own
  cwd rather than passing by coincidence
- **the loopback escape path must be demonstrated, not assumed**: with the
  dashboard enabled, the default password unchanged, and the network grant held,
  a sandboxed job must be shown to reach `/api/auth/login` and obtain a session.
  This test asserts the *accepted risk*, so that removing the risk fails the test
  and forces the spec to be updated rather than silently drifting.
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
- the two-layer gate parks a task in `Route`, and granting what it declared
  releases it;
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

1. `sandbox.rs`: version probe, argv builder (including the certificate binds and
   the conditional `--share-net`), sandbox-directory invariants, the startup
   smoke probe, plus unit tests for the argument construction and its
   **ordering**.
2. Wire into `ShellBackend`; real-bwrap tests; first mutation round.
3. Config key (`sandbox`) and the startup warning.
4. Output caps and `RLIMIT_NPROC`; runaway-producer tests.
5. Layer-1 gate and Layer-2 refusal.
6. Grants: the `Grants` set, `/allow`, `/deny`, `/allow-net`, `/deny-net`, their
   audit rows, `/approve` scoping, and the dashboard equivalents.
7. Documentation corrections, then the full gates.
