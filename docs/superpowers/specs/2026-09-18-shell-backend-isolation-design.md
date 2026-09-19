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
>
> **Revision 3, corrected after Task 3 shipped.** §1.3 has been fixed against the
> implementation on three points. Its rule "`sandbox_root` is **not an ancestor
> of `config.toml`**" was wrong — an ancestor rule refuses almost every usable
> root — and is now the narrower "does not **directly hold** `config.toml`". Its
> stated reason for that rule was overstated: it claimed a root holding
> `config.toml` would give the job a read-write bind over the credentials, but
> the argv's only read-write bind is `<job-sandbox> <job-sandbox>`, so the
> refusal is a misconfiguration guard, not an exposure. And §1.3 had omitted the
> two invariants the implementation needed: the ids must be single ordinary path
> components, and each level of the path is canonicalised and checked **before**
> the level below it is created. The ordering is the one that mattered — the
> first implementation checked containment *after* `create_dir_all`, so a task
> id of `..`, an absolute id, or a symlink at the task level created directories
> outside the root before the refusal. Fail-closed was not enough: the job never
> ran, but the filesystem side effect had already happened.
>
> **Revision 5, corrected after the second Task 3 review.** Four corrections:
> (1) §1.3 no longer calls the remaining cases "harmless" — the move residual
> creates an empty directory outside the root, measured, and the swap-after-return
> case is not a residual at all: it is closed by `--bind-fd`, verified, and owned
> by Task 5 Step 6; (2) the grant rule in §4 is extended to **ancestors** of the
> root, and given an owner (Task 8 Step 3b) instead of living in prose alone;
> (3) the root path being re-resolved per call is recorded next to it, because
> write access to the root's *parent* is enough to swap the root; (4) the root and
> every level are opened `O_PATH`, so a writable-but-unreadable root or level
> works — the read-only open had regressed that.
>
> **Revision 4, corrected after the Task 3 review.** Five more corrections, all
> of them to claims rather than to the boundary. The id rule said "containing no
> separator" while `Path::components()` resolves a trailing `/` and `/.` away, so
> the section now says what the code does — the *normalised* component is joined —
> and control characters are refused at validation rather than only escaped in
> messages. The `config.toml` guard is replaced by app-created home markers,
> because it refused every shell job in a project workspace that has one. The
> ordering claim was still too strong: "refused before anything is created" is
> false against a concurrent writer, measured at 1472 of 8246 refusals, so
> creation is now descriptor-relative and the two remaining cases are named
> rather than denied — one of which makes "no write grant may cover the sandbox
> root" a precondition rather than a remark. And the section now records the
> bind-mount bound and that containment is a component test, not a string-prefix
> one.

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
- **The three `/etc` files for name resolution are never gated** — no grant is
  needed to read them, because DNS resolution is a read. They are not *always
  bound*, though: like the certificate paths they are bound only if present,
  since bwrap aborts with exit 1 on a `--ro-bind` whose source does not exist,
  and binding unconditionally would break every shell job on a host lacking
  `/etc/resolv.conf`. Without them a job cannot resolve a hostname at all;
  measured, `getent hosts example.com` resolves correctly with them and fails
  without.

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

The job sandbox is the **only read-write bind in the argv that is derived from
the sandbox root** — a write grant adds binds of its own, but they are
operator-named and independent of it — which makes it the critical part of the
boundary. It is resolved as:

```
sandbox_root = canonicalize(configured sandbox root)?
job_sandbox  = sandbox_root / <task-id> / <job-id>
```

with these invariants, each a hard failure rather than a warning:

- `<task-id>` and `<job-id>` are each **one ordinary path component**: not
  empty, not `.` or `..`, not absolute, and containing no separator. They are
  joined onto the root, and `Path::join` lets an absolute argument replace the
  whole path while `..` walks out of it, so an id of any other shape moves the
  job directory out of the root. They are refused **before the first filesystem
  call**, which removes the traversal class outright instead of detecting it
  after it has already happened. What is joined is the component the id
  *normalises* to, never the raw string: `Path::components()` resolves a trailing
  `/` and `/.` away, so `a/` and `a/.` are the aliases of `a` that they are, and
  the path built is exactly the one above with no separator left in either id.
  An id containing a **control character** is refused too — ids are UUIDs, so a
  newline in one is only ever an attempt to forge a line in a log or an error
  message — which closes that at the source rather than relying on the escaping
  of the message;
- the resolved path is absolute;
- it is **not** `/`;
- it is a strict descendant of `sandbox_root` (after canonicalisation, so
  `..` and symlink tricks are already resolved) — strictly below it, never
  equal to it, so the job can never write at the root itself. Containment is a
  **path-component** test and not a string-prefix one: `/…/ws-evil` starts with
  `/…/ws` as a string and is outside it;
- the resolved path is **what it names** — `<sandbox_root>/<task-id>/<job-id>`
  — so a level that canonicalises to something other than itself is refused. An
  in-root symlink passes containment, since it resolves to a directory inside
  the root, and still breaks this: two ids symlinked to one directory would
  share one sandbox, which is what per-job directories exist to prevent;
- `sandbox_root` is not `/`, and `sandbox_root` does **not directly hold** a
  file this application creates in its own home directory: `haos-green.db` or
  `web-auth.toml`. The default root is `<home>/workspace` and the job directory
  is `<home>/workspace/<task-id>/<job-id>`, so an operator who points the root
  at `<home>` itself is refused — the realistic mistake, because the home layout
  puts `workspace/` beside those files.

  This is refused as a **misconfiguration**, not as an exposure. The only
  read-write bind derived from the sandbox root is the job directory, so a root
  one level too high does not by itself hand the job the credentials; an earlier
  revision of this section claimed it did, and that overstatement is exactly how
  a later reader concludes the check guards something it does not. It is worth
  refusing anyway, because a root one level too high is a mistake no one should
  make silently, and because every later `/allow <path>` grant is drawn from the
  operator's picture of where the sandbox lives.

  The markers are deliberately app-created names, and deliberately **not
  `config.toml`**. Revision 3 keyed the guard on `config.toml`, which refuses
  every shell job in any project workspace that has one — a Rust or Python
  project has one — and reports the denial as a *security* refusal. A control
  that can only break the feature is worse than the narrow one it replaces. The
  rule is also about what the root **directly holds**, not about `config.toml`
  anywhere below it: an "is not an ancestor of `config.toml`" rule refuses almost
  every plausible root, since `/home/user` is an ancestor of
  `/home/user/.haos-green/config.toml` and so is every directory above any home
  that holds one. A rule that refuses everything usable is a rule that gets
  worked around.

  The guard is a heuristic and it fails **open**: a home whose database is pinned
  elsewhere by `config.toml` has neither marker, and no refusal fires. That is
  the right direction for this one — the boundary does not rest on it, and a
  false refusal here stops every shell job;
- the directory is created if absent, and **each level is created relative to a
  descriptor for the level above it, opened `O_PATH | O_DIRECTORY | O_NOFOLLOW`,
  then canonicalised and checked before the level below it is attempted. All three
  flags are load-bearing, and each was shown by mutation to be:
  `O_NOFOLLOW` — without it a symlink swapped in just before the open becomes the
  parent descriptor for the level below, and that level is then created on the far
  side of it (measured as a failing concurrent test); `O_DIRECTORY` — without it a
  symlink is opened as a descriptor **for the symlink** (`O_PATH` with
  `O_NOFOLLOW` and no `O_DIRECTORY` is the "open the link itself" form, not a
  refusal) and a FIFO is accepted as a level, so the refusal arrives one level
  down and names the wrong path; `O_PATH` — without it a root that is writable and
  traversable but not readable (mode 0333) is refused with `Permission denied`,
  which the read-only open did. `O_PATH` also means an open can no longer block on
  a FIFO at all, so `O_DIRECTORY`'s role there is correctness rather than the
  liveness guard it was before. A pre-existing
  symlink is refused with nothing written through it, which is also the
  CVE-2026-87766 precondition. Order is part of the invariant, not an
  implementation detail: a check that runs *after* the directory has been created
  is not containment.

  Against a filesystem that is not being modified underneath the call, a path
  that is going to be refused **by this containment check** is refused before
  anything is created. That scope is the whole claim, and it is narrower than it
  reads: the check lives in `resolve_job_dir`, and a job refused *later* — by
  Layer 2's grant refusal in `ShellBackend::run`, which runs after
  `resolve_job_dir` has returned — has already had its
  `<root>/<task-id>/<job-id>` directory created. A refused job gains nothing from
  an empty directory, so this is a documentation correction and not a defect, but
  "refused before anything is created" does not hold for that path. A
  **concurrent** writer is a different claim, and revisions 3 and 4 stated a
  stronger one than the code could deliver: with creation by path, a writer
  looping on the swap of `<root>/<task-id>` got a directory created outside the
  root — measured at **1472 of 8246 refusals over 15 s** of swapping, first hit
  after 4 refusals. Creating each level with `mkdirat` on the descriptor of the
  verified level above it removes that: the level below is created inside the
  directory the descriptor names, or not at all, and the module's concurrent test
  fails against the path-based form.

  Two cases remain, both needing a local writer with write access to the root.
  Neither is harmless, and saying so is the point of this paragraph:

  - a writer that **moves** the verified directory outside the root gets the next
    level created *inside it*, because a descriptor follows the inode and not the
    name. The call still fails closed — it refuses, and never *returns* a path
    outside the root, so nothing is mounted from there — but an **empty directory
    is created outside the root**. Pinned deterministically by
    `the_move_residual_creates_a_directory_outside_the_root_and_is_refused`, which
    swaps the move in between the two levels instead of racing a thread for it;
    measured with an adversarial mover over 20000 calls: 16462 destinations gained
    a `job-1` after the move, 19242 calls were refused, 758 succeeded, and **0**
    returned a path outside the root. Revision 3's rule — "a refusal that leaves
    directories behind is not a refusal" — is about what is reachable through the
    mount, and on that measure this is still a refusal; the directory is created
    all the same, so it is stated as a cost rather than waved away. The writer
    needs write access to both ends to move the directory, so it gains no
    privilege it did not already have;
  - a writer that swaps a level *after* this function returns, but before
    bubblewrap opens the path in the argv, defeats the **mount**: the returned
    path is not what gets mounted, bubblewrap resolves it again when it runs.
    Verified rather than assumed — with `<root>/task-1` replaced by a symlink to
    `<elsewhere>` after the call, `bwrap --bind <root>/task-1/job-1 <dest>` mounts
    `<elsewhere>/job-1` as the job's read-write directory, and the probe read the
    other directory's file through the mount. This one is **not** a documented
    residual: it is closed in the argv by handing bubblewrap the **descriptor**
    instead of the path. `bwrap --bind-fd <fd> <dest>` binds the inode the
    descriptor names — verified by renaming the directory away and putting a
    symlink in its place, after which the fd-based bind still read the original
    directory's file while the path-based bind read the symlink's target. Task 5
    Step 6 owns that change, and it is the reason the job directory has to be
    more than a `PathBuf`.

  Because both are reachable by a *job* when a grant covers the root, **no write
  grant may cover the sandbox root or any ancestor of it** — see §4 for the rule
  and Task 8 Step 3b for the step that enforces it. The default root is the same
  directory the chat agent's shell tool uses as its working directory, so the
  precondition is load-bearing rather than theoretical. The root **path** is also
  re-resolved on every call, so write access to the root's *parent* is enough to
  swap `<root>` for a symlink between the canonicalise and the open — measured at
  73 of 4000 calls returning a job directory under the swap target. The ancestor
  rule covers that case too, because an ancestor grant is a grant on the parent.

  Bound: a **bind mount** at any level defeats these checks, because a mountpoint
  is in-root *as a path* and `canonicalize` cannot see the difference —
  `mount --bind <elsewhere> <root>/task-1` resolves to `<root>/task-1/job-1`
  while the directory is created on `<elsewhere>`. It needs mount privilege, and
  a `st_dev` comparison would catch only the cross-device case, so it is recorded
  here rather than guarded by a check that would not hold.

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

> **A grant must not cover the sandbox root, or any ancestor of it.** The job
> directory is resolved before the job starts, and the checks that resolve it
> assume no *job* can write the levels it walks: with write access to the root, a
> job can plant a symlink that a later job's setup follows. Creating each level on
> a descriptor rather than a path removes the directory-creation half of that
> (§1.3); the mount half is closed by passing the descriptor to bubblewrap
> (`--bind-fd`, §1.3 and Task 5 Step 6); and what remains — the move residual — is
> kept out of a job's reach by this rule.
>
> **Ancestors, not just the root.** A grant of `<home>` covers `<home>/workspace`
> as surely as a grant of `<home>/workspace` does, and the root path is
> re-resolved on every call, so a writable *parent* is enough to swap the root
> itself (§1.3). The test is one line: refuse the grant when
> `sandbox_root.starts_with(granted)`. A grant *inside* the root is not refused by
> this rule — it does not cover the root — and the exact-path matching above means
> it cannot reach the root's own levels either.
>
> `/allow <root>` is grantable in the code as it stands, so this is a rule the
> grant layer has to enforce, not a property it already has: **Task 8 Step 3b** is
> the step that adds the refusal, with the test and the mutant that show it works.
> A rule that lives only in a spec paragraph is a rule nobody implements.

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
- the sandbox directory is writable, and `--chdir` took effect. The probe pins
  its cwd to **`/`** — a path that is present inside the sandbox and is not the
  job directory. **Pinning a cwd *outside* the sandbox is wrong and disables the
  check**: `bwrap(1)` uses `HOME` as the cwd when `--chdir` is absent *and the
  current cwd is not present inside the sandbox*, and this argv sets `HOME` to
  the job directory and binds it — so an unbound pinned cwd makes bwrap fall back
  to the job directory, with or without `--chdir`. Measured against the real
  binary: with an unbound pinned cwd, removing `--chdir` left `probe()` returning
  `Ok(())`; with the cwd pinned to `/`, the same mutation fails with
  `expected pwd=<job>, got Some("/")`. Isolated rule, measured: cwd `/` →
  preserved; cwd unbound + `HOME` bound → job directory; cwd unbound + `HOME`
  unbound → `/`. Because this rests on a documented fallback that a future
  bubblewrap could change, a **static** argv assertion backs it up: `--chdir
  <job_dir>` must sit immediately before `/bin/sh`;
- `hostname` is `haos-sandbox`;
- `/etc/passwd` is not readable, and `/etc/shadow` does not exist;
- **the CA bundle is readable inside the sandbox**, network-free:
  `[ -r /etc/ssl/certs/ca-certificates.crt ]`, guarded by the same
  `exists()` rule the argv binds with, so a host without the path skips the check
  rather than demanding it. This is the check that has teeth and it needs no
  network: with both binds the bundle resolves to
  `/etc/ca-certificates/extracted/tls-ca-bundle.pem`; with **only**
  `/etc/ssl/certs` bound it is unreadable — the dangling-symlink state that
  produces `curl: (77)`;
- **HTTPS works end-to-end, but only when the network grant is held.** A request
  to an HTTPS endpoint succeeds under a grant (measured `http=200`, and
  `openssl s_client` reporting `Verify return code: 0 (ok)`) and, with only
  `/etc/ssl/certs` bound, fails with `curl: (77) error adding trust anchors`.
  **The check must not run unconditionally.** Revision 3 gates `--share-net` on
  the network grant, so with the shipped empty grant set the sandbox has `lo` and
  nothing else, and an unconditional HTTPS check reports
  `SmokeTestFailed("curl: (6) Could not resolve host")` for every operator who has
  not typed `/allow-net` — failing the probe, and refusing shell jobs, on a
  sandbox that is working correctly. Revision 2 could assert it unconditionally
  only because `host_network = true` made `--share-net` always present; revision
  3 removed that assumption, so the check is conditioned on the grant and the
  network-free bundle check above carries the certificate guarantee;
- a TCP connect to the host's loopback **fails** unless the network grant is
  held, and **succeeds** when it is — the probe asserts the behaviour of the
  grant set actually in force, so both states are covered rather than assuming
  the default;
- creating a nested user namespace fails (proves `--disable-userns` actually took
  effect on this kernel).

> **What the probe cannot detect, stated rather than implied.** Removing
> `--assert-userns-disabled` while `--disable-userns` remains is **not**
> observable at runtime: with `--disable-userns` present the behaviour is
> identical, because the flag verifies rather than acts. The probe therefore does
> not guard it, and a mutation removing only that flag will survive. It is kept
> for the failure mode where `--disable-userns` silently does *not* take effect,
> which is what it exists to catch.
>
> **The three resolver files are bound but inert without the network grant.**
> `getent hosts example.com` fails with `resolv.conf`, `hosts` and
> `nsswitch.conf` all bound and no `--share-net`, because there is no route to a
> resolver. They are bound regardless of the grant because a network grant can be
> issued at any time and re-building the argv per grant is not worth it — but the
> binding alone does not make name resolution work, and no check should assume it
> does.

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
- remove the two certificate binds → the network-free bundle check must fail
  (`bundle_readable=no`), and the end-to-end HTTPS check under a network grant
  must fail with `(77)`
- bind `/etc/ssl/certs` **without** `/etc/ca-certificates` → both must still
  fail, which is what proves the second bind is load-bearing rather than
  redundant. This is the mutation that matters, because a check that only ever
  sees the working configuration cannot tell the two binds apart
- remove `--chdir` with the probe's cwd pinned to `/` → the cwd check must catch
  it. **This mutation only has teeth with the cwd pinned inside the sandbox**:
  with an unbound pinned cwd it survives, because bwrap falls back to `HOME`,
  which is the job directory
- run the end-to-end HTTPS check with **no** network grant → it must be skipped,
  not failed. A probe that demands HTTPS without a grant refuses shell jobs on a
  correct sandbox
- grant a path read-write, then `/deny` it → the write must be refused again
- grant `/var/lib` and attempt to write `/var/lib/docker/x` → refused, proving a
  grant covers exactly the named path and not its children
- spawn `bwrap` with its cwd already inside the job directory and remove
  `--chdir` → this mutation **survives by design** and is recorded as a known
  limit rather than a passing check; see the `--chdir` bullet above for why an
  unbound pinned cwd cannot detect it
- **the loopback escape path must be demonstrated, not assumed**: with the
  dashboard enabled, the default password unchanged, and the network grant held,
  a sandboxed job must be shown to reach `/api/auth/login` and obtain a session.
  This test asserts the *accepted risk*, so that removing the risk fails the test
  and forces the spec to be updated rather than silently drifting.
- remove `--hostname` → the host's hostname must be visible
- set the sandbox root to `/` → config load must refuse
- **grant a path that covers the sandbox root, or any ancestor of it** → the
  grant must be refused. Mutating the rule's `root.starts_with(granted)` to
  `root == granted` must let the ancestor cases through (`/allow <home>` accepted
  while `<home>/workspace` is the root) and leave the two legitimate grants —
  a sibling of the root and a path inside it — passing. Task 8 Step 3b owns this;
  it is the only thing keeping a job from writing the levels `resolve_job_dir`
  walks
- drop `O_PATH` from the two opens → a root or level that is writable and
  traversable but not readable (mode 0333) must be refused with
  `cannot open the sandbox root …: Permission denied`, which is what the read-only
  open did. **Only observable as a non-root user** — the kernel bypasses the
  permission bits for root, so this mutation survives a root run and fails a
  uid-1000 run, which is how it is measured
- drop `O_DIRECTORY` → a FIFO at a level must no longer be refused *at that
  level*: the open succeeds and the error names `…/task-1/job-1` instead, and a
  symlinked level is opened as a descriptor for the symlink rather than refused
- drop `O_NOFOLLOW` from the level open → a symlinked level is followed, so the
  open succeeds and returns a descriptor for the symlink's target
- drop `O_CLOEXEC` → under the fixed design this is **not** the inheritance
  mechanism and the mutation is caught differently: inheritance comes from the
  child-side clear in `SandboxArgv::command`'s `pre_exec`, so dropping
  `O_CLOEXEC` means the *original* descriptor is inherited by every unrelated
  child of the supervisor — a C1-class defect, not a way to make the job work.
  The assertion that catches it is
  `fd_flags(jd.fd.as_raw_fd()) & FD_CLOEXEC != 0` in the job-directory test
- compare containment as **text** rather than as path components → the sibling
  case (`/…/ws-evil` beside `/…/ws`) must be refused as `OutsideRoot` and is
  instead refused as `NotItself`, which the clause assertion catches even though
  the refusal still happens
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
