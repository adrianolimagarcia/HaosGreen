# Shell Backend Isolation Design

## Objective

Make the supervisor's `ShellBackend` containment **real**. Today it runs the
operator's task text as a shell command with no containment at all, behind a
three-substring check that `sh` semantics defeat. After this work a shell job
runs inside a bubblewrap sandbox that cannot see the host's home directory,
`/etc`, or the supervisor's environment — and when that sandbox is unavailable
the operator is **asked**, not silently obeyed.

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
job.

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
   would turn this into remote shell with no second line of defence.

## Constraints

- Never run a shell job unisolated without an explicit operator decision.
- The consent must be revocable and must not survive a process restart.
- Preserve `Route -> Execute` and `/approve`: the state machine gains no state.
- Keep the default configuration safe for an operator who changes nothing.
- A host without bubblewrap must remain usable, but only with consent.
- Do not widen what any A2A peer can reach.
- Every containment property needs a mutation proving the test has teeth.
- Never commit `config.toml`, `.env`, `.measure/`, or generated artifacts.

## Verified environment facts

Measured on the development host (CachyOS, kernel 7.2.4-3-cachyos,
`bwrap` at `/usr/bin/bwrap`, `max_user_namespaces = 125706`). These are observed
results, not assumptions, and the implementation depends on them.

| Probe | Observed |
|---|---|
| `bwrap --unshare-all … /bin/sh -c 'id -u'` | `uid=0` inside the userns, no root outside |
| `$HOME` reachable inside? | **No** — the path does not exist in the namespace |
| `/etc/passwd` inside? | **No** — `No such file or directory` |
| Sandbox dir bound at its **real** path | visible, writable, absolute paths keep working |
| `--clearenv` | exported variables are **empty** inside |
| `--unshare-all` | only `lo` in `/proc/net/dev`; TCP to a local port refused |
| `--unshare-all --share-net` | `lo enp2s0 wlan0 tailscale0 virbr0`; real TCP succeeds |
| `cat /etc/hostname` inside | `No such file or directory` — the original attack fails |
| DNS without `/etc` | resolved — mechanism **not** explained, so not relied upon |
| `--ro-bind` of `resolv.conf` + `nsswitch.conf` + `hosts` | DNS resolves; `/etc/passwd` and `/etc/shadow` stay invisible |

The DNS row is the reason the design binds a named file set rather than relying
on the resolver's fallback: an unexplained behaviour must not become a load-
bearing assumption. Note `/etc/resolv.conf` is a symlink to
`/run/systemd/resolve/stub-resolv.conf` on the host, and the bind follows it.

## Architecture

### 1. A new unit: `src/supervisor/backend/sandbox.rs`

One responsibility — decide how a command is isolated and build the invocation —
kept out of `ShellBackend`, which stays about running jobs. This makes the
policy testable without a backend, and keeps the containment contract readable
in one place.

```rust
pub enum SandboxMode { Bwrap, None }

pub struct Sandbox {
    mode: SandboxMode,
    network: bool,
    bwrap: Option<PathBuf>,   // None when the probe failed
}

impl Sandbox {
    /// Probe once: `bwrap --version` **and** a functional smoke test.
    pub fn probe(mode: SandboxMode, network: bool) -> Sandbox;
    pub fn isolation_available(&self) -> bool;
    pub fn command(&self, cmd: &str, dir: &Path) -> Command;
}
```

`probe` must run a real `bwrap … /bin/sh -c true`, because *present is not the
same as working*: user namespaces can be disabled by sysctl or by a container
policy, and `bwrap --version` would still succeed. The result is computed once
at startup and cached.

### 2. The containment contract

Exact argv for an isolated job:

```
bwrap --unshare-all [--share-net] --die-with-parent --clearenv
      --ro-bind /usr /usr
      --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64
      --proc /proc --dev /dev --tmpfs /tmp
      --ro-bind <resolv.conf> <resolv.conf>     # only when network = true and the file exists
      --ro-bind <nsswitch.conf> <nsswitch.conf>
      --ro-bind <hosts> <hosts>
      --bind <sandbox> <sandbox>
      --chdir <sandbox>
      --setenv HOME <sandbox>
      --setenv PATH /usr/bin:/bin
      /bin/sh -c <cmd>
```

`--share-net` is added only when `network = true`; `--unshare-all` otherwise
stands alone, which is what removes networking. `--die-with-parent` ties the
sandbox to the supervisor so a lease-lost abort cannot leave it behind.

The sandbox directory is bound at its **real** path rather than a `/work`
alias, so a command that already refers to an absolute path inside the sandbox
keeps working. The trade is that the namespace still needs the parent path to
exist; `bwrap` creates it.

### 3. Fail-closed in two layers

**Layer 1 — before anything runs.** Classification already determines whether a
task routes to the shell backend. When isolation is unavailable and no consent
has been granted, the task is routed to `RequireApproval` and parks in `Route`.
This reuses the existing machinery: `Route -> Execute` is already a legal edge
and `/approve` already takes it, so the state machine is unchanged.

This layer exists only in `sandbox = "bwrap"`. With `sandbox = "none"` the
operator has already decided, so nothing is gated and nothing is asked — the
mode is the standing consent.

The predicate must **not** be a second copy of the routing logic, or the gate
and the executor will drift apart. It is computed by planning the task
(`Planner::new().plan(&task)`) and asking the registry which backend each job
resolves to, through the same selection the orchestrator uses.

**Layer 2 — at the job.** If a shell job reaches `ShellBackend` without
isolation and without consent, it **refuses**: the job fails with a named error
and no process is spawned. This is the backstop that makes "the pipeline never
runs unisolated in silence" true regardless of how it got there.

### 4. The consent

A process-scoped, in-memory grant — `Arc<AtomicBool>` shared between the
`Supervisor` (which gates and grants) and the `ShellBackend` (which enforces).
`main.rs` creates it and hands it to both.

- Granted by `/approve <id>` on a task parked for this reason, or by the
  dashboard's approve button; the grant takes effect for the rest of the
  process, so later tasks do not ask again.
- Recorded in `sup_transitions`: the reason names that the operator consented to
  running without isolation, so the audit trail shows it.
- Revoked by a new `/unsafe-shell off` command and its dashboard equivalent,
  and unconditionally by a restart. The restart-revokes property matches the
  dashboard's existing session model.

### 5. Configuration

```toml
[supervisor.shell]
sandbox = "bwrap"   # "bwrap" (default) | "none"
network = true      # inside the sandbox; false removes networking entirely
```

`"none"` is the explicit, documented opt-out for a host that cannot run
bubblewrap and whose operator accepts the risk; it logs a startup warning and
never asks. Any other value is refused at load, so a typo cannot silently
disable isolation.

`network` applies only to sandboxed jobs: with `sandbox = "none"` there is no
namespace and therefore nothing to restrict, so the key is ignored rather than
implying a protection it cannot provide.

## Error handling

- The probe failing is not fatal to startup: the supervisor still runs, the
  reason is logged once, and shell tasks park for approval instead.
- A refused job returns `JobStatus::Failed` with an error naming the missing
  isolation, and spawns nothing.
- A missing `resolv.conf`/`nsswitch.conf`/`hosts` degrades name resolution but
  must never fail open on isolation — the file set is best-effort, the
  namespace is not.
- A non-zero `bwrap` exit is reported as the job's failure with its stderr, the
  same way a failing command is today.

## Testing and verification

- **Isolation proofs (real `bwrap`, integration).** A job that reads a file
  outside the sandbox fails and its output does not contain the secret. `$HOME`
  and `/etc/passwd` are unreachable. The sandbox directory stays writable. The
  network matches `network`: a TCP attempt succeeds with `true` and fails with
  `false`.
- **Environment proof.** A variable exported into the test process is **not**
  visible to a sandboxed job.
- **Fail-closed proofs.** With the probe forced to fail, a shell task parks in
  `Route`; no job row reports success; after consent it runs and the audit row
  records the consent; after `/unsafe-shell off` it parks again.
- **Mutations, each with observed output, in a `/tmp` copy with its own
  `CARGO_TARGET_DIR`:** removing `--unshare-all` must make the escape test fail;
  removing `--clearenv` must make the environment test fail; removing the
  sandbox `--bind` must make the writable-sandbox test fail; removing the
  Layer-2 refusal must make the fail-closed test fail.
- **Absence handling.** If `bwrap` is genuinely unavailable, the isolation tests
  skip with a loud reason rather than passing silently, and the fail-closed
  tests still run — they are the ones that must hold on such a host.
- Full gates before commit: `cargo fmt --all -- --check`,
  `cargo clippy --all-targets -- -D warnings`, `cargo test`.

## Documentation corrections

- `CLAUDE.md:208` — the claim that command operations are contained by
  `validate_sandbox_path()` is false for this path; replace it with the actual
  contract and name the paths it does and does not cover.
- `shell.rs:19` — remove the TODO; the new comment states that `validate()` is a
  heuristic, not containment, and points at the sandbox for the real boundary.
- `CLAUDE.md` Supervisor section — document `[supervisor.shell]`, the consent
  model, its session scope, and the revoke command.
- `config.example.toml` — add the `[supervisor.shell]` keys.

## Non-goals

- No seccomp, no container runtime, no root, no `chroot`.
- No new state in the supervisor state machine.
- No change to how tasks are classified or routed to the shell backend. The
  shell backend still runs the task text as a command; isolation bounds the
  damage, it does not make natural-language-as-shell sensible. Removing that
  route is a separate decision.
- No sandboxing of `claude_code`, `codex`, or `script`. They spawn processes
  too, but none is registered in production (`main.rs` registers only reasoning
  and shell), so they are a follow-up rather than part of this change.

## Delivery sequence

1. `sandbox.rs` with the probe and the argv builder, plus unit tests for the
   argument construction.
2. Wire the sandbox into `ShellBackend` and prove isolation with real-bwrap
   tests, including the mutation round.
3. Add the config keys and the startup probe/warning.
4. Add the Layer-1 route-time gate and the Layer-2 refusal.
5. Add the consent, its audit row, `/approve` integration, and
   `/unsafe-shell off` plus the dashboard equivalent.
6. Correct the documentation, then run the full gates.
