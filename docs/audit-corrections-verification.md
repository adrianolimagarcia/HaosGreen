# Audit correction verification and operational limits

## Verification status
Fresh local gates passed on the current production snapshot: `cargo fmt --all -- --check`, `cargo check --all-targets --locked`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --all-targets --locked`, and `cargo build --release --locked`. Library: 1094 passed, 1 ignored; all executed integration suites passed (web: 91 passed, 1 ignored). Live credential/environment-dependent tests remained ignored. Initial Clippy failure in two new socket fixtures was corrected by asserting nonzero reads, then gates reran successfully. Dependency `proc-macro-error2` emits a future-incompatibility notice.

Real Agent entry-point regressions in `tests/runtime_wiring.rs` now pass (5/5), with fresh formatting and all-target Clippy checks: runtime model switch, deterministic pre-attachment snapshot/vision consistency, verifier dispatch, exact remote allowlist denial, and independently absent remote dispatch handler. Inference is fake; context-window/compaction coherence, bundled skill bootstrap and live model behavior are not independently asserted. Directed isolated mutation checks remain in progress.

Local static checks: all four workflow YAML files parse with PyYAML; four explicitly Bash steps pass `bash -n`. This is syntax validation, not GitHub runner execution. README no longer recommends the removed autonomy setting; historical design/plan documents retain their original references and are not current config examples.

## External administration
`gh api repos/adrianolimagarcia/HaosGreen/branches/main/protection` returned HTTP 404 `Branch not protected`. Required checks should include Check, Format, Clippy, Test, and Build after those workflows successfully run. Remote repository settings have not been changed.

## Review findings being closed
- Scheduler review found stale queued cancellation, terminal writes overwriting cancellation, and active-before-registration races. Persisted generation fencing and explicit registration eligibility are being implemented; initial scoped tests do not prove these races.
- Routing review found two active-model reads (vision vs request), unsafe text-based fallback classification and Kimi malformed JSON coercion. Production fixes and real Agent entry-point tests are in progress.
- MCP review found startup connect failures missing the retry queue and weak same-credential snapshot-retention assertions; both were returned to the implementer.
- Migration review requested propagation of vector-schema inspection errors as well as ALTER errors. Independent re-review confirms those errors propagate and tests assert schema metadata and legacy message/prompt preservation; scoped worker runs passed, final full gates pending.

## Residual security and performance limits
- A2A source allowlists use the directly connected socket IP. Behind a reverse proxy this is the proxy IP, not the original peer. Do not trust arbitrary Forwarded/X-Forwarded-For headers; direct private-network deployment or an explicitly trusted proxy design is needed for peer-IP enforcement.
- Unix O_NOFOLLOW hardening is not an equivalent Windows reparse-point-safe guarantee. Windows deployments with untrusted workspace contents require additional platform hardening.
- MCP deadlines are currently fixed constants (30s connect/OAuth; 60s tool call), not configuration knobs. Serial server refresh/reconnect may extend polling cycles beyond 60s when several servers stall. Timeout abandons an in-flight remote call; it does not guarantee cancellation of remote side effects. rmcp stdio drop performs asynchronous direct-child cleanup, not verified process-tree termination.
- No SQLite pool or provider dependency consolidation is justified without workload measurements. Preserve WAL, existing security boundaries, and compatibility.
- Linux-local verification cannot certify macOS/Windows release architectures; the release workflow now installs its explicit target, checks binary architecture, runs a credential-free CLI usage smoke path and produces archive SHA256 sidecars. These matrix steps have not yet been executed on GitHub runners.
