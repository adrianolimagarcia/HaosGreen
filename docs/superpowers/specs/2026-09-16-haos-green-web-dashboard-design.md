# HaosGreen Web Dashboard — Design Spec

**Status:** Approved for planning (operator decisions recorded below)
**Date:** 2026-09-16
**Supersedes:** nothing. Extends the existing embedded setup wizard.

---

## 1. Goal

Ship a complete operational web dashboard embedded in the `haos-green` binary,
served by Axum on its own listener, covering four surfaces:

1. **Chat** — talk to the same agent the Telegram bot uses, with streaming.
2. **Supervisor** — inspect and control autonomous tasks.
3. **Logs** — live view of structured tracing events.
4. **A2A** — listener status, inbound/outbound peers, connection testing.

The dashboard is a second front door to a process that already has shell
execution. Every design decision below is subordinate to that fact.

---

## 2. Operator decisions (binding)

These were chosen explicitly by the operator and are recorded so that future
readers do not mistake them for oversights:

| Decision | Choice | Consequence accepted |
|---|---|---|
| Authentication | Username + password, default `admin`/`admin` | A reachable dashboard with an unchanged password is fully open to anyone who can reach the port |
| Forced password change | **Disabled** | The default password stays usable indefinitely; the dashboard cannot rely on a first-login gate |
| Bearer token | Optional, toggleable from settings | Off by default; when on, grants API access without a session |
| IP allowlist | Configurable from settings, supports single IPs and CIDR ranges | Empty list means any source IP may attempt login |
| Chat privilege | Same agent, same full tool set as the Telegram operator | Anyone authenticated gets `execute_command` on the host |
| Frontend | Vanilla HTML/CSS/JS embedded via `include_str!` | No build step, no npm, no CDN |
| Supervisor listing | `list_recent(limit)` with a hard cap of 20 | Older tasks are reachable only by direct id |

### 2.1 Compensating controls for the accepted risk

Because forced change is disabled, the following are **mandatory** and are not
optional features:

- Default bind is `127.0.0.1`. Exposing the dashboard requires an explicit
  `bind` change, and a non-loopback bind logs a startup warning.
- Login is rate limited per source IP: the first five failures are answered
  `401`, the sixth starts a 5 s lockout that doubles on every further failure
  and saturates at the 300 s window (§4.5). A successful login clears it.
- Every request must carry a `Host` header naming this dashboard, and every
  response carries a restrictive CSP and `X-Frame-Options: DENY` (§4.5.1).
- A persistent, non-dismissible banner is shown in the UI while the password
  equals the default.
- A warning is logged at every startup while the password equals the default.
- The password can be changed from the settings page at any time.

The default-password check compares in constant time and never logs the value.

---

## 3. Architecture

### 3.1 Module layout

```
src/web/
  mod.rs           — WebConfig wiring, spawn(), router and layer assembly
  auth.rs          — Argon2id hashing, session store, bearer, IP allowlist,
                     login rate limiting, CSRF enforcement
  state.rs         — WebState: shared handles for all route modules
  logs.rs          — tracing Layer + bounded ring buffer
  routes/
    mod.rs
    chat.rs        — chat sessions and SSE streaming
    supervisor.rs  — task listing and lifecycle control
    logs.rs        — log stream and query
    a2a.rs         — listener status, peer inventory, connection test
    settings.rs    — password change, bearer toggle, IP allowlist CRUD
  assets/
    index.html
    app.js
    style.css
```

Assets are embedded with `include_str!`, following the existing pattern at
`src/setup/wizard.rs:25`. No build step, no npm, no CDN — the binary stays
self-contained and reproducible.

### 3.2 Why a new module rather than extending the setup wizard

The setup wizard runs as a one-shot process (`haos-green --setup`) that exits
after saving config. The dashboard is a long-lived operational surface with
authentication, streaming, and mutable state. Merging them would give the
wizard a live shell and give the dashboard setup-time lifecycle assumptions.
They share nothing but the Axum dependency.

### 3.3 Startup wiring

`src/main.rs` spawns the dashboard next to the existing A2A listener
(`src/main.rs:468-501`), reusing the `Agent`, `MemoryStore` connection, and
`Supervisor` already constructed there. A dashboard failure must never take the
Telegram bot down — the same rule the A2A listener already follows: log the
error, continue.

### 3.4 Dependencies

One new crate: `argon2 = "0.5"` for Argon2id password hashing. The repository
currently has only `sha2` and `subtle`; neither is a password KDF, and
hand-rolling one is not acceptable. `ipnet` (already a dependency) provides
CIDR matching. No other new dependency.

---

## 4. Authentication and security

### 4.1 Credential storage

Password hashes live in `<home>/web-auth.toml`, mode `0600`, **outside**
`config.toml`. That file also holds the optional bearer token and its enabled
flag. Keeping secrets out of `config.toml` matters because `config.toml` is the
file that documentation, tooling, and users copy around.

```toml
# <home>/web-auth.toml
password_hash = "$argon2id$v=19$m=19456,t=2,p=1$..."
bearer_enabled = false
bearer_token_hash = ""   # only a hash is stored; the token is shown once
```

The bearer token is generated with a CSPRNG, displayed exactly once at
generation time, and thereafter only verifiable — never recoverable. The UI
shows a fingerprint, never the value.

### 4.2 Sessions

- Session id: 256 bits from a CSPRNG.
- Server-side store with TTL (`session_ttl_hours`, default 12).
- Cookie: `HttpOnly; SameSite=Strict; Path=/`, plus `Secure` when `public_url`
  is https. An unset `public_url` means **no** `Secure` flag — the bound
  address cannot settle whether the deployment is https (the same loopback
  listener is https behind a TLS proxy and plain HTTP without one), so an https
  deployment must set `public_url`.
- Logout removes the session server-side; expiry is enforced on every request.

### 4.3 CSRF

`SameSite=Strict` alone is insufficient for a dashboard that mutates state, so
every mutating method additionally requires the header
`X-Haos-Green-CSRF: 1`. Requests missing it are rejected before any handler runs.

Header names are case-insensitive but hyphens are significant, so the spelling
is fixed by the server constant `web::middleware::CSRF_HEADER`
(`x-haos-green-csrf`) and every client must match it exactly. This follows the
existing A2A peer header convention (`x-haos-green-a2a-peer`).

### 4.4 IP allowlist

Accepts single addresses and CIDR ranges, parsed with `ipnet`. Semantics,
deliberately different from the A2A listener and documented in the UI:

- **Empty list** → any source IP may attempt login. The password is the gate.
- **Non-empty list** → strict enforcement, denied before authentication runs.

A2A fails closed on an empty list because it has no other credential. The
dashboard has a password, so an empty list is not a silent hole — but the UI
states the difference explicitly so an operator is never misled.

"Denied before authentication runs" covers **every** route, not only the
protected ones: `/api/auth/login` and the three static assets (`/`, `/app.js`,
`/style.css`) are each wrapped in the gate as a layer of their own, so a source
outside the list receives 403 and no body — not the login page, not the shell,
and not an extractor error describing the expected request shape. The gate also
runs **before bearer authentication**, so a valid bearer token presented from a
non-listed address is refused like any other request from that address.

Entries are matched by **address family**: `ipnet` never matches an IPv4 rule
against an IPv6 peer, and `IpGate::permits` makes that explicit for
IPv4-mapped addresses (`::ffff:10.0.0.1` does not match `10.0.0.0/8`). An
operator who lists only `::/0` and browses over IPv4 is locked out.

Changing the list from the dashboard is **in-memory only**: `PUT
/api/settings/allow-ips` replaces the live gate and does not rewrite
`config.toml`, so a restart restores the configured list. A list that excludes
the operator's own address locks them out until that restart.

#### 4.4.1 The reverse-proxy caveat

The gate keys on the **real socket peer address** (`ConnectInfo<SocketAddr>`),
never on `X-Forwarded-For` or any other client-supplied header — a header an
attacker can set is not an access control. The consequence is that behind a
TLS-terminating reverse proxy every client arrives from the proxy's address:

- the allowlist cannot distinguish one client from another; it either admits
  the proxy (and therefore everyone it serves) or refuses all of them;
- the login limiter has the same blind spot — see §4.5.

Running the dashboard behind a proxy therefore does not narrow access; the
password and the bearer token remain the only per-client controls. If the
proxy is the deployment model, treat the allowlist as a proxy-level control and
enforce it there instead.

### 4.5 Login rate limiting

Per source IP, keyed on the same real socket peer address as §4.4. The
implementation (`web::auth`), stated exactly:

- The first **five** failed attempts from one source are answered `401`.
- The **sixth** attempt is answered `429`: the lockout is 5 s, and it **doubles
  on every further failure** (10 s, 20 s, 40 s, 80 s, 160 s, …), saturating at
  the **300 s** lockout window from the eleventh failure onward. The check runs
  before the password is verified, so a locked-out source cannot spend Argon2
  work or probe passwords.
- The failure counter is cleared by a successful login, or by 300 s passing
  with no failures at all. Serving a lockout does **not** reset it — resetting
  would flatten the backoff into "five guesses every five seconds", which is
  weaker than a flat lockout.
- The limiter remembers at most 1024 distinct sources, evicting the least
  recently failed one, so varying the source cannot grow it without bound.
- Lockouts are logged, and the `429` body reports the remaining delay in
  seconds.

**Behind a reverse proxy every client shares one address**, so this limiter is
per *proxy*, not per client: five bad passwords from anyone lock out everyone,
including the operator. That is the price of keying on an address the client
cannot forge, and it is the reason §4.4.1 recommends enforcing the allowlist at
the proxy instead.

### 4.5.1 Host validation and response headers

Two controls apply to every response, on every route:

- **`Host` validation.** A request whose `Host` header is neither the
  configured `public_url` host nor the bound address (`localhost`,
  `127.0.0.1` and `[::1]` are accepted on the bound port) is refused with 403,
  including a request with no `Host` at all. This is the DNS-rebinding defence:
  the dashboard binds to loopback and ships with `admin`/`admin`, so an attacker
  page whose hostname re-resolves to `127.0.0.1` reaches it from the operator's
  own browser over loopback — where the allowlist sees nothing — and its
  JavaScript is same-origin with the rebound hostname, so the CSRF header is no
  obstacle. `Host` is derived from the URL and is the one thing the browser will
  not let that page forge.
- **Response headers.** `Content-Security-Policy: default-src 'self';
  frame-ancestors 'none'`, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`, on
  every response including 403s. The CSP is compatible with the shipped shell
  because it contains no inline script, style, or event-handler attribute.

A non-loopback `bind` without `public_url` logs a startup warning: the listener
answers only to the bound address and the loopback names, so a browser reaching
it by name is refused.

### 4.6 Chat privilege — stated plainly

The web chat reuses the same agent, the same tool registry, and therefore the
same capabilities as the Telegram operator, including `execute_command`. Any
authenticated user has shell execution on the host. This is intentional and
matches the product's existing model; it is the reason sections 4.1-4.5 exist.

### 4.7 Secret hygiene

Passwords, session ids, and bearer tokens are never logged. The log view
applies `supervisor::redact::redact` to every entry before display. The A2A
peer views render tokens redacted.

---

## 5. Data surfaces

### 5.1 Chat

Web sessions are isolated from Telegram conversations. Each session keeps its
own history and has its own cancel token.

```
POST /api/chat/sessions               → create session
GET  /api/chat/sessions               → list sessions
GET  /api/chat/sessions/{id}/messages → history
POST /api/chat/sessions/{id}/messages → send; responds with an SSE stream
```

Streaming reuses `Agent::run_with_policy_streaming_history`
(`src/agent.rs:1578`), passing prior user/assistant turns, a token channel
(`stream_token_tx`) that the SSE handler drains, and an explicit tool policy.

**Tool policy:** the operator gets the full tool set the loop would otherwise
offer, computed from the live sources rather than a hand-written list, which
would silently drift as tools are added.

> **Correction (verified against the code).** An earlier draft of this spec said
> the policy should be the wildcard `vec!["*".to_string()]`, on the assumption
> that the wildcard expands wherever it is consumed. It does not. `"*"` is
> expanded only by `a2a::policy::resolve_allowed_tools`; the agentic loop itself
> filters with a literal membership test:
>
> ```rust
> // src/loop_runner.rs:109-114
> let tool_defs = if let Some(ref whitelist) = self.config.allowed_tools {
>     let mut all = self.tools.all_definitions();
>     all.extend(self.mcp.tool_definitions());
>     all.into_iter()
>         .filter(|d| whitelist.contains(&d.function.name))
>         .collect()
> ```
>
> Passing `vec!["*".to_string()]` would therefore match no tool at all and hand
> the operator a chat that silently cannot use a single tool — a silent
> capability failure with no error anywhere.

The policy is the union of the two sources the loop draws from:

1. `ToolRegistry::all_definitions()` — the built-in tools.
2. `McpManager::tool_definitions()` — MCP tools, which the loop also offers
   (`src/loop_runner.rs:111`). Omitting these would silently withhold every MCP
   tool from the dashboard while the Telegram bot kept them.

An empty policy means "no tools" and is the fail-closed default; the web route
must never pass an empty policy by accident, and a test must prove that it does
not. `invoke_agent` and `spawn_agents` are not registry tools and are
unreachable here in any case: `run_with_policy_streaming_history` passes
`special_tool_handler: None` deliberately (`src/agent.rs:1637-1649`), so the
dashboard cannot dispatch subagents.

Cancel tokens are namespaced `web:{session_id}` so they cannot collide with
Telegram's `/stop` or A2A task cancellation.

SSE event kinds: `token`, `tool_call`, `tool_result`, `done`, `error`.

### 5.2 Supervisor

```
GET  /api/supervisor/tasks            → list_recent(20)
GET  /api/supervisor/tasks/{id}       → task + jobs + transitions + artifacts
POST /api/supervisor/tasks            → submit a new task
POST /api/supervisor/tasks/{id}/pause
POST /api/supervisor/tasks/{id}/resume
POST /api/supervisor/tasks/{id}/cancel
POST /api/supervisor/tasks/{id}/approve
```

`supervisor::store` currently exposes `get`, `list_resumable_task_ids`,
`jobs_for_task`, and `transitions` — there is **no** general listing. This spec
requires adding `list_recent(limit: usize)` ordered by creation time descending,
clamped to a hard maximum of 20 regardless of the requested limit.

### 5.3 Logs

An in-memory ring buffer of roughly 2000 recent tracing events, fed by a custom
`tracing_subscriber::Layer` installed at startup.

```
GET /api/logs/stream        → SSE of new events
GET /api/logs?limit=N       → recent events
```

Each event carries timestamp, level, target, and message. Redaction is applied
at render time. The buffer is bounded so the dashboard can never be the cause
of unbounded memory growth.

### 5.4 A2A

```
GET  /api/a2a/status      → listener enabled/bound URL, advertised card name, peer counts
GET  /api/a2a/peers       → inbound peers, tokens redacted
GET  /api/a2a/outbound    → outbound peers, tokens redacted
PUT  /api/a2a/outbound    → write outbound peers; tokens are write-only
POST /api/a2a/test        → real Agent Card discovery against a configured peer
```

The connection test calls the existing `A2aClient::discover` so the operator
tests the real code path rather than a bespoke probe. Tokens are never returned
by any endpoint, not even to an authenticated operator — the UI shows a
fingerprint and accepts a replacement.

### 5.5 Settings

```
GET  /api/settings          → current non-secret settings, default-password flag
POST /api/settings/password → change password (requires current password)
POST /api/settings/bearer   → enable/disable; on enable, returns the token once
PUT  /api/settings/allow-ips→ replace the IP allowlist
```

---

## 6. Frontend design

### 6.1 Visual direction — neuromorphic light, green pulled toward white

A soft, light, tactile surface language. Depth comes from light and shadow, not
from hard borders.

**Palette**

| Role | Value |
|---|---|
| Page background | `#eef3ee` |
| Raised surface | `#f7faf7` |
| Sunken surface | `#e6ece6` |
| Primary text | `#243027` |
| Muted text | `#5c6b5e` |
| Accent (soft green) | `#7cc47f` |
| Accent highlight (toward white) | `#b8e6bb` |
| Danger | `#a34d4d` |

No saturated neon. The green reads as a calm, light mint, brightening toward
white at interactive highlights.

**Contrast:** `--text-muted` and `--danger` were darkened from the values first
proposed (`#6b7a6d` at 4.04:1 and `#c96a6a` at 3.25:1) because both failed WCAG
AA for body text against `--bg`. The values above measure 5.02:1 and 5.02:1
respectively. `--accent` is intentionally left at 1.86:1: it is used only for
fills and decorative marks that always sit beside a text label, never as the
sole carrier of meaning.

**Neuromorphic treatment**

- Dual soft shadows: light from top-left (`-6px -6px 14px #ffffff`), dark to
  bottom-right (`6px 6px 14px #c9d6c9`).
- Pressed/active states invert to inset shadows.
- Corner radius 16-20px; generous spacing; no 1px grey dividers.

**Icons**

Inline SVG, thin stroke, monochrome in the accent colour. Motifs drawn from the
"Green" in the project name — leaf, shield, network — used subtly as navigation
and status marks, not as decoration.

**Layout**

Persistent sidebar (Chat, Supervisor, Logs, A2A, Settings) plus a main panel.
Light theme only; no dark mode in this scope. Usable down to 380px width.

**Default-password banner**

While the password equals the default, a persistent non-dismissible banner sits
at the top of every view, linking to Settings.

---

## 7. Configuration

```toml
[web]
enabled = false
bind = "127.0.0.1:8787"
public_url = ""            # optional; also decides the Secure cookie flag
session_ttl_hours = 12
allow_ips = []             # empty = any source IP; non-empty = strict allowlist
```

`WebConfig::validate()` runs at startup and rejects an unparseable `bind`, a
`public_url` without a scheme, `session_ttl_hours` of 0, and an unparseable
allowlist entry. Validation failure means the listener is **not** started; the
Telegram bot still runs. Secrets live in `<home>/web-auth.toml`, never here.

`allow_ips` set from the dashboard (`PUT /api/settings/allow-ips`) is held **in
memory only** — it never rewrites this file, so a restart restores the
configured list, and a list that excludes the operator's own address locks them
out until that restart (§4.4). `public_url` is both the `Secure`-cookie switch
and the host the dashboard answers to (§4.5.1); a non-loopback `bind` without it
logs a startup warning.

---

## 8. Testing strategy

**Unit**

- Argon2id hash/verify round trip; wrong password rejected.
- Default-password detection, including constant-time comparison.
- Session creation, expiry, logout, and rejection of unknown ids.
- IP allowlist: IPv4, IPv6, CIDR ranges, malformed entries, empty-list semantics.
- Login rate limiting and lockout, including counter reset on success.
- CSRF: mutating request without the header is rejected.
- Bearer toggle: off rejects the header, on accepts a valid token and rejects
  an invalid one.
- Log ring buffer bound is respected under flood.
- `list_recent` clamps to 20 even when asked for more.

**Integration** (ephemeral port, real HTTP, no mocks)

- Unauthenticated request to every protected route returns 401.
- Wrong password is rejected; correct password yields a working session.
- Chat send produces a well-formed SSE stream with a terminal `done` event.
- Supervisor listing, log query, and A2A status respond with expected shapes.
- Password change invalidates the old password.

**Mutation tests** — these guard security properties and must be shown to have
teeth by temporarily breaking the implementation and observing failure:

- Remove the auth check → the 401 tests must fail.
- Remove the CSRF check → the CSRF test must fail.
- Pass an empty tool policy to the chat route → the policy test must fail.

---

## 9. Delivery phases

The five surfaces share one listener, one auth model, and one frontend shell, so
they belong in a single spec. They are not equally risky, so they ship in
phases, each independently testable and committable:

1. **Foundation** — `[web]` config, listener, auth (password, session, CSRF,
   rate limit, IP allowlist, bearer), settings routes, and the frontend shell
   with the neuromorphic design system.
2. **Chat** — session store, SSE streaming, tool policy, cancel tokens.
3. **Supervisor** — `list_recent(20)`, task detail, lifecycle controls.
4. **Logs** — tracing layer, ring buffer, SSE stream.
5. **A2A** — status, peer inventory, connection test.

Phase 1 is a prerequisite for the rest. Phases 2-5 are independent of each
other and may land in any order after it.

---

## 10. Non-goals

- Dark mode.
- WebSocket transport; SSE covers the streaming need.
- Multiple users, roles, or per-user permissions — one operator identity.
- TLS termination inside the process; use a reverse proxy or Tailscale.
- Editing `config.toml` from the UI.
- Self-upgrade or binary reload from the UI.
- Persisting chat sessions across process restarts.

---

## 11. Open risks

| Risk | Severity | Handling |
|---|---|---|
| Default `admin`/`admin` with no forced change | High if the port is exposed | Loopback default bind, startup warning, persistent UI banner, rate limiting, settings page |
| Web chat carries full tool set including shell | High by design | Matches existing Telegram model; documented in section 4.6 |
| Bearer token grants API access without a session | Medium | Off by default; stored hashed; shown once; toggle is operator-controlled |
| Empty IP allowlist permits any source to attempt login | Medium | Explicit UI copy; password and rate limiting are the gate |
| Log buffer growth | Low | Hard-bounded ring buffer |
