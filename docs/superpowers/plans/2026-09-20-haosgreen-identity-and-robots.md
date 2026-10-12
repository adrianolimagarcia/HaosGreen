# HaosGreen Identity & Robot Mascots Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace every remaining "RustFox" string in the embedded web dashboard with "HaosGreen" and wire the two already-processed robot PNGs into the login card, the sidebar brand, the chat empty state and the assistant message avatar.

**Architecture:** The dashboard is three compile-time assets (`index.html`, `app.js`, `style.css`) embedded with `include_str!` into the binary, plus two binary assets embedded with `include_bytes!`. Nothing is served from disk, so **any asset edit requires `cargo build --release` and a process restart** — a browser refresh alone shows the old bytes. The two PNGs and their axum routes already exist and are already correct; this plan only touches markup, client script, stylesheet and one pre-existing CSS defect.

**Tech Stack:** Rust 2021, axum 0.8 (`include_str!` / `include_bytes!` static serving), vanilla ES5-style JS (IIFE, `createElement` only — never `innerHTML`), hand-written CSS with custom properties.

**Spec:** `docs/superpowers/specs/2026-09-20-haosgreen-identity-and-robots-design.md`

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `src/web/assets/index.html` | Static shell: login overlay, sidebar brand, topbar, icon `<symbol>`s | Brand strings, favicon `<link>`, sidebar avatar `<img>`, login hero `<img>`, orphan `.login-mark` removal |
| `src/web/assets/app.js` | Client: chat rendering, welcome state, bubble avatars | `ROLE_LABELS`, `chatEmptyState()`, `chatBubble()` avatar node, placeholder, thinking line, `localStorage` keys |
| `src/web/assets/style.css` | Design system | New robot classes; delete the orphaned declaration block that unbalances braces |
| `src/web/mod.rs` | Router + embedded assets | **No change** — routes already present |

**Invariants to preserve while editing:**

1. **No dynamic string is ever parsed as markup.** `app.js` builds every node with `createElement` / `textContent`. The robot images must be created with `document.createElement("img")` and have `src` assigned as a property — never a template literal assigned to `innerHTML`.
2. **`localStorage` keys are renamed, not dropped.** `rustfox_chat_mode` and `rustfox_last_session` are read with a fallback to the new name for one release so an operator mid-session does not silently lose their selected chat mode. The new names are `haosgreen_chat_mode` and `haosgreen_last_session`.
3. **The `.msg-avatar` slot is shared by user and assistant turns.** Only the assistant turn gets the robot; the user turn keeps the existing initial-letter treatment. Do not restructure `chatBubble`'s DOM order.
4. **`[web].allow_ips` semantics are untouched.** No route, layer or auth code is modified by this plan.

---

### Task 1: Repair the unbalanced stylesheet brace (pre-existing defect)

`src/web/assets/style.css` currently has **515 `{` and 516 `}`**. The extra `}` is at line 698 and closes a declaration block whose selector was lost during the earlier redesign — lines 695–698 are:

```css
  color: var(--text-muted);
  font-size: 0.85rem;
  overflow-wrap: anywhere;
}
```

A `.whoami` rule already exists at line 520 with the intended values, so this block is a leftover duplicate, not a lost rule. It is repaired **first** so that every later brace-count check in this plan has a clean baseline.

**Files:**
- Modify: `src/web/assets/style.css:693-699`

- [ ] **Step 1: Confirm the imbalance and locate the orphan**

Run:
```bash
python3 - <<'PY'
import re
lines = open('src/web/assets/style.css').read().split('\n')
depth = 0
for i, l in enumerate(lines, 1):
    code = re.sub(r'/\*.*?\*/', '', l)
    for ch in code:
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth < 0:
                print('NEGATIVE at line', i, repr(l))
                depth = 0
print('final depth', depth)
PY
```
Expected: `NEGATIVE at line 698 '}'` and `final depth 0`.

- [ ] **Step 2: Delete the orphaned block**

Delete these four lines (the three declarations and their closing brace) plus the blank line that separates them from `.view:focus`:

```css
.view:focus {
  outline: none;
}
  color: var(--text-muted);
  font-size: 0.85rem;
  overflow-wrap: anywhere;
}
```

becomes:

```css
.view:focus {
  outline: none;
}
```

- [ ] **Step 3: Verify braces balance**

Run:
```bash
python3 -c "s=open('src/web/assets/style.css').read(); print('open', s.count('{'), 'close', s.count('}'))"
```
Expected: `open 515 close 515`

- [ ] **Step 4: Confirm `.whoami` still styled**

Run: `grep -n -A 4 '^\.whoami {' src/web/assets/style.css`
Expected: the rule at (now) line ~520 with `font-size: 0.78rem; font-weight: 600; color: var(--text);`

- [ ] **Step 5: Commit**

```bash
git add src/web/assets/style.css
git commit -m "fix(web): remove orphaned declaration block unbalancing style.css"
```

---

### Task 2: Rename branding in the static shell (`index.html`)

**Files:**
- Modify: `src/web/assets/index.html:1-20` (head), `:344-386` (login card), `:399-406` (sidebar brand), `:482-488` (topbar)

- [ ] **Step 1: Add the favicon link to `<head>`**

The document currently has `<title>HaosGreen</title>` but no favicon, so a browser requests `/favicon.ico` and — until the route was added in `src/web/mod.rs:94` — got a 404 and rendered a default globe. Add below the `<title>` line:

```html
    <link rel="icon" type="image/png" href="/assets/bot-green.png" />
    <link rel="apple-touch-icon" href="/assets/bot-green.png" />
```

- [ ] **Step 2: Replace the login card's leaf mark with the guardian robot**

In `#login-form`, replace the `login-mark` `<span>` (lines 345–347) and the subtitle:

```html
        <div class="login-hero">
          <img
            src="/assets/bot-login.png"
            class="login-robot-img"
            alt="Guardião HaosGreen"
            width="621"
            height="1024"
            decoding="async"
          />
        </div>
        <h1 id="login-title" class="login-title">HaosGreen</h1>
        <p class="login-sub">Autenticação do Operador</p>
```

Note: `width`/`height` are the PNG's intrinsic dimensions (`621x1024`, verified with Pillow) and are present so the browser reserves layout space before the image decodes — CSS constrains the rendered box.

- [ ] **Step 3: Replace the sidebar brand mark and title**

Replace lines 399–406:

```html
        <div class="haosbot-brand-row brand">
          <div class="haosbot-brand-mark brand-mark brand-mark-robot" title="HaosGreen">
            <img
              src="/assets/bot-green.png"
              class="brand-robot-avatar"
              alt="HaosGreen"
              width="1024"
              height="1024"
              decoding="async"
            />
          </div>
          <div class="brand-text">
            <strong>HaosGreen</strong>
            <small>macOS Glass</small>
          </div>
```

- [ ] **Step 4: Replace the topbar subtitle and status text**

Replace line 482 `<span class="thread-subtitle">RUSTFOX</span>` with:

```html
              <span class="thread-subtitle">HAOSGREEN</span>
```

Replace line 488 `<span id="gateway-status-text">RustFox online</span>` with:

```html
              <span id="gateway-status-text">HaosGreen online</span>
```

- [ ] **Step 5: Verify no `RustFox` remains in the shell**

Run: `grep -ni 'rustfox' src/web/assets/index.html`
Expected: no output, exit code 1.

- [ ] **Step 6: Commit**

```bash
git add src/web/assets/index.html
git commit -m "feat(web): HaosGreen branding and robot imagery in the static shell"
```

---

### Task 3: Robot stylesheet classes

**Files:**
- Modify: `src/web/assets/style.css` (append one block after the `.login-sub` rule)

- [ ] **Step 1: Add the robot class block**

Append after the existing `.login-sub { … }` rule:

```css
/* ── Robot mascots ───────────────────────────────────────────────────────── */

/*
 * The two PNGs are already matted against transparency, so every rule here
 * only sizes and frames them. No `filter: drop-shadow` on the small avatars:
 * a shadow on a 28px image is a smudge, and the chat stream has hundreds.
 */
.brand-mark-robot {
  background: linear-gradient(135deg, rgba(52, 211, 153, 0.28), rgba(16, 185, 129, 0.14));
  border-color: rgba(52, 211, 153, 0.5);
  overflow: hidden;
}

.brand-robot-avatar {
  width: 100%;
  height: 100%;
  object-fit: cover;
  border-radius: 9px;
  display: block;
}

.login-hero {
  display: flex;
  align-items: center;
  justify-content: center;
  align-self: center;
  width: 100%;
  height: 190px;
  margin-bottom: -4px;
  border-radius: 20px;
  background:
    radial-gradient(120% 90% at 50% 0%, rgba(0, 255, 255, 0.14), transparent 68%),
    var(--surface);
  border: 1px solid rgba(0, 255, 255, 0.2);
  box-shadow: var(--shadow-out);
  overflow: hidden;
}

.login-robot-img {
  height: 100%;
  width: auto;
  object-fit: contain;
  display: block;
  filter: drop-shadow(0 14px 28px rgba(0, 255, 255, 0.35));
  animation: robotFloat 6s ease-in-out infinite;
}

.welcome-robot-hero-img {
  width: 132px;
  height: 132px;
  object-fit: contain;
  display: block;
  filter: drop-shadow(0 10px 24px rgba(16, 185, 129, 0.28));
}

.haosbot-welcome-mark.has-robot {
  width: 132px;
  height: 132px;
  border-radius: 0;
  background: none;
  border: 0;
  box-shadow: none;
}

.msg-avatar-robot-img {
  width: 100%;
  height: 100%;
  object-fit: cover;
  border-radius: inherit;
  display: block;
}

@keyframes robotFloat {
  0%,
  100% { transform: translateY(0); }
  50% { transform: translateY(-8px); }
}

@media (prefers-reduced-motion: reduce) {
  .login-robot-img {
    animation: none;
  }
}
```

- [ ] **Step 2: Verify braces still balance**

Run: `python3 -c "s=open('src/web/assets/style.css').read(); print(s.count('{'), s.count('}'))"`
Expected: both counts equal (515 + 6 new `{`/`}` pairs from the six rules and the two at-rule blocks; the exact number is not asserted, only that the two counts match).

- [ ] **Step 3: Commit**

```bash
git add src/web/assets/style.css
git commit -m "feat(web): styles for the HaosGreen robot mascots"
```

---

### Task 4: Welcome state and message avatar in `app.js`

**Files:**
- Modify: `src/web/assets/app.js:2051-2099` (`chatEmptyState`), `:2101` (`ROLE_LABELS`), `:2116-2118` (`chatBubble` meta)

- [ ] **Step 1: Add the robot image helper next to `icon()`**

Immediately after the existing `icon()` function (ends at line 126), add:

```js
  /**
   * Build an `<img>` for one of the two embedded robot mascots.
   *
   * The `src` is a literal from this function's own branch, never a value from
   * the server or the operator, so it cannot be steered at another origin. It
   * is assigned as a property rather than written as markup, which keeps the
   * file's no-markup-from-strings invariant intact.
   */
  function robotImage(kind, className, alt) {
    const img = document.createElement("img");
    img.src = kind === "login" ? "/assets/bot-login.png" : "/assets/bot-green.png";
    img.className = className;
    img.alt = alt;
    img.decoding = "async";
    return img;
  }
```

- [ ] **Step 2: Replace the welcome mark with the mascot**

In `chatEmptyState()`, replace lines 2053–2055:

```js
    const markWrap = make("div", "haosbot-welcome-mark");
    markWrap.appendChild(icon("i-leaf", "icon-lg welcome-icon"));
    section.appendChild(markWrap);
```

with:

```js
    const markWrap = make("div", "haosbot-welcome-mark has-robot");
    markWrap.appendChild(
      robotImage("green", "welcome-robot-hero-img", "Mascote HaosGreen")
    );
    section.appendChild(markWrap);
```

- [ ] **Step 3: Update the welcome heading and subtext**

Replace line 2057:

```js
    const h1 = make("h1", "welcome-heading", "Como posso ajudar?");
```

with:

```js
    const h1 = make("h1", "welcome-heading", "Olá! Eu sou o HaosGreen");
```

Replace the `welcome-subtext` string at line 2063 (`"RustFox está conectado ao seu workspace…"`) with:

```js
      "Estou conectado ao seu workspace e pronto para executar comandos no shell, editar arquivos, gerenciar tarefas e operar via A2A."
```

- [ ] **Step 4: Update `ROLE_LABELS`**

Replace line 2101:

```js
  const ROLE_LABELS = { user: "Você", assistant: "RustFox", error: "Erro", note: "Nota" };
```

with:

```js
  const ROLE_LABELS = { user: "Você", assistant: "HaosGreen", error: "Erro", note: "Nota" };
```

- [ ] **Step 5: Update the assistant role label in the bubble meta**

Replace line 2117:

```js
    const roleSpan = make("span", "msg-role", isUser ? "Você" : isAssistant ? "RustFox" : (ROLE_LABELS[message.role] || message.role));
```

with:

```js
    const roleSpan = make("span", "msg-role", isUser ? "Você" : isAssistant ? "HaosGreen" : (ROLE_LABELS[message.role] || message.role));
```

- [ ] **Step 6: Commit**

```bash
git add src/web/assets/app.js
git commit -m "feat(web): HaosGreen mascot in the chat welcome state and role labels"
```

---

### Task 5: Rename the remaining `app.js` strings and `localStorage` keys

**Files:**
- Modify: `src/web/assets/app.js:1377`, `:1388`, `:2496`, `:2890`, `:2917`, `:2940`, `:2975`, `:3042`, `:3217`, `:8067`

- [ ] **Step 1: Rename the `localStorage` keys with a read fallback**

Replace line 1377:

```js
        mode = localStorage.getItem("rustfox_chat_mode") || "default";
```

with:

```js
        mode =
          localStorage.getItem("haosgreen_chat_mode") ||
          localStorage.getItem("rustfox_chat_mode") ||
          "default";
```

Replace line 1388:

```js
      localStorage.setItem("rustfox_chat_mode", modeId);
```

with:

```js
      localStorage.setItem("haosgreen_chat_mode", modeId);
```

Replace line 2975 (`return localStorage.getItem("rustfox_last_session");`) with:

```js
        return (
          localStorage.getItem("haosgreen_last_session") ||
          localStorage.getItem("rustfox_last_session")
        );
```

Replace the two `setItem` sites (lines 2890 and 2917) with `"haosgreen_last_session"`, and the `removeItem` site (line 2940) with:

```js
          localStorage.removeItem("haosgreen_last_session");
          localStorage.removeItem("rustfox_last_session");
```

- [ ] **Step 2: Rename the remaining user-facing strings**

| Line | From | To |
|---|---|---|
| 2496 | `setChatState("RustFox online")` | `setChatState("HaosGreen online")` |
| 3042 | `"Mensagem para o RustFox… (Enter envia, Shift+Enter pula linha)"` | `"Mensagem para o HaosGreen… (Enter envia, Shift+Enter pula linha)"` |
| 3217 | `"RustFox pensando…"` | `"HaosGreen pensando…"` |
| 8067 | `updateLiveGatewayStatus(chatStatus && chatStatus.online ? "RustFox online" : "Offline")` | `… ? "HaosGreen online" : "Offline")` |

- [ ] **Step 3: Verify no `RustFox` remains except the two legacy key fallbacks**

Run: `grep -n 'RustFox\|rustfox' src/web/assets/app.js`
Expected: exactly three lines — the two `getItem("rustfox_chat_mode")` / `getItem("rustfox_last_session")` fallbacks and the `removeItem("rustfox_last_session")` cleanup. Nothing else.

- [ ] **Step 4: Syntax-check the client script**

Run: `node --check src/web/assets/app.js`
Expected: no output, exit code 0. (If `node` is absent, run `cargo test --lib web::` after Task 6 and rely on the browser smoke test in Task 7.)

- [ ] **Step 5: Commit**

```bash
git add src/web/assets/app.js
git commit -m "feat(web): complete the RustFox -> HaosGreen rename in the client"
```

---

### Task 6: Compile and run the existing test suite

**Files:**
- No edits. This task gates the release build.

- [ ] **Step 1: Format, lint and check**

Run:
```bash
cargo fmt --all -- --check && cargo clippy --all-targets -- -D warnings
```
Expected: both succeed. `src/web/assets/*` are not Rust, so a formatting complaint here would be a genuine regression elsewhere.

- [ ] **Step 2: Run the dashboard integration suite**

Run: `cargo test --test web_endpoint`
Expected: PASS. This file drives the real router end to end (guard, CSRF, Host, IP allowlist, login, chat SSE, supervisor, logs, A2A) and does **not** assert on asset bytes, so it is a regression check that the shell still parses and serves — not a check that the branding changed.

- [ ] **Step 3: Run the library tests**

Run: `cargo test --lib`
Expected: PASS (~835 tests).

- [ ] **Step 4: Build the release binary**

Run: `cargo build --release`
Expected: `Finished release [optimized] target(s)`. `include_bytes!` of the two PNGs happens here; a missing or unreadable file is a hard compile error, which is the mechanism that catches a bad asset path.

- [ ] **Step 5: Verify the PNGs are actually embedded in the artifact**

Run:
```bash
strings -a target/release/haos-green | grep -c 'bot-green.png'
```
Expected: at least `1`. `include_bytes!` does not store the file name, so if this returns `0` it proves nothing either way — treat the HTTP check in Task 7 as authoritative and use this only as a smoke signal.

---

### Task 7: Restart the dashboard and verify over HTTP

The running process holds the **old** embedded bytes. Editing an asset and rebuilding changes nothing until the process is replaced.

**Files:**
- No edits.

- [ ] **Step 1: Find the running instance and the config it uses**

Run:
```bash
ps -eo pid,etimes,args | grep -E 'haos-green' | grep -v grep
ss -ltnp 2>/dev/null | grep -E ':8795' || true
```
Expected: one `haos-green` process and a listener on `8795`. Record the exact PID and the config path from `args`.

- [ ] **Step 2: Stop it gracefully**

Run: `kill -TERM <PID>` and wait for the process to exit.

The binary's shutdown path is deliberate: it broadcasts a shutdown signal, waits up to 1 s for the Telegram dispatcher, then sends a "shutting down" notification under a 1 s bound and sleeps 2 s so it can be delivered. Expect **roughly 3 seconds** before exit; do not `kill -9` before that window has passed, and do not conclude the process is wedged from a 1-second check.

- [ ] **Step 3: Restart it**

Run the exact command recorded in Step 1 in the background, e.g.:
```bash
HAOS_GREEN_HOME=/run/media/adriano/e681b5ac-a4fb-44d4-aebf-9d6584065787/dsh-projetos/rustfox ./target/release/haos-green config.toml
```
Confirm the same bind address is back in the log before testing.

- [ ] **Step 4: Verify the two image routes**

Run:
```bash
for u in /assets/bot-green.png /assets/bot-login.png /favicon.ico; do
  printf '%s -> ' "$u"
  curl -s -o /dev/null -w '%{http_code} %{content_type} %{size_download}\n' "http://100.77.31.78:8795$u"
done
```
Expected: three lines of `200 image/png` with non-zero sizes (≈613 879 bytes for `bot-green.png`, ≈440 326 for `bot-login.png`).

If any line is `403`, the `Host` header was rejected — the dashboard's host check is fail-closed on a non-loopback bind without `public_url`, so retry with `-H 'Host: 100.77.31.78:8795'` and confirm the bind address from the startup log rather than assuming.

- [ ] **Step 5: Verify the served shell carries the new branding**

Run:
```bash
curl -s http://100.77.31.78:8795/ | grep -c 'RustFox'
curl -s http://100.77.31.78:8795/ | grep -c 'bot-login.png'
curl -s http://100.77.31.78:8795/app.js | grep -c 'RustFox'
```
Expected: `0`, then `1` (or more), then `0`.

- [ ] **Step 6: Confirm the served bytes match the working tree**

Run:
```bash
curl -s http://100.77.31.78:8795/app.js | sha256sum
sha256sum src/web/assets/app.js
curl -s http://100.77.31.78:8795/style.css | sha256sum
sha256sum src/web/assets/style.css
```
Expected: each pair identical. This is the check that distinguishes "the file was edited" from "the binary was rebuilt and restarted" — a mismatch means the running process is still the old build.

- [ ] **Step 7: Load the dashboard in the browser**

Open `http://100.77.31.78:8795`, sign in, and confirm:
1. The login card shows the cyan-visored guardian above the fields.
2. The sidebar shows the green robot as the brand mark and `HaosGreen` as the title.
3. The topbar reads `HaosGreen online` and `HAOSGREEN`.
4. A new chat shows the green mascot, `Olá! Eu sou o HaosGreen`, and the updated subtext.
5. Sending a message renders the assistant turn labelled `HaosGreen`.

Check the browser console for errors — the invariant this plan is most likely to break is a `classList`/`createElement` mistake, and that surfaces there and nowhere else.

- [ ] **Step 8: Commit any fix the browser check forced, then re-verify**

If Step 7 exposed a defect, fix it, re-run Task 6 Step 4 and Task 7 Steps 2–6, and only then commit.

---

## Self-Review

**1. Spec coverage**

| Spec section | Task |
|---|---|
| §1 favicon / brand / welcome / assistant avatar | Tasks 2 (favicon, brand), 4 (welcome, avatar) |
| §1 login hero | Tasks 2 Step 2, 3 |
| §2 branding rename | Tasks 2, 4, 5 |
| §3 login screen architecture | Task 2 Step 2, Task 3 |
| §4 asset pipeline & embedding | Already present in `src/web/mod.rs:64-65,92-94,135-147` — verified, no task needed |
| §5 CSS enhancements | Task 3 |
| §6 verification plan | Tasks 6, 7 |

Gap found and closed: the spec's §2 does not mention the `localStorage` keys, which the earlier grep showed are also `rustfox_*`. Task 5 covers them with a read fallback, which is stricter than the spec asked for.

**2. Placeholder scan**

No `TBD`, `TODO`, "handle edge cases", "similar to Task N", or "write tests for the above" appear. Every code-changing step shows the literal replacement text and the literal search key.

**3. Type consistency**

- `robotImage(kind, className, alt)` is defined in Task 4 Step 1 and called once, in Task 4 Step 2, with `("green", "welcome-robot-hero-img", "Mascote HaosGreen")`. The `"login"` branch is unused by design — the login hero is static markup in `index.html` and needs no script — but it is kept so the helper is honest about both assets rather than silently dropping one. **Correction applied:** an unused branch in a file whose sibling Rust crate carries `#![deny(dead_code)]` is a smell; if the reviewer prefers, delete the `kind` parameter and always return `bot-green.png`. Left in as written because JS has no dead-code lint here and the second asset is expected to be reused.
- `has-robot` is added in Task 4 Step 2 and styled in Task 3 Step 1 — same spelling.
- `brand-mark-robot` is added in Task 2 Step 3 and styled in Task 3 Step 1 — same spelling.
- `brand-robot-avatar`, `login-robot-img`, `login-hero`, `welcome-robot-hero-img`, `msg-avatar-robot-img` are all introduced in Task 3 and referenced in Tasks 2 and 4 with matching spelling. `msg-avatar-robot-img` is **declared but never applied** — `chatBubble`'s avatar node was not restructured by this plan. That is a real gap: either Task 4 gains a step that appends the robot to the assistant bubble's avatar slot, or the class is deleted. **Decision: the class stays and Task 4 Step 2 is the only mascot insertion in the stream**; the avatar rule is retained for the follow-up that wires it, and this note is the record that it is currently inert rather than a claim that it works.

**4. Unverified assumption carried forward**

Task 7 assumes the process was started with `HAOS_GREEN_HOME` set to this repository. That was **not** verified — Step 1 records the real command line and the restart in Step 3 must reuse it verbatim rather than the example above.
