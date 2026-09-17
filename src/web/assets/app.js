/*
 * HaosGreen dashboard client (shell, design system, settings, chat, supervisor).
 *
 * Two rules hold everywhere in this file.
 *
 *  * No dynamic string is ever parsed as markup. Elements are built with
 *    `createElement`, values from the server and from the operator are written
 *    with `textContent`, and no markup is ever assigned from a string — not
 *    even for the icons, which are `<symbol>`s in index.html instantiated by
 *    cloning a `<template>`. The invariant is grep-checkable: the assignment
 *    that would break it does not occur in this file.
 *  * Nothing leaves this origin. `api()` is the only network entry point and it
 *    only ever fetches a path on the server that served this page, so the
 *    dashboard renders identically with networking disabled.
 *
 * Chat streams a real agent run over SSE. `EventSource` cannot be used for it
 * — the request is a POST with a JSON body — so the response is read through
 * `fetch`'s `ReadableStream` and the SSE frames are reassembled by hand; see
 * the decoder below. The supervisor view lists real tasks and drives their
 * lifecycle through `/api/supervisor/*`. The logs view tails the dashboard's
 * own bounded tracing buffer through the same decoder, dispatching on the
 * `log` event name. A2A is still a deliberate empty state: a stub that invented
 * rows would be worse than an honest "not yet".
 */

(function () {
  "use strict";

  /*
   * The exact spelling the server checks: `middleware::CSRF_HEADER`, which is
   * "x-haos-green-csrf". Header names are case-insensitive, but hyphens are
   * not, so the word boundaries have to match the constant character for
   * character — the design spec's "X-HaosGreen-CSRF" spelling is not the one
   * the running server accepts, and a request carrying it is answered 403
   * before any handler runs.
   */
  const CSRF_HEADER = "x-haos-green-csrf";
  const DEFAULT_ROUTE = "/chat";
  const MUTATING = ["POST", "PUT", "PATCH", "DELETE"];

  /** The five surfaces. `body` describes the stub still owed by a later phase. */
  const VIEWS = {
    "/chat": {
      title: "Chat",
      icon: "i-leaf",
      // Implemented: the chat view is built by `renderChat`, not by the stub.
      body: ""
    },
    "/supervisor": {
      title: "Supervisor",
      icon: "i-shield",
      // Implemented: the supervisor view is built by `renderSupervisor`.
      body: ""
    },
    "/logs": {
      title: "Logs",
      icon: "i-bars",
      // Implemented: the logs view is built by `renderLogs`.
      body: ""
    },
    "/a2a": {
      title: "A2A",
      icon: "i-node",
      body: "A2A will show the listener status, the inbound and outbound peers, and run a real Agent Card discovery test."
    },
    "/settings": {
      title: "Settings",
      icon: "i-gear",
      body: ""
    }
  };

  const ROUTES = Object.keys(VIEWS);

  const state = {
    /** The last `GET /api/settings` body, or null while signed out. */
    settings: null,
    route: DEFAULT_ROUTE,
    /** Unsaved IP allowlist edits, mirroring the server's list until saved. */
    allowDraft: []
  };

  /* ── DOM helpers ───────────────────────────────────────────────────────── */

  function byId(id) {
    return document.getElementById(id);
  }

  function make(tag, className, text) {
    const node = document.createElement(tag);
    if (className) {
      node.className = className;
    }
    if (text !== undefined && text !== null) {
      node.textContent = String(text);
    }
    return node;
  }

  function clear(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  /** An inline SVG icon cloned from the sprite template in index.html. */
  function icon(name, extraClass) {
    const template = byId("icon-template");
    const svg = template.content.firstElementChild.cloneNode(true);
    if (extraClass) {
      svg.classList.add(extraClass);
    }
    svg.querySelector("use").setAttribute("href", "#" + name);
    return svg;
  }

  /**
   * Write a status line.
   *
   * `kind` is "ok", "warn", "error" or null/absent for a neutral note. The
   * message is always plain text; the colour signal lives in the mark and the
   * tinted surface, because --danger on --surface is only 3.5:1 and would be
   * unreadable as body-sized coloured text.
   */
  function setStatus(node, kind, message) {
    if (!node) {
      return;
    }
    const text = message === undefined || message === null ? "" : String(message);
    node.className = kind ? "status status-" + kind : "status";
    node.textContent = text;
    node.hidden = text === "";
  }

  function cardHead(iconName, titleText) {
    const head = make("div", "card-head");
    const mark = make("span", "card-mark");
    mark.appendChild(icon(iconName));
    head.appendChild(mark);
    head.appendChild(make("h2", "card-title", titleText));
    return head;
  }

  function field(id, labelText, type, autocomplete) {
    const wrap = make("div", "field");
    const label = make("label", "field-label", labelText);
    label.setAttribute("for", id);
    const input = document.createElement("input");
    input.id = id;
    input.name = id;
    input.type = type;
    input.required = true;
    if (autocomplete) {
      input.setAttribute("autocomplete", autocomplete);
    }
    if (type === "password") {
      input.spellcheck = false;
    } else {
      input.setAttribute("autocapitalize", "none");
      input.setAttribute("autocorrect", "off");
      input.spellcheck = false;
    }
    wrap.appendChild(label);
    wrap.appendChild(input);
    return { wrap: wrap, input: input };
  }

  function button(label, className, type) {
    const node = make("button", className || "btn", label);
    node.type = type || "button";
    return node;
  }

  /* ── The one network entry point ───────────────────────────────────────── */

  /**
   * Call the dashboard API.
   *
   * Every mutating method carries the CSRF header, which the server requires on
   * POST, PUT, PATCH and DELETE — including login, which is otherwise public.
   * Credentials are same-origin, so the session cookie rides along.
   *
   * On a non-2xx the returned promise rejects with an `Error` whose `message` is
   * the server's own text and whose `status` is the HTTP status, so callers can
   * branch on 401 (session gone) without string matching.
   */
  async function api(path, options) {
    const opts = options || {};
    const method = (opts.method || "GET").toUpperCase();
    const headers = Object.assign({ Accept: "application/json" }, opts.headers || {});
    const init = { method: method, credentials: "same-origin", headers: headers };

    if (MUTATING.indexOf(method) !== -1) {
      headers[CSRF_HEADER] = "1";
    }

    if (opts.body !== undefined && opts.body !== null) {
      headers["Content-Type"] = "application/json";
      init.body = typeof opts.body === "string" ? opts.body : JSON.stringify(opts.body);
    }

    let response;
    try {
      response = await window.fetch(path, init);
    } catch (cause) {
      const unreachable = new Error(
        "The dashboard server could not be reached. Check that HaosGreen is still running."
      );
      unreachable.status = 0;
      unreachable.cause = cause;
      throw unreachable;
    }

    const raw = await response.text();
    let body = null;
    if (raw) {
      try {
        body = JSON.parse(raw);
      } catch (ignored) {
        body = null;
      }
    }

    if (!response.ok) {
      let message = "";
      if (body && typeof body === "object") {
        if (typeof body.message === "string") {
          message = body.message;
        } else if (typeof body.error === "string") {
          message = body.error;
        }
      }
      if (!message) {
        // The server answers errors with a short plain-text body. Truncated so
        // an unexpected HTML error page cannot fill the status line.
        message = raw.trim().slice(0, 200) || "Request failed with status " + response.status + ".";
      }
      const failure = new Error(message);
      failure.status = response.status;
      throw failure;
    }

    return body === null ? {} : body;
  }

  /* ── Session ───────────────────────────────────────────────────────────── */

  function showBoot(visible) {
    byId("boot").hidden = !visible;
  }

  function showLogin(message) {
    state.settings = null;
    state.allowDraft = [];
    // The chat transcript belongs to the session that just ended: the server's
    // session store is keyed per web session, so keeping it on screen would
    // show the next operator a conversation they cannot reach. The supervisor
    // view is torn down for the same reason — its poll timer must not keep
    // reading the task list for a signed-out browser — and so is the log view,
    // whose stream would otherwise keep an abandoned tab attached to the
    // server's log buffer.
    resetChat();
    supervisorUnmount();
    logsUnmount();
    renderBanner();
    byId("app").hidden = true;
    byId("login-overlay").hidden = false;
    setStatus(byId("login-error"), message ? "error" : null, message || "");
    byId("login-username").focus();
  }

  function enterApp(settings) {
    state.settings = settings && typeof settings === "object" ? settings : {};
    byId("login-overlay").hidden = true;
    byId("app").hidden = false;
    byId("whoami").textContent =
      typeof state.settings.username === "string" && state.settings.username
        ? "Signed in as " + state.settings.username
        : "Signed in";
    renderBanner();
    navigate();
  }

  async function refreshSettings() {
    const settings = await api("/api/settings");
    state.settings = settings && typeof settings === "object" ? settings : {};
    return state.settings;
  }

  /** Show the sign-in overlay when the session is gone, else a status error. */
  function handleFailure(error, statusNode, fallback) {
    if (error && error.status === 401) {
      showLogin("Your session expired. Sign in again.");
      return;
    }
    setStatus(statusNode, "error", (error && error.message) || fallback);
  }

  function loginMessage(error) {
    if (!error) {
      return "Sign in failed.";
    }
    if (error.status === 401) {
      return "Incorrect username or password.";
    }
    if (error.status === 429) {
      return "Too many failed attempts from this address. Wait a moment and try again.";
    }
    if (error.status === 403) {
      return error.message || "This request was refused.";
    }
    return error.message || "Sign in failed.";
  }

  async function submitLogin(event) {
    event.preventDefault();
    const usernameInput = byId("login-username");
    const passwordInput = byId("login-password");
    const errorNode = byId("login-error");
    const submit = byId("login-submit");

    const username = usernameInput.value;
    const password = passwordInput.value;
    if (!username || !password) {
      setStatus(errorNode, "error", "Enter both a username and a password.");
      return;
    }

    setStatus(errorNode, null, "");
    submit.disabled = true;
    try {
      await api("/api/auth/login", {
        method: "POST",
        body: { username: username, password: password }
      });
      passwordInput.value = "";
      const settings = await api("/api/settings");
      enterApp(settings);
    } catch (error) {
      passwordInput.value = "";
      setStatus(errorNode, "error", loginMessage(error));
    } finally {
      submit.disabled = false;
    }
  }

  async function signOut() {
    const buttonNode = byId("logout");
    buttonNode.disabled = true;
    try {
      await api("/api/auth/logout", { method: "POST" });
    } catch (error) {
      // A session that is already gone answers 401; that is still a sign-out.
      if (error && error.status !== 401) {
        window.console.warn("HaosGreen dashboard: sign-out request failed");
      }
    } finally {
      buttonNode.disabled = false;
    }
    clear(byId("view"));
    showLogin("");
  }

  /* ── Routing ───────────────────────────────────────────────────────────── */

  function routeFromHash() {
    const raw = window.location.hash.replace(/^#/, "");
    return ROUTES.indexOf(raw) === -1 ? DEFAULT_ROUTE : raw;
  }

  function updateNav(route) {
    const items = document.querySelectorAll(".nav-item");
    for (let i = 0; i < items.length; i += 1) {
      const item = items[i];
      const active = item.getAttribute("data-route") === route;
      item.classList.toggle("is-active", active);
      if (active) {
        item.setAttribute("aria-current", "page");
      } else {
        item.removeAttribute("aria-current");
      }
    }
  }

  function navigate() {
    const route = routeFromHash();
    if (window.location.hash.replace(/^#/, "") !== route) {
      // Normalises an unknown or empty fragment; hashchange re-enters here.
      window.location.hash = "#" + route;
      return;
    }

    state.route = route;
    updateNav(route);
    byId("view-title").textContent = VIEWS[route].title;

    const host = byId("view");
    // Every view owns the whole panel, so the previous one is torn down first —
    // including the chat view's DOM references, which a run that outlives the
    // view would otherwise keep writing into, the supervisor view's poll
    // timer, and the log view's tail, which must not survive a route change.
    chatUnmount();
    supervisorUnmount();
    logsUnmount();
    clear(host);
    if (route === "/settings") {
      renderSettings(host);
    } else if (route === "/chat") {
      renderChat(host);
    } else if (route === "/supervisor") {
      renderSupervisor(host);
    } else if (route === "/logs") {
      renderLogs(host);
    } else {
      renderStub(host, route);
    }
    window.scrollTo(0, 0);
  }

  /* ── Default-password banner ───────────────────────────────────────────── */

  /**
   * Render the banner into every view while the password equals the default.
   *
   * It is a caution, not an error: the accent gradient reads as "attention"
   * without the alarm of red. There is deliberately no dismiss control — the
   * design spec makes it persistent and non-dismissible, because a reachable
   * dashboard with the default password is open to anyone who can reach the
   * port.
   */
  function renderBanner() {
    const slot = byId("banner-slot");
    clear(slot);
    const settings = state.settings;
    if (!settings || settings.uses_default_password !== true) {
      return;
    }

    const banner = make("div", "banner-warning");
    banner.setAttribute("role", "status");
    banner.appendChild(icon("i-shield", "icon-lg"));

    const text = make("p", "banner-text");
    text.appendChild(make("strong", null, "This dashboard is still using the default password."));
    text.appendChild(
      document.createTextNode(
        " Anyone who can reach this port can sign in and run commands on the host. Change it in Settings."
      )
    );
    banner.appendChild(text);

    const link = make("a", "btn btn-accent banner-action", "Go to Settings");
    link.setAttribute("href", "#/settings");
    banner.appendChild(link);

    slot.appendChild(banner);
  }

  /* ── Empty states for the later phases ─────────────────────────────────── */

  function renderStub(host, route) {
    const view = VIEWS[route];
    const card = make("section", "card empty-state");
    const mark = make("div", "empty-mark");
    mark.appendChild(icon(view.icon, "icon-lg"));
    card.appendChild(mark);
    card.appendChild(make("h2", "empty-title", view.title + " arrives in a later phase"));
    card.appendChild(make("p", "empty-body", view.body));
    card.appendChild(
      make(
        "p",
        "empty-note",
        "Phase 1 ships the shell, the design system and the settings surface. This view stays empty until its phase lands; no placeholder data is shown here."
      )
    );
    host.appendChild(card);
  }

  /* ── Settings ──────────────────────────────────────────────────────────── */

  function renderSettings(host) {
    const account = make("section", "card");
    account.appendChild(cardHead("i-leaf", "Account"));
    const facts = make("dl", "facts");
    account.appendChild(facts);
    host.appendChild(account);

    function renderFacts() {
      const settings = state.settings || {};
      clear(facts);
      addFact(facts, "Signed in as", stringOr(settings.username, "unknown"));
      addFact(facts, "Session lifetime", sessionLifetime(settings.session_ttl_hours));
      addFact(
        facts,
        "Password",
        settings.uses_default_password === true
          ? "Default password — change it below"
          : "Custom password set"
      );
      addFact(facts, "Bearer authentication", bearerSummary(settings));
    }
    renderFacts();

    function afterChange() {
      renderFacts();
      renderBanner();
    }

    host.appendChild(passwordCard(afterChange));
    host.appendChild(bearerCard(afterChange));
    host.appendChild(allowlistCard());
  }

  function addFact(list, term, value) {
    const row = make("div", "fact");
    row.appendChild(make("dt", null, term));
    row.appendChild(make("dd", null, value));
    list.appendChild(row);
  }

  function stringOr(value, fallback) {
    return typeof value === "string" && value.length > 0 ? value : fallback;
  }

  function sessionLifetime(hours) {
    const value = typeof hours === "number" && isFinite(hours) ? hours : null;
    if (value === null) {
      return "unknown";
    }
    return value === 1 ? "1 hour" : value + " hours";
  }

  function bearerSummary(settings) {
    if (settings.bearer_enabled !== true) {
      return "Disabled";
    }
    const fingerprint = stringOr(settings.bearer_fingerprint, "");
    return fingerprint ? "Enabled (token fingerprint " + fingerprint + ")" : "Enabled";
  }

  /* ── Settings: password ────────────────────────────────────────────────── */

  function passwordCard(afterChange) {
    const card = make("section", "card");
    card.appendChild(cardHead("i-shield", "Password"));
    card.appendChild(
      make(
        "p",
        "card-note",
        "The dashboard has a single operator account. Changing the password keeps the current session alive, and the default password stops working immediately."
      )
    );

    const form = make("form", "stack");
    form.noValidate = true;
    const current = field("pw-current", "Current password", "password", "current-password");
    const next = field("pw-new", "New password", "password", "new-password");
    form.appendChild(current.wrap);
    form.appendChild(next.wrap);

    const submit = button("Change password", "btn btn-accent", "submit");
    const actions = make("div", "actions");
    actions.appendChild(submit);
    form.appendChild(actions);

    const status = make("p", "status");
    status.setAttribute("role", "status");
    status.hidden = true;
    form.appendChild(status);

    form.addEventListener("submit", async function (event) {
      event.preventDefault();
      const currentValue = current.input.value;
      const nextValue = next.input.value;
      if (!currentValue || !nextValue) {
        setStatus(status, "error", "Fill in both the current and the new password.");
        return;
      }

      submit.disabled = true;
      setStatus(status, null, "");
      try {
        await api("/api/settings/password", {
          method: "POST",
          body: { current: currentValue, new: nextValue }
        });
        current.input.value = "";
        next.input.value = "";
        setStatus(
          status,
          "ok",
          "Password changed. The previous password no longer works, and the default-password banner is gone."
        );
        refreshSettings()
          .then(afterChange)
          .catch(function () {
            // The change already succeeded; a failed re-read must not undo it.
          });
      } catch (error) {
        handleFailure(error, status, "The password could not be changed.");
      } finally {
        submit.disabled = false;
      }
    });

    card.appendChild(form);
    return card;
  }

  /* ── Settings: bearer token ────────────────────────────────────────────── */

  function bearerCard(afterChange) {
    const card = make("section", "card");
    card.appendChild(cardHead("i-copy", "Bearer token"));
    card.appendChild(
      make(
        "p",
        "card-note",
        "A bearer token authenticates API requests without a browser session. Only a SHA-256 digest is stored, so the token itself can never be read back — not by this page, and not by the server."
      )
    );

    const row = make("div", "switch");
    const input = document.createElement("input");
    input.type = "checkbox";
    input.id = "bearer-toggle";
    input.checked = !!(state.settings && state.settings.bearer_enabled === true);
    const track = make("span", "switch-track");
    track.appendChild(make("span", "switch-thumb"));
    row.appendChild(input);
    row.appendChild(track);
    row.appendChild(make("span", "switch-label", "Enable bearer authentication"));
    card.appendChild(row);

    const meta = make("p", "meta");
    card.appendChild(meta);

    const status = make("p", "status");
    status.setAttribute("role", "status");
    status.hidden = true;
    card.appendChild(status);

    const reveal = make("div", "reveal");
    reveal.hidden = true;
    reveal.appendChild(make("h3", "reveal-title", "Copy this token now"));
    reveal.appendChild(
      make(
        "p",
        "reveal-warning",
        "This is the only time the token is ever shown. It is stored as a hash and cannot be recovered, so copy it before you leave this page. Enabling bearer authentication again mints a new token and invalidates this one."
      )
    );
    const tokenValue = make("code", "token-value");
    reveal.appendChild(tokenValue);
    const revealActions = make("div", "actions");
    const copy = button("Copy token", "btn", "button");
    revealActions.appendChild(copy);
    reveal.appendChild(revealActions);
    const copyStatus = make("p", "status");
    copyStatus.setAttribute("role", "status");
    copyStatus.hidden = true;
    reveal.appendChild(copyStatus);
    card.appendChild(reveal);

    function renderMeta() {
      const settings = state.settings || {};
      if (settings.bearer_enabled === true) {
        const fingerprint = stringOr(settings.bearer_fingerprint, "");
        meta.textContent = fingerprint
          ? "Bearer authentication is on. Active token fingerprint: " +
            fingerprint +
            ". The token itself is not stored and cannot be shown again."
          : "Bearer authentication is on. The token itself is not stored and cannot be shown again.";
      } else {
        meta.textContent = "Bearer authentication is off. Only a browser session can reach the API.";
      }
    }
    renderMeta();

    input.addEventListener("change", async function () {
      const wanted = input.checked;
      input.disabled = true;
      setStatus(status, null, "");
      try {
        const body = await api("/api/settings/bearer", {
          method: "POST",
          body: { enabled: wanted }
        });

        if (wanted && typeof body.token === "string" && body.token.length > 0) {
          tokenValue.textContent = body.token;
          setStatus(copyStatus, null, "");
          reveal.hidden = false;
          setStatus(
            status,
            "warn",
            "Bearer authentication is enabled. Copy the token above now — it is never shown again."
          );
        } else {
          tokenValue.textContent = "";
          reveal.hidden = true;
          setStatus(
            status,
            "ok",
            "Bearer authentication is disabled. Any token that was issued no longer authenticates."
          );
        }

        if (state.settings) {
          state.settings.bearer_enabled = wanted;
          if (!wanted) {
            state.settings.bearer_fingerprint = undefined;
          }
        }
        renderMeta();
        afterChange();
        refreshSettings()
          .then(function () {
            input.checked = state.settings.bearer_enabled === true;
            renderMeta();
            afterChange();
          })
          .catch(function () {
            // The toggle already succeeded; a failed re-read must not undo it.
          });
      } catch (error) {
        input.checked = !wanted;
        handleFailure(error, status, "The bearer setting could not be changed.");
      } finally {
        input.disabled = false;
      }
    });

    copy.addEventListener("click", function () {
      copyToken(tokenValue, copyStatus);
    });

    return card;
  }

  /**
   * Copy the revealed token, or select it when the Clipboard API is not usable.
   *
   * `navigator.clipboard` only exists in a secure context, and a dashboard
   * reached over plain HTTP on a LAN address is not one. Selecting the text is
   * an honest fallback: the operator still gets the token with the keyboard.
   */
  async function copyToken(tokenValue, statusNode) {
    const value = tokenValue.textContent;
    if (!value) {
      return;
    }

    try {
      if (!window.navigator.clipboard || !window.navigator.clipboard.writeText) {
        throw new Error("clipboard unavailable");
      }
      await window.navigator.clipboard.writeText(value);
      setStatus(statusNode, "ok", "Token copied to the clipboard.");
    } catch (error) {
      selectText(tokenValue);
      setStatus(
        statusNode,
        "warn",
        "This browser will not let the page copy automatically. The token is selected — copy it with your keyboard before leaving this page."
      );
    }
  }

  function selectText(node) {
    const selection = window.getSelection ? window.getSelection() : null;
    if (!selection || !document.createRange) {
      return;
    }
    const range = document.createRange();
    range.selectNodeContents(node);
    selection.removeAllRanges();
    selection.addRange(range);
  }

  /* ── Settings: IP allowlist ────────────────────────────────────────────── */

  function allowlistCard() {
    const card = make("section", "card");
    card.appendChild(cardHead("i-node", "IP allowlist"));

    const asymmetry = make("p", "card-note");
    asymmetry.appendChild(make("strong", null, "An empty list permits any source address."));
    asymmetry.appendChild(
      document.createTextNode(
        " A non-empty list is a strict allowlist: only the listed addresses may reach the dashboard, and every other source is refused before authentication runs — including the login page."
      )
    );
    card.appendChild(asymmetry);

    card.appendChild(
      make(
        "p",
        "card-note",
        "Entries are single addresses (10.0.0.5) or CIDR ranges (10.0.0.0/8). A change takes effect on the very next request and is held in memory only: restarting HaosGreen reloads the list from config.toml."
      )
    );

    const list = make("ul", "allow-list");
    card.appendChild(list);

    const form = make("form", "allow-add");
    form.noValidate = true;
    const label = make("label", "sr-only", "Address or CIDR range");
    label.setAttribute("for", "allow-input");
    const input = document.createElement("input");
    input.type = "text";
    input.id = "allow-input";
    input.name = "allow-input";
    input.placeholder = "10.0.0.0/8";
    input.setAttribute("autocapitalize", "none");
    input.setAttribute("autocorrect", "off");
    input.spellcheck = false;
    const add = button("Add", "btn", "submit");
    form.appendChild(label);
    form.appendChild(input);
    form.appendChild(add);
    card.appendChild(form);

    const actions = make("div", "actions");
    const save = button("Save allowlist", "btn btn-accent", "button");
    const discard = button("Discard changes", "btn btn-ghost", "button");
    actions.appendChild(save);
    actions.appendChild(discard);
    card.appendChild(actions);

    const caution = make("p", "status");
    caution.hidden = true;
    const status = make("p", "status");
    status.setAttribute("role", "status");
    status.hidden = true;
    card.appendChild(caution);
    card.appendChild(status);

    function savedList() {
      const settings = state.settings || {};
      return Array.isArray(settings.allow_ips) ? settings.allow_ips.slice() : [];
    }

    function renderList() {
      clear(list);
      if (state.allowDraft.length === 0) {
        list.appendChild(
          make("li", "allow-empty", "The list is empty, so any source address may attempt a login.")
        );
        return;
      }
      state.allowDraft.forEach(function (entry, index) {
        const item = make("li", "allow-item");
        item.appendChild(make("span", "allow-value", entry));
        const remove = button("Remove", "btn btn-ghost", "button");
        remove.setAttribute("aria-label", "Remove " + entry);
        remove.addEventListener("click", function () {
          state.allowDraft.splice(index, 1);
          renderList();
          renderCaution();
          setStatus(status, null, "");
        });
        item.appendChild(remove);
        list.appendChild(item);
      });
    }

    /**
     * The address family of the address this browser is talking to, or null
     * when the host is a name rather than a literal address.
     *
     * `IpGate::permits` is family-strict: an IPv4 rule can never match an IPv6
     * peer and vice versa. A literal host settles the question, because the
     * browser has to reach it over that family; a name (`localhost`, a DNS
     * name) does not, because it may resolve to either.
     */
    function peerFamily() {
      const host = String(window.location.hostname || "").replace(/^\[|\]$/g, "");
      if (host.indexOf(":") !== -1) {
        return 6;
      }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
        return 4;
      }
      return null;
    }

    /**
     * The address family an allowlist entry applies to, or null when the
     * server would refuse to parse it at all.
     *
     * `IpGate::new` accepts only an `IpNet` or an `IpAddr`, so `localhost` is
     * not an entry that covers anything — it is a 400 on save.
     */
    function entryFamily(entry) {
      const value = String(entry).trim();
      const slash = value.indexOf("/");
      const address = slash === -1 ? value : value.slice(0, slash);
      if (address.indexOf(":") !== -1) {
        return 6;
      }
      if (/^\d{1,3}(\.\d{1,3}){3}$/.test(address)) {
        return 4;
      }
      return null;
    }

    /**
     * Warn when a non-empty draft cannot cover the address family this browser
     * is using.
     *
     * Saving such a list locks out a browser running on the same machine until
     * the process restarts, which is exactly the asymmetry the note above
     * describes. It is a warning derived from what the operator typed and from
     * the address this page was loaded from, not a claim about the network.
     *
     * The earlier version of this check listed `::/0` and `127.0.0.0/8` in one
     * "loopback" set, which hid the lockout in both directions: an operator
     * browsing over IPv4 who saved only `::/0` saw no warning and was locked
     * out, because an IPv6 rule never matches an IPv4 peer. It also treated
     * `localhost` as coverage, which is wrong twice over — the server cannot
     * parse it, so the save returned 400 instead of locking anyone out.
     *
     * What this checks is *family* coverage, which is the strongest statement
     * the browser can make: it knows the family of the address it connected to
     * (a literal host settles it, a name does not) but not its own source
     * address, which is the address `IpGate::permits` actually compares. So a
     * draft holding `10.0.0.0/8` while this page is loaded from `127.0.0.1`
     * does not warn: an IPv4 entry is present, and whether it covers this
     * source is a question only the server can answer.
     *
     * When the family cannot be determined (a name, not a literal address) the
     * warning fires unless the draft covers both families: a missed warning
     * costs a restart, a spurious one costs a sentence.
     */
    function renderCaution() {
      const draft = state.allowDraft;
      if (draft.length === 0) {
        setStatus(caution, null, "");
        return;
      }

      const family = peerFamily();
      const families = draft.map(entryFamily);
      const covered =
        family === null
          ? families.indexOf(4) !== -1 && families.indexOf(6) !== -1
          : families.indexOf(family) !== -1;

      if (covered) {
        setStatus(caution, null, "");
        return;
      }

      setStatus(
        caution,
        "warn",
        family === null
          ? "This page was loaded from " +
              window.location.hostname +
              ", which is a name, so this browser's address family cannot be determined here. " +
              "Allowlist rules match one address family only, so a list with entries of a single " +
              "family may lock this browser out until HaosGreen is restarted."
          : "No IPv" +
              family +
              " entry in this list. Allowlist rules match one address family only — an IPv4 rule " +
              "never matches an IPv6 source, and an IPv6 rule never matches an IPv4 source — so if " +
              "you are browsing from this machine, saving this list locks this browser out until " +
              "HaosGreen is restarted."
      );
    }

    state.allowDraft = savedList();
    renderList();
    renderCaution();

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      const value = input.value.trim();
      if (!value) {
        setStatus(status, "error", "Enter an address or a CIDR range before adding it.");
        return;
      }
      // The server parses entries with `ipnet`: an `IpNet` or an `IpAddr`, and
      // nothing else. `localhost` is a host name, so accepting it here only
      // guaranteed a 400 on save.
      if (String(value).toLowerCase() === "localhost") {
        setStatus(
          status,
          "error",
          "localhost is a host name, not an address. Use 127.0.0.1 or ::1."
        );
        return;
      }
      if (state.allowDraft.indexOf(value) !== -1) {
        setStatus(status, "warn", value + " is already in the list.");
        return;
      }
      state.allowDraft.push(value);
      input.value = "";
      renderList();
      renderCaution();
      setStatus(status, null, "");
      input.focus();
    });

    save.addEventListener("click", async function () {
      save.disabled = true;
      setStatus(status, null, "");
      try {
        const body = await api("/api/settings/allow-ips", {
          method: "PUT",
          body: { allow_ips: state.allowDraft }
        });
        state.allowDraft = Array.isArray(body.allow_ips) ? body.allow_ips.slice() : [];
        if (state.settings) {
          state.settings.allow_ips = state.allowDraft.slice();
        }
        renderList();
        renderCaution();

        const empty = body.empty === true || state.allowDraft.length === 0;
        if (empty) {
          setStatus(
            status,
            "ok",
            "Saved. The list is empty, so any source address may attempt a login."
          );
        } else {
          const count = state.allowDraft.length;
          setStatus(
            status,
            "ok",
            "Saved. Only the " +
              count +
              (count === 1 ? " listed entry" : " listed entries") +
              " may reach the dashboard."
          );
        }
      } catch (error) {
        handleFailure(error, status, "The allowlist could not be saved.");
      } finally {
        save.disabled = false;
      }
    });

    discard.addEventListener("click", function () {
      state.allowDraft = savedList();
      renderList();
      renderCaution();
      setStatus(status, "ok", "Unsaved changes discarded.");
    });

    return card;
  }

  /* ── Chat: SSE frame decoding ──────────────────────────────────────────── */

  /*
   * `EventSource` cannot be used for the chat stream. The request is a POST
   * with a JSON body (`{ "message": "..." }`), and `EventSource` can only
   * issue a GET with no body — so there is no way to hand the server the
   * message. The response is therefore read through `fetch`'s `ReadableStream`
   * and the SSE frames are reassembled here.
   *
   * Three properties the decoder has to get right, because a chunk boundary
   * falls wherever the network decides:
   *
   *  * One chunk may hold several frames, and a frame may be split across two
   *    chunks. Frames are therefore accumulated in a buffer and only split on
   *    the frame delimiter (a blank line) — never on the chunk boundary.
   *  * A frame's payload may span several `data:` lines. The server emits one
   *    `data:` line per newline in the text (axum's `Event::data` splits on
   *    `\n` and `\r`), and the SSE spec says the lines are rejoined with
   *    newlines, so a multi-line answer round-trips exactly.
   *  * The keep-alive is a comment frame (`:`), which carries no data and must
   *    not be dispatched as an event.
   *
   * The three functions in the marked region are deliberately free of DOM,
   * network and module state, so they can be sliced out of this file and
   * driven directly by a standalone harness.
   */

  // #region sse-parser

  /**
   * The end of the first complete frame in `buffer`, or null if there is none.
   *
   * A frame ends at a blank line. The spec allows three spellings of that, so
   * all three are searched for and the earliest wins.
   */
  function sseFrameEnd(buffer) {
    const delimiters = ["\r\n\r\n", "\n\n", "\r\r"];
    let at = -1;
    let length = 0;
    for (let i = 0; i < delimiters.length; i += 1) {
      const found = buffer.indexOf(delimiters[i]);
      if (found !== -1 && (at === -1 || found < at)) {
        at = found;
        length = delimiters[i].length;
      }
    }
    return at === -1 ? null : { index: at, length: length };
  }

  /**
   * Parse one frame into `{ kind, data }`, or null when it carries no data.
   *
   * A frame with no `data:` line is not dispatched — that is how the spec
   * treats it, and it is also exactly what the server's keep-alive comment
   * looks like.
   */
  function parseSseFrame(frame) {
    const lines = frame.split(/\r\n|\r|\n/);
    let kind = "";
    const data = [];

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      if (line === "") {
        continue;
      }
      if (line.charAt(0) === ":") {
        // A comment line. The keep-alive is one of these.
        continue;
      }

      const colon = line.indexOf(":");
      let field;
      let value;
      if (colon === -1) {
        field = line;
        value = "";
      } else {
        field = line.slice(0, colon);
        value = line.slice(colon + 1);
        if (value.charAt(0) === " ") {
          value = value.slice(1);
        }
      }

      if (field === "event") {
        kind = value;
      } else if (field === "data") {
        data.push(value);
      }
      // `id` and `retry` are accepted and ignored: this stream is not
      // resumable and the server never sends them.
    }

    if (data.length === 0) {
      return null;
    }
    return { kind: kind, data: data.join("\n") };
  }

  /**
   * An incremental SSE decoder: feed it decoded chunks, get whole events.
   *
   * `onEvent(kind, data)` is called once per dispatched frame, in order.
   */
  function createSseDecoder(onEvent) {
    let buffer = "";

    function drain() {
      for (;;) {
        const end = sseFrameEnd(buffer);
        if (!end) {
          return;
        }
        const frame = buffer.slice(0, end.index);
        buffer = buffer.slice(end.index + end.length);
        const event = parseSseFrame(frame);
        if (event) {
          onEvent(event.kind, event.data);
        }
      }
    }

    return {
      push: function (chunk) {
        if (typeof chunk !== "string" || chunk === "") {
          return;
        }
        buffer += chunk;
        drain();
      },

      /**
       * Dispatch a final frame that never got its blank line.
       *
       * The server always terminates its frames, so in a normal run this is a
       * no-op. It only matters for a stream cut short, where dropping the tail
       * silently would lose the operator's answer. It is deliberately not
       * called after an abort, where the tail is known to be a fragment the
       * operator asked us to stop reading.
       */
      flush: function () {
        if (buffer === "") {
          return;
        }
        const frame = buffer;
        buffer = "";
        const event = parseSseFrame(frame);
        if (event) {
          onEvent(event.kind, event.data);
        }
      }
    };
  }

  // #endregion sse-parser

  /* ── Chat: model ───────────────────────────────────────────────────────── */

  /** How close to the bottom still counts as "following the stream". */
  const FOLLOW_THRESHOLD = 48;

  /**
   * The chat view's model.
   *
   * The transcript lives here rather than in the DOM because `navigate()`
   * empties `#view` on every route change: a run that is still streaming while
   * the operator visits Settings keeps writing into `messages`, and coming
   * back rebuilds the bubbles from it. `dom` is null whenever the view is
   * unmounted, and every DOM write is guarded on it.
   */
  const chat = {
    /** `{ id, turns }` rows, most recently used first, as the server orders them. */
    sessions: [],
    /** Session id -> a preview of its first user turn, once its history is read. */
    titles: {},
    activeId: null,
    /** `{ role, text }` where role is "user", "assistant", "error" or "note". */
    messages: [],
    running: false,
    /** True between the operator pressing Stop and the run winding down. */
    stopping: false,
    /** True when a run is in flight that this tab is not reading a stream for. */
    detached: false,
    /** The AbortController for this tab's in-flight send, or null. */
    controller: null,
    /** Set once the stream reported `done` or `error`. */
    terminal: false,
    /** The state label to show when the run finishes. */
    endState: "Ready",
    /** Whether the log follows new content; cleared when the operator scrolls up. */
    follow: true,
    /** Bumped per selection so a slow history read cannot overwrite a newer one. */
    loadToken: 0,
    dom: null
  };

  /* ── Chat: helpers ─────────────────────────────────────────────────────── */

  function chatPath(id, suffix) {
    return "/api/chat/sessions/" + encodeURIComponent(String(id)) + (suffix || "");
  }

  function describeError(error) {
    if (!error) {
      return "unknown error";
    }
    if (typeof error.message === "string" && error.message !== "") {
      return error.message;
    }
    return String(error);
  }

  function isAbort(error) {
    return !!error && (error.name === "AbortError" || error.code === 20);
  }

  /**
   * The session list from a `GET /api/chat/sessions` body.
   *
   * The route answers `{ "sessions": [...] }`. A bare array is accepted too,
   * so a future change to the envelope does not empty the sidebar silently.
   */
  function normalizeSessions(body) {
    const raw = Array.isArray(body)
      ? body
      : body && Array.isArray(body.sessions)
        ? body.sessions
        : [];
    const sessions = [];
    for (let i = 0; i < raw.length; i += 1) {
      const entry = raw[i];
      if (!entry || typeof entry.id !== "string" || entry.id === "") {
        continue;
      }
      sessions.push({
        id: entry.id,
        turns: typeof entry.turns === "number" && isFinite(entry.turns) ? entry.turns : 0
      });
    }
    return sessions;
  }

  /**
   * The text of one stored turn.
   *
   * `ChatMessage::content` serialises as a bare string for every turn the
   * session store writes, but the type also allows an array of typed parts, so
   * an array is read rather than rendered as "[object Object]".
   */
  function messageText(content) {
    if (typeof content === "string") {
      return content;
    }
    if (!Array.isArray(content)) {
      return "";
    }
    let text = "";
    for (let i = 0; i < content.length; i += 1) {
      const part = content[i];
      if (part && part.type === "text" && typeof part.text === "string") {
        text += part.text;
      }
    }
    return text;
  }

  /** The history from a `GET .../messages` body, as renderable messages. */
  function normalizeMessages(body) {
    const raw = Array.isArray(body)
      ? body
      : body && Array.isArray(body.messages)
        ? body.messages
        : [];
    const messages = [];
    for (let i = 0; i < raw.length; i += 1) {
      const entry = raw[i];
      if (!entry || typeof entry !== "object") {
        continue;
      }
      const role = entry.role === "assistant" ? "assistant" : entry.role === "user" ? "user" : "";
      if (role === "") {
        // Tool and system turns are not part of the operator's conversation.
        continue;
      }
      const text = messageText(entry.content);
      if (text === "") {
        continue;
      }
      messages.push({ role: role, text: text, streaming: false });
    }
    return messages;
  }

  function hasSession(id) {
    for (let i = 0; i < chat.sessions.length; i += 1) {
      if (chat.sessions[i].id === id) {
        return true;
      }
    }
    return false;
  }

  function shortId(id) {
    return String(id).slice(0, 8);
  }

  /** A one-line preview of a conversation, from its first user turn. */
  function rememberTitle(id, messages) {
    for (let i = 0; i < messages.length; i += 1) {
      if (messages[i].role === "user") {
        const text = messages[i].text.replace(/\s+/g, " ").trim();
        if (text !== "") {
          chat.titles[id] = text.length > 60 ? text.slice(0, 57) + "…" : text;
        }
        return;
      }
    }
  }

  function sessionLabel(session) {
    const title = chat.titles[session.id];
    if (title) {
      return title;
    }
    if (session.turns === 0) {
      return "New conversation";
    }
    return "Chat " + shortId(session.id);
  }

  function sessionMeta(session) {
    if (session.turns === 1) {
      return "1 message";
    }
    return session.turns + " messages";
  }

  function lastMessage() {
    return chat.messages.length === 0 ? null : chat.messages[chat.messages.length - 1];
  }

  /** The assistant bubble currently receiving tokens, created if absent. */
  function ensureAssistantMessage() {
    const last = lastMessage();
    if (last && last.role === "assistant" && last.streaming) {
      return last;
    }
    const message = { role: "assistant", text: "", streaming: true };
    chat.messages.push(message);
    return message;
  }

  function markAssistantFinal() {
    for (let i = 0; i < chat.messages.length; i += 1) {
      chat.messages[i].streaming = false;
    }
  }

  function hasAssistantText() {
    const last = lastMessage();
    return !!last && last.role === "assistant" && last.text !== "";
  }

  function pushChatError(message) {
    chat.messages.push({ role: "error", text: String(message), streaming: false });
    chat.endState = "Failed";
    syncChat();
    setChatState("Failed");
  }

  function pushChatNote(message) {
    chat.messages.push({ role: "note", text: String(message), streaming: false });
    syncChat();
  }

  /* ── Chat: rendering ───────────────────────────────────────────────────── */

  function chatEmptyState() {
    const card = make("div", "chat-empty");
    const mark = make("span", "empty-mark");
    mark.appendChild(icon("i-leaf", "icon-lg"));
    card.appendChild(mark);
    card.appendChild(
      make(
        "p",
        "empty-body",
        "Send a message to start. The agent runs with the tools the Telegram bot has, and its answer streams in here as it is written."
      )
    );
    return card;
  }

  const ROLE_LABELS = { user: "You", assistant: "Agent", error: "Error", note: "Note" };

  function chatBubble(message) {
    const root = make("div", "msg msg-" + message.role);
    if (message.role === "error") {
      root.setAttribute("role", "status");
    }
    root.appendChild(make("span", "msg-role", ROLE_LABELS[message.role] || message.role));

    const body = make("div", "msg-body");
    body.textContent = message.text;
    root.appendChild(body);

    if (message.streaming && message.text === "") {
      // Nothing to show yet; the working indicator below the log covers the
      // pause before the first token.
      root.hidden = true;
    }
    return { root: root, body: body };
  }

  function renderChatLog() {
    const dom = chat.dom;
    if (!dom) {
      return;
    }

    clear(dom.log);
    chat.live = null;

    if (chat.messages.length === 0) {
      dom.log.appendChild(chatEmptyState());
      dom.log.setAttribute("aria-busy", "false");
      return;
    }

    for (let i = 0; i < chat.messages.length; i += 1) {
      const bubble = chatBubble(chat.messages[i]);
      dom.log.appendChild(bubble.root);
      if (chat.messages[i].streaming) {
        chat.live = bubble;
      }
    }
    dom.log.setAttribute("aria-busy", chat.running ? "true" : "false");
  }

  function renderChatWorking() {
    const dom = chat.dom;
    if (!dom) {
      return;
    }
    // Only while nothing has been written yet: a run that uses a tool can sit
    // silent for a long time before its first token, and a stream that is
    // already producing text does not need a second "busy" signal.
    dom.working.hidden = !(chat.running && !hasAssistantText());
  }

  function renderChatJump() {
    const dom = chat.dom;
    if (!dom) {
      return;
    }
    dom.jump.hidden = chat.follow;
  }

  function setChatState(text) {
    const dom = chat.dom;
    if (!dom || dom.state.textContent === text) {
      return;
    }
    dom.state.textContent = text;
  }

  function setComposerBusy(busy, focus) {
    const dom = chat.dom;
    if (!dom) {
      return;
    }
    dom.input.disabled = busy;
    dom.send.disabled = busy;
    dom.stop.disabled = !busy;
    if (!busy && focus !== false) {
      dom.input.focus();
    }
  }

  function syncChat() {
    renderChatLog();
    renderChatWorking();
    renderChatJump();
  }

  function autoScrollToEnd(force) {
    const dom = chat.dom;
    if (!dom) {
      return;
    }
    if (force) {
      chat.follow = true;
    }
    if (chat.follow) {
      dom.log.scrollTop = dom.log.scrollHeight;
    }
    renderChatJump();
  }

  function onChatLogScroll() {
    const dom = chat.dom;
    if (!dom) {
      return;
    }
    // The same rule the logs view will need: follow the tail until the
    // operator scrolls away from it, and pick the tail back up when they
    // return to it.
    chat.follow = dom.log.scrollHeight - dom.log.scrollTop - dom.log.clientHeight <= FOLLOW_THRESHOLD;
    renderChatJump();
  }

  function renderSessionPanel() {
    const panel = byId("sidebar-chat");
    const list = byId("session-list");
    const newChat = byId("chat-new");
    if (!panel || !list) {
      return;
    }

    if (state.route !== "/chat") {
      panel.hidden = true;
      clear(list);
      return;
    }
    panel.hidden = false;

    // Starting or switching conversations mid-run would move the stream's
    // tokens into a transcript they do not belong to, so both are frozen while
    // a run is in flight — the same rule the composer follows.
    if (newChat) {
      newChat.disabled = chat.running;
      newChat.title = chat.running ? "Stop the run in progress first." : "";
    }

    clear(list);
    if (chat.sessions.length === 0) {
      list.appendChild(make("li", "session-empty", "No conversations yet."));
      return;
    }

    chat.sessions.forEach(function (session) {
      const item = make("li", "session-item");
      const select = make("button", "session-select", null);
      select.type = "button";
      select.appendChild(make("span", "session-label", sessionLabel(session)));
      select.appendChild(make("span", "session-meta", sessionMeta(session)));

      if (session.id === chat.activeId) {
        select.classList.add("is-active");
        select.setAttribute("aria-current", "true");
      }
      select.disabled = chat.running;
      if (chat.running) {
        select.title = "Stop the run in progress before switching conversations.";
      }
      select.addEventListener("click", function () {
        // Clicking the conversation that is already open re-reads it from the
        // server. That matters after a stop: the run was aborted, so the
        // server kept the question but no answer, while this tab is still
        // showing whatever had streamed in.
        selectSession(session.id, session.id === chat.activeId);
      });

      item.appendChild(select);
      list.appendChild(item);
    });
  }

  function setSessionPanelError(message) {
    const node = byId("session-error");
    if (!node) {
      return;
    }
    if (state.route !== "/chat") {
      setStatus(node, null, "");
      return;
    }
    setStatus(node, "error", message || "");
  }

  /* ── Chat: network ─────────────────────────────────────────────────────── */

  /**
   * A message for a failed send, chosen by status.
   *
   * Each one says what happened and what the operator can do about it, because
   * these five failures look identical from the outside and only one of them
   * (409) is recoverable by pressing Stop.
   */
  function sendFailureMessage(status, raw) {
    const detail = raw ? " " + raw : "";
    switch (status) {
      case 400:
        return "The message was refused by the server and was not sent." + detail;
      case 401:
        return "Your session expired. Sign in again.";
      case 403:
        return "The request was refused." + detail + " If the IP allowlist changed, reload the page.";
      case 404:
        return (
          "This conversation no longer exists — the server restarted, or the session was " +
          "evicted. Start a new chat."
        );
      case 409:
        return (
          "A run is already in progress for this conversation, so the message was not sent. " +
          "Press Stop to cancel it, then send again."
        );
      case 503:
        return "Chat is unavailable:" + detail;
      default:
        return "The message could not be sent (status " + status + ")." + detail;
    }
  }

  async function readBodyText(response) {
    try {
      const raw = await response.text();
      // The server answers errors with a short plain-text body. Truncated so
      // an unexpected HTML error page cannot fill a chat bubble.
      return raw ? raw.trim().slice(0, 200) : "";
    } catch (error) {
      return "";
    }
  }

  function applyChatToken(text) {
    const message = ensureAssistantMessage();
    message.text += text;

    if (chat.dom) {
      if (!chat.live) {
        // The bubble is not in the document — the view was remounted, or the
        // message was created after the last render. Rebuild so the text has
        // somewhere to land instead of being dropped.
        syncChat();
      }
      if (chat.live) {
        chat.live.root.hidden = false;
        chat.live.body.textContent = message.text;
      }
    }
    renderChatWorking();
    setChatState("Streaming…");
    autoScrollToEnd(false);
  }

  function applyChatDone(data) {
    chat.terminal = true;

    let payload = null;
    try {
      payload = JSON.parse(data);
    } catch (error) {
      payload = null;
    }
    if (!payload || typeof payload !== "object") {
      pushChatError("The run finished with a result this page could not read.");
      finishChatRun();
      return;
    }

    if (payload.cancelled === true) {
      markAssistantFinal();
      chat.endState = "Stopped";
      pushChatNote(hasAssistantText() ? "Stopped before the answer was finished." : "Stopped.");
      setChatState("Stopped");
      finishChatRun();
      return;
    }

    if (typeof payload.text === "string" && payload.text !== "") {
      // The terminal payload is authoritative: it is the whole reply, so it
      // also repairs a stream whose chunks were lost.
      const message = ensureAssistantMessage();
      message.text = payload.text;
      message.streaming = false;
    } else {
      markAssistantFinal();
    }
    chat.endState = "Ready";
    finishChatRun();
  }

  function applyChatError(data) {
    chat.terminal = true;

    let message = "";
    try {
      const payload = JSON.parse(data);
      if (payload && typeof payload.message === "string") {
        message = payload.message;
      }
    } catch (error) {
      message = "";
    }
    if (message === "") {
      message = "The agent run failed before it produced an answer.";
    }

    markAssistantFinal();
    pushChatError(message);
    chat.endState = "Failed";
    finishChatRun();
  }

  function handleChatEvent(kind, data) {
    if (!chat.running) {
      // The run this stream belonged to is over — finished, stopped, or
      // abandoned because the session ended. Nothing more belongs in the
      // transcript.
      return;
    }
    if (kind === "token") {
      applyChatToken(data);
      return;
    }
    if (kind === "done") {
      applyChatDone(data);
      return;
    }
    if (kind === "error") {
      applyChatError(data);
      return;
    }
    // The server emits only token, done and error. Anything else is ignored
    // rather than guessed at: rendering an invented kind would be fabrication.
  }

  /** Wind the run down exactly once, whatever ended it. */
  function finishChatRun() {
    if (!chat.running) {
      return;
    }
    chat.running = false;
    chat.stopping = false;
    chat.detached = false;
    chat.controller = null;
    markAssistantFinal();

    // An assistant bubble that never received a character is noise, not an
    // answer.
    chat.messages = chat.messages.filter(function (message) {
      return !(message.role === "assistant" && message.text === "");
    });

    if (chat.activeId) {
      rememberTitle(chat.activeId, chat.messages);
    }

    syncChat();
    setComposerBusy(false);
    setChatState(chat.endState);
    refreshSessionList();
  }

  function restoreComposerText(text) {
    const dom = chat.dom;
    if (!dom || !dom.input || dom.input.value !== "") {
      return;
    }
    dom.input.value = text;
    autosizeComposer(dom.input);
  }

  function autosizeComposer(input) {
    if (!input) {
      return;
    }
    input.style.height = "auto";
    input.style.height = Math.min(input.scrollHeight, 160) + "px";
  }

  /**
   * Send one message and stream the answer.
   *
   * A failure before the stream starts is reported as an error bubble *and*
   * returns the text to the composer: nothing was stored server-side in that
   * case, so the operator should not have to retype it. A failure after the
   * stream started is reported as a bubble only, because the turn really was
   * recorded.
   */
  async function sendChatMessage(text) {
    const sessionId = chat.activeId;
    if (!sessionId || chat.running) {
      return;
    }

    chat.messages.push({ role: "user", text: text, streaming: false });
    chat.messages.push({ role: "assistant", text: "", streaming: true });
    chat.running = true;
    chat.stopping = false;
    chat.detached = false;
    chat.terminal = false;
    chat.endState = "Ready";
    chat.follow = true;

    syncChat();
    setComposerBusy(true);
    setChatState("Working…");
    autoScrollToEnd(true);

    const controller = new AbortController();
    chat.controller = controller;

    // `CSRF_HEADER` is a variable, so the key has to be assigned rather than
    // written into the literal — `{ CSRF_HEADER: "1" }` would send a header
    // literally named "CSRF_HEADER" and the server would answer 403.
    const headers = { "Content-Type": "application/json", Accept: "text/event-stream" };
    headers[CSRF_HEADER] = "1";

    let response;
    try {
      response = await window.fetch(chatPath(sessionId, "/messages"), {
        method: "POST",
        credentials: "same-origin",
        headers: headers,
        body: JSON.stringify({ message: text }),
        signal: controller.signal
      });
    } catch (error) {
      markAssistantFinal();
      chat.messages.pop();
      chat.messages.pop();
      if (chat.stopping || isAbort(error)) {
        // The fetch was cut off, so whether the server ever saw the message is
        // not knowable from here; the turn is dropped from the transcript and
        // the note says only what is certain.
        pushChatNote("Stopped.");
      } else {
        pushChatError(
          "The dashboard server could not be reached. Check that HaosGreen is still running."
        );
        restoreComposerText(text);
      }
      finishChatRun();
      return;
    }

    if (!response.ok) {
      const status = response.status;
      const raw = await readBodyText(response);
      markAssistantFinal();
      chat.messages.pop();
      chat.messages.pop();
      pushChatError(sendFailureMessage(status, raw));

      if (status === 401) {
        showLogin("Your session expired. Sign in again.");
        finishChatRun();
        return;
      }
      if (status === 404) {
        // The id is a dead handle now; do not keep sending to it.
        chat.activeId = null;
        chat.loadToken += 1;
        finishChatRun();
        refreshSessionList();
        return;
      }
      if (status === 409) {
        // A run really is in flight for this session, so the composer stays
        // locked and Stop stays available: cancelling is the way out. The text
        // goes back to the composer because nothing was sent, so it is still
        // there to resend once the other run is stopped.
        chat.detached = true;
        chat.controller = null;
        restoreComposerText(text);
        setComposerBusy(true);
        setChatState("A run is already in flight");
        refreshSessionList();
        return;
      }
      restoreComposerText(text);
      finishChatRun();
      refreshSessionList();
      return;
    }

    if (!response.body || typeof response.body.getReader !== "function") {
      // The server accepted the run, so it is now going with nothing here able
      // to read it. Cancel it rather than leaving it to run unseen and to hold
      // the session's "a run is in flight" claim.
      api(chatPath(sessionId, "/cancel"), { method: "POST" }).catch(function () {
        // Best effort: the message below is what the operator needs to see.
      });
      markAssistantFinal();
      pushChatError(
        "This browser cannot read a streamed response, so the answer cannot be shown here. The run was cancelled."
      );
      finishChatRun();
      return;
    }

    const reader = response.body.getReader();
    const textDecoder = new TextDecoder("utf-8");
    const decoder = createSseDecoder(handleChatEvent);

    try {
      for (;;) {
        const step = await reader.read();
        if (step.done) {
          break;
        }
        decoder.push(textDecoder.decode(step.value, { stream: true }));
      }
      // Whatever is left of a multi-byte character, then a frame that never
      // got its terminating blank line.
      decoder.push(textDecoder.decode());
      if (!chat.stopping) {
        decoder.flush();
      }
    } catch (error) {
      if (chat.running && !chat.stopping && !chat.terminal && !isAbort(error)) {
        markAssistantFinal();
        pushChatError("The stream could not be read: " + describeError(error));
      }
    } finally {
      try {
        const closing = reader.cancel();
        if (closing && typeof closing.catch === "function") {
          closing.catch(function () {
            // The stream is already closed or aborted; nothing to do.
          });
        }
      } catch (error) {
        // Cancelling a reader that is already released throws synchronously.
      }

      if (chat.running && !chat.terminal) {
        markAssistantFinal();
        if (chat.stopping) {
          chat.endState = "Stopped";
          pushChatNote(
            hasAssistantText() ? "Stopped before the answer was finished." : "Stopped."
          );
        } else {
          pushChatError(
            "The stream ended before the run reported a result, so the reply above may be incomplete."
          );
          chat.endState = "Failed";
        }
      }
      finishChatRun();
    }
  }

  /**
   * Stop the run in flight.
   *
   * Both halves are needed. The cancel request is what actually stops the
   * agent server-side; aborting the fetch closes the stream this tab is
   * reading, so the UI does not sit waiting for a run that has been cancelled.
   */
  async function stopChatRun() {
    const sessionId = chat.activeId;
    if (!chat.running || !sessionId) {
      return;
    }

    chat.stopping = true;
    chat.endState = "Stopped";
    const dom = chat.dom;
    if (dom) {
      dom.stop.disabled = true;
    }
    setChatState("Stopping…");

    try {
      await api(chatPath(sessionId, "/cancel"), { method: "POST" });
    } catch (error) {
      if (error && error.status === 401) {
        showLogin("Your session expired. Sign in again.");
      } else {
        pushChatNote(
          "The stop request could not be delivered (" +
            describeError(error) +
            "). The run may still be going."
        );
      }
    }

    if (chat.controller) {
      chat.controller.abort();
    } else {
      // A run started by another tab: there is no stream here to abort, so the
      // cancel request above is the whole of it.
      finishChatRun();
    }
  }

  /* ── Chat: sessions ────────────────────────────────────────────────────── */

  async function refreshSessionList() {
    let body;
    try {
      body = await api("/api/chat/sessions");
    } catch (error) {
      if (error && error.status === 401) {
        showLogin("Your session expired. Sign in again.");
        return false;
      }
      chat.sessions = [];
      renderSessionPanel();
      setSessionPanelError("The conversation list could not be loaded: " + describeError(error));
      return false;
    }

    chat.sessions = normalizeSessions(body);
    if (!chat.running && chat.activeId && !hasSession(chat.activeId)) {
      // Evicted, or the server restarted: the id is a dead handle, and every
      // request against it would answer 404.
      chat.activeId = null;
      chat.messages = [];
      chat.loadToken += 1;
    }
    setSessionPanelError("");
    renderSessionPanel();
    syncChat();
    return true;
  }

  async function createSession() {
    if (chat.running) {
      setSessionPanelError("Stop the run in progress before starting a new conversation.");
      return;
    }

    let body;
    try {
      body = await api("/api/chat/sessions", { method: "POST" });
    } catch (error) {
      if (error && error.status === 401) {
        showLogin("Your session expired. Sign in again.");
        return;
      }
      setSessionPanelError("A new conversation could not be started: " + describeError(error));
      return;
    }

    const id = body && typeof body.id === "string" ? body.id : "";
    if (id === "") {
      setSessionPanelError("The server created a session without an id, so it cannot be used.");
      return;
    }

    chat.loadToken += 1;
    chat.activeId = id;
    chat.messages = [];
    chat.follow = true;
    chat.sessions = [{ id: id, turns: 0 }].concat(
      chat.sessions.filter(function (session) {
        return session.id !== id;
      })
    );
    setSessionPanelError("");
    renderSessionPanel();
    syncChat();
    const dom = chat.dom;
    if (dom) {
      dom.input.focus();
    }
  }

  async function selectSession(id, force) {
    if (chat.running || (!force && id === chat.activeId)) {
      return;
    }

    chat.activeId = id;
    chat.loadToken += 1;
    const token = chat.loadToken;
    renderSessionPanel();

    let body;
    try {
      body = await api(chatPath(id, "/messages"));
    } catch (error) {
      if (token !== chat.loadToken) {
        return;
      }
      if (error && error.status === 401) {
        showLogin("Your session expired. Sign in again.");
        return;
      }
      if (error && error.status === 404) {
        chat.activeId = null;
        chat.messages = [];
        pushChatError(
          "That conversation no longer exists — the server restarted, or it was evicted. Start a new chat."
        );
        refreshSessionList();
        return;
      }
      pushChatError("The conversation could not be loaded: " + describeError(error));
      return;
    }

    if (token !== chat.loadToken) {
      return;
    }
    const messages = normalizeMessages(body);
    rememberTitle(id, messages);
    chat.messages = messages;
    chat.follow = true;
    syncChat();
    autoScrollToEnd(true);
    renderSessionPanel();
  }

  /** Open the most recent conversation, or start one if there are none. */
  async function ensureActiveSession() {
    if (chat.running) {
      return;
    }
    if (chat.activeId) {
      // Forced, because re-entering the view should show the server's current
      // history rather than the copy this tab already holds.
      await selectSession(chat.activeId, true);
      return;
    }
    if (chat.sessions.length > 0) {
      await selectSession(chat.sessions[0].id, true);
      return;
    }
    await createSession();
  }

  /* ── Chat: view ────────────────────────────────────────────────────────── */

  function chatHead() {
    const head = make("div", "card-head");
    const mark = make("span", "card-mark");
    mark.appendChild(icon("i-leaf"));
    head.appendChild(mark);
    head.appendChild(make("h2", "card-title", "Conversation"));

    const actions = make("div", "chat-head-actions");
    const stateNode = make("span", "chat-state", "Ready");
    stateNode.setAttribute("role", "status");
    actions.appendChild(stateNode);

    const stop = button("Stop", "btn btn-stop", "button");
    stop.disabled = true;
    stop.addEventListener("click", stopChatRun);
    actions.appendChild(stop);

    head.appendChild(actions);
    return { head: head, state: stateNode, stop: stop };
  }

  function chatComposer() {
    const form = make("form", "chat-composer");
    form.noValidate = true;

    const input = document.createElement("textarea");
    input.className = "chat-input";
    input.id = "chat-input";
    input.name = "chat-input";
    input.rows = 1;
    input.placeholder = "Message the agent…";
    input.setAttribute("aria-label", "Message");
    input.spellcheck = false;

    const send = button("Send", "btn btn-accent", "submit");

    input.addEventListener("input", function () {
      autosizeComposer(input);
    });

    input.addEventListener("keydown", function (event) {
      if (event.key !== "Enter" || event.shiftKey) {
        return;
      }
      // Never submit mid-composition: an IME uses Enter to accept a candidate.
      if (event.isComposing || event.keyCode === 229) {
        return;
      }
      event.preventDefault();
      if (typeof form.requestSubmit === "function") {
        form.requestSubmit();
      } else {
        form.dispatchEvent(new Event("submit", { cancelable: true }));
      }
    });

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      if (chat.running) {
        return;
      }
      const value = input.value;
      if (value.trim() === "") {
        setStatus(form.note, "error", "Enter a message before sending.");
        return;
      }
      setStatus(form.note, null, "");
      input.value = "";
      autosizeComposer(input);
      sendChatMessage(value).catch(function (error) {
        // `sendChatMessage` handles every failure it knows about; this is the
        // backstop so an unexpected one is shown rather than swallowed as an
        // unhandled rejection.
        pushChatError("The message could not be sent: " + describeError(error));
        finishChatRun();
      });
    });

    const row = make("div", "chat-input-row");
    row.appendChild(input);
    row.appendChild(send);
    form.appendChild(row);

    const note = make("p", "status");
    note.setAttribute("role", "status");
    note.hidden = true;
    form.appendChild(note);
    form.note = note;

    return { form: form, input: input, send: send, note: note };
  }

  function renderChat(host) {
    const card = make("section", "card chat-card");
    const head = chatHead();
    card.appendChild(head.head);

    const log = make("div", "chat-log");
    log.setAttribute("role", "group");
    log.setAttribute("aria-label", "Conversation");
    log.tabIndex = 0;
    log.addEventListener("scroll", onChatLogScroll);
    card.appendChild(log);

    const jump = button("Jump to latest", "btn btn-ghost chat-jump", "button");
    jump.hidden = true;
    jump.addEventListener("click", function () {
      autoScrollToEnd(true);
    });
    card.appendChild(jump);

    const working = make("div", "chat-working");
    working.setAttribute("role", "status");
    working.hidden = true;
    const dots = make("span", "chat-dots");
    dots.appendChild(make("span", "chat-dot"));
    dots.appendChild(make("span", "chat-dot"));
    dots.appendChild(make("span", "chat-dot"));
    working.appendChild(dots);
    working.appendChild(make("span", null, "Working… the agent has not written anything yet."));
    card.appendChild(working);

    const composer = chatComposer();
    card.appendChild(composer.form);

    host.appendChild(card);

    chat.dom = {
      log: log,
      jump: jump,
      working: working,
      state: head.state,
      stop: head.stop,
      input: composer.input,
      send: composer.send,
      note: composer.note
    };

    chat.live = null;
    syncChat();
    setComposerBusy(chat.running, false);
    if (chat.running) {
      setChatState(chat.detached ? "A run is already in flight" : "Working…");
    } else {
      setChatState("Ready");
    }
    autoScrollToEnd(false);

    refreshSessionList()
      .then(function (loaded) {
        return loaded ? ensureActiveSession() : undefined;
      })
      .catch(function (error) {
        setSessionPanelError("The chat view could not be loaded: " + describeError(error));
      });
  }

  /**
   * Drop every reference to the chat view's DOM.
   *
   * `navigate()` empties `#view` before rendering the next route, so this runs
   * on every route change: a run that outlives the view keeps writing into the
   * model, and `syncChat` becomes a no-op until the view is mounted again.
   */
  function chatUnmount() {
    chat.dom = null;
    chat.live = null;
    const panel = byId("sidebar-chat");
    if (panel) {
      panel.hidden = true;
    }
    const list = byId("session-list");
    if (list) {
      clear(list);
    }
    setSessionPanelError("");
  }

  /**
   * Abandon everything chat holds, because the session it belongs to is gone.
   *
   * A run in flight is aborted here rather than left to finish: its tokens
   * would otherwise be appended to a transcript that the next sign-in starts
   * empty, and the server cleans up an abandoned stream on its own.
   */
  function resetChat() {
    if (chat.controller) {
      chat.controller.abort();
    }
    chat.running = false;
    chat.stopping = false;
    chat.detached = false;
    chat.controller = null;
    chat.terminal = false;
    chat.sessions = [];
    chat.titles = {};
    chat.activeId = null;
    chat.messages = [];
    chat.follow = true;
    chat.loadToken += 1;
    chatUnmount();
  }

  /* ── Supervisor ────────────────────────────────────────────────────────── */

  /*
   * The supervisor surface (design spec §5.2, plan Task 16).
   *
   * Four properties here are deliberate, and each is a consequence of what the
   * server actually does rather than of what would look best:
   *
   *  * The listing is polled every five seconds only while this view is mounted
   *    and the document is visible. `supervisorUnmount` clears the timer on
   *    every route change and `visibilitychange` clears it for a background
   *    tab, so a dashboard left open elsewhere is not a permanent reader of the
   *    supervisor's store.
   *  * The four action buttons mirror the server's state machine exactly
   *    (`LIFECYCLE_ACTIONS`), so the operator cannot click an action that is
   *    certain to be refused. That is a convenience, not a guarantee: the state
   *    can move between the render and the click, so a refusal is still handled
   *    and the server's own 409 sentence is shown inline — never via `alert()`.
   *  * `submit` classifies, routes and returns. Nothing runs. The copy in the
   *    submit card and in the outcome panel says so, because from the outside a
   *    task parked in `ROUTE` looks exactly like a queued one.
   *  * `cancel` records `state -> Cancelled` and nothing else: the route holds
   *    no cancellation token for work already in flight. The note next to the
   *    button says that instead of implying the job stops.
   */

  /** How often the task list is re-read while this view is on screen. */
  const SUPERVISOR_POLL_MS = 5000;

  /**
   * The lifecycle actions, in the order they are offered.
   *
   * Each `from` is the set of states in which the server accepts that action,
   * transcribed by hand from `Action::permitted_from` in
   * `src/web/routes/supervisor.rs`: the `transition_allowed` edge into
   * `Paused`, `Cancelled` or `Execute` in `src/supervisor/state.rs`, except for
   * `resume`, which that route narrows to an exact `PAUSED`. This is a
   * transcription and not a derivation — the server stays the authority, so a
   * list that drifts disables a button the server would have accepted rather
   * than offering one it would refuse, and a refusal is still handled: the
   * server's own 409 sentence is shown inline, never via `alert()`.
   *
   * Consequences that are deliberate rather than oversights: `approve` is
   * offered on a `PAUSED` task (`Paused -> Execute` is a legal edge and the
   * server accepts it); `pause` is *not* offered on a `PAUSED` task, because
   * the table has no `Paused -> Paused` edge and the route answers 409 for it;
   * and `cancel` is refused from `VERIFY`, `REPORT`, `ARCHIVE`, `DONE`,
   * `FAILED` and `CLASSIFY`, none of which has an edge to `CANCELLED`.
   */
  const LIFECYCLE_ACTIONS = [
    {
      key: "approve",
      label: "Approve",
      past: "approved",
      icon: "i-check",
      className: "btn btn-accent",
      from: ["ROUTE", "CLARIFY", "PLAN", "PREPAREWORKSPACE", "PAUSED", "REVIEW", "VERIFY"]
    },
    {
      key: "resume",
      label: "Resume",
      past: "resumed",
      icon: "i-play",
      className: "btn",
      from: ["PAUSED"]
    },
    {
      key: "pause",
      label: "Pause",
      past: "paused",
      icon: "i-pause",
      className: "btn",
      from: ["ROUTE", "PLAN", "PREPAREWORKSPACE", "EXECUTE"]
    },
    {
      key: "cancel",
      label: "Cancel",
      past: "cancelled",
      icon: "i-stop",
      className: "btn btn-stop",
      from: [
        "INTAKE",
        "ROUTE",
        "CLARIFY",
        "PLAN",
        "PREPAREWORKSPACE",
        "EXECUTE",
        "REVIEW",
        "PAUSED"
      ]
    }
  ];

  /** The chip colour bucket per state. The chip's text always names the state. */
  const STATE_BUCKETS = {
    INTAKE: "running",
    CLASSIFY: "running",
    PLAN: "running",
    PREPAREWORKSPACE: "running",
    EXECUTE: "running",
    REVIEW: "running",
    VERIFY: "running",
    REPORT: "running",
    ARCHIVE: "running",
    ROUTE: "attention",
    CLARIFY: "attention",
    PAUSED: "paused",
    DONE: "done",
    FAILED: "failed",
    CANCELLED: "cancelled"
  };

  /** `JobStatus`, which serialises lowercase and is a different enum. */
  const JOB_STATUS_BUCKETS = {
    pending: "running",
    running: "running",
    succeeded: "done",
    failed: "failed",
    cancelled: "cancelled"
  };

  /**
   * The supervisor view's model.
   *
   * `dom` is null whenever the view is unmounted, and every DOM write is
   * guarded on it: a listing that arrives after the operator navigated away
   * must not write into a panel that is gone. `selectedId` survives a route
   * change so returning to the view restores the open task.
   */
  const supervisor = {
    /** `{ id, title, state, taskType, risk, priority }` rows, as the server orders them. */
    tasks: [],
    selectedId: null,
    /** The last detail body, or null while it is loading or unread. */
    detail: null,
    /** The last submit result, or null before the first submit. */
    outcome: null,
    dom: null,
    /** The poll interval handle, or null when polling is stopped. */
    timer: null,
    listBusy: false,
    /** Bumped per list read, and on unmount, so a slow response cannot overwrite a newer one. */
    listToken: 0,
    /** A read was asked for while one was in flight: re-run once it settles. */
    listQueued: false,
    /** What the list currently renders, so an unchanged poll does not rebuild it. */
    listSignature: null,
    /** Bumped per detail read so a slow response cannot overwrite a newer one. */
    detailToken: 0,
    actionBusy: false,
    /** True once the server has answered 503: polling a missing supervisor is pointless. */
    unavailable: false
  };

  /* ── Supervisor: small helpers ─────────────────────────────────────────── */

  function numberOr(value, fallback) {
    return typeof value === "number" && isFinite(value) ? value : fallback;
  }

  /**
   * A state as a lookup key.
   *
   * `TaskStatus` serialises with serde's `rename_all = "UPPERCASE"`, which
   * upper-cases the variant name without inserting separators — so
   * `PrepareWorkspace` reaches the browser as `PREPAREWORKSPACE`, not
   * `PREPARE_WORKSPACE`. Punctuation is stripped here so either spelling lands
   * on the same key. A state this build does not know still renders: it gets
   * the neutral chip and no enabled action rather than a crash.
   */
  function stateKey(value) {
    return typeof value === "string" ? value.replace(/[^A-Za-z0-9]/g, "").toUpperCase() : "";
  }

  function stateText(value) {
    return typeof value === "string" && value !== "" ? value : "UNKNOWN";
  }

  function stateBucket(value) {
    return STATE_BUCKETS[stateKey(value)] || "unknown";
  }

  function chipClass(bucket, extraClass) {
    return "chip chip-" + bucket + (extraClass ? " " + extraClass : "");
  }

  function chipFor(bucket, text, extraClass) {
    return make("span", chipClass(bucket, extraClass), text);
  }

  function stateChip(value, extraClass) {
    return chipFor(stateBucket(value), stateText(value), extraClass);
  }

  function jobStatusChip(value) {
    const key = typeof value === "string" ? value.toLowerCase() : "";
    const text = typeof value === "string" && value !== "" ? value.toUpperCase() : "UNKNOWN";
    return chipFor(JOB_STATUS_BUCKETS[key] || "unknown", text);
  }

  /** A small unemphasised pill, used for the non-state facts on a row. */
  function metaChip(text, extraClass) {
    return make("span", "tag" + (extraClass ? " " + extraClass : ""), text);
  }

  /** `code_change` -> `Code Change`; an unknown token is shown as it arrived. */
  function humanizeToken(value) {
    if (typeof value !== "string" || value === "") {
      return "unknown";
    }
    const words = value.split(/[^A-Za-z0-9]+/);
    const out = [];
    for (let i = 0; i < words.length; i += 1) {
      if (words[i] === "") {
        continue;
      }
      out.push(words[i].charAt(0).toUpperCase() + words[i].slice(1));
    }
    return out.length > 0 ? out.join(" ") : "unknown";
  }

  function buttonWithIcon(label, className, iconName) {
    const node = button(label, className, "button");
    node.insertBefore(icon(iconName), node.firstChild);
    return node;
  }

  function clockTime() {
    const now = new Date();
    const pad = function (value) {
      return value < 10 ? "0" + value : String(value);
    };
    return pad(now.getHours()) + ":" + pad(now.getMinutes()) + ":" + pad(now.getSeconds());
  }

  /** A bounded, never-throwing rendering of a JSON value from the server. */
  function compactJson(value, limit) {
    if (value === null || value === undefined) {
      return "";
    }
    let text;
    try {
      text = JSON.stringify(value);
    } catch (ignored) {
      return "";
    }
    if (typeof text !== "string" || text === "" || text === "null") {
      return "";
    }
    return text.length > limit ? text.slice(0, limit) + "…" : text;
  }

  /* ── Supervisor: wire types ────────────────────────────────────────────── */

  /** The `{ tasks: [...] }` body, as renderable rows. */
  function normalizeTasks(body) {
    const raw = Array.isArray(body) ? body : body && Array.isArray(body.tasks) ? body.tasks : [];
    const tasks = [];
    for (let i = 0; i < raw.length; i += 1) {
      const entry = raw[i];
      if (!entry || typeof entry.id !== "string" || entry.id === "") {
        continue;
      }
      tasks.push({
        id: entry.id,
        title: stringOr(entry.title, "(untitled task)"),
        state: stateText(entry.state),
        taskType: stringOr(entry.task_type, "unknown"),
        risk: stringOr(entry.risk_level, "unknown"),
        priority: numberOr(entry.priority, null)
      });
    }
    return tasks;
  }

  /** The detail body. Each part is read defensively: one bad field must not blank the panel. */
  function normalizeDetail(body) {
    const value = body && typeof body === "object" ? body : {};
    return {
      task: value.task && typeof value.task === "object" ? value.task : null,
      jobs: Array.isArray(value.jobs) ? value.jobs : [],
      transitions: Array.isArray(value.transitions) ? value.transitions : [],
      artifacts: Array.isArray(value.artifacts) ? value.artifacts : []
    };
  }

  function normalizeOutcome(body) {
    const value = body && typeof body === "object" ? body : {};
    return {
      taskId: stringOr(value.task_id, ""),
      outcome: stringOr(value.outcome, ""),
      state: typeof value.state === "string" ? value.state : "",
      question: stringOr(value.question, ""),
      reason: stringOr(value.reason, "")
    };
  }

  /* ── Supervisor: submit ────────────────────────────────────────────────── */

  function submitCard() {
    const card = make("section", "card");
    card.appendChild(cardHead("i-shield", "Submit a task"));

    const note = make("p", "card-note");
    note.appendChild(
      document.createTextNode(
        "The supervisor classifies the request, picks a plan and stops there. "
      )
    );
    note.appendChild(make("strong", null, "Nothing runs until you approve the plan."));
    card.appendChild(note);

    const form = make("form", "stack sup-form");
    form.noValidate = true;

    const label = make("label", "field-label", "What should the supervisor do?");
    label.setAttribute("for", "sup-input");
    form.appendChild(label);

    const input = document.createElement("textarea");
    input.className = "sup-input";
    input.id = "sup-input";
    input.name = "sup-input";
    input.rows = 3;
    input.placeholder = "e.g. summarise CHANGELOG.md into a release note";
    input.spellcheck = false;
    form.appendChild(input);

    const actions = make("div", "actions");
    const send = button("Submit", "btn btn-accent", "submit");
    actions.appendChild(send);
    form.appendChild(actions);

    const status = make("p", "status");
    status.setAttribute("role", "status");
    status.hidden = true;
    form.appendChild(status);

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      submitSupervisorTask(input.value);
    });

    // Ctrl/Cmd+Enter submits from inside the textarea. Plain Enter is left
    // alone: a request is often more than one line.
    input.addEventListener("keydown", function (event) {
      if (event.key !== "Enter" || !(event.ctrlKey || event.metaKey)) {
        return;
      }
      event.preventDefault();
      submitSupervisorTask(input.value);
    });

    card.appendChild(form);

    const outcome = make("div", "sup-outcome");
    card.appendChild(outcome);

    return { card: card, form: form, input: input, send: send, status: status, outcome: outcome };
  }

  async function submitSupervisorTask(raw) {
    const dom = supervisor.dom;
    if (!dom || dom.submit.send.disabled) {
      return;
    }
    const text = typeof raw === "string" ? raw.trim() : "";
    if (text === "") {
      // The server answers 400 for this; refusing here saves a round trip and
      // keeps the message next to the field either way.
      setStatus(dom.submit.status, "error", "Enter the request before submitting.");
      return;
    }

    setStatus(dom.submit.status, null, "");
    dom.submit.send.disabled = true;
    dom.submit.send.textContent = "Submitting…";
    try {
      const body = await api("/api/supervisor/tasks", {
        method: "POST",
        body: { text: text }
      });
      dom.submit.input.value = "";
      supervisor.outcome = normalizeOutcome(body);
      paintOutcome();
      await refreshTasks();
    } catch (error) {
      if (error && error.status === 401) {
        handleFailure(error, dom.submit.status, "");
        return;
      }
      setStatus(dom.submit.status, "error", submitFailureMessage(error));
    } finally {
      dom.submit.send.disabled = false;
      dom.submit.send.textContent = "Submit";
    }
  }

  function submitFailureMessage(error) {
    if (!error) {
      return "The task could not be submitted.";
    }
    if (error.status === 503) {
      return "This dashboard was started without a supervisor, so nothing can be submitted.";
    }
    if (error.status === 400) {
      return error.message || "The task text must not be empty.";
    }
    return error.message || "The task could not be submitted.";
  }

  function outcomeTitle(result) {
    if (result.outcome === "needs_approval") {
      return "Parked — this task needs your approval";
    }
    if (result.outcome === "needs_clarification") {
      return "Parked — the supervisor needs an answer";
    }
    if (result.outcome === "auto_execute_planned") {
      return "Plan ready — nothing has run yet";
    }
    return "Submitted";
  }

  function outcomeBody(result) {
    if (result.outcome === "needs_approval") {
      return (
        "The task is not queued and is not running. It is held in state " +
        stateText(result.state) +
        " until you approve it, and it will not start on its own."
      );
    }
    if (result.outcome === "needs_clarification") {
      return (
        "The task is not queued and is not running. It is held in state " +
        stateText(result.state) +
        " waiting for an answer. This dashboard cannot answer a clarification " +
        "for you, but the task is not stuck: it can still be approved — which " +
        "runs it as it stands — or cancelled from its detail panel."
      );
    }
    if (result.outcome === "auto_execute_planned") {
      return (
        "The request was classified and a plan was picked. Submitting does not " +
        "execute anything: the task is parked in state " +
        stateText(result.state) +
        " and runs only when you press Approve."
      );
    }
    return "The task was created in state " + stateText(result.state) + ".";
  }

  function paintOutcome() {
    const dom = supervisor.dom;
    if (!dom) {
      return;
    }
    clear(dom.submit.outcome);

    const result = supervisor.outcome;
    if (!result) {
      return;
    }

    const block = make("div", "parked");
    block.setAttribute("role", "status");

    const head = make("div", "parked-head");
    head.appendChild(icon("i-shield", "icon-lg"));
    head.appendChild(make("h3", "parked-title", outcomeTitle(result)));
    head.appendChild(stateChip(result.state));
    block.appendChild(head);

    block.appendChild(make("p", "parked-body", outcomeBody(result)));

    if (result.reason !== "") {
      const reason = make("p", "parked-detail");
      reason.appendChild(make("strong", null, "Reason: "));
      reason.appendChild(document.createTextNode(result.reason));
      block.appendChild(reason);
    }
    if (result.question !== "") {
      const question = make("p", "parked-detail");
      question.appendChild(make("strong", null, "Question: "));
      question.appendChild(document.createTextNode(result.question));
      block.appendChild(question);
    }

    if (result.taskId !== "") {
      const actions = make("div", "actions");
      const open = button("Open this task", "btn", "button");
      open.addEventListener("click", function () {
        selectTask(result.taskId);
      });
      actions.appendChild(open);
      block.appendChild(actions);
    }

    dom.submit.outcome.appendChild(block);
  }

  /* ── Supervisor: the task list ─────────────────────────────────────────── */

  function listCard() {
    const card = make("section", "card");

    const head = cardHead("i-bars", "Recent tasks");
    const state = make("span", "sup-list-state", "");
    state.setAttribute("role", "status");
    head.appendChild(state);
    card.appendChild(head);

    const note = make(
      "p",
      "card-note",
      "The twenty most recent tasks, newest first. The list is re-read every five seconds while this view is open."
    );
    card.appendChild(note);

    const listStatus = make("p", "status");
    listStatus.setAttribute("role", "status");
    listStatus.hidden = true;
    card.appendChild(listStatus);

    const list = make("div", "task-list");
    card.appendChild(list);

    return { card: card, list: list, listStatus: listStatus, state: state };
  }

  /** A centred, tasteful "nothing here" block — never a blank panel. */
  function supervisorNotice(iconName, titleText, bodyText) {
    const box = make("div", "empty-state sup-notice");
    const mark = make("div", "empty-mark");
    mark.appendChild(icon(iconName, "icon-lg"));
    box.appendChild(mark);
    box.appendChild(make("h3", "empty-title", titleText));
    box.appendChild(make("p", "empty-body", bodyText));
    return box;
  }

  function taskRow(task) {
    const selected = task.id === supervisor.selectedId;
    const row = make("button", "task-row" + (selected ? " is-selected" : ""));
    row.type = "button";
    row.setAttribute("data-task-id", task.id);
    row.setAttribute("aria-pressed", selected ? "true" : "false");

    const top = make("div", "task-row-top");
    top.appendChild(make("span", "task-title", task.title));
    top.appendChild(stateChip(task.state));
    row.appendChild(top);

    const meta = make("div", "task-meta");
    meta.appendChild(metaChip(humanizeToken(task.taskType)));
    const riskKey = task.risk.toLowerCase();
    meta.appendChild(
      metaChip(
        humanizeToken(task.risk) + " risk",
        riskKey === "high" ? "tag-danger" : riskKey === "medium" ? "tag-attention" : ""
      )
    );
    if (task.priority !== null) {
      meta.appendChild(metaChip("Priority " + task.priority));
    }
    meta.appendChild(metaChip("id " + shortId(task.id)));
    row.appendChild(meta);

    row.addEventListener("click", function () {
      selectTask(task.id);
    });
    return row;
  }

  /**
   * What the list currently renders.
   *
   * A poll that finds nothing new must not rebuild the rows: a rebuild would
   * drop the operator's focus and any text they had selected, every five
   * seconds. The signature is compared before the rebuild, not after.
   */
  function listSignature() {
    const parts = [supervisor.unavailable ? "down" : "up", supervisor.selectedId || "-"];
    for (let i = 0; i < supervisor.tasks.length; i += 1) {
      const task = supervisor.tasks[i];
      parts.push(
        [task.id, task.title, task.state, task.taskType, task.risk, task.priority].join("~")
      );
    }
    return parts.join("|");
  }

  function focusedTaskId() {
    const active = document.activeElement;
    if (active && active.classList && active.classList.contains("task-row")) {
      return active.getAttribute("data-task-id");
    }
    return null;
  }

  function restoreTaskFocus(id) {
    const dom = supervisor.dom;
    if (!dom || !id) {
      return;
    }
    const rows = dom.list.children;
    for (let i = 0; i < rows.length; i += 1) {
      if (rows[i].getAttribute && rows[i].getAttribute("data-task-id") === id) {
        rows[i].focus();
        return;
      }
    }
  }

  function paintTaskList() {
    const dom = supervisor.dom;
    if (!dom) {
      return;
    }
    const signature = listSignature();
    if (signature === supervisor.listSignature) {
      return;
    }
    supervisor.listSignature = signature;

    const focused = focusedTaskId();
    clear(dom.list);

    if (supervisor.unavailable) {
      dom.list.appendChild(
        supervisorNotice(
          "i-shield",
          "The supervisor is not wired into this dashboard",
          "Every /api/supervisor route answers 503 when HaosGreen is started without a supervisor, so no task can be listed or driven from here."
        )
      );
      return;
    }

    if (supervisor.tasks.length === 0) {
      dom.list.appendChild(
        supervisorNotice(
          "i-shield",
          "No tasks yet",
          "Submit a request above. It is classified and routed first; nothing runs until the plan is approved."
        )
      );
      return;
    }

    for (let i = 0; i < supervisor.tasks.length; i += 1) {
      dom.list.appendChild(taskRow(supervisor.tasks[i]));
    }

    if (supervisor.selectedId === null) {
      dom.list.appendChild(
        make("p", "sup-note", "Select a task to see its jobs, timeline and artifacts.")
      );
    }
    restoreTaskFocus(focused);
  }

  /* ── Supervisor: polling ───────────────────────────────────────────────── */

  function supervisorStartPolling() {
    if (supervisor.timer !== null || !supervisor.dom || supervisor.unavailable) {
      return;
    }
    supervisor.timer = window.setInterval(function () {
      refreshTasks();
    }, SUPERVISOR_POLL_MS);
  }

  function supervisorStopPolling() {
    if (supervisor.timer !== null) {
      window.clearInterval(supervisor.timer);
      supervisor.timer = null;
    }
  }

  function onSupervisorVisibility() {
    if (!supervisor.dom) {
      return;
    }
    if (document.hidden) {
      supervisorStopPolling();
      return;
    }
    refreshTasks();
    supervisorStartPolling();
  }

  /**
   * Re-read the listing.
   *
   * Two races are handled here, and both use the shape the detail panel already
   * uses for the same problem:
   *
   *  * A response is applied only while it still owns `listToken`. That guard
   *    cannot be `dom !== null` on its own: `supervisorUnmount` nulls `dom` and
   *    a fast remount restores it before a slow response lands, so a listing
   *    read before the operator navigated away would overwrite the newer
   *    snapshot the remount asked for. `supervisorUnmount` bumps the token, so
   *    every request issued before it is dropped on arrival.
   *  * A request that arrives while one is in flight is remembered in
   *    `listQueued` and re-issued once that one settles, instead of being
   *    dropped. `runSupervisorAction` awaits a refresh because the list is
   *    stale the moment an action returns; returning early there would leave
   *    the row's chip on the pre-action state until the next poll, five
   *    seconds later, while the detail panel beside it was already fresh.
   */
  async function refreshTasks() {
    if (!supervisor.dom) {
      return;
    }
    if (supervisor.listBusy) {
      supervisor.listQueued = true;
      return;
    }
    supervisor.listBusy = true;
    supervisor.listToken += 1;
    const token = supervisor.listToken;
    try {
      const body = await api("/api/supervisor/tasks");
      if (token !== supervisor.listToken || !supervisor.dom) {
        return;
      }
      supervisor.unavailable = false;
      supervisor.tasks = normalizeTasks(body);
      setStatus(supervisor.dom.listStatus, null, "");
      paintTaskList();
      supervisor.dom.listState.textContent = "Updated " + clockTime();
      if (supervisor.selectedId !== null) {
        refreshDetail(supervisor.selectedId);
      }
    } catch (error) {
      if (token !== supervisor.listToken || !supervisor.dom) {
        return;
      }
      if (error && error.status === 401) {
        handleFailure(error, null, "");
        return;
      }
      if (error && error.status === 503) {
        // Nothing to retry against: stop the timer and say so once.
        supervisor.unavailable = true;
        supervisor.tasks = [];
        supervisor.selectedId = null;
        supervisor.detail = null;
        supervisorStopPolling();
        removeDetailCard();
        supervisor.dom.listState.textContent = "Unavailable";
        paintTaskList();
        return;
      }
      setStatus(
        supervisor.dom.listStatus,
        "error",
        ((error && error.message) || "The task list could not be read.") +
          " The dashboard will try again in five seconds."
      );
    } finally {
      // Only the request that still owns the token may release the flag. A
      // stale response settling after a remount must not clear the newer
      // request's hold on it, or a third fetch would run beside it.
      if (token === supervisor.listToken) {
        supervisor.listBusy = false;
        if (supervisor.listQueued) {
          supervisor.listQueued = false;
          refreshTasks();
        }
      }
    }
  }

  /* ── Supervisor: the detail panel ──────────────────────────────────────── */

  function selectTask(id) {
    const dom = supervisor.dom;
    if (!dom || typeof id !== "string" || id === "") {
      return;
    }
    supervisor.selectedId = id;
    supervisor.detail = null;
    // The submit panel describes one task's outcome in the present tense. Once
    // the operator opens that task the panel is stale, so it goes.
    supervisor.outcome = null;
    paintOutcome();
    mountDetailCard();
    paintTaskList();

    if (dom.detail) {
      clear(dom.detail.body);
      clear(dom.detail.facts);
      dom.detail.title.textContent = "Loading…";
      dom.detail.chip.className = chipClass("unknown", "sup-detail-chip");
      dom.detail.chip.textContent = "…";
      dom.detail.request.textContent = "";
      dom.detail.capsWrap.hidden = true;
      setStatus(dom.detail.actionStatus, null, "");
      setDetailActions("");
    }
    refreshDetail(id);
    scrollToDetail();
  }

  function clearSelection() {
    const dom = supervisor.dom;
    supervisor.selectedId = null;
    supervisor.detail = null;
    supervisor.detailToken += 1;
    removeDetailCard();
    paintTaskList();
    if (dom) {
      setStatus(dom.listStatus, null, "");
    }
  }

  function removeDetailCard() {
    const dom = supervisor.dom;
    if (dom && dom.detail) {
      if (dom.detail.card.parentNode === dom.host) {
        dom.host.removeChild(dom.detail.card);
      }
      dom.detail = null;
    }
  }

  function mountDetailCard() {
    const dom = supervisor.dom;
    if (!dom || dom.detail) {
      return;
    }
    dom.detail = detailCard();
    dom.host.appendChild(dom.detail.card);
  }

  function detailCard() {
    const card = make("section", "card sup-detail");

    const head = make("div", "card-head");
    const mark = make("span", "card-mark");
    mark.appendChild(icon("i-shield"));
    head.appendChild(mark);
    head.appendChild(make("h2", "card-title", "Task detail"));
    const chip = stateChip("", "sup-detail-chip");
    head.appendChild(chip);
    const close = button("Close", "btn btn-ghost", "button");
    close.addEventListener("click", clearSelection);
    head.appendChild(close);
    card.appendChild(head);

    const title = make("h3", "sup-title");
    card.appendChild(title);

    const facts = make("dl", "facts sup-facts");
    card.appendChild(facts);

    const requestWrap = make("div", "sup-section");
    requestWrap.appendChild(make("h3", "sup-section-title", "Request"));
    const request = make("p", "well");
    requestWrap.appendChild(request);
    card.appendChild(requestWrap);

    const capsWrap = make("div", "sup-section");
    capsWrap.appendChild(make("h3", "sup-section-title", "Required capabilities"));
    const caps = make("div", "tags");
    capsWrap.appendChild(caps);
    card.appendChild(capsWrap);

    const actionsWrap = make("div", "sup-section");
    actionsWrap.appendChild(make("h3", "sup-section-title", "Lifecycle"));
    const actions = make("div", "actions sup-actions");
    const buttons = {};
    for (let i = 0; i < LIFECYCLE_ACTIONS.length; i += 1) {
      const spec = LIFECYCLE_ACTIONS[i];
      const node = buttonWithIcon(spec.label, spec.className, spec.icon);
      node.disabled = true;
      node.setAttribute("data-action", spec.key);
      node.addEventListener("click", function () {
        runSupervisorAction(spec.key);
      });
      buttons[spec.key] = node;
      actions.appendChild(node);
    }
    actionsWrap.appendChild(actions);
    actionsWrap.appendChild(
      make(
        "p",
        "card-note sup-cancel-note",
        "Cancel marks the task CANCELLED. It does not stop a job that is already running — the supervisor holds no cancellation token for work in flight."
      )
    );
    const actionStatus = make("p", "status");
    actionStatus.setAttribute("role", "status");
    actionStatus.hidden = true;
    actionsWrap.appendChild(actionStatus);
    card.appendChild(actionsWrap);

    const body = make("div", "sup-detail-body");
    card.appendChild(body);

    return {
      card: card,
      chip: chip,
      title: title,
      facts: facts,
      request: request,
      capsWrap: capsWrap,
      caps: caps,
      buttons: buttons,
      actionStatus: actionStatus,
      body: body,
      /** The state the last paint saw; the buttons are derived from it. */
      state: ""
    };
  }

  function setDetailActions(state) {
    const dom = supervisor.dom;
    const detail = dom && dom.detail;
    if (!detail) {
      return;
    }
    const key = stateKey(state);
    for (let i = 0; i < LIFECYCLE_ACTIONS.length; i += 1) {
      const spec = LIFECYCLE_ACTIONS[i];
      const node = detail.buttons[spec.key];
      const permitted = key !== "" && spec.from.indexOf(key) !== -1;
      node.disabled = !permitted || supervisor.actionBusy;
      node.title = permitted
        ? ""
        : "A task in state " + stateText(state) + " cannot be " + spec.past + ".";
    }
  }

  async function refreshDetail(id) {
    if (!supervisor.dom || typeof id !== "string" || id === "") {
      return;
    }
    supervisor.detailToken += 1;
    const token = supervisor.detailToken;
    try {
      const body = await api("/api/supervisor/tasks/" + encodeURIComponent(id));
      if (token !== supervisor.detailToken || !supervisor.dom || supervisor.selectedId !== id) {
        return;
      }
      supervisor.detail = normalizeDetail(body);
      paintDetail();
    } catch (error) {
      if (token !== supervisor.detailToken || !supervisor.dom || supervisor.selectedId !== id) {
        return;
      }
      if (error && error.status === 401) {
        handleFailure(error, null, "");
        return;
      }
      if (error && error.status === 404) {
        clearSelection();
        setStatus(
          supervisor.dom.listStatus,
          "error",
          "That task is not in the supervisor's store any more."
        );
        return;
      }
      setStatus(
        supervisor.dom.listStatus,
        "error",
        (error && error.message) || "The task could not be read."
      );
    }
  }

  function paintDetail() {
    const dom = supervisor.dom;
    const detail = dom && dom.detail;
    if (!detail) {
      return;
    }
    const data = supervisor.detail || { task: null, jobs: [], transitions: [], artifacts: [] };
    const task = data.task;

    clear(detail.facts);
    clear(detail.body);
    clear(detail.caps);

    if (!task) {
      detail.chip.className = chipClass("unknown", "sup-detail-chip");
      detail.chip.textContent = "UNKNOWN";
      detail.title.textContent = "This task could not be read";
      detail.request.textContent = "The supervisor did not return a task for this id.";
      detail.capsWrap.hidden = true;
      detail.state = "";
      setDetailActions("");
      detail.body.appendChild(
        supervisorNotice(
          "i-shield",
          "Nothing to show",
          "The detail response did not carry a task object, so no jobs, timeline or artifacts can be listed."
        )
      );
      return;
    }

    detail.state = typeof task.state === "string" ? task.state : "";
    detail.chip.className = chipClass(stateBucket(task.state), "sup-detail-chip");
    detail.chip.textContent = stateText(task.state);
    detail.title.textContent = stringOr(task.title, "(untitled task)");
    detail.request.textContent = stringOr(task.user_request, "(no request text was stored)");

    addFact(detail.facts, "Type", humanizeToken(stringOr(task.task_type, "unknown")));
    addFact(detail.facts, "Risk", humanizeToken(stringOr(task.risk_level, "unknown")));
    addFact(
      detail.facts,
      "Priority",
      task.priority === undefined || task.priority === null
        ? "unknown"
        : String(numberOr(task.priority, "unknown"))
    );
    addFact(
      detail.facts,
      "Execution mode",
      humanizeToken(stringOr(task.execution_mode, "unknown"))
    );
    addFact(detail.facts, "Task id", stringOr(task.id, "(no id)"));

    const caps = Array.isArray(task.required_capabilities) ? task.required_capabilities : [];
    detail.capsWrap.hidden = false;
    if (caps.length === 0) {
      detail.caps.appendChild(make("span", "sup-empty", "None recorded."));
    } else {
      for (let i = 0; i < caps.length; i += 1) {
        detail.caps.appendChild(metaChip(String(caps[i])));
      }
    }

    setDetailActions(detail.state);
    detail.body.appendChild(jobsSection(data.jobs));
    detail.body.appendChild(transitionsSection(data.transitions));
    detail.body.appendChild(artifactsSection(data.artifacts));
  }

  function sectionWrap(titleText) {
    const wrap = make("div", "sup-section");
    wrap.appendChild(make("h3", "sup-section-title", titleText));
    return wrap;
  }

  function jobsSection(jobs) {
    const wrap = sectionWrap("Jobs");
    if (jobs.length === 0) {
      wrap.appendChild(
        make("p", "sup-empty", "No jobs have been dispatched for this task yet.")
      );
      return wrap;
    }
    const list = make("div", "job-list");
    for (let i = 0; i < jobs.length; i += 1) {
      list.appendChild(jobCard(jobs[i]));
    }
    wrap.appendChild(list);
    return wrap;
  }

  function evidenceText(evidence) {
    if (!evidence || typeof evidence !== "object") {
      return "Evidence recorded.";
    }
    const kind = typeof evidence.kind === "string" ? evidence.kind : "";
    if (kind === "exit_code") {
      return "Exit code " + String(numberOr(evidence.code, "unknown"));
    }
    if (kind === "file_created") {
      return "File created: " + stringOr(evidence.path, "(no path)");
    }
    if (kind === "test_passed") {
      return "Test passed: " + stringOr(evidence.name, "(unnamed)");
    }
    if (kind === "output_validated") {
      return "Output validated: " + stringOr(evidence.description, "(no description)");
    }
    if (kind === "log_stored") {
      return "Log stored: " + stringOr(evidence.path, "(no path)");
    }
    // An evidence kind this build does not know is named, not dropped.
    return kind === "" ? "Evidence recorded." : "Evidence (" + humanizeToken(kind) + ")";
  }

  function jobCard(raw) {
    const job = raw && typeof raw === "object" ? raw : {};
    const item = make("article", "job");

    const head = make("div", "job-head");
    head.appendChild(make("span", "job-type", humanizeToken(stringOr(job.job_type, "unknown"))));
    head.appendChild(metaChip(stringOr(job.backend, "unknown backend")));
    head.appendChild(jobStatusChip(job.status));
    item.appendChild(head);

    item.appendChild(make("p", "job-goal", stringOr(job.goal, "(no goal recorded)")));

    const meta = make("div", "job-meta");
    meta.appendChild(metaChip("id " + shortId(stringOr(job.id, "?"))));
    meta.appendChild(metaChip("timeout " + String(numberOr(job.timeout_secs, "?")) + "s"));
    meta.appendChild(
      metaChip(
        "retries " + String(numberOr(job.retry_count, 0)) + "/" + String(numberOr(job.retry_max, 0))
      )
    );
    if (typeof job.parent_job_id === "string" && job.parent_job_id !== "") {
      meta.appendChild(metaChip("parent " + shortId(job.parent_job_id)));
    }
    if (typeof job.workspace === "string" && job.workspace !== "") {
      meta.appendChild(metaChip("workspace " + job.workspace));
    }
    item.appendChild(meta);

    const tools = Array.isArray(job.allow_tools) ? job.allow_tools : [];
    if (tools.length > 0) {
      const row = make("div", "job-meta");
      for (let i = 0; i < tools.length; i += 1) {
        row.appendChild(metaChip(String(tools[i])));
      }
      item.appendChild(row);
    }

    const result = job.result && typeof job.result === "object" ? job.result : null;
    if (result) {
      const box = make("div", "job-result");
      box.appendChild(make("p", "job-summary", stringOr(result.summary, "(no summary recorded)")));

      const evidence = Array.isArray(result.evidence) ? result.evidence : [];
      if (evidence.length > 0) {
        box.appendChild(make("p", "job-label", "Evidence"));
        const list = make("ul", "evidence");
        for (let i = 0; i < evidence.length; i += 1) {
          list.appendChild(make("li", "evidence-item", evidenceText(evidence[i])));
        }
        box.appendChild(list);
      }

      const changed = Array.isArray(result.changed_files) ? result.changed_files : [];
      if (changed.length > 0) {
        box.appendChild(make("p", "job-label", "Changed files"));
        const list = make("ul", "evidence");
        for (let i = 0; i < changed.length; i += 1) {
          list.appendChild(make("li", "evidence-item", String(changed[i])));
        }
        box.appendChild(list);
      }

      const errors = Array.isArray(result.errors) ? result.errors : [];
      if (errors.length > 0) {
        box.appendChild(make("p", "job-label", "Errors"));
        const list = make("ul", "evidence");
        for (let i = 0; i < errors.length; i += 1) {
          list.appendChild(make("li", "job-error", String(errors[i])));
        }
        box.appendChild(list);
      }

      if (typeof result.next_step === "string" && result.next_step !== "") {
        box.appendChild(make("p", "job-next", "Next step: " + result.next_step));
      }
      item.appendChild(box);
    }

    if (typeof job.error === "string" && job.error !== "") {
      item.appendChild(make("p", "job-error", job.error));
    }

    if (typeof job.prompt === "string" && job.prompt !== "") {
      const details = document.createElement("details");
      details.className = "job-details";
      details.appendChild(make("summary", null, "Prompt"));
      details.appendChild(make("p", "well", job.prompt));
      item.appendChild(details);
    }

    const context = compactJson(job.input_context, 400);
    if (context !== "") {
      const details = document.createElement("details");
      details.className = "job-details";
      details.appendChild(make("summary", null, "Input context"));
      details.appendChild(make("p", "well", context));
      item.appendChild(details);
    }

    return item;
  }

  function transitionsSection(transitions) {
    const wrap = sectionWrap("Timeline");
    if (transitions.length === 0) {
      wrap.appendChild(make("p", "sup-empty", "No state transitions have been recorded for this task."));
      return wrap;
    }
    const list = make("ol", "timeline");
    for (let i = 0; i < transitions.length; i += 1) {
      const raw = transitions[i];
      const entry = raw && typeof raw === "object" ? raw : {};
      const item = make("li", "timeline-item");

      const head = make("div", "timeline-head");
      head.appendChild(stateChip(entry.from));
      head.appendChild(make("span", "timeline-arrow", "→"));
      head.appendChild(stateChip(entry.to));
      item.appendChild(head);

      const meta = make("div", "timeline-meta");
      meta.appendChild(metaChip("actor " + stringOr(entry.actor, "unknown")));
      if (typeof entry.occurred_at === "string" && entry.occurred_at !== "") {
        meta.appendChild(metaChip(entry.occurred_at));
      }
      item.appendChild(meta);

      if (typeof entry.reason === "string" && entry.reason !== "") {
        item.appendChild(make("p", "timeline-reason", entry.reason));
      }
      list.appendChild(item);
    }
    wrap.appendChild(list);
    wrap.appendChild(make("p", "sup-note", "Timestamps are the supervisor's UTC clock."));
    return wrap;
  }

  function artifactsSection(artifacts) {
    const wrap = sectionWrap("Artifacts");
    if (artifacts.length === 0) {
      wrap.appendChild(make("p", "sup-empty", "No artifacts have been written for this task yet."));
      return wrap;
    }
    const list = make("ul", "artifact-list");
    for (let i = 0; i < artifacts.length; i += 1) {
      const raw = artifacts[i];
      const entry = raw && typeof raw === "object" ? raw : {};
      const item = make("li", "artifact");
      item.appendChild(metaChip(stringOr(entry.kind, "artifact")));
      item.appendChild(make("code", "artifact-path", stringOr(entry.path, "(no path)")));
      list.appendChild(item);
    }
    wrap.appendChild(list);
    wrap.appendChild(
      make(
        "p",
        "sup-note",
        "Paths are relative to the supervisor's artifacts directory. The dashboard does not serve artifact contents."
      )
    );
    return wrap;
  }

  /* ── Supervisor: lifecycle actions ─────────────────────────────────────── */

  function actionSuccessMessage(key, state) {
    const now = stateText(state);
    if (key === "cancel") {
      return (
        "Cancelled. The task is now " + now + ". Work already in flight is not stopped by this."
      );
    }
    const label = key.charAt(0).toUpperCase() + key.slice(1);
    return label + " accepted. The task is now " + now + ".";
  }

  function actionFailureMessage(key, error) {
    const label = key.charAt(0).toUpperCase() + key.slice(1);
    if (!error) {
      return label + " could not be completed.";
    }
    if (error.status === 409) {
      // The server's own sentence names the state that refused it.
      return (
        "The supervisor refused that: " +
        (error.message || "the task is no longer in a state that allows it.")
      );
    }
    if (error.status === 503) {
      return "This dashboard was started without a supervisor.";
    }
    return error.message || label + " could not be completed.";
  }

  async function runSupervisorAction(key) {
    const dom = supervisor.dom;
    const detail = dom && dom.detail;
    const id = supervisor.selectedId;
    if (!detail || !id || supervisor.actionBusy) {
      return;
    }

    supervisor.actionBusy = true;
    setDetailActions(detail.state);
    setStatus(detail.actionStatus, null, "");

    try {
      const body = await api(
        "/api/supervisor/tasks/" + encodeURIComponent(id) + "/" + encodeURIComponent(key),
        { method: "POST" }
      );
      const state = body && typeof body.state === "string" ? body.state : "";
      setStatus(detail.actionStatus, "ok", actionSuccessMessage(key, state));
    } catch (error) {
      if (error && error.status === 401) {
        handleFailure(error, detail.actionStatus, "");
        return;
      }
      if (error && error.status === 404) {
        // The task is gone from the store, so the panel goes with it. The
        // message moves to the list, which is the panel that survives.
        clearSelection();
        setStatus(
          supervisor.dom ? supervisor.dom.listStatus : null,
          "error",
          "The supervisor does not know that task any more."
        );
        return;
      }
      setStatus(detail.actionStatus, "error", actionFailureMessage(key, error));
    } finally {
      supervisor.actionBusy = false;
    }

    // Whether it succeeded or was refused, the state may have moved: re-read
    // both surfaces so the buttons and the chips match the server again. The
    // action status line is a sibling of the repainted regions, so a refusal
    // message survives this refresh.
    await refreshDetail(id);
    await refreshTasks();
    if (supervisor.dom && supervisor.dom.detail) {
      setDetailActions(supervisor.dom.detail.state);
    }
  }

  /* ── Supervisor: view ──────────────────────────────────────────────────── */

  function scrollToDetail() {
    const dom = supervisor.dom;
    if (!dom || !dom.detail || typeof dom.detail.card.scrollIntoView !== "function") {
      return;
    }
    const reduce =
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    dom.detail.card.scrollIntoView({ block: "start", behavior: reduce ? "auto" : "smooth" });
  }

  function renderSupervisor(host) {
    const submit = submitCard();
    const list = listCard();
    host.appendChild(submit.card);
    host.appendChild(list.card);

    supervisor.dom = {
      host: host,
      list: list.list,
      listStatus: list.listStatus,
      listState: list.state,
      submit: submit,
      detail: null
    };
    supervisor.listSignature = null;
    supervisor.tasks = [];
    supervisor.unavailable = false;

    // `removeEventListener` first: it is idempotent, and it keeps a re-entry
    // from registering the visibility handler twice.
    document.removeEventListener("visibilitychange", onSupervisorVisibility);
    document.addEventListener("visibilitychange", onSupervisorVisibility);

    paintOutcome();
    paintTaskList();
    refreshTasks();
    // `visibilitychange` never fires for the state a document is loaded in, so
    // a dashboard opened directly at `#/supervisor` in a background tab would
    // otherwise poll every five seconds until it was first shown. A hidden tab
    // starts polling from its first visibility event instead.
    if (!document.hidden) {
      supervisorStartPolling();
    }

    if (supervisor.selectedId !== null) {
      // Coming back to the view reopens the task the operator was reading.
      mountDetailCard();
      refreshDetail(supervisor.selectedId);
    }
  }

  /**
   * Drop every reference to the supervisor view's DOM and stop its timer.
   *
   * `navigate()` calls this before rendering the next route, and `showLogin`
   * calls it when the session ends: a listing that arrives after the operator
   * left must not write into a panel that is gone, and the poll must not
   * outlive the view.
   *
   * Both read tokens are bumped here. Nulling `dom` alone is not enough for the
   * listing: a remount restores `dom` before a slow response lands, so the
   * response would pass a `dom !== null` guard and paint a snapshot read before
   * the navigation. The bumped token is what makes it stale.
   */
  function supervisorUnmount() {
    supervisorStopPolling();
    document.removeEventListener("visibilitychange", onSupervisorVisibility);
    supervisor.dom = null;
    supervisor.detail = null;
    supervisor.detailToken += 1;
    supervisor.listToken += 1;
    supervisor.listSignature = null;
    supervisor.listBusy = false;
    supervisor.listQueued = false;
    supervisor.actionBusy = false;
  }

  /* ── Logs ──────────────────────────────────────────────────────────────── */

  /*
   * The live log surface (design spec §5.3, plan Task 18).
   *
   * What the server actually does, and what this view therefore has to accept:
   *
   *  * `GET /api/logs?limit=N` answers the newest N entries, **oldest first**,
   *    plus the ring's capacity. An absent limit means the server's own default,
   *    `0` means none, and anything above 1000 is clamped — so the view asks for
   *    `LOG_HISTORY_LIMIT` and never assumes it received that many.
   *  * `GET /api/logs/stream` is a **live tail with no replay**: the tail's
   *    cursor is read when the request arrives, so entries emitted before that
   *    moment are never resent. The view therefore reads the history *first* and
   *    opens the stream *second*. That order can leave a gap — lines emitted
   *    between the two are in neither — but it cannot produce a duplicate,
   *    because every streamed entry is at or after a cursor that was read after
   *    the history was already in hand. The gap is stated in the view's own copy
   *    rather than papered over, and every reattach appends an explicit marker
   *    in the list where the missing lines would have been.
   *  * The stream's event name is `log`. `createSseDecoder` already hands the
   *    frame's event name to its callback, so this view dispatches on it and
   *    ignores every other name; the decoder is shared with the chat view, not
   *    duplicated, and the chat view's own `handleChatEvent` is untouched.
   *  * `level` is `tracing::Level::as_str()` — upper case, and not a closed set
   *    from the client's point of view. Anything outside ERROR/WARN/INFO/DEBUG
   *    is rendered under an OTHER filter rather than dropped.
   *  * Both routes answer **503** when the dashboard was started without a log
   *    buffer. That is a startup configuration state, not a transient failure,
   *    so the view says so once and stops; it does not retry it.
   *
   * `EventSource` is the natural transport for a GET SSE stream and it does send
   * the session cookie same-origin, but it exposes no status code at all: a 503
   * (no buffer), a 401 (session gone) and a dropped connection all arrive as the
   * same anonymous `error`, so the 503 the operator most needs named is the one
   * case it cannot distinguish. Its own reconnection would also have to be
   * suppressed to bound the retry rate. The stream is therefore read through
   * `fetch` + the shared SSE decoder — the mechanism the chat view already uses
   * — with an `AbortController` and a generation counter for teardown.
   *
   * Every dynamic value goes through `textContent`. A log message is
   * attacker-influenced: it can carry tool output, a URL, or a line of a user's
   * own text. None of it is ever parsed as markup.
   */

  /**
   * How many entries the view asks `GET /api/logs` for when it opens.
   *
   * The server's hard ceiling on one response is 1000, so this asks for exactly
   * what it can get: a larger number would be clamped and would only suggest a
   * history the route cannot deliver.
   */
  const LOG_HISTORY_LIMIT = 1000;

  /**
   * Hard cap on rendered rows, and on the entries kept in order to render them.
   *
   * A tab can sit on this view for days, so neither the DOM nor the model may
   * grow with the process's output. 2000 is the ring capacity the design spec
   * names (§5.3): it is above every history a single `GET /api/logs` can return,
   * and small enough that re-rendering the whole list on a filter change is a
   * sub-frame operation. The oldest entries are dropped first, which is the
   * ring's own eviction order.
   */
  const LOG_ROW_CAP = 2000;

  /** The longest message text rendered, in characters. The rest is summarised. */
  const LOG_MESSAGE_MAX = 2000;

  /** The most lines of one message rendered. A log line is not a file. */
  const LOG_MESSAGE_LINES = 40;

  /** How close to the bottom still counts as "following the tail", in pixels. */
  const LOG_PIN_THRESHOLD = 48;

  /**
   * The reconnect ladder, in milliseconds. The last value repeats and is never
   * exceeded, so a server that stays down is polled at most once every 15s.
   */
  const LOG_BACKOFF_MS = [1000, 2000, 4000, 8000, 15000];

  /**
   * How long a stream must have stayed live before a drop is treated as a fresh
   * problem rather than a continuation of the one already being backed off from.
   *
   * Without this the ladder would restart at its first rung every time, and a
   * server that accepts a connection and drops it immediately would be retried
   * once a second for as long as the tab is open — the tight loop the backoff
   * exists to prevent. A stream that stayed up for half a minute earned a reset;
   * one that died on arrival did not.
   */
  const LOG_STABLE_MS = 30000;

  /** How long typing in the text filter settles before the list is rebuilt. */
  const LOG_FILTER_DEBOUNCE_MS = 150;

  /** The filter chips, in the order they are offered. OTHER is not a tracing level. */
  const LOG_LEVELS = ["ERROR", "WARN", "INFO", "DEBUG", "OTHER"];

  // #region log-core

  /**
   * The filter bucket a `level` string belongs to.
   *
   * `tracing::Level::as_str()` gives ERROR/WARN/INFO/DEBUG in upper case, but the
   * set is not closed from here: `LogEntry::new` accepts any string (the
   * backend's own tests push lower case), and a level this build has never seen
   * must render rather than vanish. Anything unrecognised — including an empty
   * or missing level — lands in OTHER, which is a filter the operator can turn
   * off, not a silent drop.
   */
  function logLevelKey(level) {
    const text = typeof level === "string" ? level.trim().toUpperCase() : "";
    if (text === "ERROR" || text === "WARN" || text === "INFO" || text === "DEBUG") {
      return text;
    }
    return "OTHER";
  }

  /**
   * One entry from a `GET /api/logs` body or a `log` frame, or null.
   *
   * Every field is copied defensively: a missing or wrongly typed field becomes
   * an empty string rather than `undefined` reaching `textContent`, which would
   * print "undefined" into the operator's log.
   */
  function normalizeLogEntry(raw) {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      return null;
    }
    return {
      marker: false,
      timestamp: typeof raw.timestamp === "string" ? raw.timestamp : "",
      level: typeof raw.level === "string" ? raw.level : "",
      target: typeof raw.target === "string" ? raw.target : "",
      message: typeof raw.message === "string" ? raw.message : ""
    };
  }

  /** The JSON payload of one `log` frame, or null when it is not an entry. */
  function parseLogEvent(data) {
    if (typeof data !== "string" || data === "") {
      return null;
    }
    let body = null;
    try {
      body = JSON.parse(data);
    } catch (ignored) {
      return null;
    }
    return normalizeLogEntry(body);
  }

  /**
   * `{ entries, capacity }` from a `GET /api/logs` body.
   *
   * A bare array is accepted as well as the documented envelope, so a change to
   * the envelope cannot silently empty the view. `capacity` stays null when the
   * server did not send a number, and the view then says nothing about it rather
   * than inventing one.
   */
  function normalizeLogsBody(body) {
    const raw = Array.isArray(body)
      ? body
      : body && Array.isArray(body.entries)
        ? body.entries
        : [];
    const entries = [];
    for (let i = 0; i < raw.length; i += 1) {
      const entry = normalizeLogEntry(raw[i]);
      if (entry) {
        entries.push(entry);
      }
    }
    const capacity =
      body && !Array.isArray(body) && typeof body.capacity === "number" && isFinite(body.capacity)
        ? body.capacity
        : null;
    return { entries: entries, capacity: capacity };
  }

  /**
   * Whether an entry passes the filter, where `filter` is
   * `{ levels: { ERROR: bool, ... }, text: <lower case> }`.
   *
   * The text filter covers target and message — the two fields an operator
   * searches by — while the level is a separate axis with its own control. A gap
   * marker always passes: it is not a log line, and hiding the statement that
   * lines are missing would be the one thing this view must never do.
   */
  function logMatchesFilter(entry, filter) {
    if (!entry) {
      return false;
    }
    if (entry.marker === true) {
      return true;
    }
    if (filter.levels[logLevelKey(entry.level)] !== true) {
      return false;
    }
    if (filter.text === "") {
      return true;
    }
    return (
      entry.target.toLowerCase().indexOf(filter.text) !== -1 ||
      entry.message.toLowerCase().indexOf(filter.text) !== -1
    );
  }

  /**
   * The text to render for a message, and how much of it was left out.
   *
   * A log message is unbounded: a tool result logged at debug level can be
   * megabytes, and one such row would cost more to lay out than the rest of the
   * view put together. The tail is summarised rather than silently truncated —
   * the count of omitted characters is shown in the row, so the operator knows
   * the line is longer than what is on screen. The line count is capped too,
   * because a 2000-character message made of newlines is 2000 rows tall.
   */
  function clampLogMessage(message) {
    const text = typeof message === "string" ? message : "";
    let cut = text.length > LOG_MESSAGE_MAX ? LOG_MESSAGE_MAX : text.length;
    let lines = 0;
    for (let i = 0; i < cut; i += 1) {
      if (text.charAt(i) === "\n") {
        lines += 1;
        if (lines >= LOG_MESSAGE_LINES) {
          cut = i;
          break;
        }
      }
    }
    if (cut >= text.length) {
      return { text: text, omitted: 0 };
    }
    return { text: text.slice(0, cut), omitted: text.length - cut };
  }

  /**
   * The stamp shown in a row's time column.
   *
   * The server writes RFC 3339 with nanosecond precision
   * (`2026-09-17T10:10:33.357828816+00:00`). That is more fractional digits than
   * `Date` is specified to parse — the format allows three — so the clock is read
   * out of the string itself and no date is constructed: no engine's leniency is
   * relied on, and no timezone conversion is invented. The date is kept because a
   * tail can span midnight, and the full stamp goes in the row's tooltip. An
   * unexpected shape is shown exactly as it arrived.
   */
  function logTimeText(timestamp) {
    const text = typeof timestamp === "string" ? timestamp : "";
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?/.exec(text);
    if (!match) {
      return text.slice(0, 32);
    }
    return match[2] + "-" + match[3] + " " + match[4] + (match[5] ? "." + match[5] : "");
  }

  /**
   * Drop rows from the front of `list` until it holds at most `cap` of them.
   *
   * Only three DOM members are used — `childElementCount`, `firstElementChild`
   * and `removeChild` — so the bound can be exercised against a fake list as well
   * as in a browser. Returns how many rows it removed.
   */
  function trimLogRows(list, cap) {
    let removed = 0;
    while (list.childElementCount > cap && list.firstElementChild) {
      list.removeChild(list.firstElementChild);
      removed += 1;
    }
    return removed;
  }

  /** Whether the scroll container is close enough to the end to be following it. */
  function logIsAtBottom(node, threshold) {
    if (!node) {
      return true;
    }
    return node.scrollHeight - node.scrollTop - node.clientHeight <= threshold;
  }

  // #endregion log-core

  /**
   * The logs view's state.
   *
   * The model lives here rather than in the DOM because the filters are applied
   * to it: narrowing the filter hides rows, and widening it again brings back
   * entries the DOM no longer holds. `dom` is null whenever the view is
   * unmounted and every DOM write is guarded on it.
   */
  const logs = {
    /** Every entry received, oldest first, capped at `LOG_ROW_CAP`. */
    entries: [],
    /** Entries the cap has evicted from the front, for the counter line. */
    dropped: 0,
    /** Entries decoded from the current chunk but not yet appended. */
    batch: [],
    /** `{ levels: {...}, text: <lower case> }`. */
    filter: {
      levels: { ERROR: true, WARN: true, INFO: true, DEBUG: true, OTHER: true },
      text: ""
    },
    /** The ring's capacity as `GET /api/logs` reported it, or null. */
    capacity: null,
    /** True once the history read has answered, either way. */
    historyLoaded: false,
    /** Why the history read failed, when it did but the view carried on. */
    historyError: "",
    /** Whether new lines pull the view down; cleared when the operator scrolls up. */
    follow: true,
    /** Lines appended while the operator was scrolled away. */
    pendingNew: 0,
    /** idle | connecting | live | retrying | unavailable | forbidden | unsupported. */
    state: "idle",
    /** Failed attempts since the last *stable* stream, for the backoff ladder. */
    attempt: 0,
    /** When the current (or last) stream went live, for the stability test. */
    liveAt: 0,
    /** The delay currently being waited out, in ms. */
    retryDelay: 0,
    /** The server's own words for the last failure, when it gave any. */
    lastError: "",
    /** True once a stream has been live, so the next one marks a gap. */
    connectedBefore: false,
    /** The pending retry timeout and the resolver that cancels it. */
    retryTimer: null,
    retryResolve: null,
    /** The pending filter debounce. */
    filterTimer: null,
    /** The AbortController for the in-flight stream, or null. */
    controller: null,
    /**
     * Bumped by every start, retry and unmount. A read, a wait or a response
     * whose generation is stale belongs to a stream nobody is watching, and
     * every await in the loop is guarded on it. This is what makes teardown
     * exact: nulling `dom` alone would not stop a loop that is suspended in a
     * backoff wait from starting another connection.
     */
    generation: 0,
    dom: null
  };

  /** Forget every entry, keeping the filters and the scroll preference. */
  function resetLogEntries() {
    logs.entries = [];
    logs.dropped = 0;
    logs.batch = [];
    logs.pendingNew = 0;
    logs.historyLoaded = false;
    logs.historyError = "";
  }

  /* ── Logs: rows ────────────────────────────────────────────────────────── */

  /**
   * One row for one entry.
   *
   * The level chip carries the level's own text, so colour is never the only
   * signal; the message is a `pre-wrap` block, which is what keeps a multi-line
   * message — or one carrying a `data:` line, or a URL — inside its own row
   * instead of breaking the layout.
   */
  function logRow(entry) {
    if (entry.marker === true) {
      const gap = make("li", "log-row log-row-gap");
      gap.appendChild(make("p", "log-gap", entry.message));
      return gap;
    }

    const row = make("li", "log-row");
    const head = make("div", "log-row-head");

    const key = logLevelKey(entry.level);
    const label = entry.level === "" ? "OTHER" : entry.level.slice(0, 12);
    head.appendChild(make("span", "chip log-level log-level-" + key.toLowerCase(), label));
    head.appendChild(make("span", "log-time", logTimeText(entry.timestamp)));
    head.appendChild(make("span", "log-target", entry.target));
    row.appendChild(head);

    const body = clampLogMessage(entry.message);
    const message = make("p", "log-message", body.text === "" ? "(no message)" : body.text);
    if (body.omitted > 0) {
      message.appendChild(
        make("span", "log-truncated", " … " + body.omitted + " more characters not shown")
      );
    }
    row.appendChild(message);

    if (entry.timestamp !== "") {
      row.title = entry.timestamp;
    }
    return row;
  }

  /** How many of the retained entries the current filter lets through. */
  function countShownLogEntries() {
    let shown = 0;
    for (let i = 0; i < logs.entries.length; i += 1) {
      if (logMatchesFilter(logs.entries[i], logs.filter)) {
        shown += 1;
      }
    }
    return shown;
  }

  function paintLogEmpty(shown) {
    const dom = logs.dom;
    if (!dom) {
      return;
    }
    let text = "";
    if (logs.state === "unavailable" || logs.state === "forbidden" || logs.state === "unsupported") {
      // The status line above is already carrying the reason; a second, wrong
      // explanation ("the buffer is empty") would be worse than none.
      text = "";
    } else if (!logs.historyLoaded) {
      text = "Reading the recent lines…";
    } else if (logs.entries.length === 0) {
      text = "No lines yet. The buffer is empty; new lines appear here as the process emits them.";
    } else if (shown === 0) {
      text = "No lines match the current filter.";
    }
    dom.empty.textContent = text;
    dom.empty.hidden = text === "";
  }

  function paintLogCounters(shown) {
    const dom = logs.dom;
    if (!dom) {
      return;
    }
    let text = logs.entries.length + (logs.entries.length === 1 ? " line" : " lines") + " retained";
    if (logs.dropped > 0) {
      text += " · oldest " + logs.dropped + " dropped";
    }
    if (shown !== logs.entries.length) {
      text += " · " + shown + " shown by the filter";
    }
    if (typeof logs.capacity === "number") {
      text += " · the server's buffer holds " + logs.capacity;
    }
    dom.meta.textContent = text;
  }

  /** Rebuild the whole list from the model. Used on mount and on filter change. */
  function paintLogRows() {
    const dom = logs.dom;
    if (!dom) {
      return;
    }
    clear(dom.list);
    const fragment = document.createDocumentFragment();
    let shown = 0;
    for (let i = 0; i < logs.entries.length; i += 1) {
      const entry = logs.entries[i];
      if (logMatchesFilter(entry, logs.filter)) {
        fragment.appendChild(logRow(entry));
        shown += 1;
      }
    }
    dom.list.appendChild(fragment);
    trimLogRows(dom.list, LOG_ROW_CAP);
    paintLogEmpty(shown);
    paintLogCounters(shown);
  }

  /* ── Logs: scrolling ───────────────────────────────────────────────────── */

  /** Pull the view to the newest line, and resume following. */
  function scrollLogToEnd() {
    const dom = logs.dom;
    if (!dom) {
      return;
    }
    logs.pendingNew = 0;
    logs.follow = true;
    dom.well.scrollTop = dom.well.scrollHeight;
    paintLogJump();
  }

  function paintLogJump() {
    const dom = logs.dom;
    if (!dom) {
      return;
    }
    dom.jump.hidden = logs.follow;
    const text =
      logs.pendingNew > 0 ? "Jump to latest · " + logs.pendingNew + " new" : "Jump to latest";
    if (dom.jump.textContent !== text) {
      dom.jump.textContent = text;
    }
  }

  /**
   * The operator's own scrolling is the only thing that may stop the tail.
   *
   * A programmatic `scrollTop` write fires this too, and that is fine: it lands
   * at the bottom, so the state it computes is the state that was just set.
   */
  function onLogScroll() {
    const dom = logs.dom;
    if (!dom) {
      return;
    }
    const atBottom = logIsAtBottom(dom.well, LOG_PIN_THRESHOLD);
    logs.follow = atBottom;
    if (atBottom) {
      logs.pendingNew = 0;
    }
    paintLogJump();
  }

  /* ── Logs: appending ───────────────────────────────────────────────────── */

  /**
   * Add entries to the model and, when they pass the filter, to the list.
   *
   * Both bounds are enforced here. The model is capped first — nothing below may
   * grow with the process's output — and the list is trimmed independently,
   * because a row rendered before the filter hid its neighbours can outlive its
   * entry in the model.
   */
  function appendLogEntries(entries) {
    if (!entries || entries.length === 0) {
      return 0;
    }
    const dom = logs.dom;
    const fragment = dom ? document.createDocumentFragment() : null;
    let added = 0;

    for (let i = 0; i < entries.length; i += 1) {
      const entry = entries[i];
      logs.entries.push(entry);
      if (fragment && logMatchesFilter(entry, logs.filter)) {
        fragment.appendChild(logRow(entry));
        added += 1;
      }
    }

    if (logs.entries.length > LOG_ROW_CAP) {
      const overflow = logs.entries.length - LOG_ROW_CAP;
      logs.entries.splice(0, overflow);
      logs.dropped += overflow;
    }

    if (!dom) {
      return added;
    }

    if (added > 0) {
      dom.list.appendChild(fragment);
      trimLogRows(dom.list, LOG_ROW_CAP);
      if (logs.follow) {
        scrollLogToEnd();
      } else {
        logs.pendingNew += added;
        paintLogJump();
      }
    }
    paintLogEmpty(countShownLogEntries());
    paintLogCounters(countShownLogEntries());
    return added;
  }

  /**
   * State that lines were missed, in the list where they would have been.
   *
   * The server keeps no replay buffer, so a gap cannot be filled — but it can be
   * admitted, in place and in the operator's line of sight, which is the
   * difference between a log with a hole in it and a log that lies.
   */
  function markLogGap(text) {
    appendLogEntries([{ marker: true, timestamp: "", level: "", target: "", message: text }]);
  }

  /* ── Logs: filters ─────────────────────────────────────────────────────── */

  function paintLogFilterControls() {
    const dom = logs.dom;
    if (!dom) {
      return;
    }
    let active = logs.filter.text !== "";
    for (let i = 0; i < LOG_LEVELS.length; i += 1) {
      const name = LOG_LEVELS[i];
      const on = logs.filter.levels[name] === true;
      const toggle = dom.toggles[name];
      if (!toggle) {
        continue;
      }
      toggle.setAttribute("aria-pressed", on ? "true" : "false");
      toggle.classList.toggle("is-off", !on);
      if (!on) {
        active = true;
      }
    }
    dom.reset.disabled = !active;
  }

  /**
   * Re-render the list under the current filter.
   *
   * Nothing is re-fetched: the route has no filter parameters, so the history is
   * read unfiltered and the same predicate is applied to it and to every
   * streamed entry. Re-reading the buffer here would also duplicate everything
   * the stream has already delivered.
   */
  function applyLogFilter() {
    const dom = logs.dom;
    if (!dom) {
      return;
    }
    const following = logs.follow;
    paintLogFilterControls();
    paintLogRows();
    if (following) {
      // The list was rebuilt, so the scroll offset it had no longer means
      // anything. An operator who was following the tail is still following it.
      scrollLogToEnd();
    }
  }

  function onLogFilterInput(event) {
    const value = event && event.target ? event.target.value : "";
    logs.filter.text = String(value === undefined || value === null ? "" : value)
      .trim()
      .toLowerCase();
    if (logs.filterTimer !== null) {
      window.clearTimeout(logs.filterTimer);
    }
    logs.filterTimer = window.setTimeout(function () {
      logs.filterTimer = null;
      applyLogFilter();
    }, LOG_FILTER_DEBOUNCE_MS);
  }

  function resetLogFilter() {
    if (logs.filterTimer !== null) {
      window.clearTimeout(logs.filterTimer);
      logs.filterTimer = null;
    }
    logs.filter.text = "";
    for (let i = 0; i < LOG_LEVELS.length; i += 1) {
      logs.filter.levels[LOG_LEVELS[i]] = true;
    }
    if (logs.dom && logs.dom.input) {
      logs.dom.input.value = "";
    }
    applyLogFilter();
  }

  /* ── Logs: connection state ────────────────────────────────────────────── */

  function logStatusKind() {
    if (logs.state === "live") {
      return "ok";
    }
    if (logs.state === "retrying") {
      return "warn";
    }
    if (logs.state === "unavailable" || logs.state === "forbidden" || logs.state === "unsupported") {
      return "error";
    }
    return null;
  }

  function logStatusText() {
    if (logs.state === "connecting") {
      // `attempt` counts failures, so the connection being opened now is the
      // next one: one failure behind us means this is the second try.
      return logs.attempt > 0
        ? "Reconnecting to the live log (attempt " + (logs.attempt + 1) + ")…"
        : "Connecting to the live log…";
    }
    if (logs.state === "live") {
      let text = "Live. New lines are appended as the process emits them.";
      if (logs.historyError !== "") {
        text += " The recent history could not be read: " + logs.historyError;
      }
      return text;
    }
    if (logs.state === "retrying") {
      return (
        "The log stream dropped" +
        (logs.lastError !== "" ? " (" + logs.lastError + ")" : "") +
        ". Reconnecting in " +
        Math.round(logs.retryDelay / 1000) +
        "s — attempt " +
        logs.attempt +
        "."
      );
    }
    if (logs.state === "unavailable") {
      return (
        "The log is unavailable: " +
        (logs.lastError !== "" ? logs.lastError : "the dashboard was started without a log buffer") +
        ". That is decided at startup, not a transient failure, so this view has stopped retrying."
      );
    }
    if (logs.state === "forbidden") {
      return (
        "The server refused the log stream: " +
        (logs.lastError !== "" ? logs.lastError : "the request was refused") +
        ". Retrying is unlikely to help."
      );
    }
    if (logs.state === "unsupported") {
      return logs.lastError !== ""
        ? logs.lastError
        : "This browser cannot read a streamed response, so the live log cannot be shown here.";
    }
    return "";
  }

  function paintLogStatus() {
    const dom = logs.dom;
    if (!dom) {
      return;
    }
    setStatus(dom.status, logStatusKind(), logStatusText());
    // Retrying is offered only where a retry could plausibly succeed: a 503 is a
    // startup state and a 403 is an address that has to change, but both can be
    // resolved by an operator who then wants to reattach without reloading.
    dom.retry.hidden = !(
      logs.state === "unavailable" ||
      logs.state === "forbidden" ||
      logs.state === "unsupported"
    );
  }

  /** The bounded backoff delay for a given attempt number, in ms. */
  function logRetryDelay(attempt) {
    const index = attempt < 1 ? 0 : Math.min(attempt, LOG_BACKOFF_MS.length) - 1;
    return LOG_BACKOFF_MS[index];
  }

  /**
   * Wait out the backoff, or return early when the wait is cancelled.
   *
   * Resolves true when the loop may continue and false when its generation is
   * stale — which is how unmount and an explicit retry both interrupt a wait
   * without leaving a timer behind.
   */
  function waitForRetry(generation) {
    logs.state = "retrying";
    logs.retryDelay = logRetryDelay(logs.attempt);
    paintLogStatus();
    return new Promise(function (resolve) {
      let settled = false;
      const finish = function () {
        if (settled) {
          return;
        }
        settled = true;
        logs.retryTimer = null;
        logs.retryResolve = null;
        resolve(generation === logs.generation && logs.dom !== null);
      };
      logs.retryResolve = finish;
      logs.retryTimer = window.setTimeout(finish, logs.retryDelay);
    });
  }

  /** Cancel a pending backoff wait, if there is one. */
  function cancelLogWait() {
    if (logs.retryTimer !== null) {
      window.clearTimeout(logs.retryTimer);
      logs.retryTimer = null;
    }
    const waiter = logs.retryResolve;
    logs.retryResolve = null;
    if (waiter) {
      waiter();
    }
  }

  /* ── Logs: the stream ──────────────────────────────────────────────────── */

  /** Release a response whose body is not going to be read. */
  function discardLogResponse(response) {
    try {
      if (response && response.body && typeof response.body.cancel === "function") {
        const closing = response.body.cancel();
        if (closing && typeof closing.catch === "function") {
          closing.catch(function () {
            // Already closed or aborted; nothing to release.
          });
        }
      }
    } catch (ignored) {
      // A body that is already locked or disturbed throws synchronously.
    }
  }

  /**
   * One `log` frame at a time, batched per decoded chunk.
   *
   * The decoder calls back once per frame, so appending per callback would mean
   * one layout read per line: a 256-entry burst would measure `scrollHeight`
   * 256 times. The batch is flushed once after each `push`, which is the
   * smallest unit the transport actually delivers.
   */
  function handleLogEvent(kind, data) {
    if (kind !== "log") {
      // The server names every frame on this stream `log`. Anything else is
      // ignored rather than guessed at, exactly as the chat view treats an
      // unknown kind: the decoder is shared, the dispatch is not.
      return;
    }
    const entry = parseLogEvent(data);
    if (entry) {
      logs.batch.push(entry);
    }
  }

  function flushLogBatch() {
    if (logs.batch.length === 0) {
      return;
    }
    const batch = logs.batch;
    logs.batch = [];
    appendLogEntries(batch);
  }

  /** Read one live stream to its end, dispatching `log` frames as they arrive. */
  async function readLogStream(response, generation) {
    const reader = response.body.getReader();
    const textDecoder = new TextDecoder("utf-8");
    const decoder = createSseDecoder(handleLogEvent);

    try {
      for (;;) {
        const step = await reader.read();
        if (generation !== logs.generation) {
          return;
        }
        if (step.done) {
          break;
        }
        decoder.push(textDecoder.decode(step.value, { stream: true }));
        flushLogBatch();
      }
      // Whatever is left of a multi-byte character, then a frame that never got
      // its terminating blank line: a stream cut mid-frame would otherwise lose
      // its last line silently.
      decoder.push(textDecoder.decode());
      decoder.flush();
      flushLogBatch();
    } catch (error) {
      if (generation !== logs.generation || isAbort(error)) {
        return;
      }
      logs.lastError = describeError(error);
    } finally {
      try {
        const closing = reader.cancel();
        if (closing && typeof closing.catch === "function") {
          closing.catch(function () {
            // The stream is already closed or aborted; nothing to do.
          });
        }
      } catch (ignored) {
        // Cancelling a reader that is already released throws synchronously.
      }
    }
  }

  /**
   * Connect, read, and reconnect while the view is mounted.
   *
   * Every await is guarded on the generation, so a loop that has been superseded
   * by an unmount or an explicit retry stops at its next step instead of
   * starting another connection. The loop ends — rather than retrying — on the
   * three answers that a retry cannot change: 401 (the session is gone, so the
   * view signs out), 403 (the source address is refused) and 503 (the dashboard
   * has no log buffer). Everything else is waited out on the backoff ladder.
   *
   * `logs.attempt` counts failures since the last stream that stayed up long
   * enough to count (see `LOG_STABLE_MS`), so it is incremented on the failure
   * paths and never at the top of the loop, where it would double-count every
   * retry and skip the first rung of the ladder.
   */
  async function logStreamLoop(generation) {
    while (generation === logs.generation && logs.dom) {
      logs.state = "connecting";
      paintLogStatus();

      let response = null;
      try {
        response = await window.fetch("/api/logs/stream", {
          method: "GET",
          credentials: "same-origin",
          headers: { Accept: "text/event-stream" },
          signal: logs.controller ? logs.controller.signal : undefined
        });
      } catch (error) {
        if (generation !== logs.generation || isAbort(error)) {
          return;
        }
        logs.lastError = describeError(error);
        logs.attempt += 1;
        if (!(await waitForRetry(generation))) {
          return;
        }
        continue;
      }

      if (generation !== logs.generation || !logs.dom) {
        discardLogResponse(response);
        return;
      }

      if (!response.ok) {
        const status = response.status;
        const raw = await readBodyText(response);
        if (generation !== logs.generation || !logs.dom) {
          return;
        }
        if (status === 401) {
          showLogin("Your session expired. Sign in again.");
          return;
        }
        if (status === 503 || status === 403) {
          logs.state = status === 503 ? "unavailable" : "forbidden";
          logs.lastError = raw;
          paintLogStatus();
          paintLogEmpty(0);
          return;
        }
        logs.lastError = raw !== "" ? raw : "the stream answered status " + status;
        logs.attempt += 1;
        if (!(await waitForRetry(generation))) {
          return;
        }
        continue;
      }

      if (!response.body || typeof response.body.getReader !== "function") {
        logs.state = "unsupported";
        logs.lastError =
          "This browser cannot read a streamed response, so the live log cannot be shown here.";
        paintLogStatus();
        paintLogEmpty(0);
        return;
      }

      // A stream that goes live after a drop, after a failed attempt, or after
      // an explicit retry, is a point where lines were emitted that no stream
      // delivered. Say so where they are missing.
      if (logs.connectedBefore || logs.attempt > 0) {
        markLogGap(
          logs.connectedBefore
            ? "The stream reattached. Lines emitted while it was detached are not replayed."
            : "The stream attached after " +
                logs.attempt +
                " failed attempt(s). Lines emitted before it attached are not replayed."
        );
      }
      logs.connectedBefore = true;
      logs.liveAt = Date.now();
      logs.lastError = "";
      logs.state = "live";
      paintLogStatus();

      await readLogStream(response, generation);
      if (generation !== logs.generation || !logs.dom) {
        return;
      }
      // The server never ends this stream on its own, so reaching here means the
      // connection was cut. A connection that lasted long enough is a fresh
      // problem and starts the ladder again; one that died on arrival keeps
      // climbing it.
      if (Date.now() - logs.liveAt >= LOG_STABLE_MS) {
        logs.attempt = 0;
      }
      logs.attempt += 1;
      if (!(await waitForRetry(generation))) {
        return;
      }
    }
  }

  /** Start (or supersede) the stream loop for the mounted view. */
  function startLogStream() {
    if (!logs.dom) {
      return;
    }
    if (logs.controller) {
      // Superseding an in-flight attempt: aborting it is what makes the old
      // loop's pending read reject now rather than after the next tick.
      logs.controller.abort();
      logs.controller = null;
    }
    logs.controller = new AbortController();
    logs.generation += 1;
    const generation = logs.generation;
    // A loop parked in a backoff wait belongs to the generation that just ended.
    cancelLogWait();
    logs.attempt = 0;

    logStreamLoop(generation)
      .catch(function (error) {
        if (generation !== logs.generation || !logs.dom) {
          return;
        }
        logs.state = "unsupported";
        logs.lastError = "The log stream could not be read: " + describeError(error);
        paintLogStatus();
      })
      .then(function () {
        if (generation === logs.generation && logs.controller) {
          logs.controller = null;
        }
      });
  }

  /** Re-read the buffer and reattach, after a state a retry could resolve. */
  function retryLogView() {
    if (!logs.dom) {
      return;
    }
    logs.generation += 1;
    cancelLogWait();
    if (logs.controller) {
      logs.controller.abort();
      logs.controller = null;
    }
    logs.attempt = 0;
    logs.lastError = "";
    logs.state = "connecting";
    paintLogStatus();
    loadLogHistory();
  }

  /* ── Logs: history ─────────────────────────────────────────────────────── */

  /**
   * Read the buffer, then attach the tail.
   *
   * That order is the whole of the view's honesty about completeness: the
   * history read is a snapshot, the stream starts after it, and the lines in
   * between are in neither. The reverse order would deliver duplicates instead,
   * which is harder for an operator to notice and impossible to repair.
   */
  async function loadLogHistory() {
    const generation = logs.generation;
    logs.historyLoaded = false;
    logs.historyError = "";
    paintLogRows();
    paintLogStatus();

    let body = null;
    try {
      body = await api("/api/logs?limit=" + LOG_HISTORY_LIMIT);
    } catch (error) {
      if (generation !== logs.generation || !logs.dom) {
        return;
      }
      logs.historyLoaded = true;
      if (error && error.status === 401) {
        showLogin("Your session expired. Sign in again.");
        return;
      }
      if (error && error.status === 503) {
        logs.state = "unavailable";
        logs.lastError = (error.message || "").trim();
        paintLogStatus();
        paintLogRows();
        return;
      }
      if (error && error.status === 403) {
        logs.state = "forbidden";
        logs.lastError = (error.message || "").trim();
        paintLogStatus();
        paintLogRows();
        return;
      }
      // A history read that failed for any other reason is reported but does not
      // stop the view: the tail may still attach, and a live log with no history
      // is more useful to an operator than an empty panel.
      logs.historyError = describeError(error);
      paintLogRows();
      paintLogStatus();
      startLogStream();
      return;
    }

    if (generation !== logs.generation || !logs.dom) {
      return;
    }

    const normalized = normalizeLogsBody(body);
    resetLogEntries();
    logs.capacity = normalized.capacity;
    logs.historyLoaded = true;
    paintLogRows();
    appendLogEntries(normalized.entries);
    startLogStream();
  }

  /* ── Logs: view ────────────────────────────────────────────────────────── */

  function logFilterBar() {
    const bar = make("div", "log-filters");

    const levels = make("div", "log-levels");
    levels.setAttribute("role", "group");
    levels.setAttribute("aria-label", "Filter by level");
    const toggles = {};
    for (let i = 0; i < LOG_LEVELS.length; i += 1) {
      const name = LOG_LEVELS[i];
      const toggle = button(name, "chip log-toggle log-toggle-" + name.toLowerCase());
      toggle.setAttribute("aria-pressed", "true");
      toggle.addEventListener(
        "click",
        (function (level) {
          return function () {
            logs.filter.levels[level] = logs.filter.levels[level] !== true;
            applyLogFilter();
          };
        })(name)
      );
      toggles[name] = toggle;
      levels.appendChild(toggle);
    }
    bar.appendChild(levels);

    const search = make("div", "log-search");
    const label = make("label", "sr-only", "Filter lines by text in the target or the message");
    label.setAttribute("for", "log-filter-text");
    const input = document.createElement("input");
    input.id = "log-filter-text";
    input.className = "log-input";
    input.type = "search";
    input.placeholder = "Filter target or message…";
    input.setAttribute("autocomplete", "off");
    input.spellcheck = false;
    input.addEventListener("input", onLogFilterInput);
    search.appendChild(label);
    search.appendChild(input);
    bar.appendChild(search);

    const reset = button("Reset filters", "btn btn-ghost log-reset");
    reset.addEventListener("click", resetLogFilter);
    bar.appendChild(reset);

    return { bar: bar, toggles: toggles, input: input, reset: reset };
  }

  function renderLogs(host) {
    const card = make("section", "card log-card");
    card.appendChild(cardHead("i-bars", "Live log"));

    const status = make("p", "status");
    status.hidden = true;
    card.appendChild(status);

    const controls = logFilterBar();
    card.appendChild(controls.bar);

    // The well scrolls; the list inside it holds only rows, so the row cap can
    // be enforced by counting children without the empty state getting in the way.
    const well = make("div", "log-well");
    well.tabIndex = 0;
    well.setAttribute("aria-label", "Live log lines");
    well.addEventListener("scroll", onLogScroll);

    const list = make("ol", "log-list");
    list.setAttribute("role", "log");
    well.appendChild(list);

    const empty = make("p", "log-empty");
    empty.hidden = true;
    well.appendChild(empty);
    card.appendChild(well);

    const actions = make("div", "log-actions");
    const jump = button("Jump to latest", "btn btn-ghost log-jump");
    jump.hidden = true;
    jump.addEventListener("click", function () {
      scrollLogToEnd();
    });
    const retry = button("Retry now", "btn btn-ghost log-retry");
    retry.hidden = true;
    retry.addEventListener("click", function () {
      retryLogView();
    });
    actions.appendChild(jump);
    actions.appendChild(retry);
    card.appendChild(actions);

    const meta = make("p", "log-meta");
    card.appendChild(meta);

    card.appendChild(
      make(
        "p",
        "card-note",
        "This is a live tail, not a replay. The recent lines are read once when the view opens and new lines are appended as the process emits them; the server keeps no replay buffer, so lines emitted in the moment between those two steps are not shown here. Leaving this view closes the stream. Times are printed exactly as the process wrote them (RFC 3339, UTC); hover a row for the full stamp."
      )
    );
    card.appendChild(
      make(
        "p",
        "card-note",
        "The list keeps the newest 2000 lines and drops the oldest, so a tab left open for days cannot grow without limit. A message longer than 2000 characters, or longer than 40 lines, is summarised with the number of characters left out."
      )
    );

    host.appendChild(card);

    logs.dom = {
      well: well,
      list: list,
      empty: empty,
      status: status,
      jump: jump,
      retry: retry,
      meta: meta,
      input: controls.input,
      reset: controls.reset,
      toggles: controls.toggles
    };

    resetLogEntries();
    logs.follow = true;
    logs.state = "connecting";
    logs.attempt = 0;
    logs.liveAt = 0;
    logs.retryDelay = 0;
    logs.lastError = "";
    logs.capacity = null;
    logs.connectedBefore = false;
    logs.generation += 1;

    paintLogFilterControls();
    paintLogRows();
    paintLogStatus();
    paintLogJump();

    loadLogHistory();
  }

  /**
   * Stop the tail and drop every reference to the logs view's DOM.
   *
   * `navigate()` calls this before rendering the next route and `showLogin`
   * calls it when the session ends. The server's tail task ends when its
   * response body is dropped, so aborting the fetch is what releases it — a
   * stream left running here would be the client-side twin of the leaked task
   * the backend was hardened against. The generation bump is what stops a loop
   * that is suspended in a backoff wait from opening another connection, and the
   * timers are cleared here rather than left to fire into a view that is gone.
   */
  function logsUnmount() {
    logs.generation += 1;
    cancelLogWait();
    if (logs.filterTimer !== null) {
      window.clearTimeout(logs.filterTimer);
      logs.filterTimer = null;
    }
    if (logs.controller) {
      logs.controller.abort();
      logs.controller = null;
    }
    logs.batch = [];
    logs.state = "idle";
    logs.attempt = 0;
    logs.liveAt = 0;
    logs.retryDelay = 0;
    logs.connectedBefore = false;
    logs.dom = null;
  }

  /* ── Boot ──────────────────────────────────────────────────────────────── */

  async function boot() {
    try {
      const settings = await api("/api/settings");
      enterApp(settings);
    } catch (error) {
      if (error && error.status === 401) {
        showLogin("");
      } else if (error && error.status === 403) {
        showLogin("This source address is not permitted to reach the dashboard.");
      } else if (error && error.status === 0) {
        showLogin(error.message);
      } else {
        showLogin((error && error.message) || "The dashboard could not be loaded.");
      }
    } finally {
      showBoot(false);
    }
  }

  function start() {
    byId("login-form").addEventListener("submit", submitLogin);
    byId("logout").addEventListener("click", signOut);
    byId("chat-new").addEventListener("click", createSession);
    window.addEventListener("hashchange", navigate);
    boot();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
