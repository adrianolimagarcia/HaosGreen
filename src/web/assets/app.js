/*
 * HaosGreen dashboard client (shell, design system, settings, chat).
 *
 * Two rules hold everywhere in this file.
 *
 *  * No dynamic string is ever parsed as markup. Elements are built with
 *    `createElement`, values from the server and from the operator are written
 *    with `textContent`, and `innerHTML` does not appear in this file at all —
 *    not even for the icons, which are `<symbol>`s in index.html instantiated
 *    by cloning a `<template>`.
 *  * Nothing leaves this origin. `api()` is the only network entry point and it
 *    only ever fetches a path on the server that served this page, so the
 *    dashboard renders identically with networking disabled.
 *
 * Chat streams a real agent run over SSE. `EventSource` cannot be used for it
 * — the request is a POST with a JSON body — so the response is read through
 * `fetch`'s `ReadableStream` and the SSE frames are reassembled by hand; see
 * the decoder below. Supervisor, Logs and A2A are still deliberate empty
 * states: a stub that invented rows would be worse than an honest "not yet".
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
      body: "Supervisor will list the most recent autonomous tasks and let you pause, resume, cancel or approve them."
    },
    "/logs": {
      title: "Logs",
      icon: "i-bars",
      body: "Logs will stream the recent tracing events kept in the bounded in-memory ring buffer."
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
    // show the next operator a conversation they cannot reach.
    resetChat();
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
    // view would otherwise keep writing into.
    chatUnmount();
    clear(host);
    if (route === "/settings") {
      renderSettings(host);
    } else if (route === "/chat") {
      renderChat(host);
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
