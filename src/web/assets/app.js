/*
 * HaosGreen dashboard client (Phase 1: shell, design system, settings).
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
 * Chat, Supervisor, Logs and A2A are deliberate empty states: Phase 1 ships the
 * shell and the settings surface, and a stub that invented rows would be worse
 * than an honest "not yet".
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

  /** The five surfaces. `body` describes what the later phase will bring. */
  const VIEWS = {
    "/chat": {
      title: "Chat",
      icon: "i-leaf",
      body: "Chat will stream the same agent the Telegram bot runs, with its tool calls visible as they happen."
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
    clear(host);
    if (route === "/settings") {
      renderSettings(host);
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
     * Warn when a non-empty draft has no loopback entry.
     *
     * Saving such a list locks out a browser running on the same machine until
     * the process restarts, which is exactly the asymmetry the note above
     * describes. It is a warning derived from what the operator typed, not a
     * claim about the network.
     */
    function renderCaution() {
      const draft = state.allowDraft;
      if (draft.length === 0) {
        setStatus(caution, null, "");
        return;
      }
      const loopback = ["127.0.0.1", "127.0.0.0/8", "::1", "localhost", "0.0.0.0/0", "::/0"];
      const covered = draft.some(function (entry) {
        return loopback.indexOf(String(entry).trim().toLowerCase()) !== -1;
      });
      if (covered) {
        setStatus(caution, null, "");
        return;
      }
      setStatus(
        caution,
        "warn",
        "No loopback entry in this list. If you are browsing from this machine, saving it locks this browser out until HaosGreen is restarted."
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
    window.addEventListener("hashchange", navigate);
    boot();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
})();
