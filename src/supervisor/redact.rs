//! Secret redaction for every string this process stores or echoes back.
//!
//! Two mechanisms, and both are load-bearing:
//!
//! 1. **Shape rules.** [`redact`] rewrites credential-shaped substrings
//!    (`api_key=…`, `auth_token=…`, `TELEGRAM_BOT_TOKEN=…`, `x-api-key: …`,
//!    `Authorization: Basic …`, `Bearer …`, a Telegram `bot<id>:<secret>` URL
//!    segment, a bare `sk-…` key) to `***`, keeping the key and the separator so
//!    the text stays readable.
//! 2. **An exact-value registry.** [`register_secrets`] is called once at
//!    startup with every secret the configuration holds, and a registered value
//!    is replaced **wherever it appears** — in a URL path, in a query string, in
//!    the middle of prose. No set of shapes can enumerate the ways a process
//!    ends up printing a credential; `reqwest`'s `Error` display is the worked
//!    example. It appends ` for url ({url})` to a transport error, so a failed
//!    call to `https://api.telegram.org/bot<token>/sendMessage` puts the raw bot
//!    token into a log message that has no key, no separator and no prefix any
//!    shape rule could recognise.
//!
//! # Why the registry is not frozen
//!
//! Registration is additive, idempotent and safe to call from any thread at any
//! time; it takes effect for every `redact()` call made after it returns. The
//! alternative — refusing registrations once `redact()` has been called — was
//! rejected: `redact()` runs on the logging hot path from the first line the
//! process emits, so a freeze would silently drop the very registration that
//! matters, and a silently dropped secret is a leak. `main.rs` registers once,
//! before the dashboard is started, so in practice there is no "after".
//!
//! The hot path stays cheap when nothing is registered: one relaxed atomic load
//! ([`ARMED`]) skips the whole exact-value pass, and the shape rules are compiled
//! once into a `OnceLock`.
//!
//! # Boundary handling: capture groups, not look-around
//!
//! The obvious spelling of "a key that is not preceded by a word character" is
//! `(?<![A-Za-z0-9])`. The `regex` crate cannot compile it — look-around is
//! explicitly unsupported (`regex` 1.13.1 `src/lib.rs:5`; `regex-syntax` 0.8.11
//! rejects `(?<!a)` with `ast::ErrorKind::UnsupportedLookAround`, see
//! `src/ast/parse.rs:3744`) — so the same predicate is written by *consuming* the
//! preceding character into a capture group and writing it back:
//! `(?:^|([^A-Za-z0-9]))`. A `\b` was the previous spelling and it is the bug
//! this module was fixed for: `\b` does not match between `_` and a letter, so
//! `auth_token=…` and `TELEGRAM_BOT_TOKEN=…` — the exact names a `.env` file
//! uses — were invisible to it.
//!
//! # Over-redaction is a bug too
//!
//! `\s*[:=]?\s*` accepted a bare space as a separator, so ordinary prose was
//! mangled: `no api token is configured yet` came out as
//! `no api token *** configured yet`. A separator is now a real `:` or `=`, and
//! the value is bounded so a rule cannot eat the rest of an unspaced line:
//! `{"api_key":"VALUE0","model":"x"}` used to collapse to `{"api_key***`, losing
//! the model name and everything after it.
//!
//! A JSON object needs one more concession: its key is *quoted*, so the
//! separator group tolerates a closing quote (`["']?\s*[:=]\s*`) — without it
//! `{"api_key":"VALUE0"}` matched nothing at all, because the character after
//! the key is `"` rather than `:`.

use regex::Regex;
use std::borrow::Cow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{OnceLock, RwLock};

/// The longest value [`register_secret`] will accept, in bytes.
///
/// A cap, not a heuristic: without one a caller could register a needle the size
/// of a file and turn every `redact()` call into a full-text scan for it. Real
/// credentials are two orders of magnitude below this (a Telegram bot token is
/// ~46 bytes, an OpenRouter key ~73).
pub const MAX_SECRET_LEN: usize = 512;

/// The shortest value [`register_secret`] will accept, in bytes.
///
/// A floor for the same reason [`MAX_SECRET_LEN`] is a cap. A short needle is
/// not a credential, and registering one is destructive rather than merely
/// useless: the value is replaced *wherever it appears*, so a three-character
/// needle would rewrite every log line, every artifact and every stored job
/// summary that happens to contain those characters — the over-redaction failure
/// this module was already fixed for once, except total. Eight is the same floor
/// the bare-`Bearer` shape rule uses ([`BEARER_VALUE`]), and it is two orders of
/// magnitude below the shortest real credential this process holds.
pub const MIN_SECRET_LEN: usize = 8;

/// What a redacted value is replaced with.
const MASK: &str = "***";

/// The key names a credential is assigned to.
///
/// `token` is a substring match in effect — `auth_token`, `bot_token` and
/// `TELEGRAM_BOT_TOKEN` all end in it — which is the point: those are the names
/// a `.env` file uses and the names the previous `\b`-anchored pattern could not
/// see.
const KEYS: &str = "authorization|api[_-]?key|password|passwd|secret|token|bearer";

/// A value that is not quoted.
///
/// Bounded so a rule cannot eat the rest of an unspaced line: it stops at
/// whitespace and at the delimiters that follow a value in JSON, TOML, a query
/// string or a parenthesised message.
const BARE_VALUE: &str = r#"[^\s,;)\]}"']+"#;

/// A value that follows a bare auth scheme (`Bearer <token>`).
///
/// Stricter than [`BARE_VALUE`], and deliberately so: with no separator to key
/// on, "`bearer` followed by a word" is ordinary English — `bearer bonds are a
/// financial instrument` is a sentence, not a credential. Requiring a
/// token-shaped value of at least eight characters keeps the shape net useful
/// without mangling prose. A bare `Bearer` whose value is shorter than that is
/// not matched by shape; a *configured* secret is still caught by the
/// exact-value registry, which is the guarantee this module actually makes.
const BEARER_VALUE: &str = "[A-Za-z0-9._~+/=-]{8,}";

/// The leading boundary every rule shares.
///
/// `${1}` in every replacement is the character this matched, written back
/// unchanged, so a rule never consumes anything outside the credential. See the
/// module documentation for why this is a capture group rather than a
/// look-behind.
const PRE: &str = r"(?:^|([^A-Za-z0-9]))";

/// The key, then an optional closing quote, then the separator.
///
/// The separator requires a real `:` or `=` — a bare space is not one, which is
/// what stopped ordinary prose from being mangled. `["']?` is there for JSON and
/// YAML, where the key is quoted and the character after it is the closing quote
/// rather than the colon.
const KEY_AND_SEP: &str = r#"(["']?\s*[:=]\s*)"#;

/// One compiled rule: a pattern and what a match becomes.
struct Rule {
    regex: Regex,
    replacement: &'static str,
}

/// The compiled shape rules, in application order.
///
/// Initialisation is non-panicking: `Regex::new` on a constant pattern can only
/// fail if the pattern itself is wrong, and this module is called from inside
/// the `tracing` layer, where a panic would unwind through whatever emitted the
/// log line. A pattern that fails to compile is skipped rather than aborting the
/// process; [`tests::every_shape_rule_compiles`] pins the count so a broken
/// pattern fails CI instead of silently narrowing the net.
static RULES: OnceLock<Vec<Rule>> = OnceLock::new();

/// Every exact secret value registered so far.
static REGISTRY: OnceLock<RwLock<Vec<String>>> = OnceLock::new();

/// True once at least one secret has been registered.
///
/// Read (acquire) on every `redact()` call: when no secret is registered — every
/// process that never configured one, and every unit test that does not opt in —
/// the exact-value pass is skipped entirely.
///
/// The load is [`Ordering::Acquire`] to pair with the [`Ordering::Release`]
/// store in [`register_secret`]. A relaxed load here would be a real (if narrow)
/// race rather than a theoretical one: the flag is what publishes the list, and
/// a reader that observed it without the acquire could in principle read a
/// `Vec` that does not yet contain the needle — a log line printed with the
/// credential still in it. On x86 the acquire load compiles to the same
/// instruction as the relaxed one, so the guarantee is free.
static ARMED: AtomicBool = AtomicBool::new(false);

fn registry() -> &'static RwLock<Vec<String>> {
    REGISTRY.get_or_init(|| RwLock::new(Vec::new()))
}

fn rules() -> &'static [Rule] {
    RULES
        .get_or_init(|| {
            let patterns: Vec<(String, &'static str)> = vec![
                // `api_key="…"`, `{"token":"…"}`. The quotes are re-emitted so
                // the redacted line stays as readable as the original.
                (
                    format!(r#"(?i){PRE}({KEYS}){KEY_AND_SEP}"[^"]*""#),
                    r#"${1}${2}${3}"***""#,
                ),
                (
                    format!(r"(?i){PRE}({KEYS}){KEY_AND_SEP}'[^']*'"),
                    r#"${1}${2}${3}'***'"#,
                ),
                // `api_key=…`, `auth_token: …`, `TELEGRAM_BOT_TOKEN=…`,
                // `x-api-key: …` and `Authorization: Basic <base64>`. The auth
                // scheme is optional and consumed only when it is one, so
                // `token=abc` and `Authorization: Basic abc` both lose their
                // value and nothing else.
                (
                    format!(
                        r"(?i){PRE}({KEYS}){KEY_AND_SEP}(?:(?:basic|bearer|token)\s+)?({BARE_VALUE})"
                    ),
                    "${1}${2}${3}***",
                ),
                // A bare scheme with no separator at all: `Bearer <token>`. The
                // previous pattern covered this by treating whitespace as a
                // separator; that leniency is gone for `key value` prose, so the
                // one shape that genuinely needs it — an auth scheme — is spelled
                // out.
                (
                    format!(r#"(?i){PRE}(bearer)(\s+)({BEARER_VALUE})"#),
                    "${1}${2}${3}***",
                ),
                // A Telegram bot token wherever it appears, including inside the
                // request URL `reqwest` prints on a transport failure.
                (
                    format!(r"(?i){PRE}bot\d+:[A-Za-z0-9_-]{{30,}}"),
                    "${1}***",
                ),
                // A bare provider key with no key name in front of it, e.g. an
                // OpenRouter key pasted into a prompt or an error. The prefix is
                // a separate literal so this file does not itself contain a
                // key-shaped string.
                (
                    format!("{PRE}{}-[A-Za-z0-9_-]{{16,}}", "sk"),
                    "${1}***",
                ),
            ];

            patterns
                .into_iter()
                .filter_map(|(pattern, replacement)| {
                    Regex::new(&pattern)
                        .ok()
                        .map(|regex| Rule { regex, replacement })
                })
                .collect()
        })
        .as_slice()
}

/// Register one exact secret value to scrub from every future [`redact`] call.
///
/// Returns `true` when the value is (or already was) registered.
///
/// Rejected, and `false`:
///
/// * **empty or whitespace-only.** An empty needle matches at every position, so
///   registering one would turn every log line into `***`. The guard is explicit
///   because the failure is total and silent.
/// * **shorter than [`MIN_SECRET_LEN`].** Same failure, less obviously: a short
///   needle is not a credential, and replacing it everywhere would mangle
///   unrelated text.
/// * **longer than [`MAX_SECRET_LEN`].** See the constant.
///
/// A rejection is **logged**, with the length and never the value: a silently
/// refused registration is a credential that stays in the logs, so the operator
/// has to be able to see that it happened. The length is what makes it
/// diagnosable — `len=4` says the configured token is not a token, `len=600`
/// says it is not one either.
///
/// Registering the same value twice is a no-op, not a second scan.
pub fn register_secret(secret: &str) -> bool {
    let needle = secret.trim();
    if needle.is_empty() {
        return false;
    }
    if needle.len() < MIN_SECRET_LEN || needle.len() > MAX_SECRET_LEN {
        // The length only. A rejected needle is by definition one this module
        // will not scrub, so logging it would put it in the logs permanently —
        // the exact outcome the caller was trying to avoid.
        tracing::warn!(
            len = needle.len(),
            min = MIN_SECRET_LEN,
            max = MAX_SECRET_LEN,
            "redact: refused a secret whose length is outside the accepted range; \
             it will NOT be scrubbed from logs"
        );
        return false;
    }
    let Ok(mut secrets) = registry().write() else {
        return false;
    };
    if secrets.iter().any(|existing| existing == needle) {
        return true;
    }
    secrets.push(needle.to_string());
    // Published only after the value is in the list, so a concurrent reader that
    // sees `ARMED` is guaranteed to see the needle too.
    ARMED.store(true, Ordering::Release);
    true
}

/// Register every value in `secrets`; returns how many were accepted.
///
/// The count, never the values: this is called at startup with the process's own
/// credentials and its result is logged.
pub fn register_secrets<'a>(secrets: impl IntoIterator<Item = &'a str>) -> usize {
    secrets
        .into_iter()
        .filter(|secret| register_secret(secret))
        .count()
}

/// Replace every registered secret value in `text` with `***`.
///
/// Runs before the shape rules: a configured value is the one thing this module
/// can guarantee is a secret, and replacing it first means no rule can split it
/// into pieces the exact match would no longer find.
fn scrub_registered(text: &str) -> String {
    let Ok(secrets) = registry().read() else {
        // A poisoned registry is a failure to redact, so the text is left
        // untouched rather than silently mangled — but note that `redact` never
        // panics while holding this lock, so poisoning is unreachable today.
        return text.to_string();
    };
    if secrets.is_empty() {
        // The second half of the arm check. `redact` only calls this once
        // `ARMED` is observed, so the branch is not the hot path's guard; it is
        // what makes this function correct on its own, for any caller.
        return text.to_string();
    }
    let mut out = text.to_string();
    for needle in secrets.iter() {
        if out.contains(needle.as_str()) {
            out = out.replace(needle.as_str(), MASK);
        }
    }
    out
}

/// Replace credential-shaped values with `***`, preserving the key and the
/// separator so the redacted text stays readable, and replace every value
/// registered through [`register_secret`] wherever it appears.
pub fn redact(s: &str) -> String {
    let mut text = Cow::Borrowed(s);

    // Acquire, pairing with the release store in `register_secret`: the flag is
    // what publishes the needle list, so the load that observes it has to be
    // ordered against the write that filled it.
    if ARMED.load(Ordering::Acquire) {
        text = Cow::Owned(scrub_registered(text.as_ref()));
    }

    for rule in rules() {
        // `replace_all` borrows `text`, so the owned result is moved out before
        // `text` is reassigned.
        let replaced = match rule.regex.replace_all(text.as_ref(), rule.replacement) {
            Cow::Owned(next) => Some(next),
            Cow::Borrowed(_) => None,
        };
        if let Some(next) = replaced {
            text = Cow::Owned(next);
        }
    }

    text.into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A Telegram-shaped bot token. Built at run time so this file never carries
    /// a credential-shaped literal.
    fn bot_token() -> String {
        format!("{}{}{}", "8123456789", ":", "A".repeat(35))
    }

    fn telegram_url() -> String {
        format!(
            "error sending request for url (https://api.telegram.org/bot{}/sendMessage)",
            bot_token()
        )
    }

    // ── The five shapes that reached the log ring unredacted ────────────────

    /// The live leak: a `reqwest` transport error renders the request URL, and
    /// the URL carries `bot<token>`. Nothing else in the message is key-shaped.
    #[test]
    fn a_telegram_bot_token_in_a_url_is_redacted() {
        let redacted = redact(&telegram_url());

        assert!(
            !redacted.contains(&bot_token()),
            "the bot token must not survive redaction: {redacted}"
        );
        assert!(
            redacted.contains("api.telegram.org"),
            "the URL is still useful for diagnosis: {redacted}"
        );
        assert!(
            redacted.contains("sendMessage"),
            "the path is still useful for diagnosis: {redacted}"
        );
    }

    /// `\b` does not match between `_` and a letter, so every underscore-joined
    /// key name was invisible to the old pattern. These are the names a `.env`
    /// file uses.
    #[test]
    fn underscore_joined_key_names_are_redacted() {
        for (input, expected) in [
            ("auth_token=VALUE0", "auth_token=***"),
            ("TELEGRAM_BOT_TOKEN=VALUE0", "TELEGRAM_BOT_TOKEN=***"),
            ("bot_token: VALUE0", "bot_token: ***"),
            ("x-api-key: VALUE0", "x-api-key: ***"),
            ("OPENROUTER_API_KEY=VALUE0", "OPENROUTER_API_KEY=***"),
        ] {
            assert_eq!(redact(input), expected, "input {input:?}");
        }
    }

    /// A `Basic` credential is a credential. The old pattern knew only `bearer`,
    /// so `Authorization: Basic <base64>` passed through untouched.
    #[test]
    fn an_authorization_basic_header_is_redacted() {
        let encoded = format!("{}{}", "dXNlcjpwYXNzd29y", "ZA==");
        let redacted = redact(&format!("Authorization: Basic {encoded}"));

        assert!(
            !redacted.contains(&encoded),
            "the encoded credential must not survive: {redacted}"
        );
        assert_eq!(redacted, "Authorization: ***");
    }

    /// A bare provider key has no key name in front of it, so no `key=value`
    /// rule can see it.
    #[test]
    fn a_bare_provider_key_is_redacted() {
        let key = format!("{}-or-v1-{}", "sk", "b".repeat(40));
        let redacted = redact(&format!("the model rejected the key {key}"));

        assert!(
            !redacted.contains(&key),
            "a bare provider key must be redacted: {redacted}"
        );
        assert_eq!(redacted, "the model rejected the key ***");
    }

    #[test]
    fn the_obvious_shapes_still_work() {
        assert_eq!(redact("api_key=VALUE0"), "api_key=***");
        assert_eq!(redact("Bearer TOKENVALUE"), "Bearer ***");
        assert_eq!(redact("password: HUNTER2"), "password: ***");
        assert_eq!(redact("nothing sensitive"), "nothing sensitive");
    }

    // ── Not redacting: the L1 over-redaction ────────────────────────────────

    /// A bare space is not a separator. The old pattern accepted one, so this
    /// sentence came out as `no api token *** configured yet`.
    #[test]
    fn ordinary_prose_mentioning_a_key_name_is_left_alone() {
        for prose in [
            "no api token is configured yet",
            "nothing sensitive",
            "the token bucket is empty",
            "api keys are stored in the config file",
            "the secret is that there is no secret",
            "bearer bonds are a financial instrument",
        ] {
            assert_eq!(redact(prose), prose, "prose was mangled: {prose:?}");
        }
    }

    /// `\S+` ate everything to the end of an unspaced line: this JSON object
    /// used to collapse to `{"api_key***`, losing the model name with it. It is
    /// also the case that proves a quoted key needs `["']?` in the separator
    /// group — without it nothing matched here at all.
    #[test]
    fn an_unspaced_json_line_keeps_everything_after_the_redacted_value() {
        let redacted = redact(r#"{"api_key":"VALUE0","model":"moonshotai/kimi-k2.6"}"#);

        assert_eq!(
            redacted, r#"{"api_key":"***","model":"moonshotai/kimi-k2.6"}"#,
            "the rest of the line must survive with its delimiters intact"
        );
    }

    #[test]
    fn a_quoted_value_does_not_swallow_its_closing_delimiter() {
        let redacted = redact("password='HUNTER2', retries=3");

        assert!(
            redacted.contains("retries=3"),
            "the following pair must survive: {redacted}"
        );
        assert!(!redacted.contains("HUNTER2"), "got {redacted}");
    }

    // ── The exact-value registry ────────────────────────────────────────────

    /// The registry is the only mechanism that catches a secret with no
    /// recognisable shape: here it sits in a URL path and in prose, with no key
    /// name and no prefix.
    #[test]
    fn a_registered_value_is_scrubbed_wherever_it_appears() {
        // A needle unique to this test: the registry is process-global and the
        // unit tests share one process.
        let secret = "registry-probe-alpha-6c1f0a5e";
        assert!(register_secret(secret), "the needle must be accepted");

        for input in [
            format!("GET https://example.invalid/{secret}/tasks"),
            format!("the call failed while using {secret} to authenticate"),
            secret.to_string(),
        ] {
            let redacted = redact(&input);
            assert!(
                !redacted.contains(secret),
                "a registered value must never survive: {redacted}"
            );
            assert!(redacted.contains(MASK), "got {redacted}");
        }
    }

    /// An empty needle matches at every position: registering one would replace
    /// the whole of every log line with `***`. The guard has to be explicit and
    /// it has to hold for whitespace too, since a value is trimmed before use.
    #[test]
    fn an_empty_or_whitespace_only_secret_is_never_registered() {
        for rejected in ["", " ", "\t", "\n", "   \t \n "] {
            assert!(
                !register_secret(rejected),
                "{rejected:?} must be refused rather than registered"
            );
        }

        // The proof that matters: output is untouched afterwards. If any of the
        // calls above had registered an empty needle, every character of this
        // line would be gone.
        let line = "a perfectly ordinary log line";
        assert_eq!(redact(line), line);
    }

    /// A needle the size of a file would make every `redact()` call a full-text
    /// scan for it.
    #[test]
    fn an_oversized_secret_is_refused() {
        let huge = "x".repeat(MAX_SECRET_LEN + 1);
        assert!(!register_secret(&huge));

        let prefix = "registry-probe-cap-";
        let at_the_cap = format!("{prefix}{}", "y".repeat(MAX_SECRET_LEN - prefix.len()));
        assert_eq!(at_the_cap.len(), MAX_SECRET_LEN);
        assert!(register_secret(&at_the_cap));
        assert!(!redact(&at_the_cap).contains(&at_the_cap));
    }

    /// A short needle is not a credential, and registering one rewrites
    /// *unrelated* text: `redact` replaces a registered value wherever it
    /// appears, so a three-character needle would mangle every log line,
    /// artifact and stored job summary that happens to contain those
    /// characters. The floor is the fix.
    #[test]
    fn a_secret_shorter_than_the_floor_is_refused() {
        // A value short enough to appear inside ordinary prose.
        let too_short = "tok";
        assert!(
            !register_secret(too_short),
            "a 3-byte needle must be refused"
        );
        assert!(
            !register_secret(&"z".repeat(MIN_SECRET_LEN - 1)),
            "one byte below the floor must be refused"
        );

        // The proof that matters: the value is still readable in ordinary text
        // afterwards. If it had been registered, every occurrence would be
        // `***` — including this sentence's.
        let prose = "the tok field of an unrelated struct is named tok";
        assert_eq!(
            redact(prose),
            prose,
            "a refused needle must not rewrite unrelated text"
        );

        // And the floor itself is accepted, so the guard is a floor rather than
        // a blanket refusal of short values.
        let at_the_floor = "floor-01";
        assert_eq!(at_the_floor.len(), MIN_SECRET_LEN);
        assert!(register_secret(at_the_floor));
        assert!(!redact(at_the_floor).contains(at_the_floor));
    }

    /// The rejection is logged with the length and never the value: a silently
    /// refused registration is a credential that stays in the logs, and a
    /// rejection logged with the needle would be worse than the silence.
    #[test]
    fn a_refused_needle_is_reported_by_length_and_never_by_value() {
        use std::io::Write as _;
        use tracing_subscriber::fmt::MakeWriter;
        use tracing_subscriber::layer::SubscriberExt;

        struct Capture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

        impl std::io::Write for Capture {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0
                    .lock()
                    .expect("the capture buffer")
                    .extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        impl<'a> MakeWriter<'a> for Capture {
            type Writer = Capture;

            fn make_writer(&'a self) -> Self::Writer {
                Capture(std::sync::Arc::clone(&self.0))
            }
        }

        let buffer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(Capture(std::sync::Arc::clone(&buffer))),
        );

        // A recognisable short value: if it were logged, the assertion below
        // would see it.
        let refused = "SHORTV";
        tracing::subscriber::with_default(subscriber, || {
            assert!(!register_secret(refused), "a 6-byte needle must be refused");
        });
        let _ = std::io::stdout().flush();

        let printed =
            String::from_utf8_lossy(&buffer.lock().expect("the capture buffer")).into_owned();
        assert!(
            !printed.contains(refused),
            "a refused needle must never be logged: {printed}"
        );
        assert!(
            printed.contains("len=6"),
            "the rejection must report the length, which is what makes it \
             diagnosable: {printed}"
        );
        assert!(
            printed.contains("will NOT be scrubbed"),
            "the operator has to learn the value is not being scrubbed: {printed}"
        );
    }

    #[test]
    fn registering_the_same_value_twice_is_idempotent() {
        let secret = "registry-probe-beta-2d9b7c34";
        assert!(register_secret(secret));
        assert!(register_secret(secret));
        assert_eq!(
            registry()
                .read()
                .map(|secrets| secrets.iter().filter(|s| *s == secret).count())
                .unwrap_or(0),
            1
        );
    }

    /// `redact` runs inside the `tracing` layer, so it must not panic — including
    /// while another thread is registering.
    #[test]
    fn redaction_is_safe_while_another_thread_registers() {
        let writer = std::thread::spawn(|| {
            for i in 0..64 {
                register_secret(&format!("registry-probe-race-{i:04}-c0ffee"));
            }
        });
        for _ in 0..64 {
            let _ = redact("token=abc api_key=def https://api.telegram.org/bot1:AAAA/sendMessage");
        }
        writer.join().unwrap();
    }

    // ── The shape rules themselves ──────────────────────────────────────────

    /// A pattern that fails to compile is skipped at run time (see [`rules`]), so
    /// the count is pinned here: a typo must fail CI, not quietly narrow the net.
    #[test]
    fn every_shape_rule_compiles() {
        assert_eq!(
            rules().len(),
            6,
            "a shape rule failed to compile and was silently skipped"
        );
    }

    /// The `regex` crate cannot compile look-around, which is why the boundaries
    /// are capture groups. This pins that fact so a future change back to
    /// `(?<![A-Za-z0-9])` fails here with the reason instead of silently
    /// disabling redaction at run time.
    #[test]
    fn look_around_is_not_available_in_this_regex_engine() {
        // Built at run time, not written as a literal: `clippy::invalid_regex`
        // denies the literal form, and the point of this test is precisely that
        // the pattern is invalid.
        let pattern = format!("{}{}", "(?<!", "[A-Za-z0-9])token");
        let error = Regex::new(&pattern).unwrap_err();
        assert!(
            error.to_string().contains("look-around"),
            "unexpected error: {error}"
        );
    }
}
