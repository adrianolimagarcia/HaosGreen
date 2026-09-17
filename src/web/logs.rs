//! Bounded in-memory ring buffer of recent tracing events, and the
//! `tracing_subscriber::Layer` that feeds it.
//!
//! The dashboard's log view (Phase 4, Task 18) reads from here; [`LogLayer`] is
//! installed by `main.rs` alongside the console formatter, so the buffer sees
//! the same events the terminal does.
//!
//! # What actually bounds this buffer
//!
//! Three limits, because "bounded by entry count" is not a bound in bytes:
//!
//! * [`LogBuffer::capacity`] entries, oldest evicted first.
//! * [`MAX_MESSAGE_BYTES`] per message, applied at capture with an explicit
//!   `… [N more characters]` marker. Without it one 100 MB line is one entry.
//! * [`DEFAULT_MAX_BYTES`] of retained text, evicted oldest-first exactly like
//!   the entry cap. The ring holds
//!   `min(capacity × per-entry size, max_bytes)` — so a capacity of 2000 with
//!   8 KiB messages is 4 MiB, not 16 MiB.
//!
//! Readers share entries through `Arc` rather than copying them: `recent` and
//! `since` bump refcounts under the lock instead of cloning payloads, so a
//! dashboard read cannot stall the process's logging path (every `tracing` call
//! in the process takes the same mutex). See
//! [`tests::readers_share_the_entry_allocation_instead_of_cloning_it`].
//!
//! Everything downstream is bounded by those: one `GET /api/logs` returns at
//! most [`crate::web::routes::logs::MAX_LIMIT`] entries (so at most
//! `MAX_LIMIT × MAX_MESSAGE_BYTES`, 8 MiB, and in practice the byte budget),
//! one SSE stream queues at most 128 serialized entries, and the number of
//! concurrent streams is capped by [`MAX_LOG_STREAMS`] permits.
//!
//! # What the layer captures, and why
//!
//! The inclusion policy has exactly two rules, and both are deliberate:
//!
//! 1. **The `EnvFilter` decides.** The layer adds no target filter of its own.
//!    `main.rs` builds its subscriber with [`log_subscriber`], which puts the same
//!    `EnvFilter` the console formatter uses into the same stack, so an event
//!    the operator's `RUST_LOG` suppresses never reaches the buffer. The
//!    dashboard therefore shows what the console shows, and the operator's
//!    existing configuration is the only knob that has to be understood.
//!
//!    (`Layered::enabled` ANDs every layer's `enabled` with the inner
//!    subscriber's, so an `EnvFilter` anywhere in the stack gates the whole
//!    stack. Its position is not load-bearing — what matters is that it is in
//!    the stack at all, which `log_subscriber` guarantees and
//!    [`tests::the_layer_respects_the_env_filter`] checks.)
//! 2. **`TRACE` is never captured.** Everything at `DEBUG` and above is. The
//!    ring holds [`LOG_BUFFER_CAPACITY`](crate::web::state::LOG_BUFFER_CAPACITY)
//!    entries; `TRACE` in this dependency tree is per-frame, per-poll transport
//!    chatter (`hyper`, `h2`, `mio`) that a single HTTP request can emit
//!    thousands of lines of. An operator who sets `RUST_LOG=trace` would
//!    otherwise find the ring holding nothing but the last few milliseconds of
//!    socket activity — the failure mode the bounded buffer has to be protected
//!    against.
//!
//! A per-target denylist was considered and rejected: it would silently hide
//! events from the operator with no way to tell that anything had been dropped,
//! and the level floor plus the operator's own filter already cover the
//! realistic flood. Every entry that *is* captured is redacted at construction
//! (see [`LogEntry::new`]).
//!
//! # The console is redacted too, at the writer
//!
//! Redacting inside this layer only protects the **ring**. `main.rs` also
//! installs the console formatter, and before [`RedactingWriter`] existed that
//! formatter had no redaction at all: every event whose `message` carried a
//! credential went to stdout — and so to `journalctl`, where
//! `setup/service.rs` tells the operator to read it — verbatim, while the
//! dashboard's copy of the same event was clean. A leak that is invisible to the
//! log-view tests and persisted on disk is the worst shape this bug could have.
//!
//! [`RedactingWriter`] closes it on the **write** path: it is a
//! [`MakeWriter`] wrapper that runs
//! [`redact`](crate::supervisor::redact::redact) over each buffer before
//! forwarding it to the writer it wraps, and [`console_layer_with`] is the
//! composition that installs it. Redacting in [`MessageVisitor`] instead would
//! have fixed nothing here: the visitor feeds the ring, which was already
//! covered.
//!
//! This is what makes the exact-value registry's stated purpose true. A shape
//! rule cannot catch a credential with no recognisable shape, and the most
//! likely secret this process emits has none — `reqwest` renders the request URL
//! in a transport error, so a failed Telegram call puts
//! `https://api.telegram.org/bot<token>/sendMessage` into a log message with no
//! key, no separator and no prefix. `main.rs` registers every configured value
//! by hand for exactly that case, and until the writer existed those
//! registrations reached the ring and nothing else.
//!
//! The cost is one `redact()` call per console line — the same work the ring
//! already does for the same events — and it is paid on the logging path of a
//! process that emits a handful of lines a second.
//!
//! # The layer is armed, not merely installed
//!
//! `main.rs` installs the layer before the configuration is loaded — the
//! subscriber has to exist before anything can log, and `--setup` runs before
//! there is a configuration at all — so the layer cannot be *absent* for an
//! instance that turns out to have `[web].enabled = false`. It is gated on an
//! [`AtomicBool`] instead: `on_event` returns on one relaxed load until `main.rs`
//! has seen a configuration that enables the dashboard. An instance that never
//! enables it pays neither the visitor, nor the redaction, nor the timestamp,
//! and retains nothing.
//!
//! The gate is deliberately **not** [`Layer::enabled`]. `Layered::enabled` ANDs
//! every layer's answer with the inner subscriber's, so a layer that answered
//! `false` would silence every layer inside it — the console formatter
//! included — turning "the dashboard is off" into "the process logs nothing".
//!
//! # The layer cannot take the process down
//!
//! `on_event` is synchronous and never awaits, holds no lock across a call to
//! anything else, and never panics: a poisoned buffer lock makes
//! [`LogBuffer::push`] drop the event rather than propagate. A diagnostic
//! convenience must not be able to kill the process that also serves Telegram.
//!
//! A poisoned lock is *not* silent, though: [`LogBuffer::poisoned`] reports it
//! and the log routes answer 503, because a ring that has stopped recording
//! while `GET /api/logs` still returns 200 with a stale list is exactly the
//! "indistinguishable from a quiet process" failure the 503 contract exists to
//! prevent.

use serde::Serialize;
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::Semaphore;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

/// Most bytes of one message the ring retains.
///
/// The message is truncated at capture, with an explicit marker, rather than
/// stored whole and truncated when rendered: the ring is what has to be bounded,
/// and a message that never enters it cannot be the reason the process grows.
/// 8 KiB is two orders of magnitude above a normal log line and well below
/// anything an operator would want to read in a browser.
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024;

/// Default budget for the retained text of a whole ring, in bytes.
///
/// The entry count alone does not bound memory: 2000 entries of a megabyte each
/// is two gigabytes. The byte budget is what makes "bounded" true regardless of
/// message size; the entry count is what keeps the *number* of entries (and so
/// the cost of a scan) bounded regardless of how small they are.
pub const DEFAULT_MAX_BYTES: usize = 4 * 1024 * 1024;

/// How many live log streams one buffer will serve at once.
///
/// Every SSE tail is a spawned task plus a 128-slot channel of serialized
/// entries — up to `128 × MAX_MESSAGE_BYTES`, about 1 MiB, per stream — and an
/// authenticated client can ask for as many as it likes, so the number of tails
/// has to be bounded by the server rather than by the client's restraint. Eight
/// covers the realistic case with room to spare (an operator with several tabs
/// open, plus a `curl` while debugging) while keeping the dashboard's tail cost
/// under ~8 MiB.
///
/// A request over the limit is answered **429 Too Many Requests**, not 503:
/// 503 is this dashboard's "started without this feature" contract, and the log
/// view treats it as terminal, whereas a stream limit is transient and has to
/// be retried.
///
/// The cap lives on the buffer rather than on `WebState` because the buffer is
/// the resource the tails consume: one buffer, one set of tails, and a test that
/// builds its own buffer gets its own cap.
pub const MAX_LOG_STREAMS: usize = 8;

/// One tracing event, already redacted.
#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    /// RFC 3339 timestamp, captured when the event reaches the buffer.
    pub timestamp: String,
    /// `tracing::Level::as_str()` of the event: `"ERROR"`, `"WARN"`, `"INFO"`
    /// or `"DEBUG"`. `"TRACE"` never appears — see the module documentation.
    pub level: String,
    pub target: String,
    pub message: String,
}

impl LogEntry {
    /// Build an entry stamped with the current time.
    ///
    /// The message is redacted here, at construction, not at render time: a
    /// secret that is never stored cannot be leaked by a later bug in a
    /// rendering path.
    ///
    /// Redaction runs **before** truncation, and the order matters: truncating
    /// first could cut a credential in half, leaving a prefix that no rule
    /// matches and that is still a disclosure.
    pub fn new(level: &str, target: &str, message: &str) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: level.to_string(),
            target: target.to_string(),
            message: truncate(crate::supervisor::redact::redact(message)),
        }
    }

    /// The bytes this entry occupies in the ring.
    fn bytes(&self) -> usize {
        self.timestamp.len() + self.level.len() + self.target.len() + self.message.len()
    }
}

/// Cut `message` down to [`MAX_MESSAGE_BYTES`] and say how much was dropped.
///
/// The cut is made on a `char` boundary so the retained text is always valid
/// UTF-8, and the marker counts *characters*, not bytes: an operator reading
/// "… [900 more characters]" should be able to trust the number.
fn truncate(message: String) -> String {
    if message.len() <= MAX_MESSAGE_BYTES {
        return message;
    }
    let total_chars = message.chars().count();
    let mut cut = MAX_MESSAGE_BYTES;
    while cut > 0 && !message.is_char_boundary(cut) {
        cut -= 1;
    }
    let kept = &message[..cut];
    let dropped = total_chars.saturating_sub(kept.chars().count());
    format!("{kept}… [{dropped} more characters]")
}

/// A fixed-capacity ring buffer of [`LogEntry`].
///
/// Every method is failure-tolerant by design: a poisoned lock drops the event
/// (on write) or returns nothing (on read). The dashboard's log view is a
/// diagnostic convenience, so it must never be able to panic the process that
/// also serves Telegram — [`LogBuffer::poisoned`] is how the failure is surfaced
/// to the operator instead.
pub struct LogBuffer {
    capacity: usize,
    max_bytes: usize,
    inner: Mutex<Inner>,
    /// Permits for live SSE tails. See [`MAX_LOG_STREAMS`].
    tail_permits: Arc<Semaphore>,
}

struct Inner {
    entries: VecDeque<Arc<LogEntry>>,
    /// Total bytes of the retained entries, kept in step with `entries` inside
    /// the same lock so a reader can never observe the two out of step.
    bytes: usize,
    /// Number of entries ever pushed — the sequence number the *next* entry
    /// will receive.
    ///
    /// This is what makes the SSE tail correct across a ring wrap. Entries have
    /// no stable identity otherwise: `recent(n)` is a window over positions, so
    /// a tail that re-read "the last N" and diffed by index would repeat
    /// entries after a wrap and skip entries when the window moved. A monotonic
    /// counter turns "what have I already sent?" into a comparison that a wrap
    /// cannot confuse. It lives inside the same lock as the entries so a reader
    /// can never observe the two out of step.
    pushed: u64,
}

impl LogBuffer {
    /// A buffer bounded by `capacity` entries and by [`DEFAULT_MAX_BYTES`].
    pub fn new(capacity: usize) -> Self {
        Self::with_max_bytes(capacity, DEFAULT_MAX_BYTES)
    }

    /// A buffer with an explicit byte budget.
    ///
    /// Separate from [`LogBuffer::new`] so the byte budget can be exercised with
    /// a few kilobytes instead of four megabytes.
    pub fn with_max_bytes(capacity: usize, max_bytes: usize) -> Self {
        Self {
            capacity,
            max_bytes,
            inner: Mutex::new(Inner {
                entries: VecDeque::with_capacity(capacity),
                bytes: 0,
                pushed: 0,
            }),
            tail_permits: Arc::new(Semaphore::new(MAX_LOG_STREAMS)),
        }
    }

    /// The permits that bound how many live tails this buffer serves.
    ///
    /// A stream takes one with `try_acquire_owned` and holds it for as long as
    /// its response body lives, so the bound is on *live* streams rather than on
    /// requests in flight, and a client that disconnects returns its permit the
    /// moment its body is dropped.
    ///
    /// Returned as an `Arc` rather than a reference because the permit has to
    /// outlive the handler that takes it: the response body owns it.
    pub fn tail_permits(&self) -> Arc<Semaphore> {
        Arc::clone(&self.tail_permits)
    }

    /// Append an entry, dropping the oldest until both limits hold.
    ///
    /// A capacity of zero is legal and discards everything. The newest entry is
    /// always retained, even if it alone exceeds the byte budget — a ring that
    /// evicted the entry it was just handed would report an empty log for a
    /// process that is logging.
    pub fn push(&self, entry: LogEntry) {
        let entry = Arc::new(entry);
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        inner.bytes = inner.bytes.saturating_add(entry.bytes());
        inner.entries.push_back(entry);
        inner.pushed = inner.pushed.saturating_add(1);

        while inner.entries.len() > self.capacity
            || (inner.bytes > self.max_bytes && inner.entries.len() > 1)
        {
            let Some(oldest) = inner.entries.pop_front() else {
                break;
            };
            inner.bytes = inner.bytes.saturating_sub(oldest.bytes());
        }
    }

    /// The most recent `limit` entries, oldest first.
    ///
    /// The entries are shared, not copied: the only work done under the lock is
    /// one refcount bump per entry. Cloning the payloads here — which is what
    /// this used to do, up to 1000 entries of arbitrary size — meant a dashboard
    /// read blocked every `tracing` call in the process for as long as the copy
    /// took.
    pub fn recent(&self, limit: usize) -> Vec<Arc<LogEntry>> {
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };
        let start = inner.entries.len().saturating_sub(limit);
        inner.entries.iter().skip(start).cloned().collect()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// The byte budget the ring evicts against.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Bytes of entry text currently retained.
    pub fn bytes(&self) -> usize {
        self.inner.lock().map(|inner| inner.bytes).unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .map(|inner| inner.entries.len())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// True when the ring has stopped recording.
    ///
    /// `push` and the readers all treat a poisoned lock as "do nothing", which
    /// on its own is indistinguishable from a quiet process: the routes would
    /// answer 200 with the entries from before the poison and an operator would
    /// see a log that simply stopped. The routes check this and answer 503.
    pub fn poisoned(&self) -> bool {
        self.inner.is_poisoned()
    }

    /// Poison the ring's lock, for tests that need to prove the 503 contract.
    ///
    /// Test-only, and `#[doc(hidden)]` for the same reason the
    /// `spawn_for_test_*` entry points in `web::mod` are: the condition it
    /// creates is otherwise unreachable (nothing in this module panics while
    /// holding the lock), and an integration test cannot reach a private field
    /// to create it.
    #[doc(hidden)]
    pub fn poison_for_test(&self) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = self.inner.lock().expect("poison_for_test: lock");
            panic!("poison_for_test: deliberately poisoning the log buffer lock");
        }));
    }

    /// The sequence number the next pushed entry will receive.
    ///
    /// Read once when an SSE tail starts: entries pushed after this call are
    /// the ones that tail is responsible for delivering.
    pub fn next_seq(&self) -> u64 {
        self.inner.lock().map(|inner| inner.pushed).unwrap_or(0)
    }

    /// Up to `max` entries whose sequence number is `>= from_seq`, oldest
    /// first, plus the `from_seq` to use on the next call.
    ///
    /// Three properties matter to the SSE tail and each is deliberate:
    ///
    /// * **No duplicates.** The returned `next` is strictly after the last
    ///   returned entry, so a caller that feeds it back can never be handed the
    ///   same entry twice — including when the ring wrapped between two calls.
    /// * **No reordering.** Entries come out in push order.
    /// * **Bounded work.** At most `max` entries are handed out, and each is a
    ///   refcount bump rather than a copy, so a caller that fell behind (or a
    ///   burst of thousands of events) costs one bounded allocation per call
    ///   rather than the whole ring.
    ///
    /// If `from_seq` is older than the oldest entry still retained — the tail
    /// fell further behind than the capacity — the gap is skipped and the
    /// returned `next` starts at the oldest retained entry. Those entries are
    /// gone; reporting the gap is the caller's business, and the tail cannot
    /// invent them.
    pub fn since(&self, from_seq: u64, max: usize) -> (Vec<Arc<LogEntry>>, u64) {
        let Ok(inner) = self.inner.lock() else {
            return (Vec::new(), from_seq);
        };

        // Sequence number of the oldest entry still retained.
        let oldest = inner.pushed.saturating_sub(inner.entries.len() as u64);
        // Clamped to `pushed` so a caller holding a sequence number from the
        // future cannot stall the cursor past the end of the buffer forever.
        let start = from_seq.max(oldest).min(inner.pushed);
        let skip = ((start - oldest) as usize).min(inner.entries.len());
        let take = (inner.entries.len() - skip).min(max);

        let entries = inner
            .entries
            .iter()
            .skip(skip)
            .take(take)
            .cloned()
            .collect();
        (entries, start + take as u64)
    }
}

/// The lowest severity the dashboard buffer keeps; `TRACE` is dropped.
///
/// `Level` orders most severe first, so `<= DEBUG` admits
/// `ERROR`/`WARN`/`INFO`/`DEBUG`.
const MIN_CAPTURED_LEVEL: Level = Level::DEBUG;

/// Whether an event at `level` is worth a slot in the ring.
fn captures(level: Level) -> bool {
    level <= MIN_CAPTURED_LEVEL
}

/// A `tracing_subscriber::Layer` that copies events into a [`LogBuffer`].
///
/// Installed by `main.rs` with the same `EnvFilter` the console formatter uses,
/// so the dashboard sees what the terminal sees, and armed by `main.rs` once it
/// knows the dashboard is enabled. See the module documentation for the
/// inclusion policy and for why the arm switch is not [`Layer::enabled`].
pub struct LogLayer {
    buffer: Arc<LogBuffer>,
    armed: Arc<AtomicBool>,
}

impl LogLayer {
    pub fn new(buffer: Arc<LogBuffer>, armed: Arc<AtomicBool>) -> Self {
        Self { buffer, armed }
    }
}

impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        // One relaxed load on the disabled path: an instance with
        // `[web].enabled = false` pays nothing else — no visitor, no redaction,
        // no timestamp, nothing retained.
        if !self.armed.load(Ordering::Relaxed) {
            return;
        }

        let metadata = event.metadata();
        if !captures(*metadata.level()) {
            return;
        }

        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);

        // `LogEntry::new` is the only construction path for an entry anywhere in
        // the crate, and it is the one that redacts.
        self.buffer.push(LogEntry::new(
            metadata.level().as_str(),
            metadata.target(),
            visitor.message.as_deref().unwrap_or_default(),
        ));
    }
}

/// The subscriber `main.rs` installs, without the console formatter.
///
/// This exists as a function rather than as two chained `.with` calls in
/// `main.rs` so that the composition the dashboard actually ships is the one
/// under test: [`tests::the_layer_respects_the_env_filter`] drives this exact
/// function and fails if the filter were dropped from it — the regression that
/// matters, a buffer holding events the console suppresses.
///
/// `Layered::enabled` ANDs every layer's `enabled` with the inner subscriber's,
/// so an `EnvFilter` anywhere in the stack gates the whole stack: the filter's
/// position is not load-bearing, only its presence. The layer therefore does
/// **not** filter itself — a layer that returned `false` from `enabled` would
/// silence every layer inside it, the console formatter included. Filtering
/// belongs to the filter, and the dashboard's on/off switch is `armed`, checked
/// inside `on_event`.
///
/// `LookupSpan` is part of the return type because `fmt::layer()`, which
/// `main.rs` adds on top, requires it; `Registry` provides it.
pub fn log_subscriber(
    filter: tracing_subscriber::EnvFilter,
    buffer: Arc<LogBuffer>,
    armed: Arc<AtomicBool>,
) -> impl Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a> + Send + Sync + 'static
{
    tracing_subscriber::registry()
        .with(filter)
        .with(LogLayer::new(buffer, armed))
}

/// The console formatter `main.rs` installs, over a redacting writer.
///
/// This exists as a function rather than as an inline
/// `fmt::layer().with_writer(...)` in `main.rs` for the same reason
/// [`log_subscriber`] does: the composition the binary actually ships is then
/// the one under test, so a change that drops the redacting wrapper fails
/// [`tests::the_console_writer_redacts_a_registered_secret`] instead of shipping.
///
/// `writer` is a parameter rather than a hard-coded `std::io::stdout` so the
/// test can capture what the formatter would have printed. `main.rs` passes
/// `std::io::stdout`.
pub fn console_layer_with<W, S>(writer: W) -> impl Layer<S>
where
    W: for<'a> MakeWriter<'a> + 'static,
    S: Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    tracing_subscriber::fmt::layer().with_writer(RedactingWriter::new(writer))
}

/// A [`MakeWriter`] that redacts everything written through it.
///
/// See the module documentation for why redacting here — and not in
/// [`MessageVisitor`] — is the fix: the visitor feeds the dashboard's ring, which
/// was already covered, while this is the only thing standing between an event
/// and stdout, `journalctl`, and the operator's terminal.
pub struct RedactingWriter<W> {
    inner: W,
}

impl<W> RedactingWriter<W> {
    /// Wrap `inner`, which is any [`MakeWriter`] — `std::io::stdout` in
    /// `main.rs`, a capture buffer in the tests.
    pub fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<'a, W> MakeWriter<'a> for RedactingWriter<W>
where
    W: MakeWriter<'a>,
{
    type Writer = RedactingWriterGuard<W::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        RedactingWriterGuard {
            inner: self.inner.make_writer(),
            pending: Vec::new(),
        }
    }
}

/// The [`io::Write`] half of [`RedactingWriter`]: buffer, redact, forward.
///
/// The buffering is not decoration. `tracing-subscriber` 0.3.23 formats a whole
/// event into a thread-local `String` and hands it over in a single `write_all`
/// (`fmt/fmt_layer.rs:1049`), so redacting per `write` call would happen to be
/// complete today — but nothing in the [`MakeWriter`] contract promises one call
/// per event, and a formatter that split a credential across two calls would
/// defeat a per-call redaction while still looking correct. Buffering to the end
/// of each line, and forwarding whatever is left when the writer is dropped,
/// makes the property independent of how many calls the formatter makes.
///
/// A line is redacted whole, before any of it is written out: redacting after
/// the fact is not possible, and redacting per fragment could cut a credential
/// in half and leave a prefix no rule matches.
pub struct RedactingWriterGuard<W: io::Write> {
    inner: W,
    pending: Vec<u8>,
}

impl<W: io::Write> RedactingWriterGuard<W> {
    /// Redact `bytes` and hand them to the wrapped writer.
    fn forward(&mut self, bytes: &[u8]) -> io::Result<()> {
        // Lossy rather than fallible: a log writer that refuses to write because
        // an event carried a stray byte would turn a cosmetic problem into a
        // silent one. The console formatter emits UTF-8, so this is a guard
        // against a caller that does not, not a conversion that normally fires.
        let text = String::from_utf8_lossy(bytes);
        let redacted = crate::supervisor::redact::redact(&text);
        self.inner.write_all(redacted.as_bytes())
    }

    /// Forward every complete line buffered so far, keeping the tail.
    fn emit_complete_lines(&mut self) -> io::Result<()> {
        let Some(last_newline) = self.pending.iter().rposition(|byte| *byte == b'\n') else {
            return Ok(());
        };
        let tail = self.pending.split_off(last_newline + 1);
        let head = std::mem::replace(&mut self.pending, tail);
        self.forward(&head)
    }

    /// Forward whatever is buffered, complete line or not.
    fn emit_pending(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = std::mem::take(&mut self.pending);
        self.forward(&pending)
    }
}

impl<W: io::Write> io::Write for RedactingWriterGuard<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.pending.extend_from_slice(buf);
        self.emit_complete_lines()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.emit_pending()?;
        self.inner.flush()
    }
}

impl<W: io::Write> Drop for RedactingWriterGuard<W> {
    fn drop(&mut self) {
        // The formatter terminates every event with a newline, so this is the
        // path for a final fragment with no newline — and for a future caller
        // that never flushes. The error is dropped rather than panicking: a
        // `Drop` that panics while the process is shutting down would abort it.
        let _ = self.emit_pending();
    }
}

/// Picks the `message` field out of an event.
///
/// Every other field is deliberately ignored: the design spec's entry shape is
/// timestamp/level/target/message, and copying structured fields into the
/// message would produce a string nobody can parse.
///
/// `tracing::info!("a {b}")` records the message as `fmt::Arguments`, which
/// arrives through `record_debug`; `tracing::info!(message = "literal")`
/// records it as a string. Both are handled, as are the scalar shapes a
/// non-string `message` field can take.
#[derive(Default)]
struct MessageVisitor {
    message: Option<String>,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            // `Debug` for `fmt::Arguments` forwards to `Display`, so this is the
            // rendered message and not a quoted debug representation.
            self.message = Some(format!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    /// An armed switch, for the tests that are about capture rather than about
    /// the arm gate.
    fn armed() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(true))
    }

    #[test]
    fn the_buffer_is_bounded_and_drops_the_oldest_first() {
        let buffer = LogBuffer::new(3);
        for i in 0..5 {
            buffer.push(LogEntry::new("info", "test", &format!("line {i}")));
        }
        let entries = buffer.recent(10);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].message, "line 2");
        assert_eq!(entries[2].message, "line 4");
    }

    #[test]
    fn recent_returns_newest_last() {
        let buffer = LogBuffer::new(10);
        buffer.push(LogEntry::new("info", "t", "first"));
        buffer.push(LogEntry::new("warn", "t", "second"));
        let entries = buffer.recent(10);
        assert_eq!(entries[0].message, "first");
        assert_eq!(entries[1].message, "second");
    }

    #[test]
    fn recent_honours_the_requested_limit() {
        let buffer = LogBuffer::new(10);
        for i in 0..6 {
            buffer.push(LogEntry::new("info", "t", &format!("line {i}")));
        }
        let entries = buffer.recent(2);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].message, "line 4");
        assert_eq!(entries[1].message, "line 5");
    }

    #[test]
    fn a_zero_capacity_buffer_discards_everything() {
        let buffer = LogBuffer::new(0);
        buffer.push(LogEntry::new("info", "t", "line"));
        assert!(buffer.is_empty());
        assert!(buffer.recent(10).is_empty());
    }

    #[test]
    fn secrets_are_redacted_in_buffered_entries() {
        let buffer = LogBuffer::new(10);
        buffer.push(LogEntry::new("info", "t", "token=abc123 secret=xyz"));
        let entries = buffer.recent(1);
        assert!(!entries[0].message.contains("abc123"));
    }

    #[test]
    fn a_concurrent_flood_does_not_exceed_the_capacity() {
        use std::sync::Arc;

        let buffer = Arc::new(LogBuffer::new(100));
        let mut handles = Vec::new();
        for thread in 0..8 {
            let buffer = Arc::clone(&buffer);
            handles.push(std::thread::spawn(move || {
                for i in 0..250 {
                    buffer.push(LogEntry::new("info", "t", &format!("{thread}:{i}")));
                }
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }
        assert_eq!(buffer.len(), 100);
        assert_eq!(buffer.recent(usize::MAX).len(), 100);
    }

    // ── The byte budget (M2) ────────────────────────────────────────────────

    /// The entry count is not a bound in bytes. With a 4 KiB budget, entries of
    /// ~1 KiB must be evicted long before the capacity of 100 is reached.
    #[test]
    fn the_ring_evicts_on_bytes_and_not_only_on_the_entry_count() {
        let buffer = LogBuffer::with_max_bytes(100, 4 * 1024);
        let payload = "z".repeat(1024);

        for i in 0..10 {
            buffer.push(LogEntry::new("info", "t", &format!("{i}{payload}")));
        }

        assert!(
            buffer.len() < 10,
            "the byte budget must evict entries the count limit would have kept: {} retained",
            buffer.len()
        );
        assert!(
            buffer.bytes() <= 4 * 1024,
            "retained bytes must stay inside the budget: {}",
            buffer.bytes()
        );

        // The newest entry is always the one that was just pushed.
        let entries = buffer.recent(1);
        assert!(entries[0].message.starts_with('9'), "got {entries:?}");
    }

    /// A single entry larger than the whole budget must not empty the ring: a
    /// process that is logging must never show an empty log.
    #[test]
    fn a_single_entry_larger_than_the_budget_is_still_retained() {
        let buffer = LogBuffer::with_max_bytes(100, 16);
        buffer.push(LogEntry::new(
            "info",
            "t",
            "a message that is longer than the budget",
        ));

        assert_eq!(buffer.len(), 1, "the newest entry must survive eviction");
    }

    // ── The per-message cap (M2) ────────────────────────────────────────────

    /// One enormous log line is one entry unless it is capped at capture.
    #[test]
    fn a_message_larger_than_the_cap_is_truncated_with_a_marker() {
        let huge = "x".repeat(MAX_MESSAGE_BYTES * 3);
        let entry = LogEntry::new("info", "t", &huge);

        assert!(
            entry.message.len() < huge.len(),
            "the message must be capped: {} bytes retained",
            entry.message.len()
        );
        assert!(
            entry.message.contains("more characters]"),
            "the truncation must be explicit: {}",
            &entry.message[entry.message.len() - 40..]
        );

        // The number in the marker is the number of characters dropped.
        let dropped = huge.chars().count() - MAX_MESSAGE_BYTES;
        assert!(
            entry
                .message
                .contains(&format!("[{dropped} more characters]")),
            "the marker must count what was dropped: {}",
            &entry.message[entry.message.len() - 40..]
        );
    }

    /// The cut must not split a multi-byte character: the retained text is a
    /// `String`, so a byte-wise cut would panic or corrupt it.
    #[test]
    fn truncation_cuts_on_a_character_boundary() {
        let huge = "é".repeat(MAX_MESSAGE_BYTES);
        let entry = LogEntry::new("info", "t", &huge);
        assert!(entry.message.starts_with('é'));
        assert!(entry.message.contains("more characters]"));
    }

    #[test]
    fn a_message_inside_the_cap_is_untouched() {
        let entry = LogEntry::new("info", "t", "a short line");
        assert_eq!(entry.message, "a short line");
    }

    // ── Readers share the payload (M1) ──────────────────────────────────────

    /// The structural claim behind the lock-contention fix: a reader does not
    /// copy an entry, it takes a reference to the one the ring already holds.
    ///
    /// A timing assertion would be flaky; pointer identity is not. If `recent`
    /// cloned the payload — which is what it did before this test existed — the
    /// two reads would return two distinct allocations with a strong count of
    /// one each, and this fails.
    #[test]
    fn readers_share_the_entry_allocation_instead_of_cloning_it() {
        let buffer = LogBuffer::new(8);
        buffer.push(LogEntry::new("info", "t", &"p".repeat(4096)));

        let first = buffer.recent(1);
        let second = buffer.recent(1);
        let via_since = buffer.since(0, 8).0;

        assert!(
            Arc::ptr_eq(&first[0], &second[0]),
            "two reads of the same entry must return the same allocation"
        );
        assert!(
            Arc::ptr_eq(&first[0], &via_since[0]),
            "`since` must hand out the ring's own entry too"
        );
        assert_eq!(
            Arc::strong_count(&first[0]),
            4,
            "one reference in the ring plus one per reader — a clone would add \
             an allocation with a count of one, not a reference"
        );
    }

    // ── The stream cap (M3) ─────────────────────────────────────────────────

    /// The buffer hands out a fixed, small number of tail permits, and gives one
    /// back when the holder drops it.
    #[test]
    fn the_tail_permits_bound_the_number_of_live_streams() {
        let buffer = LogBuffer::new(8);
        let permits: Vec<_> = (0..MAX_LOG_STREAMS)
            .map(|_| {
                buffer
                    .tail_permits()
                    .try_acquire_owned()
                    .expect("a permit inside the cap must be granted")
            })
            .collect();

        assert!(
            buffer.tail_permits().try_acquire_owned().is_err(),
            "the {MAX_LOG_STREAMS}th concurrent stream must be refused"
        );

        drop(permits);
        assert!(
            buffer.tail_permits().try_acquire_owned().is_ok(),
            "a disconnected stream must return its permit"
        );
    }

    // ── The poisoned lock (L2) ──────────────────────────────────────────────

    /// A ring that has stopped recording must be *reportable*. Without this the
    /// routes answer 200 with a stale list, which is indistinguishable from a
    /// quiet process.
    #[test]
    fn a_poisoned_lock_is_reported_and_never_panics() {
        let buffer = LogBuffer::new(8);
        buffer.push(LogEntry::new("info", "t", "before"));
        assert!(!buffer.poisoned());

        buffer.poison_for_test();

        assert!(buffer.poisoned(), "the poison must be observable");
        // And every entry point stays non-panicking, which is what keeps the
        // `tracing` layer from taking the process down.
        buffer.push(LogEntry::new("info", "t", "after"));
        assert!(buffer.recent(8).is_empty());
        assert_eq!(buffer.len(), 0);
        assert_eq!(buffer.bytes(), 0);
        assert_eq!(buffer.next_seq(), 0);
        assert!(buffer.since(0, 8).0.is_empty());
    }

    // ── The tail cursor ─────────────────────────────────────────────────────

    /// The property the SSE tail depends on: feeding the returned cursor back in
    /// never repeats an entry, even though the ring wrapped underneath it.
    #[test]
    fn since_never_repeats_an_entry_across_a_ring_wrap() {
        // The ring holds four entries and twelve are pushed through it, so it
        // wraps three times while the tail is following it.
        let buffer = LogBuffer::new(4);
        let mut cursor = buffer.next_seq();
        let mut seen: Vec<String> = Vec::new();

        for i in 0..12 {
            buffer.push(LogEntry::new("info", "t", &format!("line {i}")));
            let (entries, next) = buffer.since(cursor, 16);
            cursor = next;
            seen.extend(entries.into_iter().map(|entry| entry.message.clone()));
        }

        assert_eq!(
            seen,
            (0..12).map(|i| format!("line {i}")).collect::<Vec<_>>(),
            "a tail that keeps up must see every entry exactly once, in order"
        );
    }

    /// A tail that fell further behind than the capacity loses entries to
    /// eviction. It must resume at the oldest retained entry — never replay what
    /// it already sent, and never stall.
    #[test]
    fn since_resumes_at_the_oldest_retained_entry_after_a_gap() {
        let buffer = LogBuffer::new(3);
        let cursor = buffer.next_seq();
        assert_eq!(cursor, 0);

        for i in 0..10 {
            buffer.push(LogEntry::new("info", "t", &format!("line {i}")));
        }

        let (entries, next) = buffer.since(cursor, 16);
        assert_eq!(
            entries
                .iter()
                .map(|entry| entry.message.as_str())
                .collect::<Vec<_>>(),
            vec!["line 7", "line 8", "line 9"],
            "the tail must resume at the oldest entry still retained"
        );
        assert_eq!(next, 10);

        // And it is caught up: nothing more is available.
        let (entries, next_again) = buffer.since(next, 16);
        assert!(entries.is_empty());
        assert_eq!(next_again, 10);
    }

    #[test]
    fn since_returns_at_most_the_requested_batch_and_keeps_the_cursor_moving() {
        let buffer = LogBuffer::new(16);
        for i in 0..10 {
            buffer.push(LogEntry::new("info", "t", &format!("line {i}")));
        }

        let (first, cursor) = buffer.since(0, 4);
        let (second, cursor) = buffer.since(cursor, 4);
        let (third, cursor) = buffer.since(cursor, 4);
        let (fourth, _) = buffer.since(cursor, 4);

        assert_eq!(first.len(), 4);
        assert_eq!(second.len(), 4);
        assert_eq!(third.len(), 2);
        assert!(fourth.is_empty());

        let messages: Vec<String> = first
            .into_iter()
            .chain(second)
            .chain(third)
            .map(|entry| entry.message.clone())
            .collect();
        assert_eq!(
            messages,
            (0..10).map(|i| format!("line {i}")).collect::<Vec<_>>()
        );
    }

    /// A cursor ahead of the buffer (only reachable if a caller invents one)
    /// must not panic, must not wrap, and must not stall the caller forever.
    #[test]
    fn since_tolerates_a_cursor_from_the_future() {
        let buffer = LogBuffer::new(4);
        buffer.push(LogEntry::new("info", "t", "line"));

        let (entries, next) = buffer.since(u64::MAX, 4);
        assert!(entries.is_empty());
        assert_eq!(
            next, 1,
            "the cursor must be pulled back to the buffer's end"
        );

        let (entries, next) = buffer.since(next, 4);
        assert!(entries.is_empty());
        assert_eq!(next, 1);
    }

    #[test]
    fn a_zero_capacity_buffer_advances_the_cursor_without_retaining_anything() {
        let buffer = LogBuffer::new(0);
        buffer.push(LogEntry::new("info", "t", "line"));
        assert_eq!(buffer.next_seq(), 1);
        let (entries, next) = buffer.since(0, 4);
        assert!(entries.is_empty());
        assert_eq!(next, 1);
    }

    // ── The layer ───────────────────────────────────────────────────────────

    /// Drive a real subscriber through a real macro: the buffer must end up with
    /// the event's level, target and rendered message.
    #[test]
    fn the_layer_captures_a_real_event() {
        use tracing_subscriber::layer::SubscriberExt;

        let buffer = Arc::new(LogBuffer::new(16));
        let subscriber =
            tracing_subscriber::registry().with(LogLayer::new(Arc::clone(&buffer), armed()));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "haos_green::logs::layer_test", "rendered {} {}", "a", 42);
        });

        let entries = buffer.recent(16);
        assert_eq!(entries.len(), 1, "exactly one event was emitted");
        assert_eq!(entries[0].level, "INFO");
        assert_eq!(entries[0].target, "haos_green::logs::layer_test");
        assert_eq!(entries[0].message, "rendered a 42");
        assert!(
            !entries[0].timestamp.is_empty(),
            "every entry is stamped with the time it was captured"
        );
    }

    /// The `EnvFilter` in the stack must suppress an event before it reaches
    /// the buffer: the dashboard is required to show what the console shows.
    ///
    /// This drives [`log_subscriber`] — the composition `main.rs` installs — so
    /// dropping the filter from it (or swapping in an unfiltered subscriber)
    /// fails here.
    #[test]
    fn the_layer_respects_the_env_filter() {
        let buffer = Arc::new(LogBuffer::new(16));
        let subscriber = log_subscriber(
            tracing_subscriber::EnvFilter::new("warn"),
            Arc::clone(&buffer),
            armed(),
        );

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "haos_green::logs::filter_test", "suppressed by the filter");
            tracing::warn!(target: "haos_green::logs::filter_test", "kept by the filter");
        });

        let entries = buffer.recent(16);
        assert_eq!(
            entries.len(),
            1,
            "only the event the filter admits may be buffered, got {entries:?}"
        );
        assert_eq!(entries[0].message, "kept by the filter");
    }

    /// `TRACE` is per-frame transport chatter; the ring is too small to spend
    /// slots on it. `DEBUG` is the floor and must still be captured.
    #[test]
    fn the_layer_drops_trace_and_keeps_debug() {
        use tracing_subscriber::layer::SubscriberExt;

        let buffer = Arc::new(LogBuffer::new(16));
        let subscriber =
            tracing_subscriber::registry().with(LogLayer::new(Arc::clone(&buffer), armed()));

        tracing::subscriber::with_default(subscriber, || {
            tracing::trace!(target: "haos_green::logs::level_test", "per-frame chatter");
            tracing::debug!(target: "haos_green::logs::level_test", "diagnostic");
            tracing::error!(target: "haos_green::logs::level_test", "failure");
        });

        let entries = buffer.recent(16);
        let messages: Vec<&str> = entries.iter().map(|e| e.message.as_str()).collect();
        assert_eq!(messages, vec!["diagnostic", "failure"], "got {entries:?}");
        assert_eq!(entries[0].level, "DEBUG");
        assert_eq!(entries[1].level, "ERROR");
    }

    /// A message is redacted before it is stored, not when it is rendered.
    #[test]
    fn the_layer_redacts_the_message_at_capture() {
        use tracing_subscriber::layer::SubscriberExt;

        // Assembled at runtime so this file never carries a credential-shaped
        // literal — the same reason `routes::chat`'s tests do it.
        let secret = format!("{}{}", "s3cr3t-", "value");

        let buffer = Arc::new(LogBuffer::new(16));
        let subscriber =
            tracing_subscriber::registry().with(LogLayer::new(Arc::clone(&buffer), armed()));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "haos_green::logs::redact_test", "calling with token={secret}");
        });

        let entries = buffer.recent(16);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "calling with token=***");
        assert!(
            !format!("{entries:?}").contains(&secret),
            "the raw secret must not exist in the buffer at all"
        );
    }

    /// Structured fields other than `message` are not folded into the message.
    #[test]
    fn the_layer_captures_only_the_message_field() {
        use tracing_subscriber::layer::SubscriberExt;

        let buffer = Arc::new(LogBuffer::new(16));
        let subscriber =
            tracing_subscriber::registry().with(LogLayer::new(Arc::clone(&buffer), armed()));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "haos_green::logs::fields_test", port = 8080, "listening");
        });

        let entries = buffer.recent(16);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "listening");
    }

    // ── The arm gate (M4) ───────────────────────────────────────────────────

    /// An instance that never enables the dashboard must retain nothing: the
    /// layer is installed (the subscriber has to exist before the configuration
    /// is read) but disarmed.
    #[test]
    fn a_disarmed_layer_retains_nothing_and_can_be_armed_later() {
        use tracing_subscriber::layer::SubscriberExt;

        let buffer = Arc::new(LogBuffer::new(16));
        let armed = Arc::new(AtomicBool::new(false));
        let subscriber =
            tracing_subscriber::registry().with(LogLayer::new(Arc::clone(&buffer), armed.clone()));

        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "haos_green::logs::arm_test", "emitted while disarmed");
        });
        assert!(
            buffer.is_empty(),
            "a disarmed layer must not spend a slot on anything"
        );

        // `main.rs` arms it once it has read a configuration that enables the
        // dashboard; everything after that is captured as usual.
        armed.store(true, Ordering::Relaxed);
        tracing::subscriber::with_default(
            tracing_subscriber::registry().with(LogLayer::new(Arc::clone(&buffer), armed.clone())),
            || {
                tracing::error!(target: "haos_green::logs::arm_test", "emitted while armed");
            },
        );
        let entries = buffer.recent(16);
        assert_eq!(entries.len(), 1, "got {entries:?}");
        assert_eq!(entries[0].message, "emitted while armed");
    }

    /// The gate must not be [`Layer::enabled`]: `Layered::enabled` ANDs every
    /// layer's answer with the inner subscriber's, so a layer that returned
    /// `false` there would silence the console formatter too. This drives a
    /// two-layer stack and proves the inner layer still sees the event while
    /// `LogLayer` is disarmed.
    #[test]
    fn a_disarmed_log_layer_does_not_silence_the_layers_inside_it() {
        use std::sync::atomic::AtomicUsize;
        use tracing_subscriber::layer::{Layer, SubscriberExt};

        #[derive(Default)]
        struct Counter(Arc<AtomicUsize>);

        impl<S: Subscriber> Layer<S> for Counter {
            fn on_event(&self, _event: &Event<'_>, _context: Context<'_, S>) {
                self.0.fetch_add(1, Ordering::Relaxed);
            }
        }

        let seen = Arc::new(AtomicUsize::new(0));
        let buffer = Arc::new(LogBuffer::new(16));
        let subscriber = tracing_subscriber::registry()
            .with(Counter(Arc::clone(&seen)))
            .with(LogLayer::new(
                buffer.clone(),
                Arc::new(AtomicBool::new(false)),
            ));

        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "haos_green::logs::arm_test", "still delivered");
        });

        assert_eq!(
            seen.load(Ordering::Relaxed),
            1,
            "the inner layer must still receive the event"
        );
        assert!(buffer.is_empty());
    }

    // ── The console writer (H1) ─────────────────────────────────────────────

    /// A [`MakeWriter`] over a buffer the test can read back.
    ///
    /// `Mutex<Vec<u8>>` cannot be shared directly — `tracing-subscriber` has a
    /// `MakeWriter` impl for `Mutex<W>` but none for `Arc<Mutex<W>>` — so this
    /// wraps one in an `Arc` and takes the lock in `make_writer`.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    struct CapturedGuard<'a>(std::sync::MutexGuard<'a, Vec<u8>>);

    impl io::Write for CapturedGuard<'_> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Captured {
        type Writer = CapturedGuard<'a>;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedGuard(self.0.lock().expect("the capture buffer"))
        }
    }

    impl Captured {
        /// Everything written through this writer so far.
        fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().expect("the capture buffer")).into_owned()
        }
    }

    /// The console formatter must redact a **registered** secret, and this is the
    /// test that has teeth against the whole bug: it drives
    /// [`console_layer_with`], the composition `main.rs` installs, so replacing
    /// the redacting wrapper with a plain pass-through writer fails here.
    ///
    /// The needle is the case the exact-value registry exists for: it sits in a
    /// URL path with no key, no separator and no prefix, exactly as a `reqwest`
    /// transport error renders a Telegram bot token. No shape rule can see it.
    #[test]
    fn the_console_writer_redacts_a_registered_secret() {
        // Unique to this test: the registry is process-global and the unit tests
        // share one process.
        let secret = "<CAMPO_SECRET_console_4b7e12>";
        assert!(
            crate::supervisor::redact::register_secret(secret),
            "the needle must be accepted by the registry"
        );

        let captured = Captured::default();
        let subscriber = tracing_subscriber::registry().with(console_layer_with(captured.clone()));

        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(
                target: "haos_green::logs::console_writer_test",
                "error sending request for url (https://api.telegram.org/bot{secret}/sendMessage)"
            );
        });

        let printed = captured.contents();
        assert!(
            !printed.contains(secret),
            "a registered secret reached the console verbatim: {printed}"
        );
        // …and the line was really written, so the assertion above is not
        // passing because the writer swallowed the event.
        assert!(
            printed.contains("api.telegram.org") && printed.contains("sendMessage"),
            "the console must still receive the line, redacted: {printed}"
        );
        assert!(printed.contains("***"), "got {printed}");
    }

    /// The shape rules apply on the console path too, so a credential that was
    /// never registered is still scrubbed from stdout and `journalctl`.
    #[test]
    fn the_console_writer_applies_the_shape_rules_as_well() {
        // Built at run time so this file carries no credential-shaped literal.
        let value = format!("{}{}", "shaped-", "value-0");

        let captured = Captured::default();
        let subscriber = tracing_subscriber::registry().with(console_layer_with(captured.clone()));

        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(
                target: "haos_green::logs::console_writer_test",
                "the peer refused the call: auth_token={value}"
            );
        });

        let printed = captured.contents();
        assert!(
            !printed.contains(&value),
            "a credential-shaped value reached the console: {printed}"
        );
        assert!(printed.contains("auth_token=***"), "got {printed}");
    }

    /// A fragment with no newline is still forwarded when the writer is dropped:
    /// the formatter always terminates an event, but a writer that silently
    /// dropped the tail would lose the last line of a process that crashed
    /// mid-format.
    #[test]
    fn a_final_fragment_without_a_newline_is_still_written() {
        let captured = Captured::default();
        {
            let writer = RedactingWriter::new(captured.clone());
            let mut guard = writer.make_writer();
            guard
                .write_all(b"a line with no terminator")
                .expect("the capture buffer accepts writes");
        }

        assert_eq!(captured.contents(), "a line with no terminator");
    }

    /// The property the line buffering exists for, and the reason a per-`write`
    /// redaction would not be enough on its own: a formatter that emits a
    /// credential in two calls must still have it redacted as a whole. This
    /// drives the guard directly, because `tracing-subscriber` 0.3.23 happens to
    /// hand over one `write_all` per event and would never produce this shape.
    #[test]
    fn a_credential_split_across_two_writes_is_redacted_as_a_whole() {
        let secret = "<CAMPO_SECRET_console_split_9f21>";
        assert!(
            crate::supervisor::redact::register_secret(secret),
            "the needle must be accepted by the registry"
        );

        let captured = Captured::default();
        {
            let writer = RedactingWriter::new(captured.clone());
            let mut guard = writer.make_writer();
            guard.write_all(b"calling with ").expect("the first piece");
            guard
                .write_all(&secret.as_bytes()[..10])
                .expect("the first half of the credential");
            guard
                .write_all(&secret.as_bytes()[10..])
                .expect("the second half of the credential");
            guard.write_all(b"\n").expect("the terminator");
        }

        let printed = captured.contents();
        assert!(
            !printed.contains(secret),
            "a credential split across two writes must not survive: {printed}"
        );
        assert!(printed.contains("calling with"), "got {printed}");
    }
}
