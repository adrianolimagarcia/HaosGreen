//! Bounded in-memory ring buffer of recent tracing events, and the
//! `tracing_subscriber::Layer` that feeds it.
//!
//! The dashboard's log view (Phase 4, Task 18) reads from here; [`LogLayer`] is
//! installed by `main.rs` alongside the console formatter, so the buffer sees
//! the same events the terminal does.
//!
//! The buffer is hard-bounded: a dashboard must never be the reason a
//! long-running process grows without limit (design spec §5.3).
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
//! # The layer cannot take the process down
//!
//! `on_event` is synchronous and never awaits, holds no lock across a call to
//! anything else, and never panics: a poisoned buffer lock makes
//! [`LogBuffer::push`] drop the event rather than propagate. A diagnostic
//! convenience must not be able to kill the process that also serves Telegram.

use serde::Serialize;
use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Mutex};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

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
    pub fn new(level: &str, target: &str, message: &str) -> Self {
        Self {
            timestamp: chrono::Utc::now().to_rfc3339(),
            level: level.to_string(),
            target: target.to_string(),
            message: crate::supervisor::redact::redact(message),
        }
    }
}

/// A fixed-capacity ring buffer of [`LogEntry`].
///
/// Every method is failure-tolerant by design: a poisoned lock drops the event
/// (on write) or returns nothing (on read). The dashboard's log view is a
/// diagnostic convenience, so it must never be able to panic the process that
/// also serves Telegram.
pub struct LogBuffer {
    capacity: usize,
    inner: Mutex<Inner>,
}

struct Inner {
    entries: VecDeque<LogEntry>,
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
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            inner: Mutex::new(Inner {
                entries: VecDeque::with_capacity(capacity),
                pushed: 0,
            }),
        }
    }

    /// Append an entry, dropping the oldest when the buffer is full.
    ///
    /// A capacity of zero is legal and discards everything.
    pub fn push(&self, entry: LogEntry) {
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        inner.entries.push_back(entry);
        inner.pushed = inner.pushed.saturating_add(1);
        while inner.entries.len() > self.capacity {
            inner.entries.pop_front();
        }
    }

    /// The most recent `limit` entries, oldest first.
    pub fn recent(&self, limit: usize) -> Vec<LogEntry> {
        let Ok(inner) = self.inner.lock() else {
            return Vec::new();
        };
        let start = inner.entries.len().saturating_sub(limit);
        inner.entries.iter().skip(start).cloned().collect()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
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
    /// * **Bounded work.** At most `max` entries are cloned, so a caller that
    ///   fell behind (or a burst of thousands of events) costs one bounded
    ///   allocation per call rather than the whole ring.
    ///
    /// If `from_seq` is older than the oldest entry still retained — the tail
    /// fell further behind than the capacity — the gap is skipped and the
    /// returned `next` starts at the oldest retained entry. Those entries are
    /// gone; reporting the gap is the caller's business, and the tail cannot
    /// invent them.
    pub fn since(&self, from_seq: u64, max: usize) -> (Vec<LogEntry>, u64) {
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
/// so the dashboard sees what the terminal sees. See the module documentation
/// for the inclusion policy.
pub struct LogLayer {
    buffer: Arc<LogBuffer>,
}

impl LogLayer {
    pub fn new(buffer: Arc<LogBuffer>) -> Self {
        Self { buffer }
    }
}

impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
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
/// belongs to the filter.
///
/// `LookupSpan` is part of the return type because `fmt::layer()`, which
/// `main.rs` adds on top, requires it; `Registry` provides it.
pub fn log_subscriber(
    filter: tracing_subscriber::EnvFilter,
    buffer: Arc<LogBuffer>,
) -> impl Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a> + Send + Sync + 'static
{
    tracing_subscriber::registry()
        .with(filter)
        .with(LogLayer::new(buffer))
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
            seen.extend(entries.into_iter().map(|entry| entry.message));
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
            .map(|entry| entry.message)
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
        let subscriber = tracing_subscriber::registry().with(LogLayer::new(Arc::clone(&buffer)));

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
        let subscriber = tracing_subscriber::registry().with(LogLayer::new(Arc::clone(&buffer)));

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
        let subscriber = tracing_subscriber::registry().with(LogLayer::new(Arc::clone(&buffer)));

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
        let subscriber = tracing_subscriber::registry().with(LogLayer::new(Arc::clone(&buffer)));

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: "haos_green::logs::fields_test", port = 8080, "listening");
        });

        let entries = buffer.recent(16);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "listening");
    }
}
