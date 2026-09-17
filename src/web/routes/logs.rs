//! Log routes (design spec §5.3).
//!
//! ```text
//! GET /api/logs?limit=N   -> { "entries": [ { timestamp, level, target, message } ], "capacity": N }
//! GET /api/logs/stream    -> text/event-stream, one `log` event per entry
//! ```
//!
//! Both routes are on the guarded router, never the public one: the log is the
//! most revealing surface the dashboard has. It carries target names, file
//! paths, task ids and error text, and it is the one place a future change
//! could accidentally echo a credential that the redaction filter does not
//! recognise. Nothing about it is reachable without a session.
//!
//! Both answer **503** when the dashboard was started without a buffer, the
//! same contract as the supervisor routes: a dashboard that was never wired to
//! the tracing layer must say so rather than render an empty log, which is
//! indistinguishable from a quiet process.
//!
//! # `limit` is clamped on the server, always
//!
//! The client's number is never trusted to bound the work the server does:
//!
//! * absent (`GET /api/logs`) → [`DEFAULT_LIMIT`]
//! * a non-integer, a negative number, an empty value, or one too large for
//!   `usize` (`?limit=abc`, `?limit=-1`, `?limit=`, `?limit=1.5`,
//!   `?limit=99999999999999999999999`) → **400**. Rejected rather than silently
//!   defaulted: the only client is the dashboard's own `app.js`, so an
//!   unparseable limit is a bug in it, and answering with a plausible-looking
//!   default would hide that bug behind a working page. Surrounding whitespace
//!   is trimmed (`?limit=%205` is five).
//! * `0` → zero entries. Honoured literally; it is a legal request and it does
//!   no work.
//! * anything larger → `min(requested, MAX_LIMIT, capacity)`.
//!
//! [`MAX_LIMIT`] is a hard ceiling on the size of one response that does not
//! depend on the buffer's capacity: a buffer configured larger than
//! [`MAX_LIMIT`] must still not be dumpable in a single request, and 1000
//! entries is already far more than a log view renders. `capacity` is returned
//! in the body so the view can tell the operator how many entries are retained
//! without a second call.
//!
//! Entries are returned **oldest first**, matching the ring's own order, so the
//! view can append what it already has.
//!
//! # The stream
//!
//! `GET /api/logs/stream` is a live tail, not a replay: it delivers the entries
//! pushed **after** the request was received, and the client is expected to
//! call `GET /api/logs` first for the history. Each entry is one SSE event named
//! `log` whose data is that entry JSON-encoded.
//!
//! ## Why it cannot leak a task per abandoned tab
//!
//! A tail is a spawned task writing into an `mpsc` channel that the response
//! body drains. Dropping the body — which is what a client disconnect does —
//! drops the only receiver, so the producer's `Sender::closed()` future
//! resolves and the task returns. That is the whole termination mechanism, and
//! it does not depend on the producer ever having something to send: a tail on
//! a silent process still ends the moment its receiver goes away. Nothing in
//! the loop can block on the client either — a full channel makes `send` await,
//! and it returns `Err` (rather than hanging) as soon as the receiver is gone.
//!
//! ## Why it cannot repeat or reorder an entry across a ring wrap
//!
//! The tail follows a **sequence-number cursor**, not a window: `LogBuffer`
//! numbers every push, `LogBuffer::since` returns entries at or after a given
//! number, and the cursor it hands back always starts strictly after the last
//! entry it returned. Re-reading "the last N" and diffing by index would repeat
//! entries after a wrap and skip entries when the window moved; a monotonic
//! counter cannot do either. If the tail ever falls further behind than the
//! capacity, the evicted entries are gone and it resumes at the oldest retained
//! one — a gap it cannot invent a fix for, but never a duplicate.
//!
//! The cursor is read in the handler, before the response head is written, so
//! an entry pushed by a test (or an operator) as soon as the response is
//! visible is guaranteed to be delivered.
//!
//! ## Polling
//!
//! New entries are found by polling the ring every [`POLL_INTERVAL`]. The
//! buffer has no notification channel, and adding one would mean the layer —
//! which runs inside the process's own logging path — waking every subscriber
//! on every event. A tick takes one uncontended mutex, compares one integer,
//! and clones only the entries that are actually new (at most [`STREAM_BATCH`]
//! of them), so an idle stream costs a lock and a comparison four times a
//! second and allocates nothing. It is bounded by construction: no tick can
//! scan more than one batch.
//!
//! The interval is the worst-case latency of a new line appearing, not a
//! correctness parameter.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::time::Duration;

use crate::web::logs::LogEntry;
use crate::web::state::WebState;

/// The SSE event name carrying one [`LogEntry`].
pub const EVENT_LOG: &str = "log";

/// Entries returned when the request does not name a limit.
pub const DEFAULT_LIMIT: usize = 200;

/// Hard ceiling on the number of entries one response may carry.
pub const MAX_LIMIT: usize = 1000;

/// The body of a rejected `limit`.
const BAD_LIMIT: &str = "limit must be a non-negative integer";

/// Capacity of the channel between the tail task and the response body.
///
/// Matches `src/web/routes/chat.rs` and `src/a2a/executor.rs:223`. A full
/// channel applies backpressure to the tail rather than buffering without
/// limit; the tail is not on any path that must not block, and it stops
/// entirely once the receiver is gone.
const STREAM_CHANNEL_CAPACITY: usize = 128;

/// Most entries one poll may deliver.
///
/// Bounds the work of a single tick and the size of one burst: a tail that
/// starts behind, or a target that logs thousands of lines between two ticks,
/// drains over several ticks instead of building one enormous response.
const STREAM_BATCH: usize = 256;

/// How often the tail looks for new entries.
///
/// Bounded and cheap by construction (see the module documentation): one lock,
/// one integer comparison, and a clone of only what is new. 250 ms is the
/// worst-case delay before a new line reaches the browser, which is well under
/// what an operator perceives as "live".
const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// How often an idle stream emits a comment line.
///
/// Same value as the chat stream: an intermediary that times out an idle
/// connection would otherwise kill a quiet tail.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

pub fn router() -> Router<WebState> {
    Router::new()
        .route("/api/logs", get(recent_logs))
        .route("/api/logs/stream", get(stream_logs))
}

/// The body of `GET /api/logs`.
#[derive(Serialize)]
struct LogsResponse {
    /// Oldest first, at most `limit` of them.
    entries: Vec<LogEntry>,
    /// The ring's capacity, so the view can say how much history exists
    /// without asking twice.
    capacity: usize,
}

/// The query string of `GET /api/logs`.
///
/// `limit` is a `String` rather than a number so that a malformed value is
/// *ours* to reject with a message that names the parameter, instead of axum's
/// generic extractor rejection.
#[derive(Deserialize)]
struct LogQuery {
    limit: Option<String>,
}

/// Parse and clamp the requested limit. See the module documentation.
fn parse_limit(requested: Option<&str>, capacity: usize) -> Result<usize, &'static str> {
    let requested = match requested {
        None => DEFAULT_LIMIT,
        Some(raw) => raw.trim().parse::<usize>().map_err(|_| BAD_LIMIT)?,
    };
    Ok(requested.min(MAX_LIMIT).min(capacity))
}

async fn recent_logs(State(state): State<WebState>, Query(query): Query<LogQuery>) -> Response {
    let buffer = match state.logs_or_unavailable() {
        Ok(buffer) => buffer,
        Err((status, message)) => return (status, message).into_response(),
    };

    let capacity = buffer.capacity();
    let limit = match parse_limit(query.limit.as_deref(), capacity) {
        Ok(limit) => limit,
        Err(message) => return (StatusCode::BAD_REQUEST, message).into_response(),
    };

    Json(LogsResponse {
        entries: buffer.recent(limit),
        capacity,
    })
    .into_response()
}

async fn stream_logs(State(state): State<WebState>) -> Response {
    let buffer = match state.logs_or_unavailable() {
        Ok(buffer) => buffer,
        Err((status, message)) => return (status, message).into_response(),
    };

    // Read before the response is returned: the head reaches the client after
    // this, so anything pushed once the client can see the stream is at or after
    // the cursor and will be delivered.
    let mut next = buffer.next_seq();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Event>(STREAM_CHANNEL_CAPACITY);

    let mut tail = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        // A tick missed while the runtime was busy must not be followed by a
        // burst of catch-up ticks: the cursor makes catching up unnecessary.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // The response body holds the only receiver. When the client
                // disconnects the body is dropped, this resolves, and the task
                // ends — whether or not it had anything to send.
                _ = tx.closed() => break,
                _ = ticker.tick() => {
                    let (entries, cursor) = buffer.since(next, STREAM_BATCH);
                    next = cursor;
                    for entry in entries {
                        // A `LogEntry` is four `String`s, so this cannot fail;
                        // it is written as a skip rather than an `expect`
                        // because this task must never panic.
                        let Ok(data) = serde_json::to_string(&entry) else {
                            continue;
                        };
                        if tx.send(Event::default().event(EVENT_LOG).data(data)).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }
    });

    // Dropping this stream drops `rx`, which is what stops `tail`. The join
    // handle is awaited only so a task that ends on its own (never, today) ends
    // the body too, rather than leaving a stream that can only ever be idle.
    let stream = async_stream::stream! {
        loop {
            tokio::select! {
                biased;
                Some(event) = rx.recv() => yield Ok::<Event, Infallible>(event),
                _ = &mut tail => break,
            }
        }
    };

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(KEEP_ALIVE_INTERVAL))
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_limit_falls_back_to_the_default() {
        assert_eq!(parse_limit(None, 2000).unwrap(), DEFAULT_LIMIT);
    }

    #[test]
    fn a_limit_is_clamped_by_the_hard_maximum_and_by_the_capacity() {
        assert_eq!(parse_limit(Some("10"), 2000).unwrap(), 10);
        assert_eq!(parse_limit(Some("100000"), 2000).unwrap(), MAX_LIMIT);
        assert_eq!(parse_limit(Some("100000"), 4).unwrap(), 4);
        assert_eq!(parse_limit(Some("2000"), 2000).unwrap(), MAX_LIMIT);
    }

    #[test]
    fn a_zero_limit_is_honoured_literally() {
        assert_eq!(parse_limit(Some("0"), 2000).unwrap(), 0);
    }

    #[test]
    fn a_garbage_limit_is_rejected() {
        for raw in ["abc", "-1", "", "1.5", "99999999999999999999999", " "] {
            assert_eq!(
                parse_limit(Some(raw), 2000),
                Err(BAD_LIMIT),
                "{raw:?} must be rejected rather than silently defaulted"
            );
        }
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        assert_eq!(parse_limit(Some(" 5 "), 2000).unwrap(), 5);
    }

    /// The SSE framing must survive a message that contains everything that
    /// could break it.
    ///
    /// `serde_json` escapes control characters, so the payload is a single line
    /// and axum never sees a bare newline — and even if it did, `Event::data`
    /// splits it across `data:` lines rather than terminating the frame. The
    /// end-to-end version of this assertion (the frame a real client parses)
    /// lives in `tests/web_endpoint.rs`; axum does not expose `Event`'s
    /// serialization, so the payload is all this level can check.
    #[test]
    fn a_message_with_newlines_cannot_break_the_sse_frame() {
        let entry = LogEntry::new(
            "INFO",
            "haos_green::test",
            "first line\nsecond line\r\ndata: injected\n\nevent: injected",
        );
        let data = serde_json::to_string(&entry).unwrap();

        assert!(
            !data.contains('\n') && !data.contains('\r'),
            "the JSON payload must be a single line: {data:?}"
        );
        assert!(data.contains("\\n"), "the newline is escaped, not dropped");

        let decoded: serde_json::Value = serde_json::from_str(&data).unwrap();
        assert_eq!(decoded["message"].as_str().unwrap(), entry.message);
        assert_eq!(decoded["level"].as_str().unwrap(), "INFO");
    }
}
