//! Bounded in-memory ring buffer of recent tracing events.
//!
//! The dashboard's log view (Phase 4, Task 18) reads from here, and the
//! `tracing_subscriber::Layer` that feeds it is installed at startup (Phase 4,
//! Task 17). The buffer itself is implemented now so that `WebState` — and
//! therefore every route signature — does not have to change when the layer
//! lands.
//!
//! The buffer is hard-bounded: a dashboard must never be the reason a
//! long-running process grows without limit (design spec §5.3).

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Mutex;

/// One tracing event, already redacted.
#[derive(Clone, Debug, Serialize)]
pub struct LogEntry {
    /// RFC 3339 timestamp, captured when the event reaches the buffer.
    pub timestamp: String,
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
    entries: Mutex<VecDeque<LogEntry>>,
}

impl LogBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: Mutex::new(VecDeque::with_capacity(capacity)),
        }
    }

    /// Append an entry, dropping the oldest when the buffer is full.
    ///
    /// A capacity of zero is legal and discards everything.
    pub fn push(&self, entry: LogEntry) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        entries.push_back(entry);
        while entries.len() > self.capacity {
            entries.pop_front();
        }
    }

    /// The most recent `limit` entries, oldest first.
    pub fn recent(&self, limit: usize) -> Vec<LogEntry> {
        let Ok(entries) = self.entries.lock() else {
            return Vec::new();
        };
        let start = entries.len().saturating_sub(limit);
        entries.iter().skip(start).cloned().collect()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|e| e.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
}
