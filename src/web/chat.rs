//! Bounded in-memory chat session store for the dashboard.
//!
//! Three properties are load-bearing, and each one has a test that fails if it
//! is removed:
//!
//! * **Bounded.** A session keeps at most [`MAX_HISTORY_TURNS`] messages and the
//!   store keeps at most [`MAX_SESSIONS`] sessions. An authenticated caller is
//!   the Telegram operator, but a browser tab left open on a loop must not be
//!   able to grow this process without bound.
//! * **Isolated.** Two sessions never share a message list. The web chat is
//!   deliberately separate from Telegram conversations (design spec §5.1), so a
//!   dashboard session must not be able to read or extend a Telegram thread.
//! * **An unknown id is an error.** [`ChatSessionStore::history`] returns `Err`
//!   for an id that was never created or has been evicted, rather than an empty
//!   history. Returning `Ok(vec![])` would turn a typo — or an evicted session —
//!   into a silently brand-new conversation with no memory of what came before.
//!
//! Sessions do not survive a restart, by design (design spec §10, non-goals):
//! the store is a plain `HashMap` in the process, so a restart is a complete
//! reset of every dashboard conversation.
//!
//! There is no HTTP route that calls [`ChatSessionStore::delete`] yet: the plan
//! for this phase lists only create/list/history/send/cancel, and the store's
//! `delete` is required by its own contract (a caller must be able to drop a
//! session, and an evicted session and a deleted one must look identical). It is
//! covered by the tests below.

use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, MutexGuard};

use crate::llm::{ChatMessage, MessageContent};

/// Maximum number of messages retained per session.
///
/// One message is one turn (a user message or an assistant reply). The oldest
/// message is dropped first: a conversation's most recent context is the part
/// the model still needs, and dropping the newest would make a long chat
/// answer the first question forever.
pub const MAX_HISTORY_TURNS: usize = 256;

/// Maximum number of concurrent sessions.
///
/// Eviction, not refusal, when the cap is reached: see
/// [`ChatSessionStore::create`].
pub const MAX_SESSIONS: usize = 64;

/// Cancel-registry key for a dashboard chat session.
///
/// `Agent::cancel_token_registry` is a bare map. Telegram's `/stop` keys it by
/// `user_id` and A2A keys it by `a2a:{task_id}`, so an unnamespaced dashboard
/// key would let any of the three cancel the others' runs — and a dashboard
/// session id that happened to be a numeric string could collide with a
/// Telegram user id outright.
pub fn cancel_key(session_id: &str) -> String {
    format!("web:{session_id}")
}

/// One row of [`ChatSessionStore::list`].
#[derive(Debug, Clone, Serialize)]
pub struct ChatSessionSummary {
    pub id: String,
    /// Number of messages currently retained, capped at [`MAX_HISTORY_TURNS`].
    pub turns: usize,
}

struct Session {
    messages: VecDeque<ChatMessage>,
}

#[derive(Default)]
struct Inner {
    sessions: HashMap<String, Session>,
    /// Session ids, least recently used first.
    ///
    /// Kept as a list rather than a timestamp on each session because the cap is
    /// [`MAX_SESSIONS`] — a linear scan of 64 ids is cheaper than maintaining a
    /// second ordering structure, and "least recently used" is then exact rather
    /// than dependent on clock resolution.
    lru: VecDeque<String>,
    /// Session ids with a run in flight. See [`ChatSessionStore::begin_run`].
    running: HashSet<String>,
}

/// Bounded, in-memory, per-web-session chat history.
pub struct ChatSessionStore {
    max_sessions: usize,
    inner: Mutex<Inner>,
}

impl ChatSessionStore {
    pub fn new() -> Self {
        Self::with_capacity(MAX_SESSIONS)
    }

    /// A store with a caller-chosen session cap.
    ///
    /// Exists so the eviction tests can reach the cap without creating 64
    /// sessions; the production path is [`ChatSessionStore::new`].
    pub fn with_capacity(max_sessions: usize) -> Self {
        Self {
            // A cap of zero would make `create` return an id that is evicted
            // before the caller can use it, i.e. a session that never exists.
            max_sessions: max_sessions.max(1),
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Create a session and return its id.
    ///
    /// When the store is at capacity the least recently used session is evicted
    /// to make room, rather than the new session being refused. Refusing would
    /// turn a memory bound into a self-inflicted denial of service: an
    /// authenticated caller could open the cap's worth of sessions and the
    /// legitimate operator's "New chat" button would fail forever, with the only
    /// remedy being a process restart. Eviction costs at most the oldest idle
    /// conversation.
    pub fn create(&self) -> String {
        use rand::RngCore;

        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let id: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();

        let mut inner = self.lock();
        inner.sessions.insert(
            id.clone(),
            Session {
                messages: VecDeque::new(),
            },
        );
        inner.lru.push_back(id.clone());

        while inner.lru.len() > self.max_sessions {
            let Some(evicted) = inner.lru.pop_front() else {
                break;
            };
            inner.sessions.remove(&evicted);
            inner.running.remove(&evicted);
            // The id itself is never logged (design spec §4.7): a session id is
            // a live handle to a conversation.
            tracing::warn!(
                sessions = inner.lru.len(),
                "web: chat session cap reached; the least recently used session was evicted"
            );
        }

        id
    }

    /// The full history of `id`, oldest first.
    ///
    /// `Err` for an unknown or evicted id — never an empty history.
    pub fn history(&self, id: &str) -> Result<Vec<ChatMessage>> {
        let mut inner = self.lock();
        if !inner.sessions.contains_key(id) {
            bail!("unknown chat session");
        }
        let history = inner
            .sessions
            .get(id)
            .map(|session| session.messages.iter().cloned().collect())
            .unwrap_or_default();
        // Reading a session counts as using it, so a session the operator is
        // looking at is not the one evicted.
        inner.touch(id);
        Ok(history)
    }

    /// Append a user turn, dropping the oldest message if the cap is reached.
    pub fn append_user(&self, id: &str, text: &str) -> Result<()> {
        self.append(id, "user", text)
    }

    /// Append an assistant turn, dropping the oldest message if the cap is
    /// reached.
    pub fn append_assistant(&self, id: &str, text: &str) -> Result<()> {
        self.append(id, "assistant", text)
    }

    /// Claim the right to start a run for `id`.
    ///
    /// Returns `Ok(false)` when a run is already in flight for that session.
    ///
    /// Two concurrent runs on one session would clobber each other's cancel
    /// token, because the registry (`Agent::cancel_token_registry`) is keyed
    /// `web:{session_id}`: the second `register_cancel_token` replaces the
    /// first, and whichever run finishes first then clears the other's entry —
    /// leaving a run that `/cancel` can no longer stop. They would also
    /// interleave two assistant replies into one history.
    ///
    /// The check-and-set happens under the store's lock, so it is atomic: the
    /// two requests cannot both observe "no run in flight".
    pub fn begin_run(&self, id: &str) -> Result<bool> {
        let mut inner = self.lock();
        if !inner.sessions.contains_key(id) {
            bail!("unknown chat session");
        }
        if !inner.running.insert(id.to_string()) {
            return Ok(false);
        }
        inner.touch(id);
        Ok(true)
    }

    /// Release the claim taken by [`ChatSessionStore::begin_run`].
    ///
    /// Idempotent, and safe to call for a session that has since been evicted or
    /// deleted.
    pub fn end_run(&self, id: &str) {
        self.lock().running.remove(id);
    }

    /// Drop a session and its history. Returns whether it existed.
    pub fn delete(&self, id: &str) -> bool {
        let mut inner = self.lock();
        let existed = inner.sessions.remove(id).is_some();
        inner.lru.retain(|entry| entry != id);
        inner.running.remove(id);
        existed
    }

    /// Every live session, most recently used first.
    ///
    /// Most-recently-used first because that is the order a session list wants
    /// to render, and it is the same ordering the eviction policy uses.
    pub fn list(&self) -> Vec<ChatSessionSummary> {
        let inner = self.lock();
        inner
            .lru
            .iter()
            .rev()
            .filter_map(|id| {
                inner.sessions.get(id).map(|session| ChatSessionSummary {
                    id: id.clone(),
                    turns: session.messages.len(),
                })
            })
            .collect()
    }

    fn append(&self, id: &str, role: &str, text: &str) -> Result<()> {
        let mut inner = self.lock();
        let session = inner
            .sessions
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("unknown chat session"))?;

        session.messages.push_back(ChatMessage {
            role: role.to_string(),
            content: Some(MessageContent::from_text(text)),
            tool_calls: None,
            tool_call_id: None,
        });

        while session.messages.len() > MAX_HISTORY_TURNS {
            session.messages.pop_front();
        }

        inner.touch(id);
        Ok(())
    }

    /// The lock, recovering from poisoning.
    ///
    /// Every critical section here is a handful of `HashMap`/`VecDeque`
    /// operations on owned values: no indexing, no `unwrap`, no arithmetic and
    /// nothing that can panic on caller input, so a poisoned guard cannot expose
    /// a half-updated map. Recovering keeps one unrelated panic from permanently
    /// disabling chat, which is the failure mode of treating poison as fatal.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for ChatSessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Inner {
    fn touch(&mut self, id: &str) {
        if !self.sessions.contains_key(id) {
            return;
        }
        self.lru.retain(|entry| entry != id);
        self.lru.push_back(id.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(history: &[ChatMessage]) -> Vec<String> {
        history
            .iter()
            .map(|message| {
                message
                    .content
                    .as_ref()
                    .map(|content| content.as_text())
                    .unwrap_or_default()
            })
            .collect()
    }

    fn roles(history: &[ChatMessage]) -> Vec<String> {
        history.iter().map(|message| message.role.clone()).collect()
    }

    #[test]
    fn a_new_session_starts_empty() {
        let store = ChatSessionStore::new();
        let id = store.create();
        assert!(store.history(&id).unwrap().is_empty());
    }

    #[test]
    fn appended_turns_are_returned_in_order() {
        let store = ChatSessionStore::new();
        let id = store.create();
        store.append_user(&id, "hello").unwrap();
        store.append_assistant(&id, "hi").unwrap();

        let history = store.history(&id).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].role, "user");
        assert_eq!(history[1].role, "assistant");
        assert_eq!(texts(&history), vec!["hello", "hi"]);
    }

    #[test]
    fn the_turn_cap_drops_the_oldest_turn_not_the_newest() {
        // The plan's version of this test asserted `len() <= MAX_HISTORY_TURNS`,
        // which passes just as well if the implementation dropped the *newest*
        // turns — the exact inversion that makes a long chat answer its first
        // question forever. This asserts which turns survived.
        let store = ChatSessionStore::new();
        let id = store.create();
        let total = MAX_HISTORY_TURNS + 10;
        for turn in 0..total {
            store.append_user(&id, &format!("turn {turn}")).unwrap();
        }

        let history = store.history(&id).unwrap();
        assert_eq!(history.len(), MAX_HISTORY_TURNS);
        let kept = texts(&history);
        assert_eq!(kept.first().map(String::as_str), Some("turn 10"));
        assert_eq!(
            kept.last().map(String::as_str),
            Some(format!("turn {}", total - 1).as_str())
        );
        assert!(
            !kept.contains(&"turn 0".to_string()),
            "the FIRST turn must be the one dropped, kept: {kept:?}"
        );
        assert!(
            !kept.contains(&"turn 9".to_string()),
            "every turn above the cap must be dropped, kept: {kept:?}"
        );
    }

    #[test]
    fn the_turn_cap_counts_both_roles_together() {
        let store = ChatSessionStore::new();
        let id = store.create();
        for turn in 0..MAX_HISTORY_TURNS {
            store.append_user(&id, &format!("q{turn}")).unwrap();
            store.append_assistant(&id, &format!("a{turn}")).unwrap();
        }

        let history = store.history(&id).unwrap();
        assert_eq!(history.len(), MAX_HISTORY_TURNS);
        // 512 messages appended, 256 kept: the oldest 256 (q0..a127) are gone,
        // so the first survivor is `q128`.
        assert_eq!(history[0].role, "user");
        assert_eq!(texts(&history)[0], "q128");
        assert_eq!(texts(&history).last().map(String::as_str), Some("a255"));
        let roles = roles(&history);
        assert_eq!(roles.iter().filter(|role| *role == "user").count(), 128);
        assert_eq!(
            roles.iter().filter(|role| *role == "assistant").count(),
            128
        );
    }

    #[test]
    fn sessions_are_isolated_from_each_other() {
        let store = ChatSessionStore::new();
        let a = store.create();
        let b = store.create();
        store.append_user(&a, "only in a").unwrap();

        assert!(store.history(&b).unwrap().is_empty());
        assert_eq!(texts(&store.history(&a).unwrap()), vec!["only in a"]);
    }

    #[test]
    fn an_unknown_session_id_is_an_error_not_an_empty_history() {
        let store = ChatSessionStore::new();
        let err = store.history("missing").unwrap_err().to_string();
        assert!(
            err.contains("unknown chat session"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn appending_to_an_unknown_session_is_an_error() {
        let store = ChatSessionStore::new();
        assert!(store.append_user("missing", "x").is_err());
        assert!(store.append_assistant("missing", "x").is_err());
        // And nothing was created behind the caller's back.
        assert!(store.list().is_empty());
    }

    #[test]
    fn deleting_a_session_removes_its_history() {
        let store = ChatSessionStore::new();
        let id = store.create();
        store.append_user(&id, "x").unwrap();

        assert!(store.delete(&id));
        assert!(store.history(&id).is_err());
        assert!(store.list().is_empty());
    }

    #[test]
    fn deleting_an_unknown_session_reports_that_nothing_was_deleted() {
        let store = ChatSessionStore::new();
        assert!(!store.delete("missing"));
    }

    #[test]
    fn a_deleted_session_id_is_not_reusable() {
        // Guards against an implementation that only clears the message list:
        // a stale id must be as dead as an id that was never issued.
        let store = ChatSessionStore::new();
        let id = store.create();
        store.append_user(&id, "secret").unwrap();
        store.delete(&id);

        let fresh = store.create();
        assert_ne!(fresh, id, "a new session must get a new id");
        assert!(store.append_user(&id, "should not land").is_err());
    }

    #[test]
    fn session_ids_are_unique_and_carry_256_bits() {
        let store = ChatSessionStore::new();
        let a = store.create();
        let b = store.create();
        assert_ne!(a, b);
        assert!(
            a.len() >= 64,
            "session ids must carry at least 256 bits of entropy, got {a:?}"
        );
    }

    #[test]
    fn the_listing_reports_every_session_with_its_turn_count() {
        let store = ChatSessionStore::new();
        let a = store.create();
        let b = store.create();
        store.append_user(&a, "one").unwrap();
        store.append_assistant(&a, "two").unwrap();

        let listing = store.list();
        assert_eq!(listing.len(), 2);
        let mut ids: Vec<&str> = listing.iter().map(|summary| summary.id.as_str()).collect();
        ids.sort_unstable();
        let mut expected = vec![a.as_str(), b.as_str()];
        expected.sort_unstable();
        assert_eq!(ids, expected, "the listing must report both sessions");

        let turns: HashMap<&str, usize> = listing
            .iter()
            .map(|summary| (summary.id.as_str(), summary.turns))
            .collect();
        assert_eq!(turns[a.as_str()], 2);
        assert_eq!(turns[b.as_str()], 0);
    }

    #[test]
    fn the_listing_is_most_recently_used_first() {
        let store = ChatSessionStore::new();
        let first = store.create();
        let second = store.create();
        // Using the older session makes it the most recent one.
        store.append_user(&first, "touch").unwrap();

        let listing = store.list();
        assert_eq!(listing[0].id, first);
        assert_eq!(listing[1].id, second);
    }

    #[test]
    fn the_session_cap_evicts_the_least_recently_used_session() {
        let store = ChatSessionStore::with_capacity(2);
        let first = store.create();
        let second = store.create();
        let third = store.create();

        assert_eq!(
            store.list().len(),
            2,
            "the cap must bound the session count"
        );
        assert!(
            store.history(&first).is_err(),
            "the least recently used session must be the one evicted"
        );
        assert!(store.history(&second).is_ok());
        assert!(store.history(&third).is_ok());
    }

    #[test]
    fn a_recently_used_session_survives_eviction() {
        // Distinguishes least-recently-used from first-in-first-out: the oldest
        // session by creation order is the one that must survive here.
        let store = ChatSessionStore::with_capacity(2);
        let oldest = store.create();
        let newer = store.create();
        store.append_user(&oldest, "keep me").unwrap();

        let _newest = store.create();

        assert!(
            store.history(&oldest).is_ok(),
            "a session touched after the newer one was created must survive"
        );
        assert!(store.history(&newer).is_err());
    }

    #[test]
    fn a_cap_of_zero_still_yields_a_usable_session() {
        // `with_capacity(0)` would otherwise create a session and evict it in
        // the same call, handing the caller an id that is already dead.
        let store = ChatSessionStore::with_capacity(0);
        let id = store.create();
        assert!(store.history(&id).is_ok());
    }

    #[test]
    fn the_history_is_a_copy_so_a_caller_cannot_mutate_the_store() {
        let store = ChatSessionStore::new();
        let id = store.create();
        store.append_user(&id, "original").unwrap();

        let mut history = store.history(&id).unwrap();
        history.clear();

        assert_eq!(store.history(&id).unwrap().len(), 1);
    }

    #[test]
    fn a_second_concurrent_run_on_one_session_is_refused() {
        let store = ChatSessionStore::new();
        let id = store.create();

        assert!(store.begin_run(&id).unwrap(), "the first run may start");
        assert!(
            !store.begin_run(&id).unwrap(),
            "a second concurrent run on the same session must be refused"
        );

        store.end_run(&id);
        assert!(
            store.begin_run(&id).unwrap(),
            "the claim must be released once the run ends"
        );
    }

    #[test]
    fn a_run_claim_is_per_session() {
        let store = ChatSessionStore::new();
        let a = store.create();
        let b = store.create();

        assert!(store.begin_run(&a).unwrap());
        assert!(
            store.begin_run(&b).unwrap(),
            "one session's run must not block another's"
        );
    }

    #[test]
    fn claiming_a_run_on_an_unknown_session_is_an_error() {
        let store = ChatSessionStore::new();
        assert!(store.begin_run("missing").is_err());
    }

    #[test]
    fn ending_a_run_is_idempotent_and_safe_after_eviction() {
        let store = ChatSessionStore::with_capacity(1);
        let evicted = store.create();
        assert!(store.begin_run(&evicted).unwrap());
        let _replacement = store.create();

        // The session is gone; releasing its claim must not panic and must not
        // resurrect it.
        store.end_run(&evicted);
        store.end_run(&evicted);
        assert!(store.history(&evicted).is_err());
        assert!(!store.list().iter().any(|summary| summary.id == evicted));
    }

    #[test]
    fn deleting_a_session_releases_its_run_claim() {
        let store = ChatSessionStore::new();
        let id = store.create();
        assert!(store.begin_run(&id).unwrap());
        assert!(store.delete(&id));

        // A brand-new session with a fresh id is unaffected, and the claim set
        // did not keep the deleted id alive.
        let fresh = store.create();
        assert!(store.begin_run(&fresh).unwrap());
        assert!(!store.begin_run(&fresh).unwrap());
    }

    #[test]
    fn the_cancel_key_cannot_collide_with_telegram_or_a2a() {
        // Telegram keys the registry by bare `user_id`; A2A keys it by
        // `a2a:{task_id}`. A dashboard key must match neither.
        let session = "42";
        let key = cancel_key(session);
        assert_eq!(key, "web:42");
        assert_ne!(key, session, "a bare numeric id is a Telegram user_id key");
        assert_ne!(key, crate::a2a::executor::cancel_key(session));
        assert!(key.starts_with("web:"));
    }
}
