use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use teloxide::net::Download;
use teloxide::prelude::*;
use teloxide::types::{ParseMode, UpdateKind};
use tracing::{error, info, warn};

use async_trait::async_trait;
use teloxide::types::{InlineKeyboardButton, InlineKeyboardMarkup, MessageId};

use crate::agent::{Agent, LoopCallbackChoice, MidRunMode};
use crate::platform::sender::{
    MessageFormat as PlatformMsgFormat, PlatformMessageId, PlatformSender,
};
use crate::platform::{Attachment, AttachmentKind, IncomingMessage};
use crate::provider::Provider;
use crate::supervisor::state::transition_allowed;
use crate::supervisor::task::TaskStatus;
use crate::supervisor::{SubmitOutcome, Supervisor, SupervisorError};
use crate::tool_registry::ToolUiMode;
use crate::utils::markdown_entities::{markdown_to_entities, split_entities};
use crate::utils::rich_sender;
use crate::utils::telegram_markdown::escape_text;
use std::sync::OnceLock;

/// Helper: parse a chat_id string (e.g. "123456789") into teloxide's ChatId.
fn parse_chat_id(s: &str) -> Result<teloxide::types::ChatId> {
    Ok(teloxide::types::ChatId(s.parse::<i64>()?))
}

static BOT_TOKEN: OnceLock<String> = OnceLock::new();

/// Must be called once at startup after the Bot is created.
pub fn init_bot_token(token: String) {
    BOT_TOKEN.set(token).ok();
}

/// Message format mode for Telegram responses.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MessageFormat {
    /// `sendRichMessage` only, no fallback
    Rich,
    /// Entity-formatted `sendMessage` only, no rich path
    Markdown,
    /// Try `sendRichMessage`, fall back to entities on BadMarkdown
    Auto,
}

impl MessageFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageFormat::Rich => "rich",
            MessageFormat::Markdown => "markdown",
            MessageFormat::Auto => "auto",
        }
    }

    pub fn from_str_value(s: &str) -> Option<Self> {
        match s {
            "rich" => Some(MessageFormat::Rich),
            "markdown" => Some(MessageFormat::Markdown),
            "auto" => Some(MessageFormat::Auto),
            _ => None,
        }
    }
}

/// Load the user's preferred message format from memory.
async fn load_message_format(memory: &crate::memory::MemoryStore, user_id: &str) -> MessageFormat {
    let raw = memory
        .recall("settings", &format!("message_format_{}", user_id))
        .await
        .unwrap_or(None);
    MessageFormat::from_str_value(raw.as_deref().unwrap_or("auto")).unwrap_or(MessageFormat::Auto)
}

/// Split long messages for Telegram's 4096 char limit
#[cfg(test)]
fn split_message(text: &str, max_len: usize) -> Vec<String> {
    if text.len() <= max_len {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let mut start = 0;

    while start < text.len() {
        let mut end = (start + max_len).min(text.len());
        // Walk back to a valid UTF-8 char boundary so slicing doesn't panic
        while end > start && !text.is_char_boundary(end) {
            end -= 1;
        }
        let actual_end = if end < text.len() {
            text[start..end]
                .rfind('\n')
                .or_else(|| text[start..end].rfind(' '))
                .map(|pos| start + pos + 1)
                .unwrap_or(end)
        } else {
            end
        };

        chunks.push(text[start..actual_end].to_string());
        start = actual_end;
    }

    chunks
}

/// Parse a Telegram-style slash command into `(command, argument)`.
///
/// Returns `None` if the input does not start with `/`. The command is the
/// token immediately after the slash; the argument is the remainder of the
/// line (trimmed of surrounding whitespace).
///
/// Parse a Telegram-style slash command into `(command, argument)`.
///
/// Returns `None` if the input does not start with `/`. The command is the
/// token immediately after the slash; the argument is the remainder of the
/// line (trimmed of surrounding whitespace).
pub(crate) fn parse_command(s: &str) -> Option<(String, String)> {
    let s = s.trim_start();
    if !s.starts_with('/') {
        return None;
    }
    let rest = &s[1..];
    let mut it = rest.splitn(2, char::is_whitespace);
    let cmd = it.next()?.to_string();
    let arg = it.next().unwrap_or("").trim().to_string();
    Some((cmd, arg))
}

/// Build the static list of slash commands shown in Telegram's "/" menu.
///
/// The descriptions surface to the user via the BotFather command menu.
/// Routing for these commands lives in `handle_message`; this function only
/// publishes their existence to the Telegram client.
pub(crate) fn supported_commands() -> Vec<teloxide::types::BotCommand> {
    use teloxide::types::BotCommand;
    let mut commands = vec![
        BotCommand::new("start", "Show the welcome message and command help"),
        BotCommand::new(
            "clear",
            "Archive the current conversation, keeping past messages searchable",
        ),
        BotCommand::new("tools", "List available built-in and MCP tools"),
        BotCommand::new("skills", "List loaded skills"),
        BotCommand::new("verbose", "Toggle tool-call progress display"),
        BotCommand::new("queryrewrite", "Toggle query rewriting for memory search"),
        BotCommand::new(
            "selfupgrade",
            "Upgrade the bot to the latest version (source or release binary)",
        ),
        BotCommand::new("models", "Browse and change the OpenRouter model"),
        BotCommand::new("mode", "Set steer/queue mode for mid-processing messages"),
        BotCommand::new("stop", "Cancel the current processing gracefully"),
        BotCommand::new("btw", "Ask a parallel question while the bot is busy"),
        BotCommand::new(
            "format",
            "Switch message format: rich (native), markdown (web), auto",
        ),
    ];
    commands.extend(supervisor_commands());
    commands
}

/// The BotFather entries for the supervisor commands.
///
/// One list, read by both [`supported_commands`] and
/// [`dispatch_supervisor_command`], so the published menu and the router cannot
/// drift apart — a command advertised here and not routed (or the reverse) is
/// the exact failure this replaces.
fn supervisor_commands() -> Vec<teloxide::types::BotCommand> {
    use teloxide::types::BotCommand;
    vec![
        BotCommand::new("supervise", "Submit a task to the autonomous supervisor"),
        BotCommand::new("tasks", "List recent supervisor tasks with their states"),
        BotCommand::new("resume", "Resume a paused supervisor task: /resume <id>"),
        BotCommand::new("cancel", "Cancel a supervisor task: /cancel <id>"),
        BotCommand::new(
            "approve",
            "Approve a supervisor task awaiting approval: /approve <id>",
        ),
        BotCommand::new(
            "clarify",
            "Answer a supervisor clarification prompt: /clarify <id> <text>",
        ),
        BotCommand::new(
            "allow",
            "Grant shell jobs write access to a host path: /allow <absolute-path>",
        ),
        BotCommand::new("deny", "Revoke a write grant: /deny <absolute-path>"),
        BotCommand::new(
            "allow_net",
            "Share the host network namespace with sandboxed shell jobs",
        ),
        BotCommand::new("deny_net", "Stop sharing the host network namespace"),
        BotCommand::new("grants", "Show the grants currently held"),
    ]
}

// ── Supervisor commands ─────────────────────────────────────────────────────

/// The command names [`dispatch_supervisor_command`] routes, without the slash.
///
/// Kept in step with [`supervisor_commands`] by the test
/// `the_published_menu_and_the_router_name_the_same_commands`, which compares
/// the two lists rather than restating either.
pub(crate) const SUPERVISOR_COMMANDS: [&str; 11] = [
    "supervise",
    "tasks",
    "resume",
    "cancel",
    "approve",
    "clarify",
    "allow",
    "deny",
    // Underscores, **not** hyphens: Telegram `BotCommand` names must match
    // `[a-z0-9_]{1,32}`, so `/allow-net` is not a command Telegram will accept
    // or publish — the plan names it that way and the plan is wrong. The
    // assertion in `test_supported_commands_lists_user_visible_commands` is what
    // caught it.
    "allow_net",
    "deny_net",
    "grants",
];

/// Longest `/supervise` task text the dispatcher forwards, in characters. The
/// same bound `Supervisor::clarify` applies to a `/clarify` answer.
pub(crate) const MAX_SUPERVISE_TEXT_CHARS: usize = crate::supervisor::MAX_TASK_TEXT_CHARS;

/// Longest task id the dispatcher will look up or echo.
///
/// Ids are UUIDs (`Task::new`), so 64 characters is already far past anything
/// legitimate; the point is that a malformed id is **refused**, never truncated
/// and echoed.
pub(crate) const MAX_TASK_ID_CHARS: usize = 64;

/// The longest host path `/allow` or `/deny` will look at.
///
/// `PATH_MAX` is 4096 on Linux, so anything longer cannot be a path that
/// resolves anyway — the bound is here so the refusal, which echoes the raw
/// string, cannot be made to carry an arbitrarily large argument.
pub(crate) const MAX_GRANT_PATH_CHARS: usize = 4096;

/// Longest task title rendered on a `/tasks` line, in characters. Titles are
/// already capped at 80 by `IntakeRouter::normalize`; this is the display cap.
const MAX_TASK_TITLE_CHARS: usize = 60;

/// Hard cap on a supervisor reply, in characters.
///
/// Telegram's limit is 4096 and the rest of this file splits longer text
/// (`split_message`, `send_entities_message`). The supervisor dispatcher
/// deliberately sends **one** message per command, so it bounds the text itself
/// — a reply that arrives in pieces is not a reply a user can act on.
pub(crate) const MAX_SUPERVISOR_REPLY_CHARS: usize = 3500;

/// How many tasks `/tasks` lists. `TaskStore::list_recent` clamps to
/// `MAX_RECENT_TASKS` (20) regardless; this is the smaller display budget.
pub(crate) const MAX_TASKS_LISTED: usize = 10;

/// The answer to a task id that is not shaped like one.
const INVALID_TASK_ID: &str = "That is not a valid supervisor task id.";

/// The answer to a genuine supervisor fault. Fixed, like the dashboard's 500
/// body: an `anyhow` chain from `rusqlite` carries the failing statement and an
/// artifact error carries an absolute path.
const SUPERVISOR_FAULT: &str = "The supervisor could not complete that request.";

/// Who asked for a supervisor action, and where the answer goes.
///
/// `user_id` is the Telegram user id, and it is the **only** identity the
/// authorization check reads. `chat_id` is the destination, never an authority:
/// a private chat's id happens to equal the user id, a group's does not.
pub(crate) struct SupervisorActor {
    pub user_id: u64,
    pub chat_id: String,
}

/// Route one parsed supervisor command and send its single reply.
///
/// Returns `Ok(true)` when `cmd` names a supervisor command — **including** the
/// unauthorized case, which answers nothing at all — and `Ok(false)` for every
/// other command, so the caller's fall-through is unchanged.
///
/// # Authorization
///
/// The allowed-user check is the **first** statement, before the argument is
/// parsed, before the supervisor is touched and before anything is sent. An
/// unauthorized sender therefore gets no supervisor action, no supervisor data
/// and no reply: not even an error, because a reply is itself an oracle about
/// which commands exist.
///
/// This is the second of two checks, not the only one. The first is the
/// `filter_map` on the `dptree` message handler in [`run`], which drops a
/// message from a user outside `telegram.allowed_user_ids` before
/// `handle_message` is called at all — for *every* command, supervisor or not.
/// That filter is the production gate; this one is what makes the dispatcher
/// safe to call directly, and it is the one the tests exercise.
///
/// # Bounded replies
///
/// Every reply is redacted (`supervisor::redact`), because task titles, submit
/// outcomes and clarification text are user- or model-derived, and then bounded
/// by [`bounded_reply`]. No path echoes an `anyhow` chain, and the whole chain
/// is logged instead.
pub(crate) async fn dispatch_supervisor_command(
    cmd: &str,
    arg: &str,
    actor: &SupervisorActor,
    allowed_user_ids: &[u64],
    supervisor: &Supervisor,
    sender: &dyn PlatformSender,
) -> Result<bool> {
    if !SUPERVISOR_COMMANDS.contains(&cmd) {
        return Ok(false);
    }

    if !allowed_user_ids.contains(&actor.user_id) {
        warn!(
            user_id = actor.user_id,
            command = cmd,
            "Refused a supervisor command from a user outside telegram.allowed_user_ids"
        );
        return Ok(true);
    }

    let reply = match cmd {
        "supervise" => supervise_command(arg, actor, supervisor).await,
        "tasks" => tasks_command(supervisor).await,
        "resume" => lifecycle_command(arg, supervisor, LifecycleAction::Resume).await,
        "cancel" => lifecycle_command(arg, supervisor, LifecycleAction::Cancel).await,
        "approve" => lifecycle_command(arg, supervisor, LifecycleAction::Approve).await,
        "clarify" => clarify_command(arg, supervisor).await,
        "allow" => allow_command(arg, actor, supervisor).await,
        "deny" => deny_command(arg, actor, supervisor).await,
        "allow_net" => allow_net_command(actor, supervisor).await,
        "deny_net" => deny_net_command(actor, supervisor).await,
        "grants" => grants_command(supervisor),
        // Unreachable while `SUPERVISOR_COMMANDS` and this match agree. A
        // bounded answer rather than a panic keeps the two honest.
        other => format!("Unknown supervisor command: /{other}"),
    };

    let reply = bounded_reply(&crate::supervisor::redact::redact(&reply));
    // Plain text: `TelegramAdapter` applies no parse mode for `Rich`, so the
    // bytes composed here are the bytes delivered. The replies contain task
    // titles and ids, and MarkdownV2 would reject an unescaped `_` or `*` in
    // either — a formatting convention is not worth a failed send.
    sender
        .send_message(&actor.chat_id, &reply, PlatformMsgFormat::Rich)
        .await
        .context("send a supervisor command reply")?;
    Ok(true)
}

/// Record a grant change in the audit log, and say so in the reply when that
/// fails.
///
/// The grant is **already in force** when this runs, so a failed audit must not
/// report the command as failed — that would be a false statement about the
/// boundary. It reports the *audit* as failed, which is a different and
/// actionable thing.
async fn audit_note(supervisor: &Supervisor, actor: &SupervisorActor, reason: &str) -> String {
    match supervisor
        .audit_grant(&actor.user_id.to_string(), reason)
        .await
    {
        Ok(()) => String::new(),
        Err(e) => {
            format!("\nWARNING: the grant took effect, but its audit row was NOT written: {e:#}")
        }
    }
}

/// `/allow <absolute-path>` — grant a shell job read-write access to one host
/// path, for every future job until it is revoked.
///
/// The reply names what is **now held**, not merely what changed: a grant is
/// cumulative state, and an operator issuing two grants needs to see the set,
/// not the delta.
async fn allow_command(arg: &str, actor: &SupervisorActor, supervisor: &Supervisor) -> String {
    // Bounded like every other argument, and for the same reason: the refusal
    // echoes the raw string, and `bounded_reply` truncates the *reply* but not
    // the work done to build it. `MAX_TASK_TEXT_CHARS` and `MAX_TASK_ID_CHARS`
    // exist for exactly this; a grant path had no bound until this one.
    if arg.chars().count() > MAX_GRANT_PATH_CHARS {
        return format!("Refused: that path is longer than {MAX_GRANT_PATH_CHARS} characters.");
    }
    match supervisor.allow_path(arg) {
        Ok(path) => format!(
            "Granted write access to {}.\nHeld now: {}{}",
            path.display(),
            supervisor.granted(),
            audit_note(
                supervisor,
                actor,
                &format!("grant write {}", path.display())
            )
            .await
        ),
        // `{e:#}` rather than `{e}`: anyhow's plain `Display` prints only the
        // outermost context, and the refusal reasons are in the chain.
        Err(e) => format!("Refused: {e:#}"),
    }
}

/// `/deny <absolute-path>` — revoke a write grant.
async fn deny_command(arg: &str, actor: &SupervisorActor, supervisor: &Supervisor) -> String {
    if arg.chars().count() > MAX_GRANT_PATH_CHARS {
        return format!("Refused: that path is longer than {MAX_GRANT_PATH_CHARS} characters.");
    }
    match supervisor.deny_path(arg) {
        Ok(path) => format!(
            "Revoked write access to {}.\nHeld now: {}{}",
            path.display(),
            supervisor.granted(),
            audit_note(
                supervisor,
                actor,
                &format!("revoke write {}", path.display())
            )
            .await
        ),
        Err(e) => format!("Refused: {e:#}"),
    }
}

/// `/allow-net` — share the host network namespace with sandboxed jobs.
///
/// The reply carries the warning, because this is the grant that widens the
/// boundary most: with it, a sandboxed job can reach a local service that can
/// run commands on the host.
async fn allow_net_command(actor: &SupervisorActor, supervisor: &Supervisor) -> String {
    format!(
        "Granted the host network namespace. A sandboxed job can now reach anything this host \
         can, including loopback services.\nHeld now: {}{}",
        supervisor.allow_network(),
        audit_note(supervisor, actor, "grant the host network namespace").await
    )
}

/// `/deny-net` — stop sharing the host network namespace.
async fn deny_net_command(actor: &SupervisorActor, supervisor: &Supervisor) -> String {
    format!(
        "Revoked the host network namespace.\nHeld now: {}{}",
        supervisor.deny_network(),
        audit_note(supervisor, actor, "revoke the host network namespace").await
    )
}

/// `/grants` — what the operator currently holds.
///
/// Without this the four commands above are write-only, and an operator who has
/// forgotten whether `/allow-net` was issued has no way to find out short of
/// restarting the process.
fn grants_command(supervisor: &Supervisor) -> String {
    format!("Held: {}", supervisor.granted())
}

/// `/supervise <text>` — create and route a supervisor task.
///
/// Like `POST /api/supervisor/tasks`, this **creates and routes** the task; it
/// does not run the pipeline. `submit` classifies, applies policy and stops, and
/// a task that policy auto-executes is still left in `Route` — running it here
/// would be a second execution path beside `/approve` and `/resume`, and would
/// block the bot's message handler for the length of a plan.
///
/// Because nothing runs, the reply is the whole hand-off: it names the state and
/// the exact command that moves the task on ([`submit_reply`]). A reply that
/// only said "created" would leave the user with a task that never runs and no
/// way to find out why.
async fn supervise_command(arg: &str, actor: &SupervisorActor, supervisor: &Supervisor) -> String {
    let text = arg.trim();
    if text.is_empty() {
        return "Usage: /supervise <task text>".to_string();
    }
    let chars = text.chars().count();
    if chars > MAX_SUPERVISE_TEXT_CHARS {
        return format!(
            "The task text is {chars} characters; the limit is {MAX_SUPERVISE_TEXT_CHARS}."
        );
    }

    // `platform`/`user_id`/`chat_id` are the origin recorded in `sup_tasks`,
    // so a task submitted from Telegram is distinguishable from a dashboard one
    // and attributable to the user who asked for it.
    let outcome = match supervisor
        .submit(
            "telegram",
            &actor.user_id.to_string(),
            Some(&actor.chat_id),
            text,
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(e) => return fault("submit a supervisor task", &e),
    };

    let task_id = outcome.task_id();
    let state = match supervisor.state(&task_id).await {
        Ok(state) => state_name(&state),
        Err(e) => return fault("read a supervisor task's state", &e),
    };

    submit_reply(&outcome, &state)
}

/// The reply for a `submit` that succeeded.
///
/// Every arm names the state and the command that moves the task forward, so
/// the command surface is complete without executing anything: `submit` parks
/// the task (`Route` for a planned or approval-pending one, `Clarify` for an
/// ambiguous one) and only `/approve`, `/resume` or `/clarify` ever run it.
///
/// # The two policy decisions that arrive as `NeedsApproval`
///
/// `PolicyDecision::UseFallbackBackend` and `PolicyDecision::StopAndReport` are
/// funnelled by `submit` into `SubmitOutcome::NeedsApproval` with their `Debug`
/// spelling as the `reason` (see the `other =>` arm of `submit`), so their
/// replies name the reason verbatim and offer **both** available actions rather
/// than guessing which one applies. Splitting them into their own outcome
/// variants would mean changing `SubmitOutcome`, which is a change to the
/// supervisor's contract and out of scope here.
fn submit_reply(outcome: &SubmitOutcome, state: &str) -> String {
    let task_id = outcome.task_id();
    match outcome {
        SubmitOutcome::AutoExecutePlanned { .. } => format!(
            "Supervisor task {task_id} created (state {state}).\n\
             Nothing runs until you ask: /approve {task_id}"
        ),
        SubmitOutcome::NeedsClarification { question, .. } => format!(
            "Supervisor task {task_id} needs clarification (state {state}): {question}\n\
             Answer with /clarify {task_id} <text>"
        ),
        SubmitOutcome::NeedsApproval { reason, .. } => format!(
            "Supervisor task {task_id} needs approval (state {state}): {reason}\n\
             Approve with /approve {task_id}, or drop it with /cancel {task_id}"
        ),
    }
}

/// `/tasks` — the most recent supervisor tasks, newest first.
///
/// Bounded twice: [`MAX_TASKS_LISTED`] rows, and [`MAX_TASK_TITLE_CHARS`] per
/// title, so the reply is a predictable size whatever is in the store.
async fn tasks_command(supervisor: &Supervisor) -> String {
    let tasks = match supervisor.store().list_recent(MAX_TASKS_LISTED).await {
        Ok(tasks) => tasks,
        Err(e) => return fault("list supervisor tasks", &e),
    };
    if tasks.is_empty() {
        return "No supervisor tasks.".to_string();
    }

    let mut lines = vec![format!(
        "Supervisor tasks ({} most recent, newest first):",
        tasks.len()
    )];
    for task in &tasks {
        // Redact **before** truncating. The other order can cut a credential in
        // half and leave the leading part of the value in the reply, which is
        // still a leak — and the reply is redacted again as a whole by the
        // dispatcher, so a value that straddles the row boundary is caught too.
        let title = crate::supervisor::redact::redact(task.title.trim());
        lines.push(format!(
            "- {}  {}  {}",
            task.id,
            state_name(&task.status),
            truncate_chars(&title, MAX_TASK_TITLE_CHARS)
        ));
    }
    lines.join("\n")
}

/// A lifecycle action, expressed as the precondition the state machine puts on
/// the task's current state.
///
/// The same three actions and the same pre-checks the dashboard's
/// `routes::supervisor::Action` applies, so a task refused from Telegram is
/// refused from the dashboard for the same reason.
#[derive(Debug, Clone, Copy)]
enum LifecycleAction {
    Resume,
    Cancel,
    Approve,
}

impl LifecycleAction {
    fn usage(self) -> &'static str {
        match self {
            Self::Resume => "Usage: /resume <task id>",
            Self::Cancel => "Usage: /cancel <task id>",
            Self::Approve => "Usage: /approve <task id>",
        }
    }

    /// Whether a task in `current` may take this action.
    ///
    /// `resume` is deliberately stricter than the table: `Paused -> Execute` is
    /// a legal edge, but `Supervisor::resume` refuses any task that is not
    /// `Paused`, and a task parked in `Route` awaiting approval must not run
    /// without one.
    fn permitted_from(self, current: &TaskStatus) -> bool {
        match self {
            Self::Resume => *current == TaskStatus::Paused,
            Self::Cancel => transition_allowed(current.clone(), TaskStatus::Cancelled),
            Self::Approve => transition_allowed(current.clone(), TaskStatus::Execute),
        }
    }

    /// The conflict text. It names the task's current state and nothing else —
    /// no path, no error chain.
    fn refusal(self, current: &TaskStatus) -> String {
        let state = state_name(current);
        match self {
            Self::Resume => format!(
                "Cannot resume: the task is in state {state}, and only a PAUSED task can be resumed."
            ),
            Self::Cancel => format!("Cannot cancel: the task is in state {state}."),
            Self::Approve => format!("Cannot approve: the task is in state {state}."),
        }
    }

    /// The success text, in the past tense of the action.
    fn done(self, id: &str, state: &str) -> String {
        match self {
            Self::Resume => format!("Task {id} resumed; it is now {state}."),
            Self::Cancel => format!("Task {id} cancelled; it is now {state}."),
            Self::Approve => format!("Task {id} approved; it is now {state}."),
        }
    }

    async fn apply(self, supervisor: &Supervisor, id: &str) -> Result<()> {
        match self {
            Self::Cancel => supervisor.cancel(id).await,
            // `resume` and `approve` run the plan and return its report, which
            // is persisted as the task's `result` artifact — the reply does not
            // echo it.
            Self::Resume => supervisor.resume(id).await.map(|_report| ()),
            Self::Approve => supervisor.approve(id).await.map(|_report| ()),
        }
    }
}

/// `/resume <id>`, `/cancel <id>`, `/approve <id>`.
///
/// # Conflict is decided before the supervisor is called
///
/// A refusal is a fact about the task's current state, so this reads that state
/// first and answers without attempting the operation — the same shape the
/// dashboard route has. Only an error that survives the pre-check can be a
/// fault, and the three kinds are answered with three different sentences: a
/// missing task, a state conflict, and a genuine fault.
///
/// The pre-check cannot cover a task that moves between it and the call; there
/// the error **type** is the signal left, read with `anyhow::Error::downcast_ref`
/// on [`SupervisorError`] rather than by matching error text.
async fn lifecycle_command(arg: &str, supervisor: &Supervisor, action: LifecycleAction) -> String {
    let id = match validated_task_id(arg) {
        Some(id) => id,
        None if arg.trim().is_empty() => return action.usage().to_string(),
        None => return INVALID_TASK_ID.to_string(),
    };

    let task = match supervisor.store().get(id).await {
        Ok(Some(task)) => task,
        Ok(None) => return not_found(id),
        Err(e) => return fault("read a supervisor task", &e),
    };

    if !action.permitted_from(&task.status) {
        return action.refusal(&task.status);
    }

    if let Err(e) = action.apply(supervisor, id).await {
        return classify_lifecycle_failure(action, id, &e);
    }

    match supervisor.state(id).await {
        Ok(state) => action.done(id, &state_name(&state)),
        Err(e) => fault("read a supervisor task's state", &e),
    }
}

/// `/clarify <id> <text>` — answer a `Clarify` prompt and resume the task.
///
/// The state is checked here as well as inside `Supervisor::clarify`, for the
/// same reason the lifecycle actions are: a task in the wrong state must be
/// answered as a conflict without touching the audit trail. `clarify` keeps its
/// own check because it is a public method, not because this one is trusted.
async fn clarify_command(arg: &str, supervisor: &Supervisor) -> String {
    let arg = arg.trim();
    let Some(separator) = arg.find(char::is_whitespace) else {
        return "Usage: /clarify <id> <text>".to_string();
    };
    let Some(id) = validated_task_id(&arg[..separator]) else {
        return INVALID_TASK_ID.to_string();
    };
    let text = arg[separator..].trim();
    if text.is_empty() {
        return "Usage: /clarify <id> <text>".to_string();
    }
    let chars = text.chars().count();
    if chars > MAX_SUPERVISE_TEXT_CHARS {
        return format!(
            "The clarification text is {chars} characters; the limit is {MAX_SUPERVISE_TEXT_CHARS}."
        );
    }

    match supervisor.store().get(id).await {
        Ok(Some(task)) if task.status != TaskStatus::Clarify => {
            return format!(
                "Cannot clarify: the task is in state {}, and only a task in CLARIFY can be clarified.",
                state_name(&task.status)
            );
        }
        Ok(None) => return not_found(id),
        Err(e) => return fault("read a supervisor task", &e),
        Ok(Some(_)) => {}
    }

    match supervisor.clarify(id, text).await {
        // The report is persisted as the task's `result` artifact; the reply
        // names the resulting state instead of echoing it.
        Ok(_report) => match supervisor.state(id).await {
            Ok(state) => format!(
                "Clarification recorded; task {id} is now {}.",
                state_name(&state)
            ),
            Err(e) => fault("read a supervisor task's state", &e),
        },
        Err(e) => classify_lifecycle_failure_typed(id, &e),
    }
}

/// The reply for a supervisor call that failed.
///
/// Not-found, conflict and fault are three different sentences, and the
/// difference is read from the error's **type**, never from its text: rewording
/// a `bail!` in `supervisor/mod.rs` must not silently reclassify a refusal as a
/// fault. A `StateRefusal` names the state the store actually holds, so a raced
/// refusal reads the same as one caught by the pre-check.
fn classify_lifecycle_failure(action: LifecycleAction, id: &str, error: &anyhow::Error) -> String {
    match error.downcast_ref::<SupervisorError>() {
        Some(SupervisorError::StateRefusal { from, .. }) => action.refusal(from),
        _ => classify_lifecycle_failure_typed(id, error),
    }
}

/// The same classification for a call with no [`LifecycleAction`] (`/clarify`,
/// and any future caller), which has no per-action phrasing to fall back on.
fn classify_lifecycle_failure_typed(id: &str, error: &anyhow::Error) -> String {
    match error.downcast_ref::<SupervisorError>() {
        Some(SupervisorError::NotFound { .. }) => not_found(id),
        Some(SupervisorError::StateRefusal { from, .. }) => format!(
            "Cannot do that: task {id} is in state {}, which does not allow it.",
            state_name(from)
        ),
        Some(SupervisorError::AlreadyRunning { .. }) => {
            format!("Task {id} is already running.")
        }
        // Cause-neutral on purpose: `LeaseLost` is raised both when another
        // owner really took the task over and when the lease store could not be
        // reached, and this error does not carry the distinction.
        Some(SupervisorError::LeaseLost { .. }) => format!(
            "The execution lease for task {id} is no longer held by this run; the task was not run."
        ),
        None => fault("apply a supervisor lifecycle action", error),
    }
}

/// The reply for a task id that resolved to no row.
fn not_found(id: &str) -> String {
    format!("No supervisor task with id {id}.")
}

/// Log the **whole** `anyhow` chain and answer with the fixed sentence.
///
/// `error = %error` would print only the outermost context, so a failure whose
/// real cause is `no such table: sup_transitions` would be logged as nothing but
/// `insert sup_tasks` — undiagnosable, and the log view renders exactly this
/// line. The body stays fixed: a `rusqlite` error carries the failing statement
/// and an artifact error carries an absolute path.
fn fault(what: &str, error: &anyhow::Error) -> String {
    error!(
        error = %format!("{error:#}"),
        what = %what,
        "telegram: supervisor command failed"
    );
    SUPERVISOR_FAULT.to_string()
}

/// The task id in `raw`, or `None` when it is missing, oversized, or shaped like
/// something that is not an id.
///
/// Ids are UUIDs, so anything outside `[A-Za-z0-9_-]` is a typo or an attempt to
/// smuggle a path, a newline or a mention into a reply. Bounded here rather than
/// echoed and truncated later: a malformed id is refused, never repeated.
fn validated_task_id(raw: &str) -> Option<&str> {
    let id = raw.trim();
    if id.is_empty() || id.chars().count() > MAX_TASK_ID_CHARS {
        return None;
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return None;
    }
    Some(id)
}

/// The persisted name of a state — the spelling `sup_tasks.state` holds and the
/// dashboard renders (`serde`'s `UPPERCASE` renaming), not `Debug`'s.
///
/// Total: `TaskStatus` is a plain enum that always serializes, and the fallback
/// exists so a future variant with a custom serializer degrades to `Debug`
/// rather than panicking in a reply.
fn state_name(state: &TaskStatus) -> String {
    serde_json::to_value(state)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_else(|| format!("{state:?}"))
}

/// Cut `text` to at most `max` characters, on a character boundary, appending an
/// ellipsis when anything was dropped.
fn truncate_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max).collect();
    out.push('…');
    out
}

/// Bound a reply to [`MAX_SUPERVISOR_REPLY_CHARS`] characters.
///
/// The cut lands on the last line break inside the budget when there is one, so
/// `/tasks` cannot be truncated mid-word — the failure mode a byte-offset cut
/// produces, and the one that makes a listing unreadable.
fn bounded_reply(reply: &str) -> String {
    const SUFFIX: &str = "\n…(truncated)";
    if reply.chars().count() <= MAX_SUPERVISOR_REPLY_CHARS {
        return reply.to_string();
    }
    // The suffix is part of the reply, so it is spent out of the budget rather
    // than appended on top of it: taking the full budget here and then pushing
    // the suffix returned up to `MAX_SUPERVISOR_REPLY_CHARS + 13` characters,
    // i.e. more than the bound this function exists to enforce.
    let head: String = reply
        .chars()
        .take(MAX_SUPERVISOR_REPLY_CHARS - SUFFIX.chars().count())
        .collect();
    let cut = head.rfind('\n').map(|at| at + 1).unwrap_or(head.len());
    let mut out = head[..cut].to_string();
    out.push_str(SUFFIX);
    out
}

/// Send startup notification to all allowed users.
/// Best-effort: logs failures, never blocks startup.
pub async fn notify_startup(
    bot: &teloxide::Bot,
    allowed_user_ids: &[u64],
    model: &str,
    mcp_count: usize,
    skills_count: usize,
    embedding_enabled: bool,
) {
    let memory_status = if embedding_enabled {
        "embedding enabled"
    } else {
        "FTS5 only"
    };

    let msg = format!(
        "HaosGreen is online 🌿\nModel: {model}\nMCP: {mcp} server(s) connected\nSkills: {skills} loaded\nMemory: {memory}",
        model = model, mcp = mcp_count, skills = skills_count, memory = memory_status,
    );

    for &user_id in allowed_user_ids {
        let chat_id = teloxide::types::ChatId(user_id as i64);
        if let Err(e) = bot.send_message(chat_id, &msg).await {
            warn!(
                "Failed to send startup notification to user {}: {}",
                user_id, e
            );
        }
    }
}

/// Send shutdown notification to all allowed users.
/// Best-effort: logs failures, never blocks shutdown.
pub async fn notify_shutdown(bot: &teloxide::Bot, allowed_user_ids: &[u64]) {
    let msg = "HaosGreen is going offline. Goodbye!";

    for &user_id in allowed_user_ids {
        let chat_id = teloxide::types::ChatId(user_id as i64);
        if let Err(e) = bot.send_message(chat_id, msg).await {
            warn!(
                "Failed to send shutdown notification to user {}: {}",
                user_id, e
            );
        }
    }
}

/// The non-`Agent` dependencies the message handler needs, injected through the
/// `dptree` so `handle_message` stays a plain function.
///
/// Both values are the ones `main.rs` already holds: the same
/// `telegram.allowed_user_ids` the `dptree` filter uses, and the process's
/// **single** `Arc<Supervisor>` — the one the web dashboard also holds. No
/// second supervisor and no second SQLite store is constructed for Telegram;
/// a second one would be a second `sup_execution_leases` owner for the same
/// database, which is exactly what the cross-process lease exists to refuse.
#[derive(Clone)]
pub struct TelegramDispatch {
    /// Re-checked inside [`dispatch_supervisor_command`], after the `dptree`
    /// filter has already dropped unauthorized messages.
    pub allowed_user_ids: Arc<Vec<u64>>,
    pub supervisor: Arc<Supervisor>,
}

/// Run the Telegram bot platform
pub async fn run(
    agent: Arc<Agent>,
    allowed_user_ids: Vec<u64>,
    bot: Arc<teloxide::Bot>,
    supervisor: Arc<Supervisor>,
) -> Result<()> {
    let bot = (*bot).clone();

    info!("Starting Telegram platform...");

    // Send startup notifications (best-effort) — before agent is moved into dptree
    notify_startup(
        &bot,
        &allowed_user_ids,
        &agent.config.openrouter.model,
        agent.mcp.server_count(),
        agent.skills.read().await.len(),
        agent.memory.embeddings.is_available(),
    )
    .await;

    // Publish the slash-command menu to Telegram so clients show suggestions.
    // Best-effort: a network failure here must not block the bot from running.
    let commands = supported_commands();
    let count = commands.len();
    match bot.set_my_commands(commands).await {
        Ok(_) => info!("Registered {} Telegram commands", count),
        Err(e) => warn!(error = %e, "Failed to register Telegram commands"),
    }

    let dispatch = TelegramDispatch {
        allowed_user_ids: Arc::new(allowed_user_ids.clone()),
        supervisor,
    };

    let message_handler = Update::filter_message()
        .filter_map({
            let allowed = allowed_user_ids.clone();
            move |msg: Message| {
                let user = msg.from.as_ref()?;
                if allowed.contains(&user.id.0) {
                    Some(msg)
                } else {
                    None
                }
            }
        })
        .endpoint(handle_message);

    let callback_handler = Update::filter_callback_query()
        .filter_map({
            let allowed = allowed_user_ids.clone();
            move |q: CallbackQuery| {
                if allowed.contains(&q.from.id.0) {
                    Some(q)
                } else {
                    None
                }
            }
        })
        .endpoint(handle_model_callback);

    let loop_callback_handler = Update::filter_callback_query()
        .filter_map(|q: CallbackQuery| {
            if q.data
                .as_deref()
                .is_some_and(|d| d.contains(r#""type":"loop""#))
            {
                Some(q)
            } else {
                None
            }
        })
        .endpoint(handle_loop_callback);

    let handler = dptree::entry()
        .branch(message_handler)
        .branch(loop_callback_handler)
        .branch(callback_handler);

    Dispatcher::builder(bot, handler)
        .dependencies(dptree::deps![agent, dispatch])
        // Commands (like /btw) bypass per-chat serialization for true concurrency.
        // Regular messages keep per-chat ordering to avoid race conditions.
        .distribution_function(|upd: &Update| {
            let is_cmd = match &upd.kind {
                UpdateKind::Message(m)
                | UpdateKind::EditedMessage(m)
                | UpdateKind::ChannelPost(m) => {
                    m.text().map(|t| t.starts_with('/')).unwrap_or(false)
                }
                _ => false,
            };
            if is_cmd {
                None
            } else {
                upd.chat().map(|c| c.id)
            }
        })
        .default_handler(|upd| async move {
            warn!("Unhandled update: {:?}", upd.id);
        })
        .error_handler(LoggingErrorHandler::with_custom_text("telegram"))
        .build()
        .dispatch()
        .await;

    Ok(())
}

/// Send entities-only fallback (no rich path).
async fn send_entities_message(bot: &Bot, chat_id: ChatId, markdown: &str) -> ResponseResult<()> {
    let (text, entities) = markdown_to_entities(markdown);
    let chunks = split_entities(&text, &entities, 4090);
    if chunks.is_empty() {
        return Ok(());
    }
    for (i, (chunk_text, chunk_entities)) in chunks.iter().enumerate() {
        if i == 0 {
            bot.send_message(chat_id, chunk_text)
                .entities(chunk_entities.clone())
                .await?;
        } else {
            bot.send_message(chat_id, chunk_text)
                .entities(chunk_entities.clone())
                .await
                .ok();
        }
    }
    Ok(())
}

/// Send a markdown string with the user's preferred format mode.
pub async fn send_markdown_message(
    bot: &Bot,
    chat_id: ChatId,
    markdown: &str,
    format: MessageFormat,
) -> ResponseResult<()> {
    match format {
        MessageFormat::Rich => {
            let token = BOT_TOKEN.get().expect("BOT_TOKEN not initialized");
            let processed = crate::utils::markdown_entities::preprocess_markdown(markdown);
            rich_sender::send_rich_messages(token, chat_id.0, &processed)
                .await
                .map_err(|e| {
                    teloxide::RequestError::Io(Arc::new(std::io::Error::other(format!("{e}"))))
                })?;
            Ok(())
        }
        MessageFormat::Markdown => send_entities_message(bot, chat_id, markdown).await,
        MessageFormat::Auto => {
            let token = BOT_TOKEN.get().expect("BOT_TOKEN not initialized");

            let entity_sender = || async { send_entities_message(bot, chat_id, markdown).await };

            match rich_sender::try_send_rich_fallback(token, chat_id.0, markdown, &entity_sender)
                .await
            {
                Ok(()) => Ok(()),
                Err(e) => {
                    warn!("send_markdown_message all paths failed: {e}");
                    Err(teloxide::RequestError::Io(Arc::new(std::io::Error::other(
                        format!("{e}"),
                    ))))
                }
            }
        }
    }
}

/// Read the tool UI mode for a user, with backward compatibility for the old
/// `tool_ui_enabled_{user_id}` boolean key.
async fn read_tool_ui_mode(agent: &Agent, user_id: &str) -> ToolUiMode {
    // Try new key first
    let new_key = format!("tool_ui_mode_{}", user_id);
    match agent.memory.recall("settings", &new_key).await {
        Ok(Some(val)) => return ToolUiMode::from_memory(Some(&val)),
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, "Failed to recall tool UI mode"),
    }
    // Fallback: migrate from old boolean key. Only persist when the old key
    // actually exists, so the default (no key) stays a live decision.
    let old_key = format!("tool_ui_enabled_{}", user_id);
    match agent.memory.recall("settings", &old_key).await {
        Ok(Some(old_val)) => {
            let mode = ToolUiMode::from_memory(Some(&old_val));
            agent
                .memory
                .remember("settings", &new_key, mode.as_str(), None)
                .await
                .ok();
            mode
        }
        Ok(None) => ToolUiMode::Minimal,
        Err(e) => {
            tracing::warn!(error = %e, "Failed to recall legacy tool UI setting");
            ToolUiMode::Minimal
        }
    }
}

/// Show models for a selected provider, or prompt for text search.
/// When prompting for text search, stores pending state in memory so the next
/// user message from this user routes to `handle_model_search` scoped to this provider.
async fn handle_provider_model_select(
    bot: Bot,
    chat_id: ChatId,
    agent: &Arc<Agent>,
    provider_name: &str,
    provider: &dyn Provider,
    user_id: &str,
) -> ResponseResult<()> {
    let set_pending = |agent: &Arc<Agent>, user_id: &str| {
        let agent = agent.clone();
        let user_id = user_id.to_string();
        let provider_name = provider_name.to_string();
        Box::pin(async move {
            agent
                .memory
                .remember(
                    "settings",
                    &format!("model_search_pending_{}", user_id),
                    "true",
                    None,
                )
                .await
                .ok();
            agent
                .memory
                .remember(
                    "settings",
                    &format!("model_search_provider_{}", user_id),
                    &provider_name,
                    None,
                )
                .await
                .ok();
        })
    };

    if !provider.config().discover_models {
        let prompt = format!(
            "Send me a model name or ID to search for on **{provider_name}**.\n\
             Example: `{}`",
            provider.default_model()
        );
        bot.send_message(chat_id, &prompt).await?;
        set_pending(agent, user_id).await;
        return Ok(());
    }

    match provider.list_models(&agent.llm.client).await {
        Ok(models) if models.len() <= 20 => {
            use teloxide::types::{InlineKeyboardButton, InlineKeyboardMarkup};
            let mut keyboard: Vec<Vec<InlineKeyboardButton>> = models
                .iter()
                .map(|m| {
                    let qualified = format!("{}/{}", provider_name, m);
                    vec![InlineKeyboardButton::callback(
                        m.clone(),
                        format!("model_select:{}", qualified),
                    )]
                })
                .collect();
            keyboard.push(vec![InlineKeyboardButton::callback(
                "\u{1F50D} Search all",
                "model_search_prompt",
            )]);
            keyboard.push(vec![InlineKeyboardButton::callback(
                "\u{274C} Cancel",
                "model_select:cancel",
            )]);

            let reply = format!("Models on **{provider_name}** ({}):", models.len());
            bot.send_message(chat_id, &reply)
                .reply_markup(InlineKeyboardMarkup::new(keyboard))
                .await?;
        }
        Ok(models) => {
            let prompt = format!(
                "**{provider_name}** has {} models available.\n\
                 Send me a model name or ID to search for.",
                models.len()
            );
            bot.send_message(chat_id, &prompt).await?;
            set_pending(agent, user_id).await;
        }
        Err(e) => {
            let prompt = format!(
                "Could not load model list from **{provider_name}**: {e}\n\
                 Send a model name or ID directly."
            );
            bot.send_message(chat_id, &prompt).await?;
            set_pending(agent, user_id).await;
        }
    }

    Ok(())
}
/// Accept a text model query and attempt to set the active model.
/// If the query is a bare name (e.g. "deepseek v4 flash"), fetches the
/// provider's model list via `list_models()` and does fuzzy matching to
/// resolve the actual model ID (e.g. "deepseek/deepseek-v4-flash").
///
/// If the user previously selected a provider via the inline keyboard,
/// the search is scoped to that provider.
async fn handle_model_search(
    bot: Bot,
    chat_id: ChatId,
    agent: &Arc<Agent>,
    query: &str,
    user_id: &str,
) -> ResponseResult<()> {
    // If query already has a known provider prefix, set directly
    if let Some((prefix, _)) = query.split_once('/') {
        if agent.registry.get_provider(prefix).is_some() {
            return set_model_and_reply(bot, chat_id, agent, query).await;
        }
    }

    // Determine which provider to search
    let stored_provider = agent
        .memory
        .recall("settings", &format!("model_search_provider_{}", user_id))
        .await
        .unwrap_or(None);

    let provider_name = stored_provider
        .clone()
        .unwrap_or_else(|| agent.registry.default_provider_name().to_string());

    // Clear stored provider so it doesn't affect future searches
    if stored_provider.is_some() {
        agent
            .memory
            .forget("settings", &format!("model_search_provider_{}", user_id))
            .await
            .ok();
    }

    let provider = match agent.registry.get_provider(&provider_name) {
        Some(p) => p,
        None => {
            return set_model_and_reply(
                bot,
                chat_id,
                agent,
                &format!("{}/{}", provider_name, query),
            )
            .await;
        }
    };

    // Fetch model list and fuzzy match
    match provider.list_models(&agent.llm.client).await {
        Ok(models) if !models.is_empty() => {
            let q = query.to_lowercase().replace(['-', '_', '.', ' '], "");

            // Exact match (full model ID)
            if let Some(exact) = models
                .iter()
                .find(|m| m.to_lowercase() == query.to_lowercase())
            {
                return set_model_and_reply(
                    bot,
                    chat_id,
                    agent,
                    &format!("{}/{}", provider_name, exact),
                )
                .await;
            }

            // Fuzzy match: normalize both sides and check containment
            let mut matches: Vec<&String> = models
                .iter()
                .filter(|m| {
                    m.to_lowercase()
                        .replace(['-', '_', '.', ' '], "")
                        .contains(&q)
                })
                .collect();
            matches.sort();
            matches.truncate(10);

            match matches.len() {
                0 => {
                    // No fuzzy match — try direct set anyway
                    return set_model_and_reply(
                        bot,
                        chat_id,
                        agent,
                        &format!("{}/{}", provider_name, query),
                    )
                    .await;
                }
                1 => {
                    return set_model_and_reply(
                        bot,
                        chat_id,
                        agent,
                        &format!("{}/{}", provider_name, matches[0]),
                    )
                    .await;
                }
                _ => {
                    let mut reply = format!(
                        "Multiple models match '{}' on **{}**:\n\n",
                        query, provider_name
                    );
                    for m in &matches {
                        reply.push_str(&format!("`{}/{m}`\n", provider_name));
                    }
                    reply.push_str("\nUse `/models <full_model_id>` to set one.");
                    bot.send_message(chat_id, escape_text(&reply))
                        .parse_mode(ParseMode::MarkdownV2)
                        .await?;
                }
            }
        }
        _ => {
            // API unavailable or empty list — try direct set
            return set_model_and_reply(
                bot,
                chat_id,
                agent,
                &format!("{}/{}", provider_name, query),
            )
            .await;
        }
    }

    Ok(())
}

/// Set the model and send a success/failure reply.
async fn set_model_and_reply(
    bot: Bot,
    chat_id: ChatId,
    agent: &Arc<Agent>,
    model_id: &str,
) -> ResponseResult<()> {
    match agent.set_model(model_id).await {
        Ok(()) => {
            let reply = format!("✅ Model changed to `{}`", model_id);
            bot.send_message(chat_id, escape_text(&reply))
                .parse_mode(ParseMode::MarkdownV2)
                .await?;
        }
        Err(e) => {
            bot.send_message(
                chat_id,
                escape_text(&format!("Failed to save model: {:#}", e)),
            )
            .parse_mode(ParseMode::MarkdownV2)
            .await?;
        }
    }
    Ok(())
}

async fn handle_message(
    bot: Bot,
    msg: Message,
    agent: Arc<Agent>,
    dispatch: TelegramDispatch,
) -> ResponseResult<()> {
    let user = match msg.from.as_ref() {
        Some(user) => user,
        None => return Ok(()),
    };

    let user_id = user.id.0;
    let user_name = user.first_name.clone();
    let mut msg_format = load_message_format(&agent.memory, &user_id.to_string()).await;

    // For media messages, use caption as text; for text messages, use msg.text()
    let text = msg
        .text()
        .or_else(|| msg.caption())
        .unwrap_or("")
        .to_string();

    // Temp dir for file downloads — created lazily by download_telegram_file
    let temp_dir = std::env::temp_dir().join(format!("haos_green_{}", uuid::Uuid::new_v4()));

    let mut attachments: Vec<Attachment> = Vec::new();

    // Handle photo attachments — last PhotoSize is the highest resolution
    if let Some(photos) = msg.photo() {
        if let Some(largest) = photos.last() {
            let file_id = largest.file.id.to_string();
            match download_telegram_file(&bot, &file_id, &temp_dir, None).await {
                Ok((path, mime)) => {
                    attachments.push(Attachment {
                        kind: AttachmentKind::Image,
                        path,
                        mime_type: mime,
                        file_name: None,
                    });
                }
                Err(e) => warn!("Failed to download photo: {:#}", e),
            }
        }
    }

    // Handle document attachments
    if let Some(doc) = msg.document() {
        let file_id = doc.file.id.to_string();
        let file_name = doc.file_name.clone();
        match download_telegram_file(&bot, &file_id, &temp_dir, file_name.as_deref()).await {
            Ok((path, mime)) => {
                let kind = classify_attachment_kind(&mime, file_name.as_deref());
                attachments.push(Attachment {
                    kind,
                    path,
                    mime_type: mime,
                    file_name,
                });
            }
            Err(e) => warn!("Failed to download document: {:#}", e),
        }
    }

    // Skip if there is nothing to process
    if text.is_empty() && attachments.is_empty() {
        return Ok(());
    }

    // Check if user is in model-search-pending state (tapped "Search models" button).
    let search_pending = agent
        .memory
        .recall("settings", &format!("model_search_pending_{}", user_id))
        .await
        .unwrap_or(None)
        .map(|v| v == "true")
        .unwrap_or(false);
    if search_pending && !text.is_empty() && !text.starts_with('/') {
        agent
            .memory
            .remember(
                "settings",
                &format!("model_search_pending_{}", user_id),
                "false",
                None,
            )
            .await
            .ok();
        // Treat message as a model search query — dispatch to shared model search logic.
        return handle_model_search(bot, msg.chat.id, &agent, &text, &user_id.to_string()).await;
    }

    info!(
        "Telegram message from {} ({}): {} [attachments: {}]",
        user_name,
        user_id,
        if text.is_empty() { "(no text)" } else { &text },
        attachments.len()
    );

    // Handle commands
    if text == "/clear" {
        if let Err(e) = agent
            .clear_conversation("telegram", &user_id.to_string())
            .await
        {
            error!("Failed to clear conversation: {}", e);
        }
        return send_markdown_message(
            &bot,
            msg.chat.id,
            "Conversation archived. Past messages remain searchable.",
            msg_format,
        )
        .await;
    }

    if text == "/start" {
        let help = "Hello! I'm your AI assistant. Send me a message and I'll help you.\n\n\
             Commands:\n\
             **/clear** — Clear conversation history\n\
             **/tools** — List available tools\n\
             **/skills** — List loaded skills\n\
             **/update-skills** — Re-sync bundled skills (backs up local edits)\n\
             **/verbose** — Toggle tool call progress display\n\
             **/queryrewrite** — Toggle query rewriting for memory search\n\
             **/format** — Switch message format: rich, markdown, or auto\n\
             **/selfupgrade** — Upgrade the bot (source or release binary)\n\
             **/models** — Browse and change the model\n\
             **/stop** — Cancel the current processing gracefully\n\
             **/btw** — Ask a parallel question while the bot is busy";
        return send_markdown_message(&bot, msg.chat.id, help, msg_format).await;
    }

    if text == "/tools" {
        let all_tools = agent.all_tool_definitions();
        let mut builtin = Vec::new();
        let mut mcp_servers: BTreeMap<String, Vec<&crate::llm::ToolDefinition>> = BTreeMap::new();

        // Known MCP server names (same list as friendly_tool_name in tool_notifier.rs)
        // Sorted by length descending to match longest first (handles server names with underscores)
        const KNOWN_MCP_SERVERS: [&str; 14] = [
            "google-workspace",
            "google_workspace",
            "brave-search",
            "brave_search",
            "filesystem",
            "puppeteer",
            "github",
            "sqlite",
            "threads",
            "notion",
            "fetch",
            "git",
            "context7",
            "qdrant",
        ];

        for tool in &all_tools {
            if let Some(rest) = tool.function.name.strip_prefix("mcp_") {
                let server = KNOWN_MCP_SERVERS
                    .iter()
                    .find(|server| rest.starts_with(&format!("{}_", server)))
                    .map(|s| s.to_string())
                    .or_else(|| {
                        // Unknown server: split on first underscore
                        rest.find('_').map(|sep| rest[..sep].to_string())
                    });
                match server {
                    Some(s) => mcp_servers.entry(s).or_default().push(tool),
                    None => builtin.push(tool),
                }
            } else {
                builtin.push(tool);
            }
        }

        let mut tool_list = format!("**Built-in tools** ({}):\n", builtin.len());
        for tool in &builtin {
            tool_list.push_str(&format!(
                "  - `{}`: {}\n",
                tool.function.name, tool.function.description
            ));
        }
        tool_list.push('\n');

        for (server, tools) in &mcp_servers {
            tool_list.push_str(&format!("**MCP: {}** ({}):\n", server, tools.len()));
            for tool in tools {
                tool_list.push_str(&format!(
                    "  - `{}`: {}\n",
                    tool.function.name, tool.function.description
                ));
            }
            tool_list.push('\n');
        }

        return send_markdown_message(&bot, msg.chat.id, &tool_list, msg_format).await;
    }

    if text == "/skills" {
        let skills_guard = agent.skills.read().await;
        let skills = skills_guard.list();
        if skills.is_empty() {
            return send_markdown_message(&bot, msg.chat.id, "No skills loaded.", msg_format).await;
        }
        let mut skill_list = String::from("**Loaded skills:**\n\n");
        for skill in &skills {
            skill_list.push_str(&format!("- **{}**: {}\n", skill.name, skill.description));
        }
        return send_markdown_message(&bot, msg.chat.id, &skill_list, msg_format).await;
    }

    if text == "/updateskills" || text == "/update-skills" {
        let mut lines = Vec::new();

        match crate::skills::embed::overwrite_skills(&agent.config.skills.directory).await {
            Ok(r) => lines.push(format!(
                "Skills — {} written, {} backed up.",
                r.written, r.backed_up
            )),
            Err(e) => lines.push(format!("Skills update failed: {e}")),
        }
        match crate::skills::embed::overwrite_agents(&agent.config.agents.directory).await {
            Ok(r) => lines.push(format!(
                "Agents — {} written, {} backed up.",
                r.written, r.backed_up
            )),
            Err(e) => lines.push(format!("Agents update failed: {e}")),
        }

        let (s, a) = agent.reload_skills_and_agents().await;
        lines.push(format!("Reloaded: {s} skill(s), {a} agent(s) active."));

        return send_markdown_message(&bot, msg.chat.id, &lines.join("\n"), msg_format).await;
    }

    if text == "/verbose" {
        let current = read_tool_ui_mode(&agent, &user_id.to_string()).await;
        let new_mode = current.next();
        agent
            .memory
            .remember(
                "settings",
                &format!("tool_ui_mode_{}", user_id),
                new_mode.as_str(),
                None,
            )
            .await
            .ok();
        return send_markdown_message(&bot, msg.chat.id, new_mode.reply_message(), msg_format)
            .await;
    }

    // Accept both the canonical `/queryrewrite` (registered with Telegram —
    // Bot API command names cannot contain hyphens) and the legacy
    // `/query-rewrite` form for users with existing muscle memory.
    if text == "/queryrewrite" || text == "/query-rewrite" {
        let current = agent
            .memory
            .recall("settings", &format!("query_rewrite_enabled_{}", user_id))
            .await
            .unwrap_or(None);
        // When no per-user setting exists, fall back to the global config default.
        let currently_on = match current.as_deref() {
            Some("true") => true,
            Some("false") => false,
            _ => agent.config.memory.query_rewriter_enabled,
        };
        let new_value = if currently_on { "false" } else { "true" };
        agent
            .memory
            .remember(
                "settings",
                &format!("query_rewrite_enabled_{}", user_id),
                new_value,
                None,
            )
            .await
            .ok();
        let reply = if new_value == "true" {
            "🔍 **Query rewriting enabled.** Follow-up questions will be rewritten before memory search."
        } else {
            "🔍 **Query rewriting disabled.** Messages will be searched as-is."
        };
        return send_markdown_message(&bot, msg.chat.id, reply, msg_format).await;
    }

    // Handle /btw <text> for context-forked side question
    if text == "/btw" || text.starts_with("/btw ") {
        let btw_text = text
            .strip_prefix("/btw")
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .unwrap_or("What are you doing?")
            .to_string();

        // Reply immediately, then answer in background
        let _ = send_markdown_message(
            &bot,
            msg.chat.id,
            "⏳ **BTW question sent to subagent...**",
            msg_format,
        )
        .await;

        let agent_clone = agent.clone();
        let bot_clone = bot.clone();
        let chat_id = msg.chat.id;
        let user_id_str = user_id.to_string();
        let btw_format = msg_format;
        tokio::spawn(async move {
            // Load conversation context inside the spawned task
            let conversation_id = match agent_clone
                .memory
                .get_or_create_conversation("telegram", &user_id_str)
                .await
            {
                Ok(id) => id,
                Err(e) => {
                    let _ = send_markdown_message(
                        &bot_clone,
                        chat_id,
                        &format!("**BTW error:** {}", e),
                        btw_format,
                    )
                    .await;
                    return;
                }
            };
            let messages = agent_clone
                .memory
                .load_messages_with_limit(
                    &conversation_id,
                    agent_clone.config.memory.max_raw_messages,
                )
                .await
                .unwrap_or_default();

            let forked = crate::agent::build_btw_context(&messages, &btw_text);
            // Use the agent's current model (qualified string like "openrouter/qwen/qwen3-235b-a22b")
            let model = agent_clone.current_model.read().await.clone();
            match agent_clone
                .llm
                .chat_completion_with_model(&forked, &[], &model)
                .await
            {
                Ok(response) => {
                    let text = response
                        .message
                        .content
                        .as_ref()
                        .map(|c| c.as_text())
                        .unwrap_or_default();
                    let _ = send_markdown_message(&bot_clone, chat_id, &text, btw_format).await;
                }
                Err(e) => {
                    let _ = send_markdown_message(
                        &bot_clone,
                        chat_id,
                        &format!("**BTW error:** {}", e),
                        btw_format,
                    )
                    .await;
                }
            }
        });

        return Ok(());
    }

    // Supervisor commands, before the /self-upgrade and /models dispatch below
    // so no later `starts_with` branch can shadow them. `dispatch_supervisor_command`
    // returns `false` for every other command, so this is transparent to them.
    if let Some((cmd, arg)) = parse_command(&text) {
        let actor = SupervisorActor {
            user_id,
            chat_id: msg.chat.id.0.to_string(),
        };
        match dispatch_supervisor_command(
            &cmd,
            &arg,
            &actor,
            &dispatch.allowed_user_ids,
            &dispatch.supervisor,
            &TelegramAdapter::new(bot.clone()),
        )
        .await
        {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => {
                // A failed *send* is not worth failing the update over: the
                // supervisor action (if any) has already happened, and the
                // dispatcher's error handler logs the rest.
                error!(error = %format!("{e:#}"), "Failed to answer a supervisor command");
                return Ok(());
            }
        }
    }

    // Combined parse_command dispatch for /self-upgrade and /models.
    if let Some((cmd, arg)) = parse_command(&text) {
        match cmd.as_str() {
            "self-upgrade" | "selfupgrade" => {
                let branch = if arg.is_empty() { "main" } else { &arg };

                let (progress_tx, mut progress_rx) =
                    tokio::sync::mpsc::unbounded_channel::<String>();

                let sent = bot
                    .send_message(msg.chat.id, "🔄 Starting self-upgrade...")
                    .await?;

                let bot_clone = bot.clone();
                let bot_progress = bot.clone();
                let chat_id = msg.chat.id;
                let msg_id = sent.id;
                let branch_owned = branch.to_string();

                let progress_handle = tokio::spawn(async move {
                    let mut buffer = String::from("🔄 Self-upgrading...\n");
                    while let Some(step) = progress_rx.recv().await {
                        buffer.push_str(&format!("{}\n", step));
                        if buffer.len() > 3500 {
                            let suffix = "\n...(truncated)";
                            let trunc = buffer.len() - 3500 + suffix.len();
                            buffer =
                                format!("...{}", &buffer[buffer.len().saturating_sub(trunc)..]);
                            buffer.push_str(suffix);
                        }
                        let _ = bot_progress
                            .edit_message_text(chat_id, msg_id, &buffer)
                            .await;
                    }
                });

                let result =
                    crate::learning::self_upgrade(&branch_owned, "auto", Some(progress_tx)).await;

                // Wait for progress to be fully displayed.
                progress_handle.await.ok();

                match result {
                    Ok(log) => {
                        let display = if log.len() > 3500 {
                            format!("{}...\n(truncated)", &log[..3500])
                        } else {
                            log
                        };
                        bot_clone
                            .edit_message_text(
                                chat_id,
                                msg_id,
                                format!("✅ Upgrade successful!\n\n{}", display),
                            )
                            .await
                            .ok();
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        let _ = crate::learning::restart_bot();
                    }
                    Err(e) => {
                        bot_clone
                            .edit_message_text(
                                chat_id,
                                msg_id,
                                format!("❌ Upgrade failed:\n{}", e),
                            )
                            .await
                            .ok();
                    }
                }

                return Ok(());
            }
            "models" => {
                if !arg.is_empty() {
                    return handle_model_search(
                        bot,
                        msg.chat.id,
                        &agent,
                        &arg,
                        &user_id.to_string(),
                    )
                    .await;
                }

                let providers = agent.registry.provider_names();

                if providers.len() == 1 {
                    // Single provider: jump straight to model search
                    let provider_name = providers[0].clone();
                    let provider = match agent.registry.get_provider(&provider_name) {
                        Some(p) => p,
                        None => {
                            bot.send_message(
                                msg.chat.id,
                                escape_text(&format!("Provider '{}' not found.", provider_name)),
                            )
                            .parse_mode(ParseMode::MarkdownV2)
                            .await?;
                            return Ok(());
                        }
                    };
                    let user_id = user_id.to_string();
                    return handle_provider_model_select(
                        bot,
                        msg.chat.id,
                        &agent,
                        &provider_name,
                        provider,
                        &user_id,
                    )
                    .await;
                }

                // Multiple providers: show inline keyboard
                let current = agent.current_model.read().await;
                let reply = format!("Active model: `{}`\n\nSelect a provider:", *current);
                use teloxide::types::{InlineKeyboardButton, InlineKeyboardMarkup};
                let mut keyboard: Vec<Vec<InlineKeyboardButton>> = providers
                    .iter()
                    .map(|name| {
                        vec![InlineKeyboardButton::callback(
                            name.clone(),
                            format!("provider_select:{}", name),
                        )]
                    })
                    .collect();
                keyboard.push(vec![InlineKeyboardButton::callback(
                    "❌ Cancel",
                    "model_select:cancel",
                )]);

                bot.send_message(msg.chat.id, &reply)
                    .reply_markup(InlineKeyboardMarkup::new(keyboard))
                    .await?;
                return Ok(());
            }
            _ => {} // ignore unknown commands for now
        }
    }

    // Handle /format command — switch message output format
    if text.starts_with("/format") {
        let parts: Vec<&str> = text.splitn(2, |c: char| c.is_whitespace()).collect();
        let sub = parts.get(1).copied().unwrap_or("");
        match sub {
            "rich" | "markdown" | "auto" => {
                let fmt = MessageFormat::from_str_value(sub).unwrap();
                msg_format = fmt;
                agent
                    .memory
                    .remember(
                        "settings",
                        &format!("message_format_{}", user_id),
                        sub,
                        None,
                    )
                    .await
                    .ok();
                return send_markdown_message(
                    &bot,
                    msg.chat.id,
                    &format!(
                        "✅ **Format changed to {}.** {}",
                        sub,
                        match fmt {
                            MessageFormat::Rich => "Using sendRichMessage (Telegram native only).",
                            MessageFormat::Markdown =>
                                "Using entity-formatted sendMessage (works everywhere).",
                            MessageFormat::Auto => "Try rich, fall back to entities on failure.",
                        }
                    ),
                    msg_format,
                )
                .await;
            }
            "" => {
                return send_markdown_message(
                    &bot,
                    msg.chat.id,
                    &format!(
                        "Current format: **{}**\n\n\
                         Use `/format rich`, `/format markdown`, or `/format auto` to change.\n\n\
                         - **rich** — sendRichMessage (Telegram native only)\n\
                         - **markdown** — entity-formatted sendMessage (works everywhere)\n\
                         - **auto** — try rich, fall back to entities",
                        msg_format.as_str()
                    ),
                    msg_format,
                )
                .await;
            }
            _ => {
                return send_markdown_message(
                    &bot,
                    msg.chat.id,
                    "Unknown format. Use `/format rich`, `/format markdown`, or `/format auto`.",
                    msg_format,
                )
                .await;
            }
        }
    }

    // Handle /mode command
    if text.starts_with("/mode") {
        let parts: Vec<&str> = text.splitn(2, |c: char| c.is_whitespace()).collect();
        let sub = parts.get(1).copied().unwrap_or("");
        if sub == "steer" {
            agent
                .set_mid_run_mode(&user_id.to_string(), MidRunMode::Steer)
                .await;
            return send_markdown_message(
                &bot, msg.chat.id,
                "🔄 **Mode set to steer.** Mid-processing messages will be injected as steering context.",
                msg_format,
            ).await;
        } else if sub == "queue" {
            agent
                .set_mid_run_mode(&user_id.to_string(), MidRunMode::Queue)
                .await;
            return send_markdown_message(
                &bot,
                msg.chat.id,
                "🔄 **Mode set to queue.** Mid-processing messages will wait for the next turn.",
                msg_format,
            )
            .await;
        } else if sub.is_empty() {
            let current = agent.get_mid_run_mode(&user_id.to_string()).await;
            let mode_str = current.as_str();
            return send_markdown_message(
                &bot,
                msg.chat.id,
                &format!(
                    "Current mode: **{}**\n\nUse `/mode steer` or `/mode queue` to change.",
                    mode_str
                ),
                msg_format,
            )
            .await;
        } else {
            return send_markdown_message(
                &bot,
                msg.chat.id,
                "Unknown mode. Use `/mode steer` or `/mode queue`.",
                msg_format,
            )
            .await;
        }
    }

    // Handle /stop command
    if text == "/stop" {
        if agent.cancel_processing(&user_id.to_string()).await {
            return send_markdown_message(
                &bot,
                msg.chat.id,
                "⏹ **Processing cancelled.** Accumulated state has been saved.",
                msg_format,
            )
            .await;
        } else {
            return send_markdown_message(
                &bot,
                msg.chat.id,
                "Nothing is currently processing.",
                msg_format,
            )
            .await;
        }
    }

    // CHECK: if user is currently being processed, queue non-command messages as injection
    if !text.starts_with('/') && agent.is_processing(&user_id.to_string()).await {
        let current_mode = agent.get_mid_run_mode(&user_id.to_string()).await;
        let maxed = !agent.queue_injection(&user_id.to_string(), &text).await;
        if maxed {
            return send_markdown_message(
                &bot,
                msg.chat.id,
                "⚠️ **Injection queue full** (max 10). Please wait for current processing to finish.",
                msg_format,
            )
            .await;
        }
        info!(
            "Queued '{}' as injection for user {} (mode: {:?})",
            text, user_id, current_mode
        );
        let confirm = match current_mode {
            MidRunMode::Steer => {
                "📨 **Steer queued** — will inject into current processing at next step."
            }
            MidRunMode::Queue => {
                "📨 **Message queued** — will process after current task completes."
            }
        };
        return send_markdown_message(&bot, msg.chat.id, confirm, msg_format).await;
    }

    // Send "typing" indicator
    bot.send_chat_action(msg.chat.id, teloxide::types::ChatAction::Typing)
        .await
        .ok();

    // Check tool UI mode for this user
    let tool_ui_mode = read_tool_ui_mode(&agent, &user_id.to_string()).await;

    // Set up tool event channel if not silent
    let (tool_event_tx, tool_event_rx) = if tool_ui_mode != ToolUiMode::Silent {
        let (tx, rx) = tokio::sync::mpsc::channel::<crate::platform::tool_notifier::ToolEvent>(32);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    // Spawn notifier task if not silent
    let notifier_handle = if tool_ui_mode != ToolUiMode::Silent {
        let bot_clone = bot.clone();
        let chat_id = msg.chat.id;
        let mut rx = tool_event_rx.expect("rx exists when not silent");
        let mode = tool_ui_mode;
        Some(tokio::spawn(async move {
            let mut notifier =
                crate::platform::tool_notifier::ToolCallNotifier::new(bot_clone, chat_id, mode);
            notifier.start().await;
            let mut handled_finished = false;
            while let Some(event) = rx.recv().await {
                match event {
                    crate::platform::tool_notifier::ToolEvent::Finished { success } => {
                        notifier.finish(success).await;
                        handled_finished = true;
                        break;
                    }
                    other => notifier.handle_event(other).await,
                }
            }
            // If the channel closed without an explicit Finished event, preserve
            // previous behaviour and treat it as a successful finish.
            if !handled_finished {
                notifier.finish(true).await;
            }
        }))
    } else {
        None
    };

    // When silent, send a transient "Thinking..." placeholder so the user
    // knows the bot is processing. The placeholder is **independent** of the
    // streaming output — when the first token arrives it is delivered as a NEW
    // message, and the placeholder is deleted by `handle_message` after the
    // stream completes (success or error). This keeps the placeholder a
    // standalone progress signal rather than a doomed attempt to morph into the
    // final answer.
    let placeholder_msg_id: Option<teloxide::types::MessageId> =
        if tool_ui_mode == ToolUiMode::Silent {
            match bot.send_message(msg.chat.id, "⏳ Thinking...").await {
                Ok(sent) => Some(sent.id),
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to send thinking placeholder");
                    None
                }
            }
        } else {
            None
        };

    // Streaming: set up token channel for progressive message display
    // Split threshold: use UTF-16 code units (Telegram's limit is 4096).
    // Streaming uses a conservative 3500 to leave room for mid-split growth.
    // The final flush uses markdown_to_entities + split_entities with MAX_UTF16=4090.
    const TELEGRAM_STREAM_SPLIT_UTF16: usize = 3500;

    let (stream_token_tx, stream_token_rx) = tokio::sync::mpsc::channel::<String>(128);

    // Spawn receiver task: edits Telegram message as tokens arrive
    let stream_bot = bot.clone();
    let stream_chat_id = msg.chat.id;
    let stream_format = msg_format;
    let stream_handle = tokio::spawn(async move {
        use std::time::{Duration, Instant};

        struct StreamChunk {
            content: String,
            msg_id: Option<teloxide::types::MessageId>,
        }

        let mut buffer = String::new();
        let mut current_msg_id: Option<teloxide::types::MessageId> = None;
        let mut chunks: Vec<StreamChunk> = Vec::new();
        let mut last_action = Instant::now();
        let mut rx = stream_token_rx;
        let mut buffer_utf16_len: usize = 0;

        while let Some(token) = rx.recv().await {
            buffer.push_str(&token);
            buffer_utf16_len += token.encode_utf16().count();

            // When buffer exceeds split threshold, finalize the current message
            // and reset so subsequent tokens start a new message.
            if buffer_utf16_len > TELEGRAM_STREAM_SPLIT_UTF16 {
                let snapshot = buffer.clone();
                let msg_id = if let Some(mid) = current_msg_id {
                    stream_bot
                        .edit_message_text(stream_chat_id, mid, &snapshot)
                        .await
                        .ok();
                    Some(mid)
                } else if let Ok(sent) = stream_bot.send_message(stream_chat_id, &snapshot).await {
                    Some(sent.id)
                } else {
                    None
                };
                chunks.push(StreamChunk {
                    content: snapshot,
                    msg_id,
                });
                buffer.clear();
                buffer_utf16_len = 0;
                current_msg_id = None;
                last_action = Instant::now();
                continue;
            }

            // Every 500 ms: send first message or edit existing one
            if last_action.elapsed() >= Duration::from_millis(500) {
                if let Some(msg_id) = current_msg_id {
                    stream_bot
                        .edit_message_text(stream_chat_id, msg_id, &buffer)
                        .await
                        .ok();
                } else {
                    match stream_bot.send_message(stream_chat_id, &buffer).await {
                        Ok(sent) => current_msg_id = Some(sent.id),
                        Err(e) => tracing::warn!(error = %e, "stream_handle: initial send failed"),
                    }
                }
                last_action = Instant::now();
            }
        }

        // If the last buffer had no message ID yet, send it now.
        if !buffer.is_empty() && current_msg_id.is_none() {
            match stream_bot.send_message(stream_chat_id, &buffer).await {
                Ok(sent) => current_msg_id = Some(sent.id),
                Err(e) => tracing::warn!(error = %e, "stream_handle: final send failed"),
            }
        }

        // Add the last segment as the final chunk.
        chunks.push(StreamChunk {
            content: buffer,
            msg_id: current_msg_id,
        });

        // If nothing was streamed, skip the final formatting.
        if chunks.is_empty() || chunks.iter().all(|c| c.content.is_empty()) {
            return;
        }

        // Build the full text from all chunks.
        let full_text: String = chunks.iter().map(|c| c.content.as_str()).collect();

        // Collect all message IDs for cleanup.
        let old_ids: Vec<teloxide::types::MessageId> =
            chunks.iter().filter_map(|c| c.msg_id).collect();

        const MAX_UTF16: usize = 4090;

        // Delete all old streaming messages (best-effort) so we can send fresh
        // properly-formatted chunks without orphaned plain-text messages.
        for mid in &old_ids {
            stream_bot.delete_message(stream_chat_id, *mid).await.ok();
        }

        // Pre-process markdown for spoiler/underline
        let processed = crate::utils::markdown_entities::preprocess_markdown(&full_text);
        let (plain_text, entities) = markdown_to_entities(&full_text);
        let entity_chunks = split_entities(&plain_text, &entities, MAX_UTF16);
        let rich_chunks = rich_sender::split_markdown_at_newlines(&processed, MAX_UTF16);
        let token = BOT_TOKEN.get().expect("BOT_TOKEN not initialized").clone();

        match stream_format {
            MessageFormat::Rich => {
                for chunk_md in &rich_chunks {
                    if rich_sender::send_rich_message(&token, stream_chat_id.0, chunk_md)
                        .await
                        .is_err()
                    {
                        // Rich-only mode: one failure stops the chain
                        tracing::warn!("stream_handle: rich send failed, aborting");
                        break;
                    }
                }
            }
            MessageFormat::Markdown => {
                for (ct, ce) in &entity_chunks {
                    stream_bot
                        .send_message(stream_chat_id, ct)
                        .entities(ce.clone())
                        .await
                        .ok();
                }
            }
            MessageFormat::Auto => {
                for (i, chunk_md) in rich_chunks.iter().enumerate() {
                    let result =
                        rich_sender::send_rich_message(&token, stream_chat_id.0, chunk_md).await;
                    if result.is_err() {
                        // Fallback: use entity chunk i
                        if let Some((ct, ce)) = entity_chunks.get(i) {
                            stream_bot
                                .send_message(stream_chat_id, ct)
                                .entities(ce.clone())
                                .await
                                .ok();
                        }
                    }
                }
            }
        }
    });

    // Build platform-agnostic message
    let incoming = IncomingMessage {
        platform: "telegram".to_string(),
        user_id: user_id.to_string(),
        chat_id: msg.chat.id.0.to_string(),
        user_name,
        text,
        attachments,
    };

    // Process through agent — moves stream_token_tx and tool_event_tx
    // Keep an owned clone of the tool_event_tx so we can send a terminal
    // Finished event after processing completes.
    let agent_tool_event_tx = tool_event_tx.clone();
    let process_result = match agent
        .process_message(
            &incoming,
            tool_event_tx,
            Some(stream_token_tx),
            tool_ui_mode,
        )
        .await
    {
        Ok(text) => Ok(text),
        Err(e) => {
            stream_handle.abort();
            Err(e)
        }
    };

    let process_success = process_result.is_ok();
    if let Some(tx) = agent_tool_event_tx {
        let _ = tx
            .send(crate::platform::tool_notifier::ToolEvent::Finished {
                success: process_success,
            })
            .await;
    }

    // Drop the sender to signal the notifier to stop, then await cleanup.
    // tool_event_tx is already moved into process_message — it's dropped when process_message returns.
    if let Some(handle) = notifier_handle {
        handle.await.ok();
    }

    // Wait for stream receiver to complete its final edit
    stream_handle.await.ok();

    // Cleanup temp dir used for file downloads (async to avoid blocking the executor)
    if temp_dir.exists() {
        tokio::fs::remove_dir_all(&temp_dir).await.ok();
    }

    // Delete the "Thinking..." placeholder now that the response (or error
    // reply below) has been delivered. Best-effort: ignore failures so a
    // stale placeholder never blocks reporting the actual outcome.
    if let Some(placeholder_id) = placeholder_msg_id {
        if let Err(e) = bot.delete_message(msg.chat.id, placeholder_id).await {
            tracing::warn!(error = %e, "Failed to delete thinking placeholder");
        }
    }

    if let Err(e) = process_result {
        warn!(error = %e, "Agent processing failed");
        return send_markdown_message(&bot, msg.chat.id, &format!("**Error:** {}", e), msg_format)
            .await;
    }
    // Success: response already delivered via streaming

    // Check if a self-upgrade tool call requested a restart.
    if agent
        .restart_pending
        .load(std::sync::atomic::Ordering::Acquire)
    {
        agent
            .restart_pending
            .store(false, std::sync::atomic::Ordering::Release);
        let _ = bot
            .send_message(msg.chat.id, "🔄 Self-upgrade complete. Restarting...")
            .await;
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            let _ = crate::learning::restart_bot();
        });
    }

    Ok(())
}

/// Handle callback query from loop detection inline keyboard.
/// Resolves the oneshot sender so the suspended agent loop can continue.
async fn handle_loop_callback(bot: Bot, q: CallbackQuery, agent: Arc<Agent>) -> ResponseResult<()> {
    let user_id = q.from.id.to_string();
    let data = match q.data {
        Some(ref d) => d.clone(),
        None => {
            // Even if there's no data, we must answer the callback query
            bot.answer_callback_query(q.id).await.ok();
            return Ok(());
        }
    };

    // Parse the user's choice from callback data
    let choice = if data.contains(r#""action":"continue""#) {
        LoopCallbackChoice::Continue
    } else if data.contains(r#""action":"stop""#) {
        LoopCallbackChoice::Stop
    } else if data.contains(r#""action":"add_instruction""#) {
        LoopCallbackChoice::AddInstruction
    } else {
        // Unknown action — answer and ignore
        bot.answer_callback_query(q.id).await.ok();
        return Ok(());
    };

    // Send the choice to the waiting agent loop (if any)
    if let Some(sender) = agent.take_loop_callback(&user_id).await {
        let _ = sender.send(choice);
    }

    bot.answer_callback_query(q.id).await.ok();
    Ok(())
}

/// Handle callback queries from inline keyboard buttons (e.g. model selection).
async fn handle_model_callback(
    bot: Bot,
    q: CallbackQuery,
    agent: Arc<Agent>,
) -> ResponseResult<()> {
    let callback_id = q.id.clone();
    let data = match q.data {
        Some(ref d) => d.clone(),
        None => {
            // Even if there's no data, we must answer the callback query
            bot.answer_callback_query(callback_id).await.ok();
            return Ok(());
        }
    };
    let msg = q.regular_message().cloned();

    // Remove the old unconditional answer_callback_query that had no text.
    // Each branch below now answers with the appropriate text (or silently)
    // exactly once. A second answer for the same callback_id is ignored by
    // Telegram, which previously swallowed the "⛔ Command cancelled" toast.

    if let Some(provider_name) = data.strip_prefix("provider_select:") {
        bot.answer_callback_query(callback_id.clone()).await.ok();
        if let Some(provider) = agent.registry.get_provider(provider_name) {
            if let Some(ref m) = msg {
                let user_id = q.from.id.0.to_string();
                return handle_provider_model_select(
                    bot,
                    m.chat.id,
                    &agent,
                    provider_name,
                    provider,
                    &user_id,
                )
                .await;
            }
        }
        return Ok(());
    }

    if data == "model_search_prompt" {
        bot.answer_callback_query(callback_id.clone()).await.ok();
        if let Some(m) = msg {
            let prompt = "Send me a model name or ID to search for. Examples: claude, kimi, gpt, or a full model ID like openrouter/o3-mini.";
            bot.edit_message_text(m.chat.id, m.id, prompt).await?;
        }
        // Store pending search state for this user.
        let user_id = q.from.id.0.to_string();
        agent
            .memory
            .remember(
                "settings",
                &format!("model_search_pending_{}", user_id),
                "true",
                None,
            )
            .await
            .ok();
        return Ok(());
    }

    if data == "model_select:cancel" {
        bot.answer_callback_query(callback_id.clone()).await.ok();
        if let Some(m) = msg {
            bot.edit_message_text(m.chat.id, m.id, "❌ Model selection cancelled.")
                .await?;
        }
        return Ok(());
    }

    // Handle command cancellation via CancelRegistry
    if let Some(cmd_id) = data.strip_prefix("cancel_cmd:") {
        let text = if agent.cancel_registry.cancel(cmd_id).await {
            "⛔ Command cancelled"
        } else {
            "Command already finished"
        };
        bot.answer_callback_query(callback_id).text(text).await.ok();
        return Ok(());
    }

    if let Some(model_id) = data.strip_prefix("model_select:") {
        match agent.set_model(model_id).await {
            Ok(()) => {
                let reply = format!("✅ Model changed to `{}`", model_id);
                if let Some(m) = msg {
                    bot.edit_message_text(m.chat.id, m.id, &reply).await?;
                }
            }
            Err(e) => {
                let reply = format!("Failed to save model: {:#}", e);
                if let Some(m) = msg {
                    bot.edit_message_text(m.chat.id, m.id, &reply).await?;
                }
            }
        }
    }

    bot.answer_callback_query(callback_id).await.ok();
    Ok(())
}

/// Download a Telegram file to the given directory, creating it if needed.
/// Returns (local_path, detected_mime_type).
async fn download_telegram_file(
    bot: &Bot,
    file_id: &str,
    dest_dir: &Path,
    filename: Option<&str>,
) -> Result<(PathBuf, String)> {
    std::fs::create_dir_all(dest_dir).context("Failed to create temp directory")?;

    let file = bot
        .get_file(file_id.to_string().into())
        .await
        .context("Failed to get file info from Telegram")?;

    let ext = Path::new(&file.path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin");

    let dest_name = match filename {
        Some(n) => n.to_string(),
        None => format!("{}.{}", uuid::Uuid::new_v4(), ext),
    };
    let dest_path = dest_dir.join(&dest_name);

    let mut bytes: Vec<u8> = Vec::new();
    bot.download_file(&file.path, &mut bytes)
        .await
        .context("Failed to download file from Telegram")?;

    std::fs::write(&dest_path, &bytes).context("Failed to write downloaded file")?;

    let mime = infer::get(&bytes)
        .map(|t| t.mime_type().to_string())
        .unwrap_or_else(|| mime_from_extension(ext).to_string());

    Ok((dest_path, mime))
}

/// Classify an attachment based on MIME type and filename extension fallback.
fn classify_attachment_kind(mime_type: &str, file_name: Option<&str>) -> AttachmentKind {
    if mime_type.starts_with("image/") {
        return AttachmentKind::Image;
    }
    if mime_type == "application/pdf" {
        return AttachmentKind::Pdf;
    }
    if mime_type.contains("wordprocessingml") || mime_type == "application/msword" {
        return AttachmentKind::Docx;
    }
    // Fallback: check extension
    let name = file_name.unwrap_or("");
    if name.ends_with(".pdf") {
        return AttachmentKind::Pdf;
    }
    if name.ends_with(".docx") || name.ends_with(".doc") {
        return AttachmentKind::Docx;
    }
    if name.ends_with(".jpg")
        || name.ends_with(".jpeg")
        || name.ends_with(".png")
        || name.ends_with(".gif")
        || name.ends_with(".webp")
    {
        return AttachmentKind::Image;
    }
    AttachmentKind::Other
}

fn mime_from_extension(ext: &str) -> &'static str {
    match ext {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        _ => "application/octet-stream",
    }
}

pub struct TelegramAdapter {
    bot: Bot,
}

impl TelegramAdapter {
    pub fn new(bot: Bot) -> Self {
        Self { bot }
    }
}

#[async_trait]
impl PlatformSender for TelegramAdapter {
    async fn send_message(
        &self,
        chat_id_str: &str,
        text: &str,
        format: PlatformMsgFormat,
    ) -> Result<PlatformMessageId> {
        let chat_id = parse_chat_id(chat_id_str)?;
        let parse_mode = match format {
            PlatformMsgFormat::Markdown | PlatformMsgFormat::Auto => Some(ParseMode::MarkdownV2),
            PlatformMsgFormat::Rich => None,
        };
        let mut req = self.bot.send_message(chat_id, text);
        if let Some(pm) = parse_mode {
            req = req.parse_mode(pm);
        }
        let msg = req.await?;
        Ok(format!("{}:{}", chat_id.0, msg.id.0))
    }

    async fn send_file(
        &self,
        chat_id_str: &str,
        path: &Path,
        caption: Option<&str>,
    ) -> Result<PlatformMessageId> {
        let chat_id = parse_chat_id(chat_id_str)?;
        let input_file = teloxide::types::InputFile::file(path);
        let msg = if let Some(cap) = caption {
            self.bot
                .send_document(chat_id, input_file)
                .caption(cap)
                .await?
        } else {
            self.bot.send_document(chat_id, input_file).await?
        };
        Ok(format!("{}:{}", chat_id.0, msg.id.0))
    }

    async fn show_cancel_button(
        &self,
        chat_id_str: &str,
        text: &str,
        cancel_id: &str,
    ) -> Result<PlatformMessageId> {
        let chat_id = parse_chat_id(chat_id_str)?;
        let keyboard = InlineKeyboardMarkup::new([[InlineKeyboardButton::callback(
            "Cancel",
            format!("cancel_cmd:{cancel_id}"),
        )]]);
        let msg = self
            .bot
            .send_message(chat_id, text)
            .reply_markup(keyboard)
            .await?;
        Ok(format!("{}:{}", chat_id.0, msg.id.0))
    }

    async fn edit_message(
        &self,
        chat_id_str: &str,
        message_id: &PlatformMessageId,
        text: &str,
    ) -> Result<()> {
        let chat_id = parse_chat_id(chat_id_str)?;
        let parts: Vec<&str> = message_id.split(':').collect();
        let msg_id: i32 = parts.get(1).unwrap_or(&"0").parse()?;
        self.bot
            .edit_message_text(chat_id, MessageId(msg_id), text)
            .await?;
        Ok(())
    }

    async fn delete_message(
        &self,
        chat_id_str: &str,
        message_id: &PlatformMessageId,
    ) -> Result<()> {
        let chat_id = parse_chat_id(chat_id_str)?;
        let parts: Vec<&str> = message_id.split(':').collect();
        let Some(msg_id_str) = parts.get(1) else {
            anyhow::bail!("invalid message id format: {message_id}");
        };
        let msg_id: i32 = msg_id_str.parse()?;
        self.bot.delete_message(chat_id, MessageId(msg_id)).await?;
        Ok(())
    }

    async fn notify_shutdown(&self, chat_id_str: &str) -> Result<()> {
        let chat_id = parse_chat_id(chat_id_str)?;
        self.bot
            .send_message(chat_id, "⚠️ Bot is shutting down...")
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_split_stream_at_4000_chars() {
        const TELEGRAM_LIMIT: usize = 3800;
        let short = "a".repeat(100);
        let long = "a".repeat(4000);
        assert!(short.len() < TELEGRAM_LIMIT);
        assert!(long.len() > TELEGRAM_LIMIT);
    }

    #[test]
    fn test_tool_ui_mode_from_memory() {
        use crate::tool_registry::ToolUiMode;
        assert_eq!(
            ToolUiMode::from_memory(Some("verbose")),
            ToolUiMode::Verbose
        );
        assert_eq!(
            ToolUiMode::from_memory(Some("minimal")),
            ToolUiMode::Minimal
        );
        assert_eq!(ToolUiMode::from_memory(Some("silent")), ToolUiMode::Silent);
        // backward compat
        assert_eq!(ToolUiMode::from_memory(Some("true")), ToolUiMode::Verbose);
        // "false" meant no tool UI at all → Silent, not Minimal
        assert_eq!(ToolUiMode::from_memory(Some("false")), ToolUiMode::Silent);
        assert_eq!(ToolUiMode::from_memory(None), ToolUiMode::Minimal);
        // unknown defaults to minimal
        assert_eq!(
            ToolUiMode::from_memory(Some("unknown")),
            ToolUiMode::Minimal
        );
    }

    #[test]
    fn test_tool_ui_mode_cycle() {
        use crate::tool_registry::ToolUiMode;
        assert_eq!(ToolUiMode::Minimal.next(), ToolUiMode::Verbose);
        assert_eq!(ToolUiMode::Verbose.next(), ToolUiMode::Silent);
        assert_eq!(ToolUiMode::Silent.next(), ToolUiMode::Minimal);
    }

    #[test]
    fn parse_supervise_command_extracts_request_text() {
        let parsed = super::parse_command("/supervise summarize the readme");
        assert_eq!(
            parsed,
            Some(("supervise".into(), "summarize the readme".into()))
        );
    }

    #[test]
    fn parse_command_returns_none_for_non_slash_input() {
        assert!(super::parse_command("hello world").is_none());
    }

    #[test]
    fn parse_command_handles_command_without_argument() {
        assert_eq!(
            super::parse_command("/start"),
            Some(("start".into(), "".into()))
        );
    }

    #[test]
    fn parses_all_supervisor_commands() {
        for c in [
            "/tasks",
            "/resume abc",
            "/cancel abc",
            "/approve abc",
            "/clarify abc some text",
        ] {
            assert!(super::parse_command(c).is_some(), "failed: {c}");
        }
    }

    #[test]
    fn test_split_message_empty_response_produces_no_chunks() {
        let chunks = split_message("", 4000);
        assert!(chunks.len() <= 1);
    }

    #[test]
    fn test_split_message_short_stays_intact() {
        let chunks = split_message("hello", 4000);
        assert_eq!(chunks, vec!["hello"]);
    }

    #[test]
    fn test_split_message_long_splits_at_boundary() {
        let text = "a ".repeat(3000); // 6000 chars
        let chunks = split_message(&text, 4000);
        assert_eq!(chunks.len(), 2);
        for chunk in &chunks {
            assert!(chunk.len() <= 4000);
        }
    }

    #[test]
    fn test_final_flush_uses_entity_based_conversion() {
        // The final flush must call markdown_to_entities (entity-based approach) instead of
        // MarkdownV2 parse_mode. This is a source inspection test.
        let source = include_str!("telegram.rs");
        assert!(
            source.contains("markdown_to_entities"),
            "Final flush must call markdown_to_entities for robust formatting"
        );
        assert!(
            source.contains("split_entities"),
            "Final flush must call split_entities for long message handling"
        );
    }

    #[test]
    fn test_command_responses_use_entity_formatting() {
        // Command responses now use send_markdown_message (entity-based) instead of
        // escape_text + ParseMode::MarkdownV2.
        let source = include_str!("telegram.rs");
        assert!(
            source.contains("send_markdown_message"),
            "Command responses must use send_markdown_message for entity-based formatting"
        );
    }

    #[test]
    fn test_stream_handle_does_not_require_placeholder_send() {
        // If the initial send fails, the stream handle must NOT silently swallow
        // all tokens. This test documents that the placeholder approach is fragile;
        // the implementation plan removes it entirely.
        // After the fix, a failed initial-send path no longer exists, so this test
        // verifies the new code compiles correctly without the zero-width-space literal.
        let source = include_str!("telegram.rs");
        // Check that the actual zero-width space character (U+200B) is not used as a
        // placeholder in send_message calls.
        assert!(
            !source.contains('\u{200B}'),
            "Zero-width-space placeholder must be removed from stream_handle"
        );
    }

    #[test]
    fn test_classify_attachment_kind_image_jpeg() {
        assert_eq!(
            classify_attachment_kind("image/jpeg", None),
            AttachmentKind::Image
        );
    }

    #[test]
    fn test_classify_attachment_kind_pdf() {
        assert_eq!(
            classify_attachment_kind("application/pdf", None),
            AttachmentKind::Pdf
        );
    }

    #[test]
    fn test_classify_attachment_kind_docx() {
        assert_eq!(
            classify_attachment_kind(
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                None
            ),
            AttachmentKind::Docx
        );
    }
    #[test]
    fn test_first_token_does_not_inherit_placeholder_msg_id() {
        // The streaming task must seed `current_msg_id` to `None` so the first
        // token is delivered as a NEW message rather than editing the
        // "Thinking..." placeholder. Source-inspection guard against future
        // refactors that re-introduce the seeding behavior.
        //
        // Construct the bad-pattern needle at runtime from pieces so the test
        // body itself never contains the contiguous substring being searched
        // for (otherwise the `contains` check would always trip on this very
        // test's source).
        let source = include_str!("telegram.rs");
        let bad_needle = format!(
            "current_msg_id: Option<teloxide::types::MessageId> = {}",
            "placeholder_msg_id"
        );
        assert!(
            !source.contains(&bad_needle),
            "stream_handle must NOT seed current_msg_id with the placeholder id; first token must be a new message"
        );
        let good_needle = format!(
            "let mut current_msg_id: Option<teloxide::types::MessageId> = {};",
            "None"
        );
        assert!(
            source.contains(&good_needle),
            "stream_handle must initialize current_msg_id to None"
        );
    }

    #[test]
    fn test_classify_attachment_kind_fallback_to_extension() {
        assert_eq!(
            classify_attachment_kind("application/octet-stream", Some("report.pdf")),
            AttachmentKind::Pdf
        );
        assert_eq!(
            classify_attachment_kind("application/octet-stream", Some("letter.docx")),
            AttachmentKind::Docx
        );
        assert_eq!(
            classify_attachment_kind("application/octet-stream", Some("photo.jpg")),
            AttachmentKind::Image
        );
    }

    #[test]
    fn test_placeholder_is_deleted_after_streaming() {
        // The Thinking placeholder must be cleaned up in `handle_message` after
        // `stream_handle.await`, regardless of success/error outcome.
        let source = include_str!("telegram.rs");
        assert!(
            source.contains("Failed to delete thinking placeholder"),
            "handle_message must delete the Thinking placeholder after streaming completes"
        );
    }

    #[test]
    fn test_classify_attachment_kind_unknown() {
        assert_eq!(
            classify_attachment_kind("application/zip", Some("archive.zip")),
            AttachmentKind::Other
        );
    }

    /// The grant commands refuse, grant, list and revoke — end to end through
    /// the handlers the dispatcher calls.
    ///
    /// Each refusal is asserted to start with `Refused:`, not merely to be
    /// non-empty: an implementation that answered "Granted" to `/allow /` would
    /// pass a weaker assertion while handing back the whole filesystem.
    #[tokio::test]
    async fn the_grant_commands_refuse_grant_list_and_revoke() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let sup =
            crate::supervisor::Supervisor::new_for_test(dir.path().into(), memory.connection())
                .with_sandbox_root(dir.path().into());

        // No argument, `/`, and a relative path are three different mistakes,
        // each refused rather than granted.
        for bad in ["", "/", "relative/path"] {
            let reply = allow_command(bad, &actor(), &sup).await;
            assert!(
                reply.starts_with("Refused:"),
                "{bad:?} must be refused, got {reply}"
            );
        }
        // The sandbox root itself is refused too.
        assert!(allow_command(dir.path().to_str().unwrap(), &actor(), &sup)
            .await
            .starts_with("Refused:"));

        assert!(grants_command(&sup).contains("nothing is granted"));

        let reply = allow_command("/usr", &actor(), &sup).await;
        assert!(
            reply.contains("Granted write access to /usr"),
            "got {reply}"
        );
        assert!(
            grants_command(&sup).contains("/usr"),
            "got {}",
            grants_command(&sup)
        );

        let reply = deny_command("/usr", &actor(), &sup).await;
        assert!(
            reply.contains("Revoked write access to /usr"),
            "got {reply}"
        );
        assert!(grants_command(&sup).contains("nothing is granted"));

        // Network is a separate capability, and its reply carries the warning:
        // this is the grant that widens the boundary most.
        let reply = allow_net_command(&actor(), &sup).await;
        assert!(reply.contains("network namespace"), "got {reply}");
        assert!(
            reply.contains("loopback"),
            "the warning must be in the reply: {reply}"
        );
        assert!(grants_command(&sup).contains("network"));

        assert!(deny_net_command(&actor(), &sup).await.contains("Revoked"));
        assert!(grants_command(&sup).contains("nothing is granted"));
    }

    /// A grant writes an audit row, and that row belongs to **no task**.
    ///
    /// This is the assertion the migration exists for: `sup_transitions.task_id`
    /// was `NOT NULL` with a foreign key to `sup_tasks`, so a grant's row had no
    /// legal value and both the insert and the audit were lost. The reply is
    /// checked for `WARNING` as well as the row being checked for existence —
    /// without that, a silently-failing audit would still leave the row absent
    /// and this test would fail for the right reason but name the wrong one.
    #[tokio::test]
    async fn a_grant_writes_an_audit_row_that_belongs_to_no_task() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let conn = memory.connection();
        let sup = crate::supervisor::Supervisor::new_for_test(dir.path().into(), conn.clone())
            .with_sandbox_root(dir.path().into());

        let reply = allow_command("/usr", &actor(), &sup).await;
        assert!(reply.contains("Granted"), "got {reply}");
        assert!(
            !reply.contains("WARNING"),
            "the audit row must have been written: {reply}"
        );

        let conn = conn.lock().await;
        let (task_id, reason, who): (Option<String>, String, String) = conn
            .query_row(
                "SELECT task_id, reason, actor FROM sup_transitions WHERE reason LIKE 'grant write%'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .expect("a grant must leave an audit row");
        assert!(
            task_id.is_none(),
            "a grant belongs to no task, got {task_id:?}"
        );
        assert!(
            reason.contains("/usr"),
            "the row must name the path: {reason}"
        );
        assert_eq!(who, ALLOWED_USER_ID.to_string());
    }

    /// The supervisor refuses to grant at all when it was never told its sandbox
    /// root — the ancestor check is what stops a grant from handing back the
    /// sandbox, so a guessed root would be a guessed containment check.
    #[tokio::test]
    async fn a_grant_is_refused_when_the_sandbox_root_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        // No `with_sandbox_root`.
        let sup =
            crate::supervisor::Supervisor::new_for_test(dir.path().into(), memory.connection());
        let reply = allow_command("/usr", &actor(), &sup).await;
        assert!(
            reply.starts_with("Refused:") && reply.contains("sandbox root"),
            "got {reply}"
        );
    }

    #[test]
    fn test_supported_commands_lists_user_visible_commands() {
        let cmds = supported_commands();
        let names: Vec<&str> = cmds.iter().map(|c| c.command.as_str()).collect();
        for required in &[
            "start",
            "clear",
            "tools",
            "skills",
            "verbose",
            "queryrewrite",
        ] {
            assert!(
                names.contains(required),
                "supported_commands missing /{required}: got {names:?}"
            );
        }
        // Telegram BotCommand names must match `[a-z0-9_]{1,32}`.
        for c in &cmds {
            assert!(
                c.command
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_'),
                "command '{}' contains invalid characters for Telegram BotCommand",
                c.command
            );
            assert!(
                (1..=32).contains(&c.command.len()),
                "command '{}' has invalid length {}",
                c.command,
                c.command.len()
            );
            assert!(
                !c.description.is_empty(),
                "command '{}' is missing a description",
                c.command
            );
        }
    }

    // ── Supervisor commands ─────────────────────────────────────────────────

    use crate::supervisor::task::Task;

    /// The one user id every test authorizes.
    const ALLOWED_USER_ID: u64 = 42;

    /// A chat id deliberately **different** from the user id, so a test that
    /// asserts the recorded origin proves the dispatcher used the chat and not
    /// the user (a private chat's two ids are equal, which hides the bug).
    const ACTOR_CHAT_ID: &str = "1001";

    fn actor() -> SupervisorActor {
        SupervisorActor {
            user_id: ALLOWED_USER_ID,
            chat_id: ACTOR_CHAT_ID.to_string(),
        }
    }

    fn intruder() -> SupervisorActor {
        SupervisorActor {
            user_id: 7,
            chat_id: "7".to_string(),
        }
    }

    /// A value that must never survive into a reply or an audit row.
    ///
    /// Deliberately not secret-shaped itself: the point is that it is *the value
    /// after a credential key*, which is what `supervisor::redact` scrubs. A
    /// literal that already looked like a credential would be scrubbed by any
    /// tooling that reads this file, which would hide the test's own needle.
    const LEAKY_VALUE: &str = "zz9leaky9value";

    /// A `PlatformSender` that records what was sent.
    ///
    /// The dispatcher is only observable through its sender, so this is the
    /// seam every assertion below reads: the reply text, the destination, and
    /// whether anything was sent at all.
    #[derive(Default)]
    struct RecordingSender {
        sent: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl RecordingSender {
        fn texts(&self) -> Vec<String> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .map(|(_, text)| text.clone())
                .collect()
        }

        /// The single reply, asserting there is exactly one.
        fn only_text(&self) -> String {
            let texts = self.texts();
            assert_eq!(texts.len(), 1, "expected exactly one reply, got {texts:?}");
            texts[0].clone()
        }

        fn chats(&self) -> Vec<String> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .map(|(chat, _)| chat.clone())
                .collect()
        }
    }

    #[async_trait]
    impl PlatformSender for RecordingSender {
        async fn send_message(
            &self,
            chat_id: &str,
            text: &str,
            _format: PlatformMsgFormat,
        ) -> Result<PlatformMessageId> {
            self.sent
                .lock()
                .unwrap()
                .push((chat_id.to_string(), text.to_string()));
            Ok(format!("{chat_id}:1"))
        }

        async fn send_file(
            &self,
            _chat_id: &str,
            _path: &Path,
            _caption: Option<&str>,
        ) -> Result<PlatformMessageId> {
            anyhow::bail!("RecordingSender does not send files")
        }

        async fn show_cancel_button(
            &self,
            _chat_id: &str,
            _text: &str,
            _cancel_id: &str,
        ) -> Result<PlatformMessageId> {
            anyhow::bail!("RecordingSender does not send buttons")
        }

        async fn edit_message(
            &self,
            _chat_id: &str,
            _message_id: &PlatformMessageId,
            _text: &str,
        ) -> Result<()> {
            anyhow::bail!("RecordingSender does not edit messages")
        }

        async fn delete_message(
            &self,
            _chat_id: &str,
            _message_id: &PlatformMessageId,
        ) -> Result<()> {
            anyhow::bail!("RecordingSender does not delete messages")
        }

        async fn notify_shutdown(&self, _chat_id: &str) -> Result<()> {
            anyhow::bail!("RecordingSender does not notify shutdown")
        }
    }

    /// An isolated supervisor over an in-memory store and a tempdir for
    /// artifacts — never the user's home, and never the real `haos-green.db`.
    ///
    /// The `TempDir` and `MemoryStore` are returned so the caller keeps them
    /// alive for the length of the test.
    fn test_supervisor() -> (tempfile::TempDir, crate::memory::MemoryStore, Supervisor) {
        let dir = tempfile::tempdir().unwrap();
        let memory = crate::memory::MemoryStore::open_in_memory().unwrap();
        let mut supervisor =
            Supervisor::new_for_test(dir.path().to_path_buf(), memory.connection());
        // Without a backend `execute_now` fails with "backend not found", and
        // every `resume` / `approve` / `clarify` success path would be a fault.
        supervisor
            .register_test_reasoning_backend(|prompt| async move { Ok(format!("ran:{prompt}")) });
        (dir, memory, supervisor)
    }

    /// Drive a fresh task to `state` through legal edges and return its id.
    ///
    /// Written through `record_transition` rather than through `submit`, so no
    /// test depends on a classifier decision or on the policy engine's
    /// thresholds.
    async fn task_in(supervisor: &Supervisor, state: TaskStatus) -> String {
        use TaskStatus::*;
        let task = Task::new("a task", "do the thing");
        supervisor
            .store()
            .create(&task, "telegram", &ALLOWED_USER_ID.to_string(), None)
            .await
            .unwrap();
        let path: &[(TaskStatus, TaskStatus)] = match state {
            Intake => &[],
            Route => &[(Intake, Classify), (Classify, Route)],
            Clarify => &[(Intake, Classify), (Classify, Route), (Route, Clarify)],
            Paused => &[
                (Intake, Classify),
                (Classify, Route),
                (Route, Plan),
                (Plan, Paused),
            ],
            Done => &[
                (Intake, Classify),
                (Classify, Route),
                (Route, Plan),
                (Plan, Execute),
                (Execute, Verify),
                (Verify, Report),
                (Report, Archive),
                (Archive, Done),
            ],
            other => panic!("task_in does not know how to reach {other:?}"),
        };
        for (from, to) in path {
            supervisor
                .store()
                .record_transition(&task.id, from.clone(), to.clone(), "test", None)
                .await
                .unwrap();
        }
        task.id
    }

    /// `(platform, user_id, chat_id)` as persisted in `sup_tasks`.
    async fn task_origin(
        memory: &crate::memory::MemoryStore,
        id: &str,
    ) -> (String, String, Option<String>) {
        let conn = memory.connection();
        let conn = conn.lock().await;
        conn.query_row(
            "SELECT platform, user_id, chat_id FROM sup_tasks WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
    }

    /// The `owner_id` of the live execution-lease row for `id`, or `None`.
    async fn lease_owner(memory: &crate::memory::MemoryStore, id: &str) -> Option<String> {
        let conn = memory.connection();
        let conn = conn.lock().await;
        conn.query_row(
            "SELECT owner_id FROM sup_execution_leases WHERE task_id=?1",
            [id],
            |r| r.get::<_, String>(0),
        )
        .ok()
    }

    /// Dispatch one command as the authorized actor and return whether the
    /// dispatcher claimed it.
    async fn run_command(
        supervisor: &Supervisor,
        sender: &RecordingSender,
        cmd: &str,
        arg: &str,
    ) -> bool {
        dispatch_supervisor_command(cmd, arg, &actor(), &[ALLOWED_USER_ID], supervisor, sender)
            .await
            .unwrap()
    }

    /// The published BotFather menu and the router's match arms must name the
    /// same six commands. This compares the two lists rather than restating
    /// either, so adding a command to one and not the other fails here.
    #[test]
    fn the_published_menu_and_the_router_name_the_same_commands() {
        let mut published: Vec<String> = supervisor_commands()
            .iter()
            .map(|c| c.command.clone())
            .collect();
        let mut routed: Vec<String> = SUPERVISOR_COMMANDS.iter().map(|c| c.to_string()).collect();
        assert!(!published.is_empty());
        published.sort();
        routed.sort();
        assert_eq!(published, routed);

        let all: Vec<String> = supported_commands()
            .iter()
            .map(|c| c.command.clone())
            .collect();
        for name in SUPERVISOR_COMMANDS {
            assert!(
                all.contains(&name.to_string()),
                "supported_commands must publish /{name}: got {all:?}"
            );
        }
    }

    #[tokio::test]
    async fn supervise_creates_a_task_and_records_the_telegram_origin() {
        let (_dir, memory, supervisor) = test_supervisor();
        let sender = RecordingSender::default();

        assert!(run_command(&supervisor, &sender, "supervise", "summarize the readme").await);

        let reply = sender.only_text();
        assert!(
            reply.contains("Supervisor task"),
            "unexpected reply: {reply}"
        );
        assert!(
            reply.chars().count() <= MAX_SUPERVISOR_REPLY_CHARS,
            "reply must be bounded: {reply}"
        );
        assert_eq!(sender.chats(), vec![ACTOR_CHAT_ID.to_string()]);

        let tasks = supervisor.store().list_recent(10).await.unwrap();
        assert_eq!(tasks.len(), 1, "supervise must create exactly one task");
        assert!(
            reply.contains(&tasks[0].id),
            "the reply must name the task: {reply}"
        );
        // Nothing runs on `/supervise`, so the reply must name the command that
        // does. "summarize the readme" is `GeneralAssistant`/`Low`, which the
        // default policy auto-executes — and `submit` still parks it in `Route`.
        assert_eq!(
            supervisor.state(&tasks[0].id).await.unwrap(),
            TaskStatus::Route
        );
        assert!(
            reply.contains(&format!("/approve {}", tasks[0].id)),
            "the reply must name the next step: {reply}"
        );

        // The origin is the actor, and the chat is the actor's chat — not the
        // user id, which this test deliberately made different.
        let (platform, user_id, chat_id) = task_origin(&memory, &tasks[0].id).await;
        assert_eq!(platform, "telegram");
        assert_eq!(user_id, ALLOWED_USER_ID.to_string());
        assert_eq!(chat_id.as_deref(), Some(ACTOR_CHAT_ID));
    }

    /// The ambiguous path end to end: "do the thing" is `Unknown`/`Low`, which
    /// the default policy routes to `Clarify`, and the reply must hand the user
    /// the `/clarify` command rather than leaving the task parked silently.
    #[tokio::test]
    async fn supervise_names_the_clarify_command_for_an_ambiguous_request() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let sender = RecordingSender::default();

        assert!(run_command(&supervisor, &sender, "supervise", "do the thing").await);
        let reply = sender.only_text();

        let tasks = supervisor.store().list_recent(10).await.unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(
            supervisor.state(&tasks[0].id).await.unwrap(),
            TaskStatus::Clarify,
            "the premise: an ambiguous request is parked in Clarify"
        );
        assert!(
            reply.contains(&format!("/clarify {}", tasks[0].id)),
            "the reply must name /clarify: {reply}"
        );
        assert!(
            reply.contains("CLARIFY"),
            "the reply must name the state: {reply}"
        );
        assert!(
            reply.chars().count() <= MAX_SUPERVISOR_REPLY_CHARS,
            "the reply must be bounded: {reply}"
        );
    }

    /// Every `SubmitOutcome` variant names the command that moves the task on.
    ///
    /// The three variants are constructed here rather than driven through
    /// `submit`, because `NeedsApproval` is unreachable with the default policy
    /// thresholds the test supervisor uses (the heuristic classifier never emits
    /// `High` risk) — and the point of this test is the reply for each variant,
    /// not how a variant is reached. The two reachable variants are covered end
    /// to end by the tests above.
    #[test]
    fn every_submit_outcome_names_the_command_that_moves_it_forward() {
        let cases = [
            (
                SubmitOutcome::AutoExecutePlanned {
                    task_id: "t-1".into(),
                },
                "/approve t-1",
            ),
            (
                SubmitOutcome::NeedsClarification {
                    task_id: "t-2".into(),
                    question: "which parser?".into(),
                },
                "/clarify t-2",
            ),
            (
                SubmitOutcome::NeedsApproval {
                    task_id: "t-3".into(),
                    reason: "high-risk task requires approval".into(),
                },
                "/approve t-3",
            ),
        ];

        for (outcome, command) in cases {
            let reply = submit_reply(&outcome, "ROUTE");
            assert!(
                reply.contains(command),
                "the reply for {outcome:?} must name `{command}`: {reply}"
            );
            assert!(
                reply.contains(&outcome.task_id()),
                "the reply must name the task: {reply}"
            );
            assert!(
                reply.contains("ROUTE"),
                "the reply must name the state: {reply}"
            );
            assert!(
                reply.chars().count() <= MAX_SUPERVISOR_REPLY_CHARS,
                "the reply must be bounded: {reply}"
            );
            assert!(
                !reply.contains("anyhow") && !reply.contains("/home/"),
                "the reply must not carry a chain or a path: {reply}"
            );
        }

        // The approval variant also offers the way out, because `submit` funnels
        // `UseFallbackBackend` and `StopAndReport` policy decisions into it and
        // the dispatcher cannot tell which one it is holding.
        let reply = submit_reply(
            &SubmitOutcome::NeedsApproval {
                task_id: "t-4".into(),
                reason: "StopAndReport(\"nothing to do\")".into(),
            },
            "ROUTE",
        );
        assert!(reply.contains("/cancel t-4"), "got {reply}");
        assert!(reply.contains("StopAndReport"), "got {reply}");
    }

    /// Why [`bounded_reply`] exists even though no reachable reply is long.
    ///
    /// Every reply the dispatcher composes from the store is built from capped
    /// parts, so `bounded_reply` cannot fire on those paths and deleting its call
    /// from `dispatch_supervisor_command` leaves the suite green. This test pins
    /// the one input that is *not* capped by the dispatcher — a `SubmitOutcome`'s
    /// `question`/`reason`, which is policy text — and shows both halves: the raw
    /// reply really does overflow Telegram's budget, and the composition the
    /// dispatcher applies (`bounded_reply(&redact(reply))`) brings it back inside
    /// it. It is deliberately a unit test over the reply builders: the policy the
    /// test supervisor uses cannot emit long text, so the dispatcher line itself
    /// is not drivable today, and this is the closest honest pin.
    #[test]
    fn a_long_submit_outcome_would_overflow_the_reply_budget() {
        let outcome = SubmitOutcome::NeedsClarification {
            task_id: "t-long".into(),
            question: "why? ".repeat(1000),
        };
        let raw = submit_reply(&outcome, "CLARIFY");
        assert!(
            raw.chars().count() > MAX_SUPERVISOR_REPLY_CHARS,
            "an uncapped question must be able to overflow the budget, got {}",
            raw.chars().count()
        );

        let sent = bounded_reply(&crate::supervisor::redact::redact(&raw));
        assert!(
            sent.chars().count() <= MAX_SUPERVISOR_REPLY_CHARS,
            "the dispatcher's composition must clip it, got {}",
            sent.chars().count()
        );
        assert!(
            sent.ends_with("…(truncated)"),
            "the clipped reply must say so: {}",
            &sent[sent.len().saturating_sub(40)..]
        );
    }

    #[tokio::test]
    async fn tasks_lists_each_id_with_its_state_and_caps_the_listing() {
        let (_dir, _memory, supervisor) = test_supervisor();
        for _ in 0..(MAX_TASKS_LISTED + 5) {
            let task = Task::new("a task", "req");
            supervisor
                .store()
                .create(&task, "telegram", "42", None)
                .await
                .unwrap();
        }

        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "tasks", "").await);
        let reply = sender.only_text();

        let lines: Vec<&str> = reply.lines().collect();
        assert_eq!(
            lines.len(),
            MAX_TASKS_LISTED + 1,
            "one header plus at most MAX_TASKS_LISTED rows: {reply}"
        );
        // Every row shows an id and a state, and the listing stops short of the
        // store's 20-task ceiling.
        let listed: Vec<String> = supervisor
            .store()
            .list_recent(MAX_TASKS_LISTED)
            .await
            .unwrap()
            .iter()
            .map(|t| t.id.clone())
            .collect();
        for (row, id) in lines[1..].iter().zip(listed.iter()) {
            assert!(row.contains(id.as_str()), "row must carry its id: {row}");
            assert!(row.contains("INTAKE"), "row must carry its state: {row}");
        }
        assert!(
            reply.chars().count() <= MAX_SUPERVISOR_REPLY_CHARS,
            "the listing must stay inside the reply budget: {}",
            reply.chars().count()
        );
    }

    /// A store row whose title is far longer than `IntakeRouter::normalize`
    /// would ever produce. The title cap is 80 characters at intake; this
    /// exercises the *display* cap, which must hold for any row the store holds
    /// rather than only for rows this process wrote.
    ///
    /// The two caps compose: [`MAX_TASKS_LISTED`] rows of
    /// [`MAX_TASK_TITLE_CHARS`] titles fit inside
    /// [`MAX_SUPERVISOR_REPLY_CHARS`] with room to spare, so a `/tasks` reply is
    /// never truncated at all — the outcome requirement 5 asks for.
    ///
    /// # `bounded_reply` is a backstop, not a guard on a live path
    ///
    /// Every reply this dispatcher can currently build is composed only of
    /// capped parts: task ids at most [`MAX_TASK_ID_CHARS`], titles at most
    /// [`MAX_TASK_TITLE_CHARS`] after redaction, [`MAX_TASKS_LISTED`] rows, a
    /// fixed fault sentence, and the fixed usage/refusal sentences. The largest
    /// reachable reply is therefore well inside
    /// [`MAX_SUPERVISOR_REPLY_CHARS`], which means the `bounded_reply` call in
    /// `dispatch_supervisor_command` cannot fire today and no test can drive a
    /// real reply past the budget — deleting that call leaves the suite green.
    /// It is kept because it is the only thing standing between a future reply
    /// and Telegram's 4096-character limit: the one unbounded input is a
    /// `SubmitOutcome`'s `question`/`reason`, which
    /// `a_long_submit_outcome_would_overflow_the_reply_budget` shows does exceed
    /// the budget when it is long, and which only policy text currently keeps
    /// short. If a later change removes one of the caps above, that test is the
    /// one that fails first.
    #[tokio::test]
    async fn a_full_listing_with_maximal_titles_stays_inside_the_reply_budget() {
        let (_dir, _memory, supervisor) = test_supervisor();
        for n in 0..MAX_TASKS_LISTED {
            let task = Task::new(&format!("task {n} {}", "x".repeat(600)), "req");
            supervisor
                .store()
                .create(&task, "telegram", "42", None)
                .await
                .unwrap();
        }

        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "tasks", "").await);
        let reply = sender.only_text();

        assert!(
            reply.chars().count() <= MAX_SUPERVISOR_REPLY_CHARS,
            "a full listing must fit the budget, got {} characters",
            reply.chars().count()
        );
        assert!(
            !reply.ends_with("…(truncated)"),
            "a full listing must not need truncating: {reply}"
        );
        assert_eq!(
            reply.lines().count(),
            MAX_TASKS_LISTED + 1,
            "every listed task must be shown in full"
        );
        // Each row carries a bounded title, so no row is unbounded. The row is
        // `- {id}  {state}  {title}`; the id is a UUID and the state name is at
        // most `PREPAREWORKSPACE`.
        let row_budget = 2 + MAX_TASK_ID_CHARS + 2 + 20 + 2 + MAX_TASK_TITLE_CHARS + 1;
        for row in reply.lines().skip(1) {
            assert!(
                row.chars().count() <= row_budget,
                "row is too long ({} > {row_budget}): {row}",
                row.chars().count()
            );
        }
    }

    #[tokio::test]
    async fn resume_runs_a_paused_task_and_releases_its_lease() {
        let (_dir, memory, supervisor) = test_supervisor();
        let id = task_in(&supervisor, TaskStatus::Paused).await;

        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "resume", &id).await);
        let reply = sender.only_text();
        assert!(reply.contains("resumed"), "unexpected reply: {reply}");
        assert!(reply.contains(&id), "the reply must name the task: {reply}");

        assert_eq!(supervisor.state(&id).await.unwrap(), TaskStatus::Done);
        let trail = supervisor.store().transitions(&id).await.unwrap();
        assert!(
            trail
                .iter()
                .any(|r| r.from == TaskStatus::Paused && r.to == TaskStatus::Execute),
            "resume must record Paused -> Execute, got {trail:?}"
        );
        // `execute_now` released its execution lease on the normal path.
        assert!(lease_owner(&memory, &id).await.is_none());
    }

    #[tokio::test]
    async fn cancel_marks_a_pending_task_cancelled() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let id = task_in(&supervisor, TaskStatus::Route).await;

        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "cancel", &id).await);
        let reply = sender.only_text();
        assert!(reply.contains("cancelled"), "unexpected reply: {reply}");

        assert_eq!(supervisor.state(&id).await.unwrap(), TaskStatus::Cancelled);
    }

    #[tokio::test]
    async fn approve_runs_a_task_awaiting_approval() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let id = task_in(&supervisor, TaskStatus::Route).await;

        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "approve", &id).await);
        let reply = sender.only_text();
        assert!(reply.contains("approved"), "unexpected reply: {reply}");

        assert_eq!(supervisor.state(&id).await.unwrap(), TaskStatus::Done);
        let trail = supervisor.store().transitions(&id).await.unwrap();
        assert!(
            trail
                .iter()
                .any(|r| r.from == TaskStatus::Route && r.to == TaskStatus::Execute),
            "approve must record Route -> Execute, got {trail:?}"
        );
    }

    #[tokio::test]
    async fn clarify_records_the_reason_and_resumes_a_clarify_task() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let id = task_in(&supervisor, TaskStatus::Clarify).await;

        let sender = RecordingSender::default();
        assert!(
            run_command(
                &supervisor,
                &sender,
                "clarify",
                &format!("{id} it is about the parser")
            )
            .await
        );
        let reply = sender.only_text();
        assert!(
            reply.contains("Clarification recorded"),
            "unexpected reply: {reply}"
        );

        assert_eq!(supervisor.state(&id).await.unwrap(), TaskStatus::Done);
        let trail = supervisor.store().transitions(&id).await.unwrap();
        let row = trail
            .iter()
            .find(|r| r.from == TaskStatus::Clarify && r.to == TaskStatus::Execute)
            .expect("clarify must record Clarify -> Execute");
        assert_eq!(row.reason.as_deref(), Some("it is about the parser"));
    }

    /// The half of `/clarify` that matters most: a task that is **not** in
    /// `Clarify` is refused without running anything. Without the exact-state
    /// gate, `/clarify` would be an approval in disguise for a task parked in
    /// `Route`.
    #[tokio::test]
    async fn clarify_refuses_a_task_that_is_not_in_clarify() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let id = task_in(&supervisor, TaskStatus::Route).await;
        let before = supervisor.store().transitions(&id).await.unwrap().len();

        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "clarify", &format!("{id} just do it")).await);
        let reply = sender.only_text();
        assert!(
            reply.contains("CLARIFY") && reply.contains("ROUTE"),
            "the conflict must name the real state: {reply}"
        );

        assert_eq!(supervisor.state(&id).await.unwrap(), TaskStatus::Route);
        assert_eq!(
            supervisor.store().transitions(&id).await.unwrap().len(),
            before,
            "a refused clarify must write nothing"
        );
    }

    /// A `Done` task is refused by every lifecycle command, and each refusal
    /// names the state — so a user can tell "wrong state" from "no such task".
    #[tokio::test]
    async fn a_finished_task_is_refused_by_every_lifecycle_command() {
        let (_dir, _memory, supervisor) = test_supervisor();
        for cmd in ["resume", "cancel", "approve"] {
            let id = task_in(&supervisor, TaskStatus::Done).await;
            let before = supervisor.store().transitions(&id).await.unwrap().len();

            let sender = RecordingSender::default();
            assert!(run_command(&supervisor, &sender, cmd, &id).await);
            let reply = sender.only_text();
            assert!(
                reply.contains("DONE"),
                "/{cmd} must name the state, got {reply}"
            );
            assert_eq!(supervisor.state(&id).await.unwrap(), TaskStatus::Done);
            assert_eq!(
                supervisor.store().transitions(&id).await.unwrap().len(),
                before,
                "/{cmd} must not write on a refusal"
            );
        }
    }

    #[tokio::test]
    async fn a_second_cancel_of_a_cancelled_task_writes_nothing_extra() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let id = task_in(&supervisor, TaskStatus::Route).await;

        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "cancel", &id).await);
        let after_first = supervisor.store().transitions(&id).await.unwrap().len();

        assert!(run_command(&supervisor, &sender, "cancel", &id).await);
        let texts = sender.texts();
        assert_eq!(texts.len(), 2, "one reply per invocation: {texts:?}");
        assert!(
            texts[1].contains("CANCELLED"),
            "the second cancel is a conflict: {}",
            texts[1]
        );
        assert_eq!(
            supervisor.store().transitions(&id).await.unwrap().len(),
            after_first,
            "a refused cancel must not add an audit row"
        );
    }

    #[tokio::test]
    async fn an_unauthorized_user_gets_no_supervisor_action_and_no_reply() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let id = task_in(&supervisor, TaskStatus::Route).await;
        let before = supervisor.store().transitions(&id).await.unwrap().len();
        let sender = RecordingSender::default();

        for (cmd, arg) in [
            ("supervise", "exfiltrate the config"),
            ("tasks", ""),
            ("resume", id.as_str()),
            ("cancel", id.as_str()),
            ("approve", id.as_str()),
            ("clarify", "some-id answer"),
        ] {
            let handled = dispatch_supervisor_command(
                cmd,
                arg,
                &intruder(),
                &[ALLOWED_USER_ID],
                &supervisor,
                &sender,
            )
            .await
            .unwrap();
            assert!(
                handled,
                "/{cmd} must still be claimed as a supervisor command"
            );
        }

        assert!(
            sender.texts().is_empty(),
            "an unauthorized user must receive nothing at all: {:?}",
            sender.texts()
        );
        assert_eq!(
            supervisor.store().list_recent(10).await.unwrap().len(),
            1,
            "no task may have been submitted"
        );
        assert_eq!(supervisor.state(&id).await.unwrap(), TaskStatus::Route);
        assert_eq!(
            supervisor.store().transitions(&id).await.unwrap().len(),
            before
        );
    }

    #[tokio::test]
    async fn missing_arguments_and_malformed_ids_are_refused_with_a_bounded_reply() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let long_id = "a".repeat(MAX_TASK_ID_CHARS + 1);

        for (cmd, arg, needle) in [
            ("supervise", "", "Usage: /supervise"),
            ("supervise", "   \n  ", "Usage: /supervise"),
            ("resume", "", "Usage: /resume"),
            ("cancel", "", "Usage: /cancel"),
            ("approve", "", "Usage: /approve"),
            ("clarify", "", "Usage: /clarify"),
            ("clarify", "abc", "Usage: /clarify"),
            ("clarify", "abc   ", "Usage: /clarify"),
            ("resume", "../../etc/passwd", INVALID_TASK_ID),
            ("cancel", "id;rm -rf /", INVALID_TASK_ID),
            ("approve", "with space", INVALID_TASK_ID),
            ("resume", long_id.as_str(), INVALID_TASK_ID),
            ("clarify", "../../etc/passwd answer", INVALID_TASK_ID),
        ] {
            let sender = RecordingSender::default();
            assert!(run_command(&supervisor, &sender, cmd, arg).await);
            let reply = sender.only_text();
            assert!(
                reply.starts_with(needle),
                "/{cmd} {arg:?} answered {reply:?}, expected it to start with {needle:?}"
            );
            assert!(
                reply.chars().count() < 200,
                "/{cmd} must answer concisely, got {reply:?}"
            );
            assert!(
                !reply.contains(&long_id),
                "/{cmd} must not echo an oversized id"
            );
        }

        assert!(
            supervisor.store().list_recent(10).await.unwrap().is_empty(),
            "no malformed invocation may reach the supervisor"
        );
    }

    #[tokio::test]
    async fn oversized_text_is_refused_without_echoing_it() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let too_long = "s".repeat(MAX_SUPERVISE_TEXT_CHARS + 1);

        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "supervise", &too_long).await);
        let reply = sender.only_text();
        assert!(
            reply.contains(&MAX_SUPERVISE_TEXT_CHARS.to_string()),
            "the refusal must state the limit: {reply}"
        );
        assert!(
            !reply.contains("ssssss"),
            "the refusal must not echo the text: {reply}"
        );
        assert!(reply.chars().count() <= MAX_SUPERVISOR_REPLY_CHARS);
        assert!(supervisor.store().list_recent(10).await.unwrap().is_empty());

        // `/clarify` carries the same bound.
        let id = task_in(&supervisor, TaskStatus::Clarify).await;
        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "clarify", &format!("{id} {too_long}")).await);
        let reply = sender.only_text();
        assert!(!reply.contains("ssssss"), "got {reply}");
        assert_eq!(
            supervisor.state(&id).await.unwrap(),
            TaskStatus::Clarify,
            "an oversized answer must not resume the task"
        );
    }

    /// The boundary itself: exactly the limit is accepted, one character more is
    /// not.
    #[tokio::test]
    async fn text_at_exactly_the_limit_is_accepted() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let at_limit = "s".repeat(MAX_SUPERVISE_TEXT_CHARS);

        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "supervise", &at_limit).await);
        assert!(
            sender.only_text().contains("Supervisor task"),
            "text at the limit must be accepted"
        );
        assert_eq!(supervisor.store().list_recent(10).await.unwrap().len(), 1);
    }

    /// Not-found, conflict and fault are three different sentences. A user who
    /// cannot tell them apart cannot tell a typo from a race from a broken
    /// deployment.
    #[tokio::test]
    async fn not_found_conflict_and_fault_are_three_different_answers() {
        let (_dir, _memory, supervisor) = test_supervisor();

        let sender = RecordingSender::default();
        assert!(
            run_command(
                &supervisor,
                &sender,
                "resume",
                "0f1c2d3e-0000-4000-8000-000000000000"
            )
            .await
        );
        let missing = sender.only_text();
        assert!(
            missing.starts_with("No supervisor task with id"),
            "{missing}"
        );

        let id = task_in(&supervisor, TaskStatus::Done).await;
        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "resume", &id).await);
        let conflict = sender.only_text();
        assert!(conflict.starts_with("Cannot resume"), "{conflict}");

        let fault = fault(
            "read a supervisor task",
            &anyhow::anyhow!("no such table: sup_tasks at /home/op/.haos-green/haos-green.db"),
        );
        assert_eq!(fault, SUPERVISOR_FAULT);

        assert_ne!(missing, conflict);
        assert_ne!(missing, fault);
        assert_ne!(conflict, fault);
        // The fault is a fixed sentence: no error chain, no path.
        assert!(!fault.contains("sup_tasks"), "{fault}");
        assert!(!fault.contains("/home/op"), "{fault}");
        assert!(!fault.contains(".db"), "{fault}");
    }

    /// Task text is user-supplied and lands in a reply, so it goes through
    /// `supervisor::redact` — the same scrubber every artifact write uses.
    #[tokio::test]
    async fn task_text_in_a_reply_is_redacted() {
        let (_dir, _memory, supervisor) = test_supervisor();
        // Assembled at runtime, so the contiguous `key=value` spelling never
        // appears in this file's source: a future grep for the needle must not
        // trip on the test that defines it.
        let title = format!("deploy with {}={} now", "api_key", LEAKY_VALUE);
        let task = Task::new(&title, "req");
        supervisor
            .store()
            .create(&task, "telegram", "42", None)
            .await
            .unwrap();

        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "tasks", "").await);
        let reply = sender.only_text();
        assert!(
            !reply.contains(LEAKY_VALUE),
            "a credential-shaped value must be redacted: {reply}"
        );
        assert!(reply.contains(&task.id), "the id is still listed: {reply}");
    }

    /// The clarification text is free text a human typed, and
    /// `record_transition` stores the reason verbatim — so it is redacted
    /// before it reaches the audit row.
    #[tokio::test]
    async fn a_clarification_answer_is_redacted_before_it_is_recorded() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let id = task_in(&supervisor, TaskStatus::Clarify).await;

        let sender = RecordingSender::default();
        let answer = format!("{id} {}={}", "token", LEAKY_VALUE);
        assert!(run_command(&supervisor, &sender, "clarify", &answer).await);

        let trail = supervisor.store().transitions(&id).await.unwrap();
        let row = trail
            .iter()
            .find(|r| r.from == TaskStatus::Clarify && r.to == TaskStatus::Execute)
            .expect("clarify must record Clarify -> Execute");
        assert!(
            !row.reason
                .as_deref()
                .unwrap_or_default()
                .contains(LEAKY_VALUE),
            "the audit reason must be redacted: {:?}",
            row.reason
        );
    }

    /// Extra whitespace is normal input, not a malformed argument: Telegram
    /// users type it, and `parse_command` already trims the outer edges.
    #[tokio::test]
    async fn surrounding_whitespace_is_tolerated() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let id = task_in(&supervisor, TaskStatus::Route).await;

        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "cancel", &format!("   {id}   ")).await);
        assert_eq!(supervisor.state(&id).await.unwrap(), TaskStatus::Cancelled);

        let sender = RecordingSender::default();
        assert!(run_command(&supervisor, &sender, "supervise", "  trim   me  ").await);
        assert!(sender.only_text().contains("Supervisor task"));
    }

    /// The dispatcher is transparent to every other command: it answers
    /// `false` and sends nothing, so `handle_message` falls through to the
    /// branches that own them.
    #[tokio::test]
    async fn every_other_command_falls_through_untouched() {
        let (_dir, _memory, supervisor) = test_supervisor();
        let sender = RecordingSender::default();

        for (cmd, arg) in [
            ("start", ""),
            ("clear", ""),
            ("tools", ""),
            ("models", "claude"),
            ("selfupgrade", "main"),
            ("stop", ""),
            ("supervis", "typo"),
            ("", ""),
        ] {
            assert!(
                !run_command(&supervisor, &sender, cmd, arg).await,
                "/{cmd} must not be claimed by the supervisor dispatcher"
            );
        }
        assert!(sender.texts().is_empty());
    }

    #[test]
    fn bounded_reply_keeps_short_text_and_cuts_long_text_on_a_line() {
        assert_eq!(bounded_reply("short"), "short");

        // Each row is a distinct whole line, so a cut that lands mid-row is
        // visible rather than merely shorter.
        let rows: Vec<String> = (0..200)
            .map(|n| format!("- row {n} {}", "y".repeat(60)))
            .collect();
        let long = rows.join("\n");
        assert!(
            long.chars().count() > MAX_SUPERVISOR_REPLY_CHARS * 2,
            "the fixture must be well over the budget, got {}",
            long.chars().count()
        );

        let bounded = bounded_reply(&long);
        assert!(bounded.ends_with("…(truncated)"), "{bounded}");
        let kept = bounded.trim_end_matches("…(truncated)");
        assert!(
            kept.chars().count() <= MAX_SUPERVISOR_REPLY_CHARS,
            "the kept part must fit the budget, got {}",
            kept.chars().count()
        );
        assert!(!kept.is_empty());
        for line in kept.lines().filter(|line| !line.is_empty()) {
            assert!(
                rows.contains(&line.to_string()),
                "whole rows only: {line:?}"
            );
        }
        // Multi-byte input must not panic and must not split a character.
        let accented = "é".repeat(MAX_SUPERVISOR_REPLY_CHARS * 2);
        let bounded = bounded_reply(&accented);
        assert!(bounded.ends_with("…(truncated)"));
        assert!(bounded.starts_with('é'));
    }

    #[test]
    fn truncate_chars_counts_characters_not_bytes() {
        assert_eq!(truncate_chars("abc", 5), "abc");
        // Multi-byte input must not panic and must not split a character.
        let accented = "é".repeat(10);
        let cut = truncate_chars(&accented, 4);
        assert_eq!(cut.chars().count(), 5);
        assert!(cut.starts_with("éééé"));
    }

    #[test]
    fn state_name_uses_the_persisted_spelling() {
        assert_eq!(state_name(&TaskStatus::Clarify), "CLARIFY");
        assert_eq!(
            state_name(&TaskStatus::PrepareWorkspace),
            "PREPAREWORKSPACE"
        );
        assert_eq!(state_name(&TaskStatus::Done), "DONE");
    }

    #[test]
    fn validated_task_id_accepts_uuids_and_refuses_everything_else() {
        let uuid = "0f1c2d3e-4a5b-4c6d-8e9f-0a1b2c3d4e5f";
        assert_eq!(validated_task_id(uuid), Some(uuid));
        assert_eq!(validated_task_id(&format!("  {uuid}  ")), Some(uuid));
        assert_eq!(validated_task_id(""), None);
        assert_eq!(validated_task_id("   "), None);
        assert_eq!(validated_task_id("with space"), None);
        assert_eq!(validated_task_id("../etc/passwd"), None);
        assert_eq!(validated_task_id("id\nmore"), None);
        assert_eq!(validated_task_id("id@mention"), None);
        assert_eq!(validated_task_id(&"a".repeat(MAX_TASK_ID_CHARS + 1)), None);
        assert_eq!(
            validated_task_id(&"a".repeat(MAX_TASK_ID_CHARS)),
            Some("a".repeat(MAX_TASK_ID_CHARS).as_str())
        );
    }
}
