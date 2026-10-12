use anyhow::Context;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::process::Command as TokioCommand;
use tracing::warn;

use crate::cancel_registry::CancelRegistry;
use crate::llm::{FunctionDefinition, ToolDefinition};
use crate::platform::sender::PlatformSender;
use crate::tool_registry::{ToolContext, ToolHandler, ToolResult, ToolUiMode};

/// Guard that ensures the child process and its entire process group are killed
/// if dropped (e.g. on error, cancellation, panic, or transport drop).
struct ProcessGroupGuard {
    #[cfg(unix)]
    pgid: Option<i32>,
    disarmed: bool,
}

impl ProcessGroupGuard {
    fn new(child: &tokio::process::Child) -> Self {
        #[cfg(unix)]
        let pgid = child.id().map(|id| id as i32);
        Self {
            #[cfg(unix)]
            pgid,
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }

    fn kill(&mut self) {
        if self.disarmed {
            return;
        }
        self.disarmed = true;
        #[cfg(unix)]
        if let Some(pgid) = self.pgid {
            let _ = nix::sys::signal::killpg(
                nix::unistd::Pid::from_raw(pgid),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        self.kill();
    }
}

/// Controls how command execution messages are sent to Telegram.
enum SendMode {
    /// Full live output with cancel button.
    Verbose,
    /// Cancel button only, no live edits. Message deleted on completion.
    Minimal,
    /// No message sent. Tool notifier handles nothing (silent mode).
    Silent,
}

pub struct CommandTool {
    sandbox_dir: PathBuf,
    cancel_registry: Arc<CancelRegistry>,
    sender: Arc<dyn PlatformSender>,
}

impl CommandTool {
    pub fn new(
        sandbox_dir: PathBuf,
        cancel_registry: Arc<CancelRegistry>,
        sender: Arc<dyn PlatformSender>,
    ) -> Self {
        Self {
            sandbox_dir,
            cancel_registry,
            sender,
        }
    }
}

#[async_trait]
impl ToolHandler for CommandTool {
    fn define(&self) -> Vec<ToolDefinition> {
        vec![ToolDefinition {
            tool_type: "function".to_string(),
            function: FunctionDefinition {
                name: "execute_command".to_string(),
                description: "Execute a shell command within the sandbox directory.".to_string(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "command": { "type": "string", "description": "The shell command to execute" }
                    },
                    "required": ["command"]
                }),
            },
        }]
    }

    async fn execute(&self, name: &str, args: Value, ctx: ToolContext) -> ToolResult {
        match name {
            "execute_command" => self.exec_command(&args, &ctx).await,
            _ => anyhow::bail!("CommandTool: unknown tool {name}"),
        }
    }
}

impl CommandTool {
    async fn exec_command(&self, arguments: &Value, ctx: &ToolContext) -> ToolResult {
        let command = arguments["command"]
            .as_str()
            .context("Missing 'command' argument")?;
        let cmd_id = format!("cmd_{}", uuid::Uuid::new_v4());

        let mut cmd = TokioCommand::new(if cfg!(windows) { "cmd" } else { "sh" });
        cmd.arg(if cfg!(windows) { "/C" } else { "-c" })
            .arg(command)
            .current_dir(&self.sandbox_dir)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd.spawn()?;

        // Process group guard ensures that if any setup fails (like show_cancel_button),
        // or if a panic or unexpected error occurs, the child process and its tree are killed.
        let mut pg_guard = ProcessGroupGuard::new(&child);

        let escaped_cmd = crate::utils::telegram_markdown::escape_text(command);

        // Verbose: cancel button + live output + final result
        // Minimal: cancel button (simple text) + no live output, delete on finish
        // Silent: no message at all (tool_notifier handles nothing)
        // If chat_id is empty or invalid, fallback to Silent mode rather than failing after spawn.
        let is_valid_chat = !ctx.chat_id.trim().is_empty();
        let effective_mode = if is_valid_chat {
            ctx.tool_ui_mode
        } else {
            ToolUiMode::Silent
        };

        let (msg_id, send_mode) = match effective_mode {
            ToolUiMode::Verbose => {
                let status_text =
                    format!("💻 Running: `{}`\n\n```\n⏳ Starting...\n```", escaped_cmd);
                match self
                    .sender
                    .show_cancel_button(&ctx.chat_id, &status_text, &cmd_id)
                    .await
                {
                    Ok(id) => (Some(id), SendMode::Verbose),
                    Err(e) => {
                        warn!("Failed to show cancel button: {e}; falling back to silent");
                        (None, SendMode::Silent)
                    }
                }
            }
            ToolUiMode::Minimal => {
                let status_text = format!("⏳ Running: `{}`", escaped_cmd);
                match self
                    .sender
                    .show_cancel_button(&ctx.chat_id, &status_text, &cmd_id)
                    .await
                {
                    Ok(id) => (Some(id), SendMode::Minimal),
                    Err(e) => {
                        warn!("Failed to show cancel button: {e}; falling back to silent");
                        (None, SendMode::Silent)
                    }
                }
            }
            ToolUiMode::Silent => (None, SendMode::Silent),
        };

        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
        self.cancel_registry
            .register(cmd_id.clone(), cancel_tx)
            .await;

        let (output_tx, mut output_rx) = tokio::sync::mpsc::channel::<String>(256);
        let output_tx2 = output_tx.clone();
        let mut child_stdout = child.stdout.take();
        let mut child_stderr = child.stderr.take();

        let stdout_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Some(stream) = child_stdout.as_mut() {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = output_tx
                            .send(String::from_utf8_lossy(&buf[..n]).to_string())
                            .await;
                    }
                }
            }
        });

        let stderr_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Some(stream) = child_stderr.as_mut() {
                match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let _ = output_tx2
                            .send(String::from_utf8_lossy(&buf[..n]).to_string())
                            .await;
                    }
                }
            }
        });

        const MAX_BUFFER_CHARS: usize = 100_000;
        let mut output_buffer = String::new();
        let mut last_edit = Instant::now();
        let mut exit_code: Option<i32> = None;
        let mut cancelled = false;
        tokio::pin!(cancel_rx);

        loop {
            tokio::select! {
                Some(chunk) = output_rx.recv() => {
                    output_buffer.push_str(&chunk);
                    if output_buffer.chars().count() > MAX_BUFFER_CHARS {
                        output_buffer = crate::utils::strings::truncate_tail(&output_buffer, MAX_BUFFER_CHARS);
                    }
                    if matches!(send_mode, SendMode::Verbose) && last_edit.elapsed() >= std::time::Duration::from_millis(500) {
                        let capped = crate::utils::strings::truncate_tail(&output_buffer, 3500);
                        let text = format!("💻 Running: `{}`\n\n```\n{}\n```", escaped_cmd, capped);
                        if let Some(mid) = &msg_id {
                            if let Err(e) = self.sender.edit_message(&ctx.chat_id, mid, &text).await {
                                warn!("Failed to update running message: {e}");
                            }
                        }
                        last_edit = Instant::now();
                    }
                }
                status = child.wait() => {
                    exit_code = Some(status.map(|s| s.code().unwrap_or(-1)).unwrap_or(-1));
                    break;
                }
                _ = &mut cancel_rx => {
                    cancelled = true;
                    #[cfg(unix)]
                    if let Some(pid) = child.id() {
                        let _ = nix::sys::signal::killpg(
                            nix::unistd::Pid::from_raw(pid as i32),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                    }
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    break;
                }
            }
        }

        // HG-09: Drain remaining output while awaiting reader tasks under a timeout.
        // If readers are stuck trying to send to a full channel, draining ensures they make progress.
        let drain_future = async {
            let mut readers = futures::future::join(stdout_handle, stderr_handle);
            tokio::select! {
                _ = &mut readers => {
                    while let Ok(chunk) = output_rx.try_recv() {
                        output_buffer.push_str(&chunk);
                    }
                }
                _ = async {
                    while let Some(chunk) = output_rx.recv().await {
                        output_buffer.push_str(&chunk);
                    }
                } => {}
            }
        };
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), drain_future).await;

        if output_buffer.chars().count() > MAX_BUFFER_CHARS {
            output_buffer = crate::utils::strings::truncate_tail(&output_buffer, MAX_BUFFER_CHARS);
        }

        pg_guard.disarm();

        fn format_body(buf: &str, no_output_msg: &str) -> Option<String> {
            if buf.is_empty() {
                if no_output_msg.is_empty() {
                    None
                } else {
                    Some(no_output_msg.to_owned())
                }
            } else {
                let capped = crate::utils::strings::truncate_tail(buf, 3500);
                Some(format!("```\n{}\n```", capped))
            }
        }

        let result = if cancelled {
            if let Some(mid) = &msg_id {
                match send_mode {
                    SendMode::Verbose => {
                        let body = format_body(&output_buffer, "");
                        let text = match body {
                            None => format!("❌ Cancelled: `{}`", escaped_cmd),
                            Some(b) => format!("❌ Cancelled: `{}`\n\n{}", escaped_cmd, b),
                        };
                        let _ = self.sender.edit_message(&ctx.chat_id, mid, &text).await;
                    }
                    SendMode::Minimal => {
                        // Delete the minimal message
                        let _ = self.sender.delete_message(&ctx.chat_id, mid).await;
                    }
                    // Silent mode sends no message; nothing to clean up.
                    SendMode::Silent => {}
                }
            }
            "⚠️ User cancelled the command".to_string()
        } else if let Some(code) = exit_code {
            if let Some(mid) = &msg_id {
                match send_mode {
                    SendMode::Verbose => {
                        let (icon, label) = if code == 0 {
                            ("✅", "Completed")
                        } else {
                            ("❌", "Failed")
                        };
                        let body = format_body(&output_buffer, "Command completed with no output.");
                        let text = format!(
                            "{} {}: `{}`\n\n{}",
                            icon,
                            label,
                            escaped_cmd,
                            body.unwrap_or_default()
                        );
                        let _ = self.sender.edit_message(&ctx.chat_id, mid, &text).await;
                    }
                    SendMode::Minimal => {
                        // Delete the minimal message
                        let _ = self.sender.delete_message(&ctx.chat_id, mid).await;
                    }
                    // Silent mode sends no message; nothing to clean up.
                    SendMode::Silent => {}
                }
            }
            let mut result = String::new();
            if !output_buffer.is_empty() {
                result.push_str(output_buffer.trim_end());
                result.push('\n');
            }
            result.push_str(&format!("Exit code: {}", code));
            result
        } else {
            unreachable!()
        };

        self.cancel_registry.unregister(&cmd_id).await;
        Ok(result)
    }
}
