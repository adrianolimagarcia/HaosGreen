use anyhow::Context;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::learning;
use crate::llm::{FunctionDefinition, ToolDefinition};
#[allow(unused_imports)]
use crate::platform::sender::PlatformSender;
use crate::skills::SkillRegistry;
use crate::tool_registry::{ToolContext, ToolHandler, ToolResult};
use crate::tools::{validate_home_path, validate_sandbox_path};

/// The soul files the agent may read, update or revert.
///
/// This is the single source of truth for the allowlist: the tool schemas
/// below advertise it as the `enum` for `file_name`, and the handlers check
/// against it at runtime. A JSON-schema `enum` is only a hint to the model —
/// tool-call arguments are attacker-influenced data (a prompt injected by an
/// A2A peer reaches them), so the schema and the runtime check must not be
/// two independent lists that can drift apart.
pub const SOUL_FILE_NAMES: [&str; 3] = ["SOUL.md", "AGENTS.md", "USER.md"];

/// Reject a `file_name` that is not one of [`SOUL_FILE_NAMES`].
///
/// The allowlist alone is sufficient — none of the three names contains a path
/// separator, so `home.join(name)` cannot escape `home` — but the check is
/// exact-match rather than a traversal heuristic on purpose: `config.toml`,
/// `rustfox.db`, `skills-lock.json` and `user_model.md` live in the same
/// directory as the soul files and must stay unreadable through this tool.
fn validate_soul_file_name(file_name: &str) -> anyhow::Result<()> {
    if !SOUL_FILE_NAMES.contains(&file_name) {
        anyhow::bail!(
            "Invalid soul file name '{}'. Allowed: {}",
            file_name,
            SOUL_FILE_NAMES.join(", ")
        );
    }
    Ok(())
}

/// Reject a plan `title` that is not usable as a single path component.
///
/// A title becomes `<sandbox>/.plans/<title>.json`. It is a name, not a path:
/// an absolute title makes `Path::join` discard the `.plans` prefix entirely,
/// and a `../` title walks out of the sandbox.
fn validate_plan_title(title: &str) -> anyhow::Result<()> {
    let valid = !title.is_empty()
        && !title.contains('\0')
        && !title.contains('/')
        && !title.contains('\\')
        && std::path::Path::new(title)
            .components()
            .all(|c| matches!(c, Component::Normal(_)));
    if !valid {
        anyhow::bail!(
            "Invalid plan title '{}': a plan title is a name, not a path \
             (no path separators, no '..', not absolute)",
            title
        );
    }
    Ok(())
}

/// Resolve `<sandbox>/.plans/<title>.json` and prove the result is contained.
///
/// `validate_plan_title` only proves that `title` is a single path component —
/// a *name*, not a path. It says nothing about what `.plans` itself resolves
/// to, so on its own it leaves `<sandbox>/.plans` free to be a symlink to any
/// directory on the machine. `validate_sandbox_path` canonicalises, so a
/// `.plans` directory (or a `<title>.json` file) that resolves outside the
/// sandbox is rejected instead of followed — the same gate `read_file`,
/// `write_file` and `list_files` already use.
///
/// `plan_create` must create `.plans` *before* calling this: for a path that
/// does not exist yet `validate_sandbox_path` canonicalises the **parent**, and
/// canonicalising a missing directory is an error, which would break the first
/// plan in a fresh sandbox.
fn resolve_plan_path(sandbox_dir: &Path, title: &str) -> anyhow::Result<PathBuf> {
    validate_sandbox_path(sandbox_dir, &format!(".plans/{title}.json"))
}

/// `<path>.bak`, `<path>.bak.1`, … — sibling backups in the same directory.
fn bak_path(p: &Path, suffix: &str) -> PathBuf {
    format!("{}{}", p.display(), suffix).into()
}

/// `true` when the kernel refused the open because the final path component is
/// a symlink and `O_NOFOLLOW` was set (`ELOOP`).
///
/// Non-Unix platforms get no `O_NOFOLLOW` here, so this is always `false`
/// there; see [`open_read_no_follow`] for the portability trade-off.
#[cfg(unix)]
fn is_symlink_refusal(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::ELOOP)
}

/// See the Unix definition; no `O_NOFOLLOW` is applied on this platform.
#[cfg(not(unix))]
fn is_symlink_refusal(_e: &std::io::Error) -> bool {
    false
}

/// The denial returned when `O_NOFOLLOW` refuses to follow a symlink.
fn symlink_refusal(path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "Access denied: '{}' is a symbolic link; refusing to follow it",
        path.display()
    )
}

/// Open `path` for reading, refusing to follow a symlink at the final
/// component.
///
/// Every path in this module is checked *then* used: `validate_sandbox_path` /
/// `validate_home_path` canonicalise at T1 and the handler re-opens the path by
/// name at T2. A writer that replaces the validated name with a symlink inside
/// that window redirects the open, so the check proves nothing about the
/// resolution that is actually used. `O_NOFOLLOW` moves the refusal into
/// `open(2)` itself, making the resolution that is checked the resolution that
/// is used.
#[cfg(unix)]
async fn open_read_no_follow(path: &Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .await
}

/// Non-Unix fallback: no `O_NOFOLLOW` equivalent is wired up, so the open
/// behaves exactly as `tokio::fs::read_to_string` did before this change and
/// containment rests on the `validate_*_path` check alone. Gated rather than
/// assumed so the crate keeps compiling on platforms without `O_NOFOLLOW`.
#[cfg(not(unix))]
async fn open_read_no_follow(path: &Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new().read(true).open(path).await
}

/// Open `path` for writing (create + truncate), refusing to follow a symlink at
/// the final component. See [`open_read_no_follow`].
///
/// This is not only a race fix: `validate_sandbox_path` accepts a *dangling*
/// symlink, because it only canonicalises when `exists()` is true and `exists()`
/// follows symlinks. Writing through such a link creates the file at the link
/// target, outside the sandbox.
#[cfg(unix)]
async fn open_write_no_follow(path: &Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .await
}

/// See the Unix definition; no `O_NOFOLLOW` is applied on this platform.
#[cfg(not(unix))]
async fn open_write_no_follow(path: &Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .await
}

/// Read a whole file through [`open_read_no_follow`].
async fn read_no_follow(path: &Path) -> std::io::Result<String> {
    use tokio::io::AsyncReadExt;
    let mut file = open_read_no_follow(path).await?;
    let mut buf = String::new();
    file.read_to_string(&mut buf).await?;
    Ok(buf)
}

/// Write a whole file through [`open_write_no_follow`].
async fn write_no_follow(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut file = open_write_no_follow(path).await?;
    file.write_all(content).await?;
    file.flush().await
}

/// Best-effort restore of `soul` from `bak`, without following a symlink at
/// either name.
///
/// `tokio::fs::copy` opens the destination by name and follows a symlink there,
/// so using it on the failure path would re-open the very window the no-follow
/// open exists to close — a swap that makes the write fail would then be
/// completed by the restore.
async fn restore_soul_from_backup(bak: &Path, soul: &Path) {
    if let Ok(content) = read_no_follow(bak).await {
        let _ = write_no_follow(soul, content.as_bytes()).await;
    }
}

pub struct BuiltinTools {
    skills_dir: PathBuf,
    skills: Arc<RwLock<SkillRegistry>>,
    restart_pending: Arc<AtomicBool>,
    soul_updated: Arc<AtomicBool>,
}

impl BuiltinTools {
    pub fn new(
        skills_dir: PathBuf,
        skills: Arc<RwLock<SkillRegistry>>,
        restart_pending: Arc<AtomicBool>,
        soul_updated: Arc<AtomicBool>,
    ) -> Self {
        Self {
            skills_dir,
            skills,
            restart_pending,
            soul_updated,
        }
    }
}

#[async_trait]
impl ToolHandler for BuiltinTools {
    fn define(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "read_file".to_string(),
                    description: "Read the contents of a file within the sandbox directory".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string", "description": "The file path (relative to sandbox or absolute within sandbox)" }
                        },
                        "required": ["path"]
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "write_file".to_string(),
                    description: "Write content to a file within the sandbox directory. Creates parent directories if needed.".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string", "description": "The file path (relative to sandbox or absolute within sandbox)" },
                            "content": { "type": "string", "description": "The content to write to the file" }
                        },
                        "required": ["path", "content"]
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "list_files".to_string(),
                    description: "List files and directories within a path in the sandbox directory".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string", "description": "The directory path (relative to sandbox or absolute within sandbox). Defaults to sandbox root." }
                        },
                        "required": []
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "send_file".to_string(),
                    description: "Send a file from the sandbox to the current chat. The file must already exist in the sandbox.".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "path": { "type": "string", "description": "The file path (relative to sandbox or absolute within sandbox)" },
                            "caption": { "type": "string", "description": "Optional caption for the file" }
                        },
                        "required": ["path"]
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "plan_create".to_string(),
                    description: "Create a new execution plan with ordered steps. Call this BEFORE starting any multi-step task. Stores the plan in the sandbox for tracking.".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "title": { "type": "string", "description": "Short title describing the overall goal" },
                            "steps": { "type": "array", "items": { "type": "string" }, "description": "Ordered list of step descriptions" }
                        },
                        "required": ["title", "steps"]
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "plan_update".to_string(),
                    description: "Update a step's status in the active plan. Call before starting a step (in_progress) and after finishing (done or failed).".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "step_id": { "type": "integer", "description": "Zero-based index of the step to update" },
                            "status": { "type": "string", "enum": ["todo", "in_progress", "done", "failed"], "description": "New status for the step" },
                            "notes": { "type": "string", "description": "Optional notes — result summary, error message, etc." }
                        },
                        "required": ["step_id", "status"]
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "plan_view".to_string(),
                    description: "View the current plan as a checklist. Call at the end of execution to review progress before synthesising the final answer.".to_string(),
                    parameters: json!({ "type": "object", "properties": {}, "required": [] }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "try_new_tech".to_string(),
                    description: "Run a sandboxed experiment with a new technology or approach.".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "technology": { "type": "string", "description": "Name/description of the technology being tested" },
                            "experiment_code": { "type": "string", "description": "The source code for the experiment" },
                            "language": { "type": "string", "enum": ["rust", "javascript"], "description": "Programming language (default: rust)" }
                        },
                        "required": ["technology", "experiment_code"]
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "self_upgrade".to_string(),
                    description: "Upgrade the bot to the latest version.".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "branch": { "type": "string", "description": "Git branch to build from (source mode only, default: 'main')" },
                            "mode": { "type": "string", "enum": ["auto", "source", "release"], "description": "Force a specific upgrade mode (default: 'auto')" }
                        },
                        "required": []
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "patch_skill".to_string(),
                    description: "Patch an existing skill's SKILL.md by appending content or replacing it entirely.".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "skill_name": { "type": "string", "description": "Name of the skill to patch" },
                            "patch_content": { "type": "string", "description": "Content to append (or full replacement if it starts with ---)" }
                        },
                        "required": ["skill_name", "patch_content"]
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "read_soul_file".to_string(),
                    description: "Read the full contents of a soul file (SOUL.md, AGENTS.md, or USER.md) from the home directory.".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "file_name": { "type": "string", "enum": SOUL_FILE_NAMES, "description": "Which soul file to read" }
                        },
                        "required": ["file_name"]
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "update_soul_file".to_string(),
                    description: "Update a soul file (SOUL.md, AGENTS.md, or USER.md) by appending or replacing content.".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "file_name": { "type": "string", "enum": SOUL_FILE_NAMES, "description": "Which soul file to update" },
                            "mode": { "type": "string", "enum": ["append", "replace"], "description": "append or replace content" },
                            "content": { "type": "string", "description": "Content to write" }
                        },
                        "required": ["file_name", "mode", "content"]
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "revert_soul_file".to_string(),
                    description: "Restore a soul file from its most recent .bak backup.".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "file_name": { "type": "string", "enum": SOUL_FILE_NAMES, "description": "Which soul file to revert" }
                        },
                        "required": ["file_name"]
                    }),
                },
            },
        ]
    }

    async fn execute(&self, name: &str, args: Value, ctx: ToolContext) -> ToolResult {
        match name {
            "read_file" => {
                let path = args["path"].as_str().context("Missing 'path' argument")?;
                let resolved = validate_sandbox_path(&ctx.sandbox_dir, path)?;
                // `O_NOFOLLOW`, not `read_to_string`: the containment check
                // above resolves the path at T1 and this open resolves it again
                // at T2. See `open_read_no_follow`.
                let content = read_no_follow(&resolved).await.map_err(|e| {
                    if is_symlink_refusal(&e) {
                        symlink_refusal(&resolved)
                    } else {
                        anyhow::Error::new(e)
                            .context(format!("Failed to read file: {}", resolved.display()))
                    }
                })?;
                Ok(content)
            }
            "write_file" => {
                let path = args["path"].as_str().context("Missing 'path' argument")?;
                let content = args["content"]
                    .as_str()
                    .context("Missing 'content' argument")?;
                let resolved = validate_sandbox_path(&ctx.sandbox_dir, path)?;
                if let Some(parent) = resolved.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }
                // `validate_sandbox_path` accepts a dangling symlink — it only
                // canonicalises when `exists()` is true, and `exists()` follows
                // symlinks — so `tokio::fs::write` here created the file at the
                // link target, outside the sandbox. `O_NOFOLLOW` refuses.
                write_no_follow(&resolved, content.as_bytes())
                    .await
                    .map_err(|e| {
                        if is_symlink_refusal(&e) {
                            symlink_refusal(&resolved)
                        } else {
                            anyhow::Error::new(e)
                                .context(format!("Failed to write file: {}", resolved.display()))
                        }
                    })?;
                Ok(format!(
                    "Wrote {} bytes to {}",
                    content.len(),
                    resolved.display()
                ))
            }
            "list_files" => {
                let path = args["path"].as_str().unwrap_or(".");
                let resolved = validate_sandbox_path(&ctx.sandbox_dir, path)?;
                let mut entries = Vec::new();
                let mut dir = tokio::fs::read_dir(&resolved).await?;
                while let Some(entry) = dir.next_entry().await? {
                    let name = entry.file_name().to_string_lossy().to_string();
                    let kind = if entry.file_type().await?.is_dir() {
                        "dir"
                    } else {
                        "file"
                    };
                    entries.push(format!("[{kind}] {name}"));
                }
                entries.sort();
                Ok(entries.join("\n"))
            }
            "send_file" => {
                let path = args["path"].as_str().context("Missing 'path' argument")?;
                let caption = args
                    .get("caption")
                    .and_then(|v| v.as_str())
                    .filter(|c| !c.is_empty());
                let resolved = validate_sandbox_path(&ctx.sandbox_dir, path)?;
                let metadata = tokio::fs::metadata(&resolved)
                    .await
                    .with_context(|| format!("File not found: {}", resolved.display()))?;
                const TG_FILE_LIMIT: u64 = 50 * 1024 * 1024;
                if metadata.len() > TG_FILE_LIMIT {
                    anyhow::bail!(
                        "File is {} MB — exceeds Telegram's 50 MB limit",
                        metadata.len() / 1024 / 1024
                    );
                }
                ctx.sender
                    .send_file(&ctx.chat_id, &resolved, caption)
                    .await?;
                let file_name = resolved
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("file");
                Ok(format!("File '{}' sent successfully.", file_name))
            }
            "plan_create" => {
                let title = args["title"].as_str().context("Missing 'title' argument")?;
                validate_plan_title(title)?;
                let plans_dir = ctx.sandbox_dir.join(".plans");
                // Create `.plans` *before* validating: `validate_sandbox_path`
                // canonicalises the parent of a path that does not exist yet,
                // so on a fresh sandbox with no `.plans` the check would fail
                // on the missing parent. `create_dir_all` is a no-op when
                // `.plans` already exists — including when it is a symlink,
                // which `resolve_plan_path` then rejects.
                tokio::fs::create_dir_all(&plans_dir).await?;
                let plan_path = resolve_plan_path(&ctx.sandbox_dir, title)?;
                let steps = args["steps"]
                    .as_array()
                    .context("Missing 'steps' argument")?;
                let plan = json!({
                    "title": title,
                    "steps": steps,
                    "statuses": vec![json!("todo"); steps.len()],
                });
                let body = serde_json::to_string_pretty(&plan)?;
                write_no_follow(&plan_path, body.as_bytes())
                    .await
                    .map_err(|e| {
                        if is_symlink_refusal(&e) {
                            symlink_refusal(&plan_path)
                        } else {
                            anyhow::Error::new(e)
                                .context(format!("Failed to write plan: {}", plan_path.display()))
                        }
                    })?;
                Ok(format!(
                    "Created plan '{}' with {} steps",
                    title,
                    steps.len()
                ))
            }
            "plan_update" => {
                let title = args["title"].as_str().unwrap_or("default");
                validate_plan_title(title)?;
                let step_id = args["step_id"].as_u64().context("Missing 'step_id'")? as usize;
                let status = args["status"]
                    .as_str()
                    .context("Missing 'status' argument")?;
                let _notes = args.get("notes").and_then(|v| v.as_str());
                let plan_path = resolve_plan_path(&ctx.sandbox_dir, title)?;
                let content = read_no_follow(&plan_path).await.map_err(|e| {
                    if is_symlink_refusal(&e) {
                        symlink_refusal(&plan_path)
                    } else {
                        anyhow::Error::new(e)
                            .context(format!("Failed to read plan: {}", plan_path.display()))
                    }
                })?;
                let mut plan: Value = serde_json::from_str(&content)?;
                if let Some(statuses) = plan.get_mut("statuses").and_then(|s| s.as_array_mut()) {
                    if step_id < statuses.len() {
                        statuses[step_id] = json!(status);
                        if let Some(n) = _notes {
                            if let Some(notes_arr) =
                                plan.get_mut("notes").and_then(|n| n.as_array_mut())
                            {
                                if step_id < notes_arr.len() {
                                    notes_arr[step_id] = json!(n);
                                }
                            }
                        }
                    }
                }
                let body = serde_json::to_string_pretty(&plan)?;
                write_no_follow(&plan_path, body.as_bytes())
                    .await
                    .map_err(|e| {
                        if is_symlink_refusal(&e) {
                            symlink_refusal(&plan_path)
                        } else {
                            anyhow::Error::new(e)
                                .context(format!("Failed to write plan: {}", plan_path.display()))
                        }
                    })?;
                Ok(format!("Updated step {step_id} to '{status}'"))
            }
            "plan_view" => {
                let title = args["title"].as_str().unwrap_or("default");
                validate_plan_title(title)?;
                let plan_path = resolve_plan_path(&ctx.sandbox_dir, title)?;
                let content = read_no_follow(&plan_path).await.map_err(|e| {
                    if is_symlink_refusal(&e) {
                        symlink_refusal(&plan_path)
                    } else {
                        anyhow::Error::new(e)
                            .context(format!("Failed to read plan: {}", plan_path.display()))
                    }
                })?;
                Ok(content)
            }
            "try_new_tech" => {
                let technology = args["technology"]
                    .as_str()
                    .context("Missing 'technology'")?
                    .to_string();
                let experiment_code = args["experiment_code"]
                    .as_str()
                    .context("Missing 'experiment_code'")?
                    .to_string();
                let language = args["language"].as_str().unwrap_or("rust").to_string();

                let exp_id = uuid::Uuid::new_v4().to_string();
                let exp_dir = ctx.sandbox_dir.join("experiments").join(&exp_id);
                tokio::fs::create_dir_all(&exp_dir).await?;
                tracing::info!("Running experiment '{}'", technology);

                let (filename, check_cmd, check_args) = match language.as_str() {
                    "javascript" => ("experiment.js", "node", vec!["experiment.js".to_string()]),
                    _ => {
                        let cargo_toml = "[package]\nname = \"experiment\"\nversion = \"0.1.0\"\nedition = \"2021\"\n".to_string();
                        let src_dir = exp_dir.join("src");
                        tokio::fs::create_dir_all(&src_dir).await?;
                        tokio::fs::write(exp_dir.join("Cargo.toml"), cargo_toml).await?;
                        tokio::fs::write(src_dir.join("main.rs"), &experiment_code).await?;
                        ("src/main.rs", "cargo", vec!["check".to_string()])
                    }
                };

                if language == "javascript" {
                    tokio::fs::write(exp_dir.join(filename), &experiment_code).await?;
                }

                let output = tokio::process::Command::new(check_cmd)
                    .args(&check_args)
                    .current_dir(&exp_dir)
                    .output()
                    .await?;

                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                let exit_code = output.status.code().unwrap_or(-1);
                let success = output.status.success();

                let mut result = format!("Experiment: {}\nLanguage: {}\n", technology, language);
                if !stdout.is_empty() {
                    result.push_str(&format!("STDOUT:\n{}\n", stdout));
                }
                if !stderr.is_empty() {
                    result.push_str(&format!("STDERR:\n{}\n", stderr));
                }
                result.push_str(&format!(
                    "Exit code: {}\nResult: {}\n",
                    exit_code,
                    if success { "SUCCESS" } else { "FAILED" }
                ));

                if let Err(e) = tokio::fs::remove_dir_all(&exp_dir).await {
                    tracing::warn!(
                        "Failed to clean up experiment dir '{}': {}",
                        exp_dir.display(),
                        e
                    );
                }
                Ok(result)
            }
            "self_upgrade" => {
                let branch = args["branch"].as_str().unwrap_or("main").to_string();
                let mode = args["mode"].as_str().unwrap_or("auto").to_string();

                let is_valid_branch = !branch.is_empty()
                    && !branch.starts_with('-')
                    && !branch.starts_with('/')
                    && !branch.ends_with('/')
                    && !branch.ends_with('.')
                    && !branch.ends_with(".lock")
                    && !branch.contains("..")
                    && !branch.contains("@{")
                    && !branch.contains("//")
                    && branch != "@"
                    && branch.chars().all(|c| {
                        (c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
                            && !c.is_whitespace()
                            && !c.is_control()
                            && !matches!(c, '~' | '^' | ':' | '?' | '*' | '[' | '\\')
                    });
                if !is_valid_branch {
                    return Ok(format!(
                        "Self-upgrade failed: invalid branch name '{}'",
                        branch
                    ));
                }

                match learning::self_upgrade(&branch, &mode, None).await {
                    Ok(log) => {
                        self.restart_pending
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        Ok(log)
                    }
                    Err(e) => Ok(format!("Self-upgrade failed: {:#}", e)),
                }
            }
            "patch_skill" => {
                let skill_name = args["skill_name"]
                    .as_str()
                    .context("Missing 'skill_name'")?
                    .to_string();
                let patch_content = args["patch_content"]
                    .as_str()
                    .context("Missing 'patch_content'")?
                    .to_string();
                match learning::self_patch_skill(
                    &self.skills_dir,
                    &skill_name,
                    &patch_content,
                    &self.skills,
                )
                .await
                {
                    Ok(msg) => Ok(msg),
                    Err(e) => Ok(format!("Patch failed: {:#}", e)),
                }
            }
            "read_soul_file" => {
                let file_name = args["file_name"].as_str().context("Missing 'file_name'")?;
                validate_soul_file_name(file_name)?;
                let home = ctx
                    .home_dir
                    .as_ref()
                    .context("No home directory configured")?;
                // A denial is a denial: this used to be
                // `validate_sandbox_path(home, file_name).unwrap_or_else(|_| home.join(file_name))`,
                // which turned the containment check into a no-op — the
                // rejected `../outside.txt` was then joined onto `home` anyway.
                validate_home_path(home, file_name)?;
                // …but a check is not containment. `validate_home_path`
                // canonicalises at T1; opening the path it *returned* would
                // re-resolve it at T2, so a symlink swapped in between was
                // followed and `SOUL.md` returned the OpenRouter API key out of
                // `config.toml`. Open the requested name instead — `file_name`
                // is an allowlisted single component, so `home.join(file_name)`
                // cannot traverse — and let `O_NOFOLLOW` refuse a symlink at it.
                let soul = home.join(file_name);
                match read_no_follow(&soul).await {
                    Ok(content) => Ok(content),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        Ok(format!("Soul file '{}' does not exist yet.", file_name))
                    }
                    Err(e) if is_symlink_refusal(&e) => Err(symlink_refusal(&soul)),
                    Err(e) => Ok(format!("Error reading soul file: {}", e)),
                }
            }
            "update_soul_file" => {
                let file_name = args["file_name"].as_str().context("Missing 'file_name'")?;
                validate_soul_file_name(file_name)?;
                let content = args["content"].as_str().context("Missing 'content'")?;
                let mode = args["mode"].as_str().unwrap_or("append");

                if content.contains('\0') {
                    return Ok("Content contains null bytes and was rejected.".to_string());
                }
                if content.len() > 100_000 {
                    return Ok(
                        "Content too large (max 100KB). Please consolidate the file first."
                            .to_string(),
                    );
                }

                let home = ctx
                    .home_dir
                    .as_ref()
                    .context("No home directory configured")?;
                // The allowlist above already makes `home.join(file_name)`
                // safe; validating the resolved path as well keeps the
                // containment check in one place and fails closed if the
                // soul file is a symlink out of the home directory.
                validate_home_path(home, file_name)?;
                // …and then never open the path it returned. See
                // `read_soul_file` and `open_read_no_follow`: re-resolving the
                // validated name is the check-then-use window, and this handler
                // *writes*, so a symlink swapped into it redirected the write
                // out of the home directory.
                let path = home.join(file_name);

                // Read the current content without following a symlink. Only
                // `NotFound` may be treated as "no soul file yet" — the old
                // `unwrap_or_default()` also swallowed the refusal, which would
                // have turned a symlinked soul file into a blank one and then
                // overwritten whatever the link pointed at.
                let (existing, existed) = match read_no_follow(&path).await {
                    Ok(content) => (content, true),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => (String::new(), false),
                    Err(e) if is_symlink_refusal(&e) => return Err(symlink_refusal(&path)),
                    Err(e) => {
                        return Err(anyhow::Error::new(e)
                            .context(format!("Failed to read soul file: {}", path.display())))
                    }
                };

                let new_content = match mode {
                    "append" => {
                        if existing.trim().is_empty() {
                            if content.starts_with("---") {
                                content.to_string()
                            } else {
                                format!(
                                    "---\nname: {}\nversion: 1\n---\n\n{}",
                                    file_name.trim_end_matches(".md"),
                                    content
                                )
                            }
                        } else {
                            if !existing.trim().starts_with("---") {
                                return Ok("Existing soul file has invalid format (missing frontmatter). Rejected.".to_string());
                            }
                            format!("{}\n{}", existing.trim_end(), content)
                        }
                    }
                    "replace" => {
                        if !content.trim().starts_with("---") {
                            return Ok(
                                "Replace mode requires content with YAML frontmatter".to_string()
                            );
                        }
                        content.to_string()
                    }
                    _ => return Ok("Invalid mode. Use 'append' or 'replace'.".to_string()),
                };

                if !learning::has_valid_frontmatter(&new_content) {
                    return Ok(
                        "Update would produce invalid soul file (missing frontmatter). Rejected."
                            .to_string(),
                    );
                }
                if !new_content.contains("name:") || !new_content.contains("version:") {
                    return Ok(
                        "Update rejected: frontmatter must contain 'name' and 'version' fields."
                            .to_string(),
                    );
                }

                // Rotate `.bak.2 -> .bak.3`, `.bak.1 -> .bak.2`, `.bak -> .bak.1`.
                // `rename` operates on the link itself and never follows it, so
                // these are safe even if a backup name is a symlink.
                for (old, new) in [
                    (bak_path(&path, ".bak.2"), bak_path(&path, ".bak.3")),
                    (bak_path(&path, ".bak.1"), bak_path(&path, ".bak.2")),
                    (bak_path(&path, ".bak"), bak_path(&path, ".bak.1")),
                ] {
                    if old.exists() {
                        let _ = tokio::fs::rename(&old, &new).await;
                    }
                }
                if existed {
                    let bak = bak_path(&path, ".bak");
                    // Back up the bytes just read rather than re-opening the
                    // name: `tokio::fs::copy` would follow a symlink swapped in
                    // since the read, and a symlinked backup name would send
                    // the copy outside the home directory.
                    if let Err(e) = write_no_follow(&bak, existing.as_bytes()).await {
                        if is_symlink_refusal(&e) {
                            return Err(symlink_refusal(&bak));
                        }
                    }
                }

                if let Err(e) = write_no_follow(&path, new_content.as_bytes()).await {
                    restore_soul_from_backup(&bak_path(&path, ".bak"), &path).await;
                    if is_symlink_refusal(&e) {
                        return Err(symlink_refusal(&path));
                    }
                    return Ok(format!(
                        "Failed to write soul file (restored from backup): {}",
                        e
                    ));
                }

                match read_no_follow(&path).await {
                    Ok(read_back) if read_back == new_content => {
                        self.soul_updated
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        Ok(format!(
                            "{} updated successfully. Backup at {}.bak",
                            file_name,
                            path.display()
                        ))
                    }
                    Ok(_) => {
                        restore_soul_from_backup(&bak_path(&path, ".bak"), &path).await;
                        Ok(
                            "Write verification failed (content mismatch). Restored from backup."
                                .to_string(),
                        )
                    }
                    Err(e) => {
                        restore_soul_from_backup(&bak_path(&path, ".bak"), &path).await;
                        Ok(format!(
                            "Write verification error (restored from backup): {}",
                            e
                        ))
                    }
                }
            }
            "revert_soul_file" => {
                let file_name = args["file_name"].as_str().context("Missing 'file_name'")?;
                validate_soul_file_name(file_name)?;
                let home = ctx
                    .home_dir
                    .as_ref()
                    .context("No home directory configured")?;
                validate_home_path(home, file_name)?;
                // Same check-then-use window as `read_soul_file` /
                // `update_soul_file`, but here the *write* is the restore, so
                // `tokio::fs::copy` (which opens the destination by name and
                // follows a symlink there) is replaced by the no-follow pair.
                let path = home.join(file_name);
                let bak = bak_path(&path, ".bak");
                let content = match read_no_follow(&bak).await {
                    Ok(content) => content,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        return Ok(format!("No backup found for {}", file_name))
                    }
                    Err(e) if is_symlink_refusal(&e) => return Err(symlink_refusal(&bak)),
                    Err(e) => return Ok(format!("Failed to restore backup: {}", e)),
                };
                match write_no_follow(&path, content.as_bytes()).await {
                    Ok(()) => Ok(format!("{} restored from backup.", file_name)),
                    Err(e) if is_symlink_refusal(&e) => Err(symlink_refusal(&path)),
                    Err(e) => Ok(format!("Failed to restore backup: {}", e)),
                }
            }
            _ => anyhow::bail!("BuiltinTools: unknown tool {name}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cancel_registry::CancelRegistry;
    use crate::platform::sender::{MessageFormat, PlatformMessageId};
    use crate::tool_registry::ToolUiMode;
    use std::path::Path;
    use tempfile::tempdir;

    fn make_tools() -> BuiltinTools {
        BuiltinTools::new(
            PathBuf::from("/tmp/skills"),
            Arc::new(RwLock::new(SkillRegistry::new())),
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
        )
    }

    /// `ToolContext` demands a sender. None of the tools exercised here send
    /// anything, so every method is a no-op stub.
    struct NoopSender;

    #[async_trait]
    impl PlatformSender for NoopSender {
        async fn send_message(
            &self,
            _chat_id: &str,
            _text: &str,
            _format: MessageFormat,
        ) -> anyhow::Result<PlatformMessageId> {
            Ok("test:1".to_string())
        }
        async fn send_file(
            &self,
            _chat_id: &str,
            _path: &Path,
            _caption: Option<&str>,
        ) -> anyhow::Result<PlatformMessageId> {
            Ok("test:1".to_string())
        }
        async fn show_cancel_button(
            &self,
            _chat_id: &str,
            _text: &str,
            _cancel_id: &str,
        ) -> anyhow::Result<PlatformMessageId> {
            Ok("test:1".to_string())
        }
        async fn edit_message(
            &self,
            _chat_id: &str,
            _message_id: &PlatformMessageId,
            _text: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn delete_message(
            &self,
            _chat_id: &str,
            _message_id: &PlatformMessageId,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn notify_shutdown(&self, _chat_id: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Invoke a real handler the way `loop_runner` does.
    async fn exec(
        tools: &BuiltinTools,
        name: &str,
        args: Value,
        home: &Path,
        sandbox: &Path,
    ) -> ToolResult {
        let ctx = ToolContext {
            sandbox_dir: sandbox.to_path_buf(),
            home_dir: Some(home.to_path_buf()),
            sender: Arc::new(NoopSender),
            cancel_registry: Arc::new(CancelRegistry::new()),
            user_id: "test".to_string(),
            chat_id: "0".to_string(),
            tool_ui_mode: ToolUiMode::Silent,
        };
        tools.execute(name, args, ctx).await
    }

    /// The text the LLM would see for a tool result — `loop_runner` renders an
    /// `Err` as `Error: {e}`.
    fn tool_text(result: &ToolResult) -> String {
        match result {
            Ok(text) => text.clone(),
            Err(e) => format!("Error: {e}"),
        }
    }

    /// `(home, sandbox)` with both directories created inside one tempdir.
    fn fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempdir().unwrap();
        let home = dir.path().join("home");
        let sandbox = dir.path().join("workspace");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&sandbox).unwrap();
        (dir, home, sandbox)
    }

    #[test]
    fn test_builtin_tool_definitions_includes_soul_tools() {
        let tools = make_tools();
        let defs = tools.define();
        let names: Vec<&str> = defs.iter().map(|d| d.function.name.as_str()).collect();
        assert!(
            names.contains(&"read_soul_file"),
            "read_soul_file must be in BuiltinTools definitions"
        );
        assert!(
            names.contains(&"update_soul_file"),
            "update_soul_file must be in BuiltinTools definitions"
        );
        assert!(
            names.contains(&"revert_soul_file"),
            "revert_soul_file must be in BuiltinTools definitions"
        );
    }

    #[test]
    fn test_soul_tool_definitions_have_required_file_name_enum() {
        let tools = make_tools();
        let defs = tools.define();
        for name in ["read_soul_file", "update_soul_file", "revert_soul_file"] {
            let def = defs
                .iter()
                .find(|d| d.function.name == name)
                .unwrap_or_else(|| panic!("missing tool: {name}"));
            let file_name_schema = &def.function.parameters["properties"]["file_name"];
            assert_eq!(file_name_schema["type"].as_str(), Some("string"));
            let allowed = file_name_schema["enum"].as_array().expect("enum array");
            let allowed_strs: Vec<&str> = allowed.iter().filter_map(|v| v.as_str()).collect();
            assert!(allowed_strs.contains(&"SOUL.md"));
            assert!(allowed_strs.contains(&"AGENTS.md"));
            assert!(allowed_strs.contains(&"USER.md"));
        }
    }

    // ── read_soul_file: runtime validation of `file_name` ───────────────────
    //
    // The JSON-schema `enum` on `file_name` is a hint to the LLM, not a
    // server-side constraint: the model (or a prompt injected into it by an
    // A2A peer) can put anything in the tool-call arguments. These tests drive
    // the real handler with arguments the schema would never allow.

    #[tokio::test]
    async fn test_read_soul_file_rejects_arbitrary_file_in_home() {
        let (_dir, home, sandbox) = fixture();
        std::fs::write(
            home.join("config.toml"),
            "[openrouter]\napi_key = \"SUPERSECRET\"\n",
        )
        .unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "read_soul_file",
            json!({ "file_name": "config.toml" }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            !tool_text(&result).contains("SUPERSECRET"),
            "read_soul_file leaked the OpenRouter API key from config.toml: {:?}",
            tool_text(&result)
        );
        assert!(
            result.is_err(),
            "read_soul_file must reject a file_name outside the soul-file allowlist, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_read_soul_file_rejects_traversal_file_name() {
        let (dir, home, sandbox) = fixture();
        std::fs::write(dir.path().join("outside.txt"), "OUTSIDE_CONTENT").unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "read_soul_file",
            json!({ "file_name": "../outside.txt" }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            !tool_text(&result).contains("OUTSIDE_CONTENT"),
            "read_soul_file escaped the home directory: {:?}",
            tool_text(&result)
        );
        assert!(
            result.is_err(),
            "read_soul_file must reject a traversing file_name, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_read_soul_file_rejects_absolute_file_name() {
        let (dir, home, sandbox) = fixture();
        let outside = dir.path().join("outside.md");
        std::fs::write(&outside, "OUTSIDE_ABSOLUTE_CONTENT").unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "read_soul_file",
            json!({ "file_name": outside.to_str().unwrap() }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            !tool_text(&result).contains("OUTSIDE_ABSOLUTE_CONTENT"),
            "read_soul_file accepted an absolute file_name: {:?}",
            tool_text(&result)
        );
        assert!(
            result.is_err(),
            "read_soul_file must reject an absolute file_name, got: {:?}",
            result
        );
    }

    /// A legitimate name is still not a licence to follow a symlink out of the
    /// home directory. Before the fix the containment check *did* deny this
    /// path — and `unwrap_or_else` then read it anyway.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_read_soul_file_rejects_symlink_out_of_home() {
        let (dir, home, sandbox) = fixture();
        let target = dir.path().join("outside.md");
        std::fs::write(&target, "OUTSIDE_SYMLINK_CONTENT").unwrap();
        std::os::unix::fs::symlink(&target, home.join("SOUL.md")).unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "read_soul_file",
            json!({ "file_name": "SOUL.md" }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            !tool_text(&result).contains("OUTSIDE_SYMLINK_CONTENT"),
            "read_soul_file followed a symlink out of the home directory: {:?}",
            tool_text(&result)
        );
        assert!(
            result.is_err(),
            "read_soul_file must deny a soul file that resolves outside home, got: {:?}",
            result
        );
    }

    /// Regression guard against over-fixing: the three declared names must keep
    /// working, and each must return its *own* content.
    #[tokio::test]
    async fn test_read_soul_file_reads_all_three_legitimate_names() {
        let (_dir, home, sandbox) = fixture();
        for name in ["SOUL.md", "AGENTS.md", "USER.md"] {
            std::fs::write(home.join(name), format!("CONTENT_OF_{name}")).unwrap();
        }

        let tools = make_tools();
        for name in ["SOUL.md", "AGENTS.md", "USER.md"] {
            let result = exec(
                &tools,
                "read_soul_file",
                json!({ "file_name": name }),
                &home,
                &sandbox,
            )
            .await
            .unwrap_or_else(|e| panic!("read_soul_file('{name}') must succeed: {e}"));
            assert_eq!(
                result,
                format!("CONTENT_OF_{name}"),
                "read_soul_file('{name}') returned the wrong file"
            );
        }
    }

    /// A legitimate name whose file does not exist must report that, not fall
    /// back to some other file.
    #[tokio::test]
    async fn test_read_soul_file_missing_legitimate_name_reports_missing() {
        let (_dir, home, sandbox) = fixture();
        std::fs::write(home.join("AGENTS.md"), "AGENTS_CONTENT").unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "read_soul_file",
            json!({ "file_name": "USER.md" }),
            &home,
            &sandbox,
        )
        .await;

        let text = tool_text(&result);
        assert!(
            !text.contains("AGENTS_CONTENT"),
            "a missing soul file must not resolve to a different file: {text}"
        );
        assert!(
            text.contains("does not exist"),
            "expected a not-found message for a missing soul file, got: {text}"
        );
    }

    // ── plan_* : the title is a name, not a path ────────────────────────────

    #[tokio::test]
    async fn test_plan_view_rejects_absolute_title() {
        let (dir, home, sandbox) = fixture();
        std::fs::write(dir.path().join("outside.json"), "OUTSIDE_PLAN_CONTENT").unwrap();

        let tools = make_tools();
        // `title = "/tmp/.../outside"` → `<title>.json`, and `Path::join` with an
        // absolute path discards the `.plans` prefix entirely.
        let result = exec(
            &tools,
            "plan_view",
            json!({ "title": dir.path().join("outside").to_str().unwrap() }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            !tool_text(&result).contains("OUTSIDE_PLAN_CONTENT"),
            "plan_view read outside the sandbox: {:?}",
            tool_text(&result)
        );
        assert!(
            result.is_err(),
            "plan_view must reject an absolute title, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_plan_view_rejects_traversal_title() {
        let (dir, home, sandbox) = fixture();
        // `.plans` must exist for the kernel to resolve `..` through it —
        // without it this test passes vacuously on ENOENT instead of on the
        // containment check.
        std::fs::create_dir_all(sandbox.join(".plans")).unwrap();
        // `sandbox/.plans/../../outside.json` == `<dir>/outside.json`.
        std::fs::write(dir.path().join("outside.json"), "OUTSIDE_PLAN_CONTENT").unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "plan_view",
            json!({ "title": "../../outside" }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            !tool_text(&result).contains("OUTSIDE_PLAN_CONTENT"),
            "plan_view escaped the sandbox: {:?}",
            tool_text(&result)
        );
        assert!(
            result.is_err(),
            "plan_view must reject a traversing title, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn test_plan_view_reads_plan_created_with_normal_title() {
        let (_dir, home, sandbox) = fixture();
        let tools = make_tools();

        exec(
            &tools,
            "plan_create",
            json!({ "title": "fix the login bug", "steps": ["repro", "patch"] }),
            &home,
            &sandbox,
        )
        .await
        .expect("plan_create with a normal title must succeed");

        let viewed = exec(
            &tools,
            "plan_view",
            json!({ "title": "fix the login bug" }),
            &home,
            &sandbox,
        )
        .await
        .expect("plan_view with a normal title must succeed");

        assert!(
            viewed.contains("fix the login bug"),
            "plan_view did not return the created plan: {viewed}"
        );
        assert!(viewed.contains("repro"), "plan steps missing: {viewed}");
    }

    #[tokio::test]
    async fn test_plan_create_rejects_escaping_title() {
        let (dir, home, sandbox) = fixture();
        let tools = make_tools();

        let result = exec(
            &tools,
            "plan_create",
            json!({ "title": "../../evil", "steps": ["x"] }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            result.is_err(),
            "plan_create must reject a traversing title, got: {:?}",
            result
        );
        assert!(
            !dir.path().join("evil.json").exists(),
            "plan_create wrote a plan outside the sandbox"
        );
    }

    #[tokio::test]
    async fn test_plan_update_rejects_escaping_title() {
        let (dir, home, sandbox) = fixture();
        std::fs::create_dir_all(sandbox.join(".plans")).unwrap();
        let outside = dir.path().join("outside.json");
        std::fs::write(
            &outside,
            r#"{"title":"outside","steps":["a"],"statuses":["todo"]}"#,
        )
        .unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "plan_update",
            json!({ "title": "../../outside", "step_id": 0, "status": "done" }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            result.is_err(),
            "plan_update must reject a traversing title, got: {:?}",
            result
        );
        let after = std::fs::read_to_string(&outside).unwrap();
        assert!(
            after.contains("todo"),
            "plan_update rewrote a file outside the sandbox: {after}"
        );
    }

    // ── the sibling soul tools take the same unvalidated `file_name` ────────

    #[tokio::test]
    async fn test_update_soul_file_rejects_file_name_outside_home() {
        let (dir, home, sandbox) = fixture();
        let tools = make_tools();

        let result = exec(
            &tools,
            "update_soul_file",
            json!({
                "file_name": "../outside.md",
                "mode": "replace",
                "content": "---\nname: pwn\nversion: 1\n---\n\npwned\n"
            }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            result.is_err(),
            "update_soul_file must reject a traversing file_name, got: {:?}",
            result
        );
        assert!(
            !dir.path().join("outside.md").exists(),
            "update_soul_file wrote outside the home directory"
        );
    }

    #[tokio::test]
    async fn test_revert_soul_file_rejects_file_name_outside_home() {
        let (dir, home, sandbox) = fixture();
        std::fs::write(dir.path().join("outside.md.bak"), "BAK_CONTENT").unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "revert_soul_file",
            json!({ "file_name": "../outside.md" }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            result.is_err(),
            "revert_soul_file must reject a traversing file_name, got: {:?}",
            result
        );
        assert!(
            !dir.path().join("outside.md").exists(),
            "revert_soul_file restored a backup outside the home directory"
        );
    }

    // ── plan_* : a valid *name* is not containment ──────────────────────────
    //
    // `validate_plan_title` only proves the title is a single path component.
    // It says nothing about what `.plans` resolves to, so a symlinked `.plans`
    // directory — or a symlinked `<title>.json` — redirected every plan
    // operation. These tests drive the real handlers with a real symlink
    // planted first; before the fix `plan_create` returned
    // `Ok("Created plan 'pwn' with 1 steps")` and the file landed outside the
    // sandbox, and `plan_view` returned the contents of an outside file.

    /// Escape A: `.plans` is a symlink to a directory outside the sandbox.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_plan_create_rejects_symlinked_plans_dir() {
        let (dir, home, sandbox) = fixture();
        let outside = dir.path().join("outside_plans");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, sandbox.join(".plans")).unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "plan_create",
            json!({ "title": "pwn", "steps": ["a"] }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            result.is_err(),
            "plan_create must reject a symlinked .plans directory, got: {:?}",
            result
        );
        assert!(
            !outside.join("pwn.json").exists(),
            "plan_create wrote a plan outside the sandbox through a symlinked .plans"
        );
    }

    /// Escape B: a plan *file* is a symlink to a file outside the sandbox.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_plan_view_rejects_symlinked_plan_file() {
        let (dir, home, sandbox) = fixture();
        let plans = sandbox.join(".plans");
        std::fs::create_dir_all(&plans).unwrap();
        let outside = dir.path().join("outside.json");
        std::fs::write(&outside, "OUTSIDE_SECRET_PLAN").unwrap();
        std::os::unix::fs::symlink(&outside, plans.join("leak.json")).unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "plan_view",
            json!({ "title": "leak" }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            !tool_text(&result).contains("OUTSIDE_SECRET_PLAN"),
            "plan_view read outside the sandbox through a symlinked plan file: {:?}",
            tool_text(&result)
        );
        assert!(
            result.is_err(),
            "plan_view must reject a symlinked plan file, got: {:?}",
            result
        );
    }

    /// The same for `plan_update`, which writes: the outside file must be
    /// byte-identical afterwards.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_plan_update_rejects_symlinked_plan_file() {
        let (dir, home, sandbox) = fixture();
        let plans = sandbox.join(".plans");
        std::fs::create_dir_all(&plans).unwrap();
        let outside = dir.path().join("outside.json");
        std::fs::write(
            &outside,
            r#"{"title":"outside","steps":["a"],"statuses":["todo"]}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(&outside, plans.join("leak.json")).unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "plan_update",
            json!({ "title": "leak", "step_id": 0, "status": "done" }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            result.is_err(),
            "plan_update must reject a symlinked plan file, got: {:?}",
            result
        );
        let after = std::fs::read_to_string(&outside).unwrap();
        assert!(
            after.contains("todo"),
            "plan_update rewrote a file outside the sandbox: {after}"
        );
    }

    /// A *dangling* symlink is the case `validate_sandbox_path` alone does not
    /// catch: it canonicalises only when `exists()` is true, and `exists()`
    /// follows symlinks. The containment check therefore accepts the path and
    /// the write used to create the file at the link target. `O_NOFOLLOW` is
    /// what closes it.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_plan_create_rejects_dangling_symlinked_plan_file() {
        let (dir, home, sandbox) = fixture();
        let plans = sandbox.join(".plans");
        std::fs::create_dir_all(&plans).unwrap();
        let outside_dir = dir.path().join("outside_dir");
        std::fs::create_dir_all(&outside_dir).unwrap();
        let target = outside_dir.join("pwn.json");
        std::os::unix::fs::symlink(&target, plans.join("pwn.json")).unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "plan_create",
            json!({ "title": "pwn", "steps": ["a"] }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            result.is_err(),
            "plan_create must reject a dangling symlinked plan file, got: {:?}",
            result
        );
        assert!(
            !target.exists(),
            "plan_create created a plan outside the sandbox through a dangling symlink"
        );
    }

    /// `write_file` is the pattern `plan_*` was asked to copy, and it had the
    /// same dangling-symlink hole: containment validation is not sufficient
    /// for a *write*, because the write is a second resolution of the name.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_write_file_rejects_dangling_symlink_out_of_sandbox() {
        let (dir, home, sandbox) = fixture();
        let outside_dir = dir.path().join("outside_dir");
        std::fs::create_dir_all(&outside_dir).unwrap();
        let target = outside_dir.join("pwn.txt");
        std::os::unix::fs::symlink(&target, sandbox.join("pwn.txt")).unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "write_file",
            json!({ "path": "pwn.txt", "content": "OUTSIDE_WRITE" }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            result.is_err(),
            "write_file must reject a dangling symlink, got: {:?}",
            result
        );
        assert!(
            !target.exists(),
            "write_file created a file outside the sandbox through a dangling symlink"
        );
    }

    /// Regression guard for the fix in the other direction: the containment
    /// check must not break the ordinary first-run path. On a fresh sandbox
    /// `.plans` does not exist, and `validate_sandbox_path` canonicalises the
    /// *parent* of a path that does not exist yet — so `.plans` has to be
    /// created before the check runs.
    #[tokio::test]
    async fn test_plan_create_works_in_fresh_sandbox_without_plans_dir() {
        let (_dir, home, sandbox) = fixture();
        assert!(
            !sandbox.join(".plans").exists(),
            "fixture must start without a .plans directory"
        );

        let tools = make_tools();
        let result = exec(
            &tools,
            "plan_create",
            json!({ "title": "fresh", "steps": ["one", "two"] }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            result.is_ok(),
            "plan_create must work in a fresh sandbox, got: {:?}",
            result
        );
        assert!(
            sandbox.join(".plans").join("fresh.json").is_file(),
            "plan_create did not create the plan inside the sandbox"
        );

        // …and the plan it created is readable through plan_view.
        let viewed = exec(
            &tools,
            "plan_view",
            json!({ "title": "fresh" }),
            &home,
            &sandbox,
        )
        .await
        .expect("plan_view of a freshly created plan must succeed");
        assert!(viewed.contains("one"), "plan steps missing: {viewed}");
    }

    /// Titles are free-form names, including spaces, and must keep working
    /// end-to-end after being routed through containment validation.
    #[tokio::test]
    async fn test_plan_title_with_space_round_trips() {
        let (_dir, home, sandbox) = fixture();
        let tools = make_tools();

        exec(
            &tools,
            "plan_create",
            json!({ "title": "fix the login bug", "steps": ["repro", "patch"] }),
            &home,
            &sandbox,
        )
        .await
        .expect("plan_create with a spaced title must succeed");

        let updated = exec(
            &tools,
            "plan_update",
            json!({ "title": "fix the login bug", "step_id": 0, "status": "done" }),
            &home,
            &sandbox,
        )
        .await
        .expect("plan_update with a spaced title must succeed");
        assert!(updated.contains("done"), "unexpected update: {updated}");

        let viewed = exec(
            &tools,
            "plan_view",
            json!({ "title": "fix the login bug" }),
            &home,
            &sandbox,
        )
        .await
        .expect("plan_view with a spaced title must succeed");
        assert!(viewed.contains("fix the login bug"), "got: {viewed}");
        assert!(
            viewed.contains("done"),
            "update was not persisted: {viewed}"
        );
    }

    // ── soul files: refusing a symlink at open time ─────────────────────────
    //
    // Escapes C and D are a check-then-use race: `validate_home_path`
    // canonicalises at T1 and the handler re-opened the name at T2, so a
    // writer that swapped the file for a symlink in between redirected the
    // read (`config.toml` came back with the OpenRouter API key) or the write.
    // The race window itself is not deterministically reachable from a test —
    // there is no hook between the check and the open — so these tests pin the
    // property that closes it instead: the open refuses to follow a symlink.
    //
    // The symlink target is deliberately *inside* the home directory. A link
    // pointing outside is already denied by `validate_home_path` (covered
    // above), which would make these tests pass for the wrong reason; an
    // inside-pointing link is accepted by that check and was previously
    // followed, silently mapping `SOUL.md` onto `AGENTS.md`.

    #[cfg(unix)]
    #[tokio::test]
    async fn test_read_soul_file_refuses_symlink_even_inside_home() {
        let (_dir, home, sandbox) = fixture();
        std::fs::write(home.join("AGENTS.md"), "AGENTS_CONTENT").unwrap();
        std::os::unix::fs::symlink(home.join("AGENTS.md"), home.join("SOUL.md")).unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "read_soul_file",
            json!({ "file_name": "SOUL.md" }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            !tool_text(&result).contains("AGENTS_CONTENT"),
            "read_soul_file followed a symlink: {:?}",
            tool_text(&result)
        );
        assert!(
            result.is_err(),
            "read_soul_file must refuse to follow a symlink, got: {:?}",
            result
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_update_soul_file_refuses_symlink_even_inside_home() {
        let (_dir, home, sandbox) = fixture();
        std::fs::write(home.join("AGENTS.md"), "AGENTS_CONTENT").unwrap();
        std::os::unix::fs::symlink(home.join("AGENTS.md"), home.join("SOUL.md")).unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "update_soul_file",
            json!({
                "file_name": "SOUL.md",
                "content": "---\nname: SOUL\nversion: 1\n---\n\nPWNED",
                "mode": "replace"
            }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            result.is_err(),
            "update_soul_file must refuse to follow a symlink, got: {:?}",
            result
        );
        let agents = std::fs::read_to_string(home.join("AGENTS.md")).unwrap();
        assert_eq!(
            agents, "AGENTS_CONTENT",
            "update_soul_file wrote through a symlink into another soul file"
        );
    }

    /// `revert_soul_file` restores *into* the soul path, so a symlink there
    /// must not receive the backup content either. The link target is inside
    /// home on purpose: a link pointing outside is already refused by
    /// `validate_home_path`, which would make this pass for the wrong reason.
    /// Pointing `AGENTS.md` at `USER.md` instead made the old handler derive
    /// its backup name from the *canonicalised* path (`USER.md.bak`), so it
    /// never found the backup it was asked to restore.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_revert_soul_file_refuses_symlink_even_inside_home() {
        let (_dir, home, sandbox) = fixture();
        std::fs::write(home.join("USER.md"), "USER_ORIGINAL").unwrap();
        // A backup exists, so the handler gets past the "no backup" branch.
        std::fs::write(
            home.join("AGENTS.md.bak"),
            "---\nname: AGENTS\nversion: 1\n---\n\nBACKUP_BODY",
        )
        .unwrap();
        std::os::unix::fs::symlink(home.join("USER.md"), home.join("AGENTS.md")).unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "revert_soul_file",
            json!({ "file_name": "AGENTS.md" }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            result.is_err(),
            "revert_soul_file must refuse to follow a symlink, got: {:?}",
            result
        );
        assert_eq!(
            std::fs::read_to_string(home.join("USER.md")).unwrap(),
            "USER_ORIGINAL",
            "revert_soul_file wrote the backup through a symlink into another soul file"
        );
    }

    /// The `.bak` name is also reachable inside home, so `update_soul_file`
    /// must not follow a symlink there. The link is left *dangling* on purpose:
    /// the `.bak -> .bak.1` rotation only moves a link that already resolves,
    /// so a dangling one survives to the backup write, and `tokio::fs::copy`
    /// used to create the file at the link target — outside the home directory.
    #[cfg(unix)]
    #[tokio::test]
    async fn test_update_soul_file_refuses_dangling_symlinked_backup_name() {
        let (dir, home, sandbox) = fixture();
        let target = dir.path().join("outside_backup.md");
        std::fs::write(
            home.join("SOUL.md"),
            "---\nname: SOUL\nversion: 1\n---\n\nBASE",
        )
        .unwrap();
        std::os::unix::fs::symlink(&target, home.join("SOUL.md.bak")).unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "update_soul_file",
            json!({
                "file_name": "SOUL.md",
                "content": "---\nname: SOUL\nversion: 1\n---\n\nMORE",
                "mode": "replace"
            }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            !target.exists(),
            "update_soul_file wrote its backup outside the home directory through a symlink"
        );
        assert!(
            result.is_err(),
            "update_soul_file must refuse a symlinked backup name, got: {:?}",
            result
        );
    }

    /// Regression guard: ordinary soul-file updates still work after the
    /// no-follow open, including the backup the handler advertises.
    #[tokio::test]
    async fn test_update_soul_file_still_works_and_writes_backup() {
        let (_dir, home, sandbox) = fixture();
        std::fs::write(
            home.join("SOUL.md"),
            "---\nname: SOUL\nversion: 1\n---\n\nBASE",
        )
        .unwrap();

        let tools = make_tools();
        let result = exec(
            &tools,
            "update_soul_file",
            json!({
                "file_name": "SOUL.md",
                "content": "---\nname: SOUL\nversion: 1\n---\n\nMORE",
                "mode": "replace"
            }),
            &home,
            &sandbox,
        )
        .await;

        assert!(
            result.is_ok(),
            "update_soul_file must still succeed for a regular file, got: {:?}",
            result
        );
        let updated = std::fs::read_to_string(home.join("SOUL.md")).unwrap();
        assert!(updated.contains("MORE"), "update not applied: {updated}");

        let backup = std::fs::read_to_string(home.join("SOUL.md.bak")).unwrap();
        assert!(
            backup.contains("BASE"),
            "the pre-update content must be backed up, got: {backup}"
        );

        // …and revert_soul_file restores it.
        let reverted = exec(
            &tools,
            "revert_soul_file",
            json!({ "file_name": "SOUL.md" }),
            &home,
            &sandbox,
        )
        .await
        .expect("revert_soul_file must succeed when a backup exists");
        assert!(reverted.contains("restored"), "got: {reverted}");
        let restored = std::fs::read_to_string(home.join("SOUL.md")).unwrap();
        assert!(
            restored.contains("BASE"),
            "revert did not restore: {restored}"
        );
    }
}
