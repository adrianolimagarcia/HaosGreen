use anyhow::Context;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

use crate::agent::{RunReason, ScheduledJobRequest};
use crate::llm::{FunctionDefinition, ToolDefinition};
use crate::scheduler::reminders::ScheduledTaskStore;
use crate::scheduler::{reminders::ScheduledTask, Scheduler};
use crate::tool_registry::{ToolContext, ToolHandler, ToolResult};
use teloxide::prelude::Bot;
use uuid::Uuid;

pub struct SchedulingTools {
    task_store: ScheduledTaskStore,
    scheduler: Arc<Scheduler>,
    job_tx: Sender<ScheduledJobRequest>,
    bot: Arc<Bot>,
}

impl SchedulingTools {
    pub fn new(
        task_store: ScheduledTaskStore,
        scheduler: Arc<Scheduler>,
        job_tx: Sender<ScheduledJobRequest>,
        bot: Arc<Bot>,
    ) -> Self {
        Self {
            task_store,
            scheduler,
            job_tx,
            bot,
        }
    }
}

#[async_trait]
impl ToolHandler for SchedulingTools {
    fn define(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "schedule_task".to_string(),
                    description: "Schedule a task to run at a future time.".to_string(),
                    parameters: json!({
                        "type": "object",
                        "properties": {
                            "trigger_type": { "type": "string", "enum": ["one_shot", "recurring"] },
                            "trigger_value": { "type": "string", "description": "ISO 8601 (one_shot) or 6-field cron (recurring)" },
                            "prompt": { "type": "string", "description": "The message the agent will process" },
                            "description": { "type": "string", "description": "Human-readable label" }
                        },
                        "required": ["trigger_type", "trigger_value", "prompt", "description"]
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "list_scheduled_tasks".to_string(),
                    description: "List all active scheduled tasks for the current user."
                        .to_string(),
                    parameters: json!({ "type": "object", "properties": {} }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "cancel_scheduled_task".to_string(),
                    description: "Cancel an active scheduled task by its ID.".to_string(),
                    parameters: json!({
                        "type": "object", "properties": {
                            "task_id": { "type": "string", "description": "The task ID from list_scheduled_tasks" }
                        }, "required": ["task_id"]
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "get_scheduled_task_history".to_string(),
                    description: "Retrieve execution history for a scheduled task.".to_string(),
                    parameters: json!({
                        "type": "object", "properties": {
                            "task_id": { "type": "string" }
                        }, "required": ["task_id"]
                    }),
                },
            },
            ToolDefinition {
                tool_type: "function".to_string(),
                function: FunctionDefinition {
                    name: "rerun_scheduled_task".to_string(),
                    description: "Execute a scheduled task immediately.".to_string(),
                    parameters: json!({
                        "type": "object", "properties": {
                            "task_id": { "type": "string" }
                        }, "required": ["task_id"]
                    }),
                },
            },
        ]
    }

    async fn execute(&self, name: &str, args: Value, ctx: ToolContext) -> ToolResult {
        match name {
            "schedule_task" => {
                let trigger_type = args["trigger_type"]
                    .as_str()
                    .context("Missing 'trigger_type'")?
                    .to_string();
                let trigger_value = args["trigger_value"]
                    .as_str()
                    .context("Missing 'trigger_value'")?
                    .to_string();
                let prompt_text = args["prompt"]
                    .as_str()
                    .context("Missing 'prompt'")?
                    .to_string();
                let description = args["description"]
                    .as_str()
                    .context("Missing 'description'")?
                    .to_string();

                use crate::agent::parse_one_shot_delay;
                use crate::agent::validate_cron_expr;

                let delay = if trigger_type == "one_shot" {
                    Some(
                        parse_one_shot_delay(&trigger_value)
                            .map_err(|e| anyhow::anyhow!("Invalid trigger: {e}"))?,
                    )
                } else if trigger_type == "recurring" {
                    validate_cron_expr(&trigger_value)
                        .map_err(|e| anyhow::anyhow!("Invalid cron expression: {e}"))?;
                    None
                } else {
                    anyhow::bail!(
                        "Unknown trigger_type '{trigger_type}'. Use 'one_shot' or 'recurring'."
                    );
                };

                let task_id = Uuid::new_v4().to_string();
                let task_id_for_sched = task_id.clone();
                let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
                let task = ScheduledTask {
                    id: task_id.clone(),
                    scheduler_job_id: None,
                    user_id: ctx.user_id.clone(),
                    chat_id: ctx.chat_id.clone(),
                    platform: "telegram".to_string(),
                    trigger_type: trigger_type.clone(),
                    trigger_value: trigger_value.clone(),
                    prompt: prompt_text.clone(),
                    description: description.clone(),
                    status: "registering".to_string(),
                    created_at: now.clone(),
                    next_run_at: if trigger_type == "recurring" {
                        None
                    } else {
                        Some(trigger_value.clone())
                    },
                };
                if let Err(e) = self.task_store.create(&task).await {
                    return Ok(format!("Failed to save task: {}", e));
                }

                let job_tx = self.job_tx.clone();
                let bot_clone = self.bot.clone();
                let store_clone = self.task_store.clone();
                let uid = ctx.user_id.clone();
                let cid = ctx.chat_id.clone();
                let prompt_cap = prompt_text.clone();
                let is_recurring = trigger_type == "recurring";
                let tv = trigger_value.clone();

                let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
                let fire = move || {
                    let ready = ready_rx.clone();
                    let tx = job_tx.clone();
                    let bot = bot_clone.clone();
                    let store = store_clone.clone();
                    let uid = uid.clone();
                    let cid = cid.clone();
                    let prompt = prompt_cap.clone();
                    let tid = task_id_for_sched.clone();
                    let recurring = is_recurring;
                    Box::pin(async move {
                        let incoming = crate::platform::IncomingMessage {
                            platform: "scheduled_task".to_string(),
                            user_id: format!("{uid}:{tid}"),
                            chat_id: cid,
                            user_name: String::new(),
                            text: prompt,
                            attachments: vec![],
                        };
                        let req = ScheduledJobRequest {
                            incoming,
                            bot,
                            task_id: tid,
                            is_recurring: recurring,
                            generation: 0,
                            run_reason: RunReason::Scheduled,
                            task_store: store,
                        };
                        crate::agent::dispatch_registered(&tx, req, ready).await;
                    })
                        as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
                };

                let sched_result = if let Some(d) = delay {
                    self.scheduler.add_one_shot_job(d, &description, fire).await
                } else {
                    self.scheduler.add_cron_job(&tv, &description, fire).await
                };

                match sched_result {
                    Ok(sched_id) => {
                        // Persist scheduler_job_id so cancellation can remove the job from the scheduler (HG-05)
                        if let Err(e) = self
                            .task_store
                            .register_generation(&task_id, 0, &sched_id.to_string())
                            .await
                        {
                            tracing::warn!(
                                "Failed to persist scheduler_job_id for task {}: {}, rolling back",
                                task_id,
                                e
                            );
                            let invalidation = self
                                .task_store
                                .finish_generation(&task_id, 0, "failed_registration")
                                .await;
                            let cleanup = self.scheduler.remove_job(sched_id).await;
                            invalidation
                                .context("Failed to invalidate unpersisted scheduler job")?;
                            cleanup.context("Failed to clean up unpersisted scheduler job")?;
                            return Ok(format!("Failed to persist scheduler job ID: {}", e));
                        }
                        // Publish only after the generation + UUID persistence CAS succeeds.
                        ready_tx.send_replace(true);
                        Ok(format!(
                            "Task scheduled! ID: {} — {} ({})",
                            task_id, description, trigger_value
                        ))
                    }
                    Err(e) => {
                        self.task_store
                            .finish_generation(&task_id, 0, "failed_registration")
                            .await?;
                        Ok(format!("Failed to register task with scheduler: {}", e))
                    }
                }
            }
            "list_scheduled_tasks" => {
                match self.task_store.list_active_for_user(&ctx.user_id).await {
                    Ok(tasks) if tasks.is_empty() => Ok("No active scheduled tasks.".to_string()),
                    Ok(tasks) => {
                        let tasks: Vec<ScheduledTask> = tasks;
                        let mut out = format!("Active scheduled tasks ({}):\n\n", tasks.len());
                        for t in &tasks {
                            out.push_str(&format!(
                                "ID: {}\nDescription: {}\nType: {} | Trigger: {}\nPrompt: {}\n\n",
                                t.id, t.description, t.trigger_type, t.trigger_value, t.prompt
                            ));
                        }
                        Ok(out)
                    }
                    Err(e) => Ok(format!("Failed to list tasks: {}", e)),
                }
            }
            "cancel_scheduled_task" => {
                let task_id = args["task_id"].as_str().context("Missing 'task_id'")?;
                let task = match self.task_store.get_owned(task_id, &ctx.user_id).await {
                    Ok(Some(t)) => t,
                    Ok(None) => return Ok(format!("Task not found: {task_id}")),
                    Err(e) => return Ok(format!("Failed to look up task: {e}")),
                };
                if task.status == "cancelled" {
                    return Ok(format!("Cancelled task {task_id}"));
                }
                // Fence queued and delayed callbacks before attempting scheduler cleanup.
                self.task_store.set_status(task_id, "cancelled").await?;
                if let Some(ref sched_id_str) = task.scheduler_job_id {
                    let sched_uuid = sched_id_str
                        .parse::<uuid::Uuid>()
                        .context("Cancelled task has invalid scheduler job ID")?;
                    self.scheduler
                        .remove_job(sched_uuid)
                        .await
                        .context("Task cancelled, but scheduler cleanup failed")?;
                }
                Ok(format!("Cancelled task {task_id}"))
            }
            "get_scheduled_task_history" => {
                let task_id = args["task_id"].as_str().context("Missing 'task_id'")?;
                match self.task_store.get_owned(task_id, &ctx.user_id).await {
                    Ok(Some(_)) => {}
                    Ok(None) => return Ok(format!("Task not found: {task_id}")),
                    Err(e) => return Ok(format!("Failed to look up task: {e}")),
                }
                let runs: Vec<crate::scheduler::reminders::ScheduledTaskRun> =
                    match self.task_store.get_task_runs(task_id, 50).await {
                        Ok(r) => r,
                        Err(e) => return Ok(format!("Failed to get history: {}", e)),
                    };
                if runs.is_empty() {
                    Ok("No history for this task.".to_string())
                } else {
                    let lines: Vec<String> = runs
                        .iter()
                        .map(|r| {
                            // Display response or fallback to error message (HG-06)
                            let text = r.response.as_deref().or(r.error.as_deref()).unwrap_or("");
                            let response_preview = text.chars().take(100).collect::<String>();
                            format!("[{}] {} — {}", r.run_at, r.status, response_preview)
                        })
                        .collect();
                    Ok(lines.join("\n"))
                }
            }
            "rerun_scheduled_task" => {
                let task_id = args["task_id"].as_str().context("Missing 'task_id'")?;
                let task = match self.task_store.get_owned(task_id, &ctx.user_id).await {
                    Ok(Some(t)) => t,
                    Ok(None) => return Ok(format!("Task not found: {task_id}")),
                    Err(e) => return Ok(format!("Task not found: {}", e)),
                };
                let job_tx = self.job_tx.clone();
                let bot_clone = self.bot.clone();
                let store_clone = self.task_store.clone();
                let tid = task_id.to_string();
                let uid = task.user_id.clone();
                let cid = task.chat_id.clone();
                let prompt_cap = task.prompt.clone();
                let is_recurring = task.trigger_type == "recurring";
                let previous_generation = self.task_store.generation(task_id).await?;
                let generation = if is_recurring {
                    anyhow::ensure!(
                        task.status == "active",
                        "Recurring parent must be active to rerun"
                    );
                    previous_generation
                } else {
                    anyhow::ensure!(
                        !matches!(task.status.as_str(), "active" | "registering"),
                        "One-shot task already pending; cancel it before rerunning"
                    );
                    self.task_store
                        .reactivate(task_id, previous_generation, &task.status)
                        .await?
                };
                let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
                let fire = move || {
                    let ready = ready_rx.clone();
                    let tx = job_tx.clone();
                    let bot = bot_clone.clone();
                    let store = store_clone.clone();
                    let tid = tid.clone();
                    let uid = uid.clone();
                    let cid = cid.clone();
                    let prompt = prompt_cap.clone();
                    let recurring = is_recurring;
                    Box::pin(async move {
                        let incoming = crate::platform::IncomingMessage {
                            platform: "scheduled_task".to_string(),
                            user_id: format!("{uid}:{tid}"),
                            chat_id: cid,
                            user_name: String::new(),
                            text: prompt,
                            attachments: vec![],
                        };
                        let req = ScheduledJobRequest {
                            incoming,
                            bot,
                            task_id: tid,
                            is_recurring: recurring,
                            generation,
                            run_reason: RunReason::ManualRerun,
                            task_store: store,
                        };
                        crate::agent::dispatch_registered(&tx, req, ready).await;
                    })
                        as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
                };
                match self
                    .scheduler
                    .add_one_shot_job(std::time::Duration::from_secs(1), &task.description, fire)
                    .await
                {
                    Ok(sched_id) => {
                        // For non-recurring tasks, update scheduler_job_id so cancel can remove it if needed (HG-05/06)
                        if !is_recurring {
                            if let Err(error) = self
                                .task_store
                                .register_generation(task_id, generation, &sched_id.to_string())
                                .await
                            {
                                let invalidation = self
                                    .task_store
                                    .finish_generation(task_id, generation, "failed_registration")
                                    .await;
                                let cleanup = self.scheduler.remove_job(sched_id).await;
                                invalidation.context("Failed to invalidate unpersisted rerun")?;
                                cleanup.context(
                                    "Failed to clean up rerun after persistence failure",
                                )?;
                                return Err(error.context("Failed to persist rerun scheduler job"));
                            }
                        }
                        ready_tx.send_replace(true);
                        Ok(format!("Re-run scheduled for task {task_id}"))
                    }
                    Err(e) => {
                        // Revert status if scheduler registration failed (HG-06)
                        if !is_recurring {
                            self.task_store
                                .finish_generation(task_id, generation, &task.status)
                                .await?;
                        }
                        Ok(format!("Failed to re-run task: {}", e))
                    }
                }
            }
            _ => anyhow::bail!("SchedulingTools: unknown tool {name}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::MemoryStore;
    use crate::platform::sender::{MessageFormat, PlatformMessageId, PlatformSender};
    use crate::scheduler::reminders::ScheduledTask;
    use crate::scheduler::Scheduler;
    use std::path::Path;
    use std::sync::Arc;

    struct DummySender;
    #[async_trait::async_trait]
    impl PlatformSender for DummySender {
        async fn send_message(
            &self,
            _: &str,
            _: &str,
            _: MessageFormat,
        ) -> anyhow::Result<PlatformMessageId> {
            Ok("dummy".to_string())
        }
        async fn send_file(
            &self,
            _: &str,
            _: &Path,
            _: Option<&str>,
        ) -> anyhow::Result<PlatformMessageId> {
            Ok("dummy".to_string())
        }
        async fn show_cancel_button(
            &self,
            _: &str,
            _: &str,
            _: &str,
        ) -> anyhow::Result<PlatformMessageId> {
            Ok("dummy".to_string())
        }
        async fn edit_message(
            &self,
            _: &str,
            _: &PlatformMessageId,
            _: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
        async fn delete_message(&self, _: &str, _: &PlatformMessageId) -> anyhow::Result<()> {
            Ok(())
        }
        async fn notify_shutdown(&self, _: &str) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn test_context() -> ToolContext {
        ToolContext {
            sandbox_dir: std::path::PathBuf::from("/tmp"),
            home_dir: None,
            sender: Arc::new(DummySender),
            cancel_registry: Arc::new(crate::cancel_registry::CancelRegistry::new()),
            user_id: "user-123".into(),
            chat_id: "456".into(),
            tool_ui_mode: crate::tool_registry::ToolUiMode::Minimal,
        }
    }

    #[tokio::test]
    async fn cancel_tool_removes_raw_scheduler_callback() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let store = ScheduledTaskStore::new(memory.connection());
        let scheduler = Arc::new(Scheduler::new().await.unwrap());
        scheduler.start().await.unwrap();
        let (raw_tx, mut raw_rx) = tokio::sync::mpsc::channel(1);
        let retained_sender = raw_tx.clone();
        let id = scheduler
            .add_one_shot_job(
                std::time::Duration::from_secs(1),
                "cancel-tool-raw",
                move || {
                    Box::pin(async move {
                        raw_tx.try_send(()).unwrap();
                    })
                },
            )
            .await
            .unwrap();
        let task = ScheduledTask {
            id: "cancel-tool-raw".into(),
            scheduler_job_id: Some(id.to_string()),
            user_id: "user-123".into(),
            chat_id: "456".into(),
            platform: "telegram".into(),
            trigger_type: "one_shot".into(),
            trigger_value: "2099-01-01".into(),
            prompt: "test".into(),
            description: "test".into(),
            status: "active".into(),
            created_at: "2026-01-01".into(),
            next_run_at: None,
        };
        store.create(&task).await.unwrap();
        let (job_tx, _) = tokio::sync::mpsc::channel(1);
        let tools = SchedulingTools::new(
            store,
            scheduler.clone(),
            job_tx,
            Arc::new(Bot::new("TEST_TOKEN")),
        );
        tools
            .execute(
                "cancel_scheduled_task",
                json!({"task_id": task.id}),
                test_context(),
            )
            .await
            .unwrap();
        // Raw callback bypasses eligibility: only actual scheduler removal can pass.
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(3), raw_rx.recv())
                .await
                .is_err()
        );
        drop(retained_sender);
        let (control_tx, mut control_rx) = tokio::sync::mpsc::channel(1);
        scheduler
            .add_one_shot_job(
                std::time::Duration::from_secs(1),
                "cancel-control",
                move || {
                    Box::pin(async move {
                        control_tx.try_send(()).unwrap();
                    })
                },
            )
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(4), control_rx.recv())
                .await
                .unwrap(),
            Some(())
        );
    }

    #[tokio::test]
    async fn removing_live_scheduler_job_prevents_callback() {
        let scheduler = Scheduler::new().await.unwrap();
        scheduler.start().await.unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        // Keep this sender alive: a removed callback drops its own sender.
        let retained_sender = tx.clone();
        let id = scheduler
            .add_one_shot_job(
                std::time::Duration::from_secs(1),
                "remove-live",
                move || {
                    Box::pin(async move {
                        tx.try_send(()).unwrap();
                    })
                },
            )
            .await
            .unwrap();
        scheduler.remove_job(id).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv())
                .await
                .is_err()
        );
        drop(retained_sender);
        // Positive control proves the same live scheduler actually fires raw callbacks.
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        scheduler
            .add_one_shot_job(
                std::time::Duration::from_secs(1),
                "live-control",
                move || {
                    Box::pin(async move {
                        tx.try_send(()).unwrap();
                    })
                },
            )
            .await
            .unwrap();
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_secs(4), rx.recv())
                .await
                .unwrap(),
            Some(())
        );
    }

    #[tokio::test]
    async fn registration_gate_holds_early_fire_until_decision() {
        for decision in [
            "success",
            "failure",
            "cancel",
            "cancel_after_ready",
            "committed_without_signal",
            "timeout",
            "committed_before_timeout",
        ] {
            let memory = MemoryStore::open_in_memory().unwrap();
            let store = ScheduledTaskStore::new(memory.connection());
            let task = ScheduledTask {
                id: decision.into(),
                scheduler_job_id: None,
                user_id: "user".into(),
                chat_id: "456".into(),
                platform: "telegram".into(),
                trigger_type: "one_shot".into(),
                trigger_value: "2099-01-01".into(),
                prompt: "test".into(),
                description: "test".into(),
                status: "registering".into(),
                created_at: "2026-01-01".into(),
                next_run_at: None,
            };
            store.create(&task).await.unwrap();
            let (tx, mut rx) = tokio::sync::mpsc::channel(1);
            let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
            let req = ScheduledJobRequest {
                incoming: crate::platform::IncomingMessage {
                    platform: "scheduled_task".into(),
                    user_id: "user:test".into(),
                    chat_id: "456".into(),
                    user_name: String::new(),
                    text: "test".into(),
                    attachments: vec![],
                },
                bot: Arc::new(Bot::new("TEST_TOKEN")),
                task_id: task.id.clone(),
                is_recurring: false,
                generation: 0,
                run_reason: RunReason::Scheduled,
                task_store: store.clone(),
            };
            // Poll the real callback to pending before deciding registration; no timing race.
            let fire = crate::agent::dispatch_registered(&tx, req, ready_rx);
            tokio::pin!(fire);
            assert!(futures::poll!(&mut fire).is_pending());
            assert!(rx.try_recv().is_err());
            match decision {
                "success" => {
                    store
                        .register_generation(&task.id, 0, &Uuid::new_v4().to_string())
                        .await
                        .unwrap();
                    ready_tx.send(true).unwrap();
                }
                "cancel_after_ready" => {
                    store
                        .register_generation(&task.id, 0, &Uuid::new_v4().to_string())
                        .await
                        .unwrap();
                    ready_tx.send(true).unwrap();
                    store.set_status(&task.id, "cancelled").await.unwrap();
                }
                "cancel" => {
                    store.set_status(&task.id, "cancelled").await.unwrap();
                    assert!(store
                        .register_generation(&task.id, 0, &Uuid::new_v4().to_string())
                        .await
                        .is_err());
                    drop(ready_tx);
                }
                "committed_without_signal" => {
                    store
                        .register_generation(&task.id, 0, &Uuid::new_v4().to_string())
                        .await
                        .unwrap();
                    // Durable CAS wins; simulate lost publication by dropping the sender.
                    drop(ready_tx);
                }
                "committed_before_timeout" => {
                    store
                        .register_generation(&task.id, 0, &Uuid::new_v4().to_string())
                        .await
                        .unwrap();
                    // Keep publication withheld across the actual production deadline.
                }
                "timeout" => { /* Keep the pending decision sender alive through the bound. */ }
                _ => {
                    drop(ready_tx);
                }
            }
            let bound = if matches!(decision, "timeout" | "committed_before_timeout") {
                31
            } else {
                1
            };
            tokio::time::timeout(std::time::Duration::from_secs(bound), fire)
                .await
                .unwrap();
            if matches!(
                decision,
                "success" | "committed_without_signal" | "committed_before_timeout"
            ) {
                assert!(store.is_eligible(&task.id, 0).await.unwrap());
                assert_eq!(rx.try_recv().unwrap().task_id, task.id);
            } else {
                assert!(!store.is_eligible(&task.id, 0).await.unwrap());
                assert!(
                    store
                        .register_generation(&task.id, 0, &Uuid::new_v4().to_string())
                        .await
                        .is_err(),
                    "rejected callback must fence a late commit"
                );
            }
            assert!(
                rx.try_recv().is_err(),
                "{decision} must not dispatch extra work"
            );
        }
    }

    #[tokio::test]
    async fn full_queue_rejects_without_waiting_and_records_run() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let store = ScheduledTaskStore::new(memory.connection());
        let task = ScheduledTask {
            id: "queue".into(),
            scheduler_job_id: None,
            user_id: "user".into(),
            chat_id: "456".into(),
            platform: "telegram".into(),
            trigger_type: "one_shot".into(),
            trigger_value: "2099-01-01".into(),
            prompt: "test".into(),
            description: "test".into(),
            status: "active".into(),
            created_at: "2026-01-01".into(),
            next_run_at: None,
        };
        store.create(&task).await.unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let request = || ScheduledJobRequest {
            incoming: crate::platform::IncomingMessage {
                platform: "scheduled_task".into(),
                user_id: "user:queue".into(),
                chat_id: "456".into(),
                user_name: String::new(),
                text: "test".into(),
                attachments: vec![],
            },
            bot: Arc::new(Bot::new("TEST_TOKEN")),
            task_id: task.id.clone(),
            is_recurring: false,
            generation: 0,
            run_reason: RunReason::ManualRerun,
            task_store: store.clone(),
        };
        crate::agent::dispatch_scheduled(&tx, request()).await;
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            crate::agent::dispatch_scheduled(&tx, request()),
        )
        .await
        .unwrap();
        assert_eq!(
            store.get_task_runs(&task.id, 10).await.unwrap()[0].status,
            "rejected"
        );
        let queued = rx.recv().await.unwrap();
        assert!(!store
            .is_eligible(&queued.task_id, queued.generation)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn manual_delayed_rerun_cancellation_never_dispatches() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let task_store = ScheduledTaskStore::new(memory.connection());
        let scheduler = Arc::new(Scheduler::new().await.unwrap());
        scheduler.start().await.unwrap();
        let (job_tx, mut job_rx) = tokio::sync::mpsc::channel(1);
        let tools = SchedulingTools::new(
            task_store.clone(),
            scheduler,
            job_tx,
            Arc::new(Bot::new("TEST_TOKEN")),
        );
        let task = ScheduledTask {
            id: "manual-cancel".into(),
            scheduler_job_id: None,
            user_id: "user-123".into(),
            chat_id: "456".into(),
            platform: "telegram".into(),
            trigger_type: "recurring".into(),
            trigger_value: "0 * * * * *".into(),
            prompt: "test".into(),
            description: "test".into(),
            status: "active".into(),
            created_at: "2026-01-01".into(),
            next_run_at: None,
        };
        task_store.create(&task).await.unwrap();
        tools
            .execute(
                "rerun_scheduled_task",
                json!({"task_id":task.id}),
                test_context(),
            )
            .await
            .unwrap();
        tools
            .execute(
                "cancel_scheduled_task",
                json!({"task_id":task.id}),
                test_context(),
            )
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(4), job_rx.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_schedule_task_stores_scheduler_job_id() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let task_store = ScheduledTaskStore::new(memory.connection());
        let scheduler = Arc::new(Scheduler::new().await.unwrap());
        scheduler.start().await.unwrap();
        let (job_tx, _job_rx) = tokio::sync::mpsc::channel(64);
        let bot = Arc::new(teloxide::Bot::new("TEST_TOKEN"));

        let tools = SchedulingTools::new(task_store.clone(), scheduler, job_tx, bot);

        let future_time = (chrono::Utc::now() + chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        let args = serde_json::json!({
            "trigger_type": "one_shot",
            "trigger_value": future_time,
            "prompt": "Test prompt",
            "description": "Test description"
        });

        let res = tools
            .execute("schedule_task", args, test_context())
            .await
            .unwrap();
        assert!(res.contains("Task scheduled! ID:"));

        let tasks = task_store.list_active_for_user("user-123").await.unwrap();
        assert_eq!(tasks.len(), 1);
        let task = &tasks[0];
        // HG-05: scheduler_job_id must be populated and parseable as Uuid
        assert!(task.scheduler_job_id.is_some());
        let job_id_str = task.scheduler_job_id.as_ref().unwrap();
        assert!(uuid::Uuid::parse_str(job_id_str).is_ok());
    }

    #[tokio::test]
    async fn test_cancel_scheduled_task_removes_from_scheduler_and_marks_cancelled() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let task_store = ScheduledTaskStore::new(memory.connection());
        let scheduler = Arc::new(Scheduler::new().await.unwrap());
        scheduler.start().await.unwrap();
        let (job_tx, _job_rx) = tokio::sync::mpsc::channel(64);
        let bot = Arc::new(teloxide::Bot::new("TEST_TOKEN"));

        let tools = SchedulingTools::new(task_store.clone(), Arc::clone(&scheduler), job_tx, bot);

        // Schedule task first
        let future_time = (chrono::Utc::now() + chrono::Duration::hours(1))
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string();
        let args = serde_json::json!({
            "trigger_type": "one_shot",
            "trigger_value": future_time,
            "prompt": "Test prompt",
            "description": "Test description"
        });

        let _res = tools
            .execute("schedule_task", args, test_context())
            .await
            .unwrap();
        let tasks = task_store.list_active_for_user("user-123").await.unwrap();
        let task_id = &tasks[0].id;
        let _job_id = uuid::Uuid::parse_str(tasks[0].scheduler_job_id.as_ref().unwrap()).unwrap();

        // Cancel task
        let cancel_args = serde_json::json!({ "task_id": task_id });
        let cancel_res = tools
            .execute("cancel_scheduled_task", cancel_args, test_context())
            .await
            .unwrap();
        assert_eq!(cancel_res, format!("Cancelled task {task_id}"));

        // Task should now be cancelled in DB
        let updated = task_store.get_by_id(task_id).await.unwrap().unwrap();
        assert_eq!(updated.status, "cancelled");

        let duplicate = tools
            .execute(
                "cancel_scheduled_task",
                serde_json::json!({"task_id": task_id}),
                test_context(),
            )
            .await
            .unwrap();
        assert_eq!(duplicate, cancel_res);
    }

    #[tokio::test]
    async fn test_rerun_scheduled_task_handles_status_and_job_id() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let task_store = ScheduledTaskStore::new(memory.connection());
        let scheduler = Arc::new(Scheduler::new().await.unwrap());
        scheduler.start().await.unwrap();
        let (job_tx, _job_rx) = tokio::sync::mpsc::channel(64);
        let bot = Arc::new(teloxide::Bot::new("TEST_TOKEN"));

        let tools = SchedulingTools::new(task_store.clone(), scheduler, job_tx, bot);

        // Create completed task in DB
        let task = ScheduledTask {
            id: "task-completed-1".into(),
            scheduler_job_id: None,
            user_id: "user-123".into(),
            chat_id: "456".into(),
            platform: "telegram".into(),
            trigger_type: "one_shot".into(),
            trigger_value: "in 1 minute".into(),
            prompt: "Test prompt".into(),
            description: "Completed task".into(),
            status: "completed".into(),
            created_at: "2026-07-13T10:00:00".into(),
            next_run_at: None,
        };
        task_store.create(&task).await.unwrap();
        task_store
            .set_status("task-completed-1", "completed")
            .await
            .unwrap();

        // Rerun the task
        let rerun_args = serde_json::json!({ "task_id": "task-completed-1" });
        let rerun_res = tools
            .execute("rerun_scheduled_task", rerun_args, test_context())
            .await
            .unwrap();
        assert_eq!(rerun_res, "Re-run scheduled for task task-completed-1");

        // Status should be reset to active for the rerun and have a new scheduler_job_id
        let updated = task_store
            .get_by_id("task-completed-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, "active");
        assert!(updated.scheduler_job_id.is_some());
        let generation = task_store.generation(&updated.id).await.unwrap();
        assert!(tools
            .execute(
                "rerun_scheduled_task",
                json!({"task_id": updated.id}),
                test_context()
            )
            .await
            .is_err());
        assert_eq!(
            task_store.generation(&updated.id).await.unwrap(),
            generation
        );
    }

    #[tokio::test]
    async fn test_get_scheduled_task_history_shows_error_when_response_is_none() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let task_store = ScheduledTaskStore::new(memory.connection());
        let scheduler = Arc::new(Scheduler::new().await.unwrap());
        let (job_tx, _job_rx) = tokio::sync::mpsc::channel(64);
        let bot = Arc::new(teloxide::Bot::new("TEST_TOKEN"));

        let tools = SchedulingTools::new(task_store.clone(), scheduler, job_tx, bot);

        let task = ScheduledTask {
            id: "task-hist-1".into(),
            scheduler_job_id: None,
            user_id: "user-123".into(),
            chat_id: "456".into(),
            platform: "telegram".into(),
            trigger_type: "one_shot".into(),
            trigger_value: "in 1 minute".into(),
            prompt: "Test prompt".into(),
            description: "History task".into(),
            status: "failed".into(),
            created_at: "2026-07-13T10:00:00".into(),
            next_run_at: None,
        };
        task_store.create(&task).await.unwrap();

        task_store
            .insert_run(
                "run-1",
                "task-hist-1",
                "2026-07-13T10:05:00",
                None,
                Some("Network timeout during execution"),
                "failed",
            )
            .await
            .unwrap();

        task_store
            .insert_run(
                "run-2",
                "task-hist-1",
                "2026-07-13T10:06:00",
                None,
                Some("Task misfired: trigger time passed"),
                "misfired",
            )
            .await
            .unwrap();

        let hist_args = serde_json::json!({ "task_id": "task-hist-1" });
        let hist_res = tools
            .execute("get_scheduled_task_history", hist_args, test_context())
            .await
            .unwrap();

        assert!(hist_res.contains("failed — Network timeout during execution"));
        assert!(hist_res.contains("misfired — Task misfired: trigger time passed"));
    }

    #[tokio::test]
    async fn test_ownership_enforcement() {
        let memory = MemoryStore::open_in_memory().unwrap();
        let task_store = ScheduledTaskStore::new(memory.connection());
        let scheduler = Arc::new(Scheduler::new().await.unwrap());
        scheduler.start().await.unwrap();
        let (job_tx, _job_rx) = tokio::sync::mpsc::channel(64);
        let bot = Arc::new(teloxide::Bot::new("TEST_TOKEN"));

        let tools = SchedulingTools::new(task_store.clone(), scheduler, job_tx, bot);

        let task = ScheduledTask {
            id: "task-owned-by-alice".into(),
            scheduler_job_id: None,
            user_id: "alice".into(),
            chat_id: "456".into(),
            platform: "telegram".into(),
            trigger_type: "one_shot".into(),
            trigger_value: "in 1 minute".into(),
            prompt: "Alice prompt".into(),
            description: "Alice task".into(),
            status: "active".into(),
            created_at: "2026-07-13T10:00:00".into(),
            next_run_at: None,
        };
        task_store.create(&task).await.unwrap();

        let bob_ctx = || {
            let mut ctx = test_context();
            ctx.user_id = "bob".into();
            ctx
        };

        // Bob tries to cancel Alice's task -> should fail
        let cancel_res = tools
            .execute(
                "cancel_scheduled_task",
                serde_json::json!({ "task_id": "task-owned-by-alice" }),
                bob_ctx(),
            )
            .await
            .unwrap();
        assert!(cancel_res.contains("Task not found: task-owned-by-alice"));

        // Bob tries to get history of Alice's task -> should fail
        let hist_res = tools
            .execute(
                "get_scheduled_task_history",
                serde_json::json!({ "task_id": "task-owned-by-alice" }),
                bob_ctx(),
            )
            .await
            .unwrap();
        assert!(hist_res.contains("Task not found: task-owned-by-alice"));

        // Bob tries to rerun Alice's task -> should fail
        let rerun_res = tools
            .execute(
                "rerun_scheduled_task",
                serde_json::json!({ "task_id": "task-owned-by-alice" }),
                bob_ctx(),
            )
            .await
            .unwrap();
        assert!(rerun_res.contains("Task not found: task-owned-by-alice"));

        // Alice CAN cancel her own task
        let mut alice_ctx = test_context();
        alice_ctx.user_id = "alice".into();
        let alice_cancel = tools
            .execute(
                "cancel_scheduled_task",
                serde_json::json!({ "task_id": "task-owned-by-alice" }),
                alice_ctx,
            )
            .await
            .unwrap();
        assert_eq!(alice_cancel, "Cancelled task task-owned-by-alice");
    }
}
