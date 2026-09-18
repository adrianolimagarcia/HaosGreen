use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use haos_green::agent::Agent;
use haos_green::config::Config;
use haos_green::mcp::McpManager;
use haos_green::memory::MemoryStore;
use haos_green::platform;
use haos_green::provider;
use haos_green::scheduler::tasks::register_builtin_tasks;
use haos_green::scheduler::Scheduler;
use haos_green::setup;
use haos_green::skills::loader::load_skills_from_dir;
use haos_green::tool_registry::ToolUiMode;

#[tokio::main]
async fn main() -> Result<()> {
    let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);
    let shutdown_tx = Arc::new(shutdown_tx);
    // fills it. It is built before the subscriber because the layer needs the
    // handle, and it is shared with `web::spawn` so the routes read the same
    // ring the layer writes to.
    //
    // The ring is bounded by `LOG_BUFFER_CAPACITY` entries *and* by the byte
    // budget in `web::logs` — an entry count alone bounds nothing in bytes — and
    // it stays empty until the dashboard is known to be enabled (see
    // `log_capture` below).
    let logs = Arc::new(haos_green::web::logs::LogBuffer::new(
        haos_green::web::state::LOG_BUFFER_CAPACITY,
    ));

    // Whether the ring is recording.
    //
    // The subscriber has to be installed before anything can log, and `--setup`
    // and `--service` run before a configuration has been read at all, so the
    // layer cannot simply be left out for an instance whose `[web].enabled`
    // turns out to be false. It is disarmed instead and armed below, once the
    // configuration says the dashboard is on: until then `on_event` returns on
    // one relaxed load, and the process pays neither the field visitor, nor the
    // redaction pass, nor the timestamp, and retains nothing.
    let log_capture = Arc::new(AtomicBool::new(false));

    // Initialize logging
    //
    // `web::logs::log_subscriber` is the stack that carries both the operator's
    // `EnvFilter` and the dashboard's `LogLayer`, so an event the filter
    // suppresses never reaches the buffer and the dashboard shows what the
    // terminal shows. Keeping that composition in the library is what lets a
    // test drive the same subscriber this binary installs.
    //
    // The console formatter goes on top through `web::logs::console_layer_with`,
    // never as a bare `fmt::layer()`: that layer wraps stdout in a
    // `RedactingWriter`, so the redaction `main.rs` arms below applies to the
    // terminal and to `journalctl` as well as to the dashboard's ring. Without
    // it the ring is clean and the persisted console log is not — the leak this
    // line used to be.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,haos_green=debug,rustfox=debug".into());

    haos_green::web::logs::log_subscriber(env_filter, Arc::clone(&logs), Arc::clone(&log_capture))
        .with(haos_green::web::logs::console_layer_with(std::io::stdout))
        .init();

    // Check for --setup and --service subcommands before doing anything else
    if let Some(cmd) = setup::parse_args() {
        match cmd {
            setup::Command::Setup { cli } => {
                let cfg_path = haos_green::home::resolve_config_path(
                    std::env::var("HAOS_GREEN_CONFIG_PATH")
                        .or_else(|_| std::env::var("RUSTFOX_CONFIG_PATH"))
                        .ok()
                        .as_deref(),
                    &std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                    dirs::home_dir().as_deref(),
                );
                let config_dir = cfg_path
                    .parent()
                    .map(|d| d.to_path_buf())
                    .unwrap_or_else(|| {
                        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
                    });
                return setup::wizard::run(&config_dir, cli).await;
            }
            setup::Command::Service { action } => {
                setup::service::handle(action)?;
                return Ok(());
            }
        }
    }

    // If we reach here, it's a normal bot start — resolve config path
    let config_path = haos_green::home::resolve_config_path(
        std::env::var("HAOS_GREEN_CONFIG_PATH")
            .or_else(|_| std::env::var("RUSTFOX_CONFIG_PATH"))
            .ok()
            .as_deref(),
        &std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        dirs::home_dir().as_deref(),
    );

    info!("Loading configuration from: {}", config_path.display());
    let config = Config::load(&config_path)
        .with_context(|| format!("Failed to load config from {}", config_path.display()))?;

    // Register every configured secret with the redaction filter *before*
    // anything can log one.
    //
    // Shape rules cannot catch a credential that has no recognisable shape, and
    // the most likely secret this process emits has none: a `reqwest` transport
    // error renders the request URL, so a failed Telegram call puts
    // `https://api.telegram.org/bot<token>/sendMessage` into a log message with
    // no key, no separator and no prefix. An exact-value registration catches it
    // wherever it appears — URL path, query string, or prose — and it also
    // hardens every artifact the supervisor writes, which goes through the same
    // `redact()`.
    //
    // Only the count is logged. Logging the values would be the bug.
    let registered = haos_green::supervisor::redact::register_secrets(configured_secrets(&config));

    // The dashboard is enabled, so the log ring may start recording — armed
    // *before* the line below, so the ring's first entry is the one that says
    // the scrubber is armed rather than the line after it. See `log_capture`
    // above for why this is a switch rather than an install.
    if config.web.enabled {
        log_capture.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    info!("  Secret scrubber: {registered} configured value(s) armed");

    // Build provider registry from config
    let (provider_sections, default_provider, fallback_chain) = config.build_providers();
    let registry = Arc::new(
        provider::build_registry(
            &provider_sections,
            &default_provider,
            config.parse_retry_limit(),
        )
        .context("Failed to build LLM provider registry")?,
    );
    info!(
        "  Providers: {} (default: {}, fallback: {} model(s))",
        registry.provider_count(),
        registry.default_provider_name(),
        fallback_chain.len()
    );

    // Spawn background task to warm context_window_cache for all providers
    {
        let registry_clone = Arc::clone(&registry);
        tokio::spawn(async move {
            let client = reqwest::Client::new();
            for name in registry_clone.provider_names() {
                if let Some(provider) = registry_clone.get_provider(&name) {
                    let model = provider.default_model();
                    if let Some(ctx) = provider.fetch_context_window(&client, model).await {
                        let mut cache = provider.config().context_window_cache.write().await;
                        *cache = Some(ctx);
                        tracing::info!(
                            "Context window cache: {} / {} = {} tokens",
                            name,
                            model,
                            ctx
                        );
                    }
                }
            }
        });
    }

    info!("Configuration loaded successfully");
    let default_provider_obj = registry
        .get_provider(registry.default_provider_name())
        .expect("default provider must exist");
    info!(
        "  Model: {}/{}",
        registry.default_provider_name(),
        default_provider_obj.default_model()
    );
    info!("  Sandbox: {}", config.sandbox.allowed_directory.display());
    if let Some(home) = &config.resolved_home {
        info!("  Home: {}", home.display());
    }
    info!("  Allowed users: {:?}", config.telegram.allowed_user_ids);
    info!("  MCP servers: {}", config.mcp_servers.len());
    let langsmith = std::sync::Arc::new(haos_green::langsmith::LangSmithClient::new(
        config.langsmith.as_ref(),
    ));
    if langsmith.is_enabled() {
        info!(
            "  LangSmith: enabled (project: {})",
            config.langsmith.as_ref().unwrap().project
        );
    } else {
        info!("  LangSmith: disabled (no [langsmith] config)");
    }

    // Build embedding config if configured
    let embedding_config =
        config
            .embedding
            .as_ref()
            .map(|cfg| haos_green::memory::embeddings::EmbeddingConfig {
                api_key: cfg.api_key.clone(),
                base_url: cfg.base_url.clone(),
                model: cfg.model.clone(),
                dimensions: cfg.dimensions,
            });

    // Initialize memory store (SQLite + vector embeddings)
    let memory = MemoryStore::open(
        &config.memory.database_path,
        embedding_config,
        config.memory.clone(),
    )
    .context("Failed to initialize memory store")?;
    info!("  Database: {}", config.memory.database_path.display());

    // Refresh any expiring OAuth tokens before connecting to MCP servers
    let http_client = reqwest::Client::new();
    let mut mcp_server_configs = config.mcp_servers.clone();
    let refreshed = haos_green::mcp::refresh_expiring_tokens(
        &mut mcp_server_configs,
        &config_path,
        &http_client,
    )
    .await;
    if refreshed > 0 {
        info!("  Refreshed {refreshed} expiring MCP OAuth token(s) at startup");
    }

    // Initialize MCP connections (using possibly-refreshed configs)
    let mut mcp_manager = McpManager::new();
    mcp_manager.connect_all(&mcp_server_configs).await;

    // Seed bundled skills/agents from embedded data into the home directory.
    if let Err(e) = haos_green::skills::embed::seed_skills(&config.skills.directory).await {
        warn!("Skill seeding failed: {e}");
    }
    if let Err(e) = haos_green::skills::embed::seed_agents(&config.agents.directory).await {
        warn!("Agent seeding failed: {e}");
    }
    // Write a home-side lock recording content hashes for future diff/audit.
    if let Some(home) = &config.resolved_home {
        let _ = haos_green::skills::seed::write_lock(
            "skills-lock.json",
            &config.skills.directory,
            home,
        );
        let _ = haos_green::skills::seed::write_lock(
            "agents-lock.json",
            &config.agents.directory,
            home,
        );
    }

    // Load skills from the instance directory.
    let skills =
        load_skills_from_dir(&config.skills.directory, config.skills.directory.clone()).await?;
    info!("  Skills: {}", skills.len());

    // Load agents from the instance directory.
    let agents =
        load_skills_from_dir(&config.agents.directory, config.agents.directory.clone()).await?;
    info!("  Agents: {}", agents.len());

    // Create ScheduledTaskStore sharing the existing SQLite connection
    let task_store = haos_green::scheduler::reminders::ScheduledTaskStore::new(memory.connection());

    // Create scheduler as Arc so Agent can hold it and closures can reference it
    let scheduler = Arc::new(Scheduler::new().await?);

    // Create Bot early so it can be passed to Agent
    let bot = Arc::new(teloxide::Bot::new(&config.telegram.bot_token));

    haos_green::platform::telegram::init_bot_token(config.telegram.bot_token.clone());

    // Channel for dispatching scheduled job work from fire closures to background runner
    let (job_tx, mut job_rx) =
        tokio::sync::mpsc::unbounded_channel::<haos_green::agent::ScheduledJobRequest>();

    let cancel_registry = std::sync::Arc::new(haos_green::cancel_registry::CancelRegistry::new());
    let sender: Arc<dyn haos_green::platform::sender::PlatformSender> = Arc::new(
        haos_green::platform::telegram::TelegramAdapter::new((*bot).clone()),
    );
    let a2a_skills = skills.clone();
    let skills_rw = Arc::new(tokio::sync::RwLock::new(skills.clone()));
    let agents_rw = Arc::new(tokio::sync::RwLock::new(agents.clone()));
    let restart_pending = Arc::new(AtomicBool::new(false));
    let soul_updated = Arc::new(AtomicBool::new(false));

    // The single shared handle for the outbound A2A peers. One `Arc`, cloned
    // into the `call_a2a_agent` tool below and into the dashboard's A2A state,
    // is what makes `PUT /api/a2a/outbound` reach the running agent: the route
    // writes this value, the tool reads it on its next invocation.
    let a2a_outbound: haos_green::a2a::SharedOutboundConfig =
        Arc::new(tokio::sync::RwLock::new(config.a2a.outbound.clone()));

    let mut tool_registry = haos_green::tool_registry::ToolRegistry::new();
    tool_registry.register(Box::new(haos_green::builtin_tools::BuiltinTools::new(
        config.skills.directory.clone(),
        skills_rw.clone(),
        restart_pending.clone(),
        soul_updated.clone(),
    )));
    tool_registry.register(Box::new(haos_green::memory_tools::MemoryTools::new(
        memory.clone(),
    )));
    tool_registry.register(Box::new(
        haos_green::scheduling_tools::SchedulingTools::new(
            task_store.clone(),
            Arc::clone(&scheduler),
            job_tx.clone(),
            Arc::clone(&bot),
        ),
    ));
    tool_registry.register(Box::new(haos_green::skill_tools::SkillTools::new(
        config.skills.directory.clone(),
        config.agents.directory.clone(),
        skills_rw.clone(),
        agents_rw.clone(),
    )));
    tool_registry.register(Box::new(haos_green::command_tool::CommandTool::new(
        config.sandbox.allowed_directory.clone(),
        cancel_registry.clone(),
        sender.clone(),
    )));
    // Registered unconditionally. `CallA2aAgent::define` offers nothing while
    // the shared handle holds no peers, so with an empty `[a2a.outbound]` this
    // adds no tool to the model — but it does mean a peer added later through
    // `PUT /api/a2a/outbound` is reachable without a restart. Registering it
    // only when the startup configuration was non-empty would make the first
    // peer added from the dashboard silently unusable.
    tool_registry.register(Box::new(haos_green::a2a::tool::CallA2aAgent::new(
        Arc::clone(&a2a_outbound),
    )));

    // Arc::new_cyclic so Agent can store Weak<Self> for job closure captures (breaks Arc cycle)
    let agent = Arc::new_cyclic(|weak| {
        Agent::new(
            config.clone(),
            registry.clone(),
            mcp_manager,
            memory.clone(),
            skills,
            agents,
            task_store.clone(),
            Arc::clone(&scheduler),
            weak.clone(),
            job_tx,
            Arc::clone(&langsmith),
            config_path.clone(),
            cancel_registry.clone(),
            tool_registry,
            sender.clone(),
            restart_pending.clone(),
            soul_updated.clone(),
        )
    });

    // Spawn background runner: receives ScheduledJobRequest, calls process_message, persists result, sends reply
    let agent_for_runner = Arc::clone(&agent);
    tokio::spawn(async move {
        while let Some(req) = job_rx.recv().await {
            let agent = Arc::clone(&agent_for_runner);

            // Persist run record BEFORE processing (capture fire time)
            let run_id = uuid::Uuid::new_v4().to_string();
            let run_at = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
            if let Err(e) = req
                .task_store
                .insert_run(&run_id, &req.task_id, &run_at, None, None, "running")
                .await
            {
                tracing::warn!("Failed to persist scheduled task run record: {}", e);
            }

            let response = match agent
                .process_message(&req.incoming, None, None, ToolUiMode::Minimal)
                .await
            {
                Ok(r) => {
                    if let Err(e) = req
                        .task_store
                        .update_run(&run_id, Some(&r), None, "completed")
                        .await
                    {
                        tracing::warn!("Failed to update scheduled task run record: {}", e);
                    }
                    r
                }
                Err(e) => {
                    tracing::error!("Scheduled task {} failed: {}", req.task_id, e);
                    let err_str = format!("{:#}", e);
                    if let Err(e) = req
                        .task_store
                        .update_run(&run_id, None, Some(&err_str), "failed")
                        .await
                    {
                        tracing::warn!("Failed to update failed scheduled task run record: {}", e);
                    }
                    if !req.is_recurring {
                        let _ = req.task_store.set_status(&req.task_id, "failed").await;
                    }
                    // Send error to user via rich message
                    let chat_id_val: i64 = match req.incoming.chat_id.parse() {
                        Ok(v) => v,
                        Err(_) => {
                            tracing::error!(
                                "Unparseable chat_id '{}' for task {}",
                                req.incoming.chat_id,
                                req.task_id
                            );
                            continue;
                        }
                    };
                    let chat = teloxide::types::ChatId(chat_id_val);
                    let error_msg = format!("**Scheduled task failed:** {}", e);
                    let _ = haos_green::platform::telegram::send_markdown_message(
                        &req.bot,
                        chat,
                        &error_msg,
                        haos_green::platform::telegram::MessageFormat::Auto,
                    )
                    .await;
                    continue;
                }
            };

            let chat_id_val: i64 = match req.incoming.chat_id.parse() {
                Ok(v) => v,
                Err(_) => {
                    tracing::error!(
                        "Unparseable chat_id '{}' for task {}",
                        req.incoming.chat_id,
                        req.task_id
                    );
                    continue;
                }
            };
            let chat = teloxide::types::ChatId(chat_id_val);
            if let Err(e) = haos_green::platform::telegram::send_markdown_message(
                &req.bot,
                chat,
                &response,
                haos_green::platform::telegram::MessageFormat::Auto,
            )
            .await
            {
                tracing::error!("Failed to send scheduled response: {}", e);
            }
        }
    });

    // Spawn background OAuth token refresh task: checks every 30 minutes.
    // `cfgs` is kept across ticks so that updated token_expires_at values
    // are remembered and a freshly-rotated refresh token isn't re-used.
    {
        let mut cfgs = mcp_server_configs.clone();
        let refresh_config_path = config_path.clone();
        let refresh_http_client = http_client.clone();
        tokio::spawn(async move {
            // 30-minute interval — tokens expiring within 5 min are always caught
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30 * 60));
            interval.tick().await; // skip first immediate tick
            loop {
                interval.tick().await;
                let refreshed = haos_green::mcp::refresh_expiring_tokens(
                    &mut cfgs,
                    &refresh_config_path,
                    &refresh_http_client,
                )
                .await;
                if refreshed > 0 {
                    tracing::info!(
                        "Background token refresh: updated {refreshed} MCP OAuth token(s)"
                    );
                }
            }
        });
    }

    // Register built-in background tasks and start scheduler
    let home = config
        .resolved_home
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    register_builtin_tasks(
        &scheduler,
        memory.clone(),
        haos_green::llm::LlmClient::new(registry.clone()),
        config.memory.summarize_cron.clone(),
        config.memory.summarize_threshold,
        config.learning.user_model_cron.clone(),
        home,
    )
    .await?;
    scheduler.start().await?;
    info!("  Scheduler: active");
    agent.restore_scheduled_tasks(Arc::clone(&bot)).await;
    info!("  Scheduled tasks: restored from DB");

    // Construct Supervisor with a populated backend Registry so resume /
    // future routing paths can resolve backends rather than failing with
    // "backend not found". Held alive in main's scope so the binding isn't
    // dead-code-eliminated.
    let mut sup_registry = haos_green::supervisor::backend::Registry::new();
    sup_registry.register(std::sync::Arc::new(
        haos_green::supervisor::backend::reasoning::ReasoningBackend::from_agent(
            Arc::clone(&agent),
            "supervisor".to_string(),
            "supervisor".to_string(),
        ),
    ));
    sup_registry.register(std::sync::Arc::new(
        haos_green::supervisor::backend::shell::ShellBackend::new(
            config.sandbox.allowed_directory.clone(),
        ),
    ));

    let _supervisor = Arc::new(haos_green::supervisor::Supervisor::new(
        config.supervisor.artifacts_dir.clone(),
        memory.connection(),
        sup_registry,
        config.supervisor.risk.clone(),
    ));
    match _supervisor.resumable_task_ids().await {
        Ok(ids) if !ids.is_empty() => info!(
            "  Supervisor: {} resumable task(s) found at startup",
            ids.len()
        ),
        Ok(_) => info!("  Supervisor: ready (registry has reasoning + shell backends)"),
        Err(e) => warn!("  Supervisor: failed to enumerate resumable tasks: {e}"),
    }

    // A2A listener. The outcome is *observed*, not discarded: `start_listener`
    // returns the address it actually bound and the URL the Agent Card
    // advertises, or the reason no listener is serving. That value is what the
    // dashboard's `GET /api/a2a/status` reports, so the dashboard cannot claim
    // a status nobody saw.
    let a2a_outcome = if config.a2a.enabled {
        // `spawn` binds, then derives the advertised URL from the address it
        // actually bound, so the Agent Card never advertises port 0 for an
        // ephemeral bind. Validation happens inside `start_listener`, before
        // the bind: the listener is not started on failure — but the Telegram
        // bot still is, because an A2A misconfiguration must not take the bot
        // down.
        let a2a_executor = haos_green::a2a::A2aExecutor::new(agent.clone());
        let a2a_store = haos_green::a2a::SqliteTaskStore::new(agent.memory.connection());
        haos_green::web::routes::a2a::start_listener_with_shutdown(
            &config.a2a,
            a2a_skills,
            a2a_executor,
            a2a_store,
            shutdown_tx.subscribe(),
        )
        .await
    } else {
        haos_green::web::routes::a2a::A2aListenerOutcome::Disabled
    };

    // Built whether or not the listener is running: the outbound half of the
    // A2A surface is useful with `[a2a].enabled = false` (the `call_a2a_agent`
    // tool is registered from `[a2a.outbound]` regardless), and the status
    // route reports "disabled" rather than erroring.
    //
    // `a2a_outbound` is the same handle the tool above holds, so a `PUT` on this
    // route reaches the running agent. `config_path` is the path `Config::load`
    // read at startup, so the file the route rewrites is the file the process
    // was started from.
    let a2a_web = Arc::new(haos_green::web::routes::a2a::A2aWebState::new(
        config.a2a.clone(),
        a2a_outcome,
        Arc::clone(&a2a_outbound),
        config_path.clone(),
    ));

    // Web dashboard listener. Like the A2A listener, a failure here is logged
    // and the Telegram bot keeps running: a dashboard misconfiguration must not
    // take the bot down.
    if config.web.enabled {
        if let Err(e) = config.web.validate() {
            tracing::error!(error = %e, "web configuration is invalid; the dashboard was NOT started");
        } else {
            let home = config
                .resolved_home
                .clone()
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            match haos_green::web::spawn_with_shutdown(
                config.web.clone(),
                home,
                Arc::clone(&agent),
                Arc::clone(&_supervisor),
                Arc::clone(&logs),
                Some(Arc::clone(&a2a_web)),
                {
                    let tx = Arc::clone(&shutdown_tx);
                    Arc::new(move || tx.subscribe())
                },
            )
            .await
            {
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "web dashboard failed to start"),
            }
        }
    } else {
        tracing::debug!("web dashboard disabled");
    }

    // Run the Telegram platform with signal-driven graceful shutdown
    info!("Bot is starting...");

    let dispatch_agent = Arc::clone(&agent);
    let dispatch_user_ids = config.telegram.allowed_user_ids.clone();
    let dispatch_bot = Arc::clone(&bot);
    // The **same** supervisor the dashboard holds — one `Supervisor`, one SQLite
    // store, one cross-process lease owner per run. A second one here would
    // share `haos-green.db` while believing it owned it alone.
    let dispatch_supervisor = Arc::clone(&_supervisor);

    let mut dispatch_handle = tokio::spawn(async move {
        platform::telegram::run(
            dispatch_agent,
            dispatch_user_ids,
            dispatch_bot,
            dispatch_supervisor,
        )
        .await
    });

    // Set up signal handlers (SIGINT via ctrl_c for portability, SIGTERM via unix signal)
    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to create SIGTERM handler");

    #[cfg(unix)]
    let terminate = sigterm.recv();
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, shutting down...");
        }
        _ = terminate => {
            info!("SIGTERM received, shutting down...");
        }
        result = &mut dispatch_handle => {
            // The dispatcher can finish with an error (or fail to join).  The
            // process still owns the other listeners, so always broadcast
            // shutdown and give the notification its bounded cleanup window
            // before propagating the dispatch outcome.
            let dispatch_result = result;
            let _ = shutdown_tx.send(());
            match tokio::time::timeout(
                std::time::Duration::from_secs(1),
                platform::telegram::notify_shutdown(&bot, &config.telegram.allowed_user_ids),
            )
            .await
            {
                Ok(()) => {}
                Err(_) => warn!("Telegram shutdown notification timed out"),
            }
            dispatch_result??;
            return Ok(());
        }
    };

    // Stop Telegram dispatch before the grace period so no detached work remains.
    dispatch_handle.abort();
    match tokio::time::timeout(std::time::Duration::from_secs(1), &mut dispatch_handle).await {
        Ok(Ok(Ok(()))) | Ok(Ok(Err(_))) | Ok(Err(_)) => {}
        Err(_) => warn!("Telegram dispatch did not stop within shutdown timeout"),
    }

    // Send shutdown notification
    let _ = shutdown_tx.send(());
    match tokio::time::timeout(
        std::time::Duration::from_secs(1),
        platform::telegram::notify_shutdown(&bot, &config.telegram.allowed_user_ids),
    )
    .await
    {
        Ok(()) => {}
        Err(_) => warn!("Telegram shutdown notification timed out"),
    }

    // Brief grace period for message delivery
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;

    info!("Shutdown complete.");

    Ok(())
}

/// Every secret the configuration holds, for the redaction registry.
///
/// These are registered by *value*, so they are scrubbed wherever they appear —
/// a URL path, a query string, a sentence — which is the only mechanism that
/// catches a credential with no recognisable shape. `reqwest`'s transport errors
/// are the case that matters: they render the request URL, and a Telegram bot
/// token lives in that URL's path.
///
/// Empty, unset and too-short values are filtered out by `register_secrets`
/// itself; an empty needle would match everywhere, and a needle below
/// `MIN_SECRET_LEN` is not a credential and would rewrite unrelated text. A
/// refused value is logged by length, never by value, so a mistyped token is
/// visible rather than silently unscrubbed. Nothing here is logged.
///
/// `mcp_servers[].env` is deliberately **not** registered: it is a general
/// environment map (`PATH`, `HOME`, `LANG`), and registering a value that is not
/// a secret would redact it out of every log line — the over-redaction failure
/// this module was also fixed for. A token that a server's URL embeds as a query
/// parameter is covered only by the shape rules.
fn configured_secrets(config: &Config) -> Vec<&str> {
    let mut secrets = vec![
        config.telegram.bot_token.as_str(),
        config.openrouter.api_key.as_str(),
    ];
    for peer in config.a2a.peers.values() {
        secrets.push(peer.token.as_str());
    }
    for peer in config.a2a.outbound.peers.values() {
        secrets.push(peer.token.as_str());
    }
    for server in &config.mcp_servers {
        secrets.extend(server.auth_token.as_deref());
        secrets.extend(server.refresh_token.as_deref());
    }
    secrets
}
