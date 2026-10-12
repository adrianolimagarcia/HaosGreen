//! Read-only host and runtime metrics for the dashboard's inspector panel.
//!
//! One route, `GET /api/system/stats`, on the **guarded** router: it names the
//! host's CPU, memory and disk utilisation and every tool this agent can call,
//! which is operator information and must not answer an unauthenticated
//! request. It is not on `public_router`.
//!
//! Two properties are deliberate and load-bearing:
//!
//! * **A metric that cannot be read is `null`, never a fabricated number.** The
//!   inspector draws these values as gauges; a gauge that invents a reading is
//!   worse than an empty one, because nothing distinguishes it from a real
//!   measurement. Every field below is an `Option` for exactly that reason, and
//!   the shell renders "indisponível" rather than a zero.
//! * **No secret is reachable from this module.** The response is built from
//!   structs whose fields cannot carry a token, a password or a path from the
//!   credential file. `disk.path` is the *directory* the dashboard's home lives
//!   in, never `web-auth.toml` itself.
//!
//! All host probing happens on a blocking thread: it reads `/proc`, calls
//! `statvfs`, and — for the CPU delta — sleeps between two samples. None of
//! that belongs on an async worker.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use std::path::PathBuf;
use std::time::Duration;

use crate::web::routes::a2a::A2aListenerOutcome;
use crate::web::state::WebState;

/// How long the CPU gauge integrates over.
///
/// `/proc/stat` reports cumulative jiffies, so a percentage needs two samples.
/// 120 ms is short enough to answer a poll promptly and long enough that the
/// delta is not dominated by scheduling jitter; the alternative — caching a
/// sample between requests — would make the reading depend on how often the
/// operator's browser happened to poll.
const CPU_SAMPLE_WINDOW: Duration = Duration::from_millis(120);

pub fn router() -> Router<WebState> {
    Router::new().route("/api/system/stats", get(read_stats))
}

/* ── Response shape ─────────────────────────────────────────────────────── */

#[derive(Serialize)]
struct SystemStats {
    host: HostInfo,
    cpu: CpuStats,
    memory: Option<MemoryStats>,
    disk: Option<DiskStats>,
    load: Option<LoadStats>,
    services: ServiceFlags,
    tools: ToolSummary,
}

#[derive(Serialize)]
struct HostInfo {
    os: &'static str,
    arch: &'static str,
    cores: usize,
    /// Seconds since the **host** booted, from `/proc/uptime`. It is not this
    /// process's uptime: `/proc/self/stat` would give that, but only by
    /// dividing by `sysconf(_SC_CLK_TCK)`, and the field is named for what it
    /// actually holds.
    uptime_secs: Option<u64>,
}

#[derive(Serialize)]
struct CpuStats {
    /// System-wide busy percentage over [`CPU_SAMPLE_WINDOW`].
    percent: Option<f64>,
    cores: usize,
}

#[derive(Serialize)]
struct MemoryStats {
    percent: f64,
    used_bytes: u64,
    total_bytes: u64,
}

#[derive(Serialize)]
struct DiskStats {
    percent: f64,
    used_bytes: u64,
    total_bytes: u64,
    /// The directory measured. The dashboard's home, not the credential file
    /// inside it.
    path: String,
}

#[derive(Serialize)]
struct LoadStats {
    one: f64,
    five: f64,
    fifteen: f64,
}

/// Which of the dashboard's optional handles are wired, and what the A2A
/// listener actually did.
///
/// `agent`, `supervisor` and `logs` are the same three `Option`s
/// [`WebState`] carries; a `false` here is the same fact their routes report as
/// 503. `a2a` is a word rather than a bool because "disabled" and "failed" are
/// not the same state and an operator needs to tell them apart.
#[derive(Serialize)]
struct ServiceFlags {
    agent: bool,
    supervisor: bool,
    logs: bool,
    a2a: &'static str,
}

#[derive(Serialize)]
struct ToolSummary {
    /// Every tool name the dashboard's chat may offer, from the live registry
    /// plus the connected MCP servers. Sourced from
    /// [`crate::web::routes::chat::web_tool_policy_for`], so this list and the
    /// policy the chat actually runs with cannot disagree.
    count: usize,
    names: Vec<String>,
    mcp_servers: usize,
}

/* ── Handler ────────────────────────────────────────────────────────────── */

async fn read_stats(State(state): State<WebState>) -> Response {
    // The directory the dashboard's home lives in. `credentials_path` is
    // `<home>/web-auth.toml`, so its parent is the home; falling back to `/`
    // keeps the gauge meaningful on a state built without one (the test
    // harness points it at a non-existent path).
    let disk_path = state
        .credentials_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));

    let probe = match tokio::task::spawn_blocking(move || probe_host(disk_path)).await {
        Ok(probe) => probe,
        Err(error) => {
            // A join error means the probe panicked. Report it as a failure
            // rather than as a dashboard with no CPU, which is what nulls
            // would look like.
            tracing::error!(%error, "web: the system stats probe panicked");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the system stats probe failed",
            )
                .into_response();
        }
    };

    let a2a = match &state.a2a {
        Some(a2a) => {
            let outcome = a2a.outcome.read().await;
            match &*outcome {
                A2aListenerOutcome::Disabled => "disabled",
                A2aListenerOutcome::Started { .. } => "started",
                A2aListenerOutcome::Failed { .. } => "failed",
            }
        }
        None => "unwired",
    };

    let (names, mcp_servers) = match &state.agent {
        Some(agent) => (
            crate::web::routes::chat::web_tool_policy_for(agent),
            agent.mcp.server_count(),
        ),
        None => (Vec::new(), 0),
    };

    let cores = probe.cores;
    Json(SystemStats {
        host: HostInfo {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            cores,
            uptime_secs: probe.uptime_secs,
        },
        cpu: CpuStats {
            percent: probe.cpu_percent,
            cores,
        },
        memory: probe.memory,
        disk: probe.disk,
        load: probe.load,
        services: ServiceFlags {
            agent: state.agent.is_some(),
            supervisor: state.supervisor.is_some(),
            logs: state.logs.is_some(),
            a2a,
        },
        tools: ToolSummary {
            count: names.len(),
            names,
            mcp_servers,
        },
    })
    .into_response()
}

/* ── Host probing ───────────────────────────────────────────────────────── */

#[derive(Default)]
struct HostProbe {
    cores: usize,
    cpu_percent: Option<f64>,
    memory: Option<MemoryStats>,
    disk: Option<DiskStats>,
    load: Option<LoadStats>,
    uptime_secs: Option<u64>,
}

#[cfg(target_os = "linux")]
fn probe_host(disk_path: PathBuf) -> HostProbe {
    HostProbe {
        cores: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        cpu_percent: sample_cpu_percent(),
        memory: read_memory(),
        disk: read_disk(&disk_path),
        load: read_load(),
        uptime_secs: read_uptime(),
    }
}

/// Every metric is `None` off Linux: `/proc` does not exist, and the response
/// says so instead of reporting zeroes.
#[cfg(not(target_os = "linux"))]
fn probe_host(_disk_path: PathBuf) -> HostProbe {
    HostProbe {
        cores: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        ..HostProbe::default()
    }
}

#[cfg(target_os = "linux")]
fn sample_cpu_percent() -> Option<f64> {
    let before = read_cpu_times()?;
    std::thread::sleep(CPU_SAMPLE_WINDOW);
    let after = read_cpu_times()?;
    cpu_percent(before, after)
}

#[cfg(target_os = "linux")]
fn read_cpu_times() -> Option<CpuTimes> {
    let stat = std::fs::read_to_string("/proc/stat").ok()?;
    parse_cpu_line(&stat)
}

/// Cumulative CPU jiffies from the aggregate `cpu` line of `/proc/stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuTimes {
    total: u64,
    idle: u64,
}

/// Parse the first line of `/proc/stat`.
///
/// The line is `cpu  user nice system idle iowait irq softirq steal guest
/// guest_nice`. `guest` and `guest_nice` are already counted inside `user` and
/// `nice` (Linux documents this), so summing every column would double-count
/// them; the parse therefore stops at `steal` and ignores anything past it.
///
/// `idle` is `idle + iowait`, which is the convention `top` uses: a core
/// waiting on I/O is not doing work, and counting it as busy makes a machine
/// that is merely slow to flush look pegged.
fn parse_cpu_line(stat: &str) -> Option<CpuTimes> {
    let line = stat.lines().find(|line| line.starts_with("cpu "))?;
    let mut fields = line.split_whitespace();
    if fields.next() != Some("cpu") {
        return None;
    }

    let values: Vec<u64> = fields
        .filter_map(|field| field.parse::<u64>().ok())
        .collect();
    // user, nice, system, idle, iowait, irq, softirq, steal
    if values.len() < 4 {
        return None;
    }
    let idle = values[3] + values.get(4).copied().unwrap_or(0);
    let total: u64 = values.iter().take(8).sum();
    Some(CpuTimes { total, idle })
}

/// Busy share between two cumulative samples, as a percentage.
///
/// Returns `None` when the counters did not advance (a sample window shorter
/// than one jiffy) rather than reporting 0 %, which would read as "idle".
fn cpu_percent(before: CpuTimes, after: CpuTimes) -> Option<f64> {
    let total = after.total.checked_sub(before.total)?;
    let idle = after.idle.checked_sub(before.idle)?;
    if total == 0 {
        return None;
    }
    let busy = total.saturating_sub(idle);
    Some(round1(busy as f64 * 100.0 / total as f64))
}

#[cfg(target_os = "linux")]
fn read_memory() -> Option<MemoryStats> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_meminfo(&meminfo)
}

/// `MemTotal` and `MemAvailable` from `/proc/meminfo`, in kB.
///
/// `MemAvailable` is the kernel's own estimate of what a new workload could
/// claim without swapping — the number `free` prints as "available" — and is
/// the right denominator for a utilisation gauge. `MemFree` alone counts
/// reclaimable page cache as used and would show a healthy host at 95 %.
fn parse_meminfo(meminfo: &str) -> Option<MemoryStats> {
    let mut total_kb = None;
    let mut available_kb = None;

    for line in meminfo.lines() {
        let Some((key, rest)) = line.split_once(':') else {
            continue;
        };
        let value = rest
            .split_whitespace()
            .next()
            .and_then(|value| value.parse::<u64>().ok());
        match key {
            "MemTotal" => total_kb = value,
            "MemAvailable" => available_kb = value,
            _ => {}
        }
    }

    let total_kb = total_kb?;
    let available_kb = available_kb?;
    if total_kb == 0 {
        return None;
    }

    let total_bytes = total_kb.saturating_mul(1024);
    let available_bytes = available_kb.min(total_kb).saturating_mul(1024);
    let used_bytes = total_bytes.saturating_sub(available_bytes);
    Some(MemoryStats {
        percent: round1(used_bytes as f64 * 100.0 / total_bytes as f64),
        used_bytes,
        total_bytes,
    })
}

#[cfg(target_os = "linux")]
fn read_load() -> Option<LoadStats> {
    let loadavg = std::fs::read_to_string("/proc/loadavg").ok()?;
    parse_loadavg(&loadavg)
}

/// The three load averages from `/proc/loadavg`.
///
/// A field that does not parse makes the whole reading `None` rather than a
/// partial one: a gauge labelled "load 1 min" that silently holds the 15-minute
/// value is a wrong number presented as a right one.
fn parse_loadavg(loadavg: &str) -> Option<LoadStats> {
    let mut fields = loadavg.split_whitespace();
    let one = fields.next()?.parse::<f64>().ok()?;
    let five = fields.next()?.parse::<f64>().ok()?;
    let fifteen = fields.next()?.parse::<f64>().ok()?;
    Some(LoadStats { one, five, fifteen })
}

#[cfg(target_os = "linux")]
fn read_uptime() -> Option<u64> {
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    parse_uptime(&uptime)
}

/// The first field of `/proc/uptime`, truncated to whole seconds.
fn parse_uptime(uptime: &str) -> Option<u64> {
    let seconds = uptime.split_whitespace().next()?.parse::<f64>().ok()?;
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    Some(seconds as u64)
}

/// Free space on the filesystem holding `path`.
///
/// `statvfs` is called through `libc` rather than by shelling out to `df`: the
/// dashboard must not depend on a binary being on `PATH`, and a subprocess per
/// poll would be a process-spawn amplifier driven by a browser tab.
#[cfg(target_os = "linux")]
fn read_disk(path: &std::path::Path) -> Option<DiskStats> {
    let c_path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
    // SAFETY: `statvfs` writes only into the `statvfs` we own and reads only
    // the NUL-terminated path we built; both outlive the call.
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stats) };
    if rc != 0 {
        return None;
    }

    let block_size = stats.f_frsize as u64;
    let total_blocks = stats.f_blocks as u64;
    if block_size == 0 || total_blocks == 0 {
        return None;
    }

    // `f_bfree` is free blocks including the root reserve; `f_bavail` is what
    // an unprivileged process may actually use. The gauge reports the latter,
    // because the reserve is not space this dashboard can write into.
    let available_blocks = (stats.f_bavail as u64).min(total_blocks);
    let total_bytes = total_blocks.saturating_mul(block_size);
    let available_bytes = available_blocks.saturating_mul(block_size);
    let used_bytes = total_bytes.saturating_sub(available_bytes);

    Some(DiskStats {
        percent: round1(used_bytes as f64 * 100.0 / total_bytes as f64),
        used_bytes,
        total_bytes,
        path: path.display().to_string(),
    })
}

/// One decimal place, so the JSON carries `38.2` rather than `38.199999`.
fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROC_STAT: &str = "cpu  100 20 30 400 50 5 5 10 0 0\n\
                             cpu0 50 10 15 200 25 2 2 5 0 0\n\
                             intr 12345\n";

    #[test]
    fn the_aggregate_cpu_line_is_parsed_and_guest_columns_are_not_double_counted() {
        let times = parse_cpu_line(PROC_STAT).expect("the cpu line must parse");
        // user+nice+system+idle+iowait+irq+softirq+steal = 100+20+30+400+50+5+5+10
        assert_eq!(times.total, 620);
        // idle + iowait
        assert_eq!(times.idle, 450);
    }

    #[test]
    fn a_stat_file_without_an_aggregate_line_is_not_a_reading() {
        assert!(parse_cpu_line("cpu0 1 2 3 4\nintr 9\n").is_none());
        assert!(parse_cpu_line("").is_none());
    }

    #[test]
    fn a_truncated_cpu_line_is_rejected_rather_than_partially_read() {
        // Only three columns: no `idle` field exists, so there is no idle time
        // to subtract and any percentage would be fiction.
        assert!(parse_cpu_line("cpu 100 20 30\n").is_none());
    }

    #[test]
    fn the_cpu_delta_is_the_busy_share_of_the_elapsed_jiffies() {
        let before = CpuTimes {
            total: 1000,
            idle: 800,
        };
        // 100 more jiffies, 20 of them idle -> 80 % busy.
        let after = CpuTimes {
            total: 1100,
            idle: 820,
        };
        assert_eq!(cpu_percent(before, after), Some(80.0));
    }

    #[test]
    fn a_sample_window_with_no_elapsed_jiffies_reports_nothing() {
        let sample = CpuTimes {
            total: 1000,
            idle: 800,
        };
        assert_eq!(cpu_percent(sample, sample), None);
    }

    #[test]
    fn counters_that_went_backwards_report_nothing() {
        let before = CpuTimes {
            total: 1100,
            idle: 820,
        };
        let after = CpuTimes {
            total: 1000,
            idle: 800,
        };
        assert_eq!(cpu_percent(before, after), None);
    }

    const MEMINFO: &str = "MemTotal:       16000000 kB\n\
                           MemFree:         1000000 kB\n\
                           MemAvailable:    4000000 kB\n\
                           Buffers:          500000 kB\n";

    #[test]
    fn memory_uses_mem_available_so_page_cache_is_not_counted_as_used() {
        let memory = parse_meminfo(MEMINFO).expect("meminfo must parse");
        assert_eq!(memory.total_bytes, 16_000_000 * 1024);
        // 16 GB total, 4 GB available -> 12 GB used, 75 %.
        assert_eq!(memory.used_bytes, 12_000_000 * 1024);
        assert_eq!(memory.percent, 75.0);
    }

    #[test]
    fn a_meminfo_without_mem_available_is_not_a_reading() {
        let partial = "MemTotal: 16000000 kB\nMemFree: 1000000 kB\n";
        assert!(parse_meminfo(partial).is_none());
    }

    #[test]
    fn an_available_above_total_cannot_produce_a_negative_usage() {
        let inconsistent = "MemTotal: 1000 kB\nMemAvailable: 5000 kB\n";
        let memory = parse_meminfo(inconsistent).expect("meminfo must parse");
        assert_eq!(memory.used_bytes, 0);
        assert_eq!(memory.percent, 0.0);
    }

    #[test]
    fn load_averages_are_read_in_order() {
        let load = parse_loadavg("0.52 0.38 0.31 2/512 12345\n").expect("loadavg must parse");
        assert_eq!(load.one, 0.52);
        assert_eq!(load.five, 0.38);
        assert_eq!(load.fifteen, 0.31);
    }

    #[test]
    fn a_loadavg_missing_its_third_field_is_not_a_reading() {
        assert!(parse_loadavg("0.52 0.38\n").is_none());
        assert!(parse_loadavg("0.52 0.38 high\n").is_none());
    }

    #[test]
    fn uptime_is_truncated_to_whole_seconds() {
        assert_eq!(parse_uptime("12345.67 98765.43\n"), Some(12345));
    }

    #[test]
    fn a_nonsense_uptime_is_not_a_reading() {
        assert!(parse_uptime("nan 1.0\n").is_none());
        assert!(parse_uptime("").is_none());
    }

    /// The probe runs on a real host, so it is asserted for *shape*, not for
    /// values: on Linux the CPU and memory gauges must carry a reading in
    /// range, and off Linux they must be `None` rather than zero.
    #[test]
    fn the_probe_reports_in_range_values_and_never_a_placeholder() {
        let probe = probe_host(PathBuf::from("/"));
        assert!(probe.cores >= 1, "a host always has at least one core");

        if cfg!(target_os = "linux") {
            let cpu = probe.cpu_percent.expect("Linux must produce a CPU reading");
            assert!((0.0..=100.0).contains(&cpu), "cpu out of range: {cpu}");

            let memory = probe.memory.expect("Linux must produce a memory reading");
            assert!((0.0..=100.0).contains(&memory.percent));
            assert!(memory.total_bytes > 0);

            let disk = probe.disk.expect("Linux must produce a disk reading");
            assert!((0.0..=100.0).contains(&disk.percent));
            assert!(disk.total_bytes > 0);
        } else {
            assert!(probe.cpu_percent.is_none());
            assert!(probe.memory.is_none());
        }
    }

    #[test]
    fn a_disk_path_that_does_not_exist_reports_nothing_rather_than_a_zero() {
        #[cfg(target_os = "linux")]
        assert!(read_disk(std::path::Path::new("/nonexistent-haos-green-probe")).is_none());
    }

    #[test]
    fn percentages_are_rounded_to_one_decimal() {
        assert_eq!(round1(38.199999999), 38.2);
        assert_eq!(round1(0.04), 0.0);
        assert_eq!(round1(99.96), 100.0);
    }
}
