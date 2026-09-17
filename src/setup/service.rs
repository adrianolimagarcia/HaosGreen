use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Install,
    Remove,
    Status,
    Start,
    Stop,
}

fn home_dir() -> PathBuf {
    let os_home = dirs::home_dir().expect("Could not determine home directory");
    let new_home = os_home.join(".haos-green");
    let legacy_home = os_home.join(".rustfox");
    if !new_home.exists() && legacy_home.exists() {
        legacy_home
    } else {
        new_home
    }
}

fn render_template(template: &str, bin_path: &Path) -> String {
    let home = home_dir();
    let config_path = home.join("config.toml");
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());
    template
        .replace("{{HAOS_GREEN_BIN}}", &bin_path.to_string_lossy())
        .replace("{{HAOS_GREEN_CONFIG}}", &config_path.to_string_lossy())
        .replace("{{HAOS_GREEN_HOME}}", &home.to_string_lossy())
        .replace("{{HAOS_GREEN_PATH}}", &path)
        .replace("{{RUSTFOX_BIN}}", &bin_path.to_string_lossy())
        .replace("{{RUSTFOX_CONFIG}}", &config_path.to_string_lossy())
        .replace("{{RUSTFOX_HOME}}", &home.to_string_lossy())
        .replace("{{RUSTFOX_PATH}}", &path)
}

pub fn handle(action: Action) -> Result<()> {
    match action {
        Action::Install => install(),
        Action::Remove => remove(),
        Action::Status => status(),
        Action::Start => start(),
        Action::Stop => stop(),
    }
}

fn install() -> Result<()> {
    let exe = std::env::current_exe().context("Failed to get current executable path")?;
    #[cfg(target_os = "linux")]
    {
        install_systemd(&exe)
    }
    #[cfg(target_os = "macos")]
    {
        install_launchd(&exe)
    }
    #[cfg(target_os = "windows")]
    {
        install_windows_service(&exe)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("Service installation is not supported on this platform")
    }
}

#[cfg(target_os = "linux")]
fn install_systemd(exe: &Path) -> Result<()> {
    let template = include_str!("../../scripts/services/rustfox.service.template");
    let rendered = render_template(template, exe);

    let user_service_dir = dirs::home_dir()
        .context("HOME not set")?
        .join(".config")
        .join("systemd")
        .join("user");
    std::fs::create_dir_all(&user_service_dir)
        .context("Failed to create systemd user services directory")?;

    let service_path = user_service_dir.join("haos-green.service");
    std::fs::write(&service_path, &rendered)
        .with_context(|| format!("Failed to write {}", service_path.display()))?;

    let status = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status()
        .context("Failed to run systemctl daemon-reload")?;
    if !status.success() {
        anyhow::bail!("systemctl daemon-reload failed");
    }

    let status = std::process::Command::new("systemctl")
        .args(["--user", "enable", "--now", "haos-green.service"])
        .status()
        .context("Failed to enable/start haos-green service")?;
    if !status.success() {
        anyhow::bail!("systemctl enable --now failed");
    }

    println!("✓ HaosGreen installed as a systemd user service");
    println!("  Status: systemctl --user status haos-green");
    println!("  Logs:   journalctl --user -u haos-green -f");
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_systemd() -> Result<()> {
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", "haos-green.service"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "stop", "rustfox.service"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "haos-green.service"])
        .status();
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "rustfox.service"])
        .status();

    if let Some(home) = dirs::home_dir() {
        let user_service_dir = home.join(".config").join("systemd").join("user");
        let _ = std::fs::remove_file(user_service_dir.join("haos-green.service"));
        let _ = std::fs::remove_file(user_service_dir.join("rustfox.service"));
    }
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    println!("✓ HaosGreen systemd service removed");
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_launchd(exe: &Path) -> Result<()> {
    let template = include_str!("../../scripts/services/com.rustfox.bot.plist.template");
    let rendered = render_template(template, exe);

    let agent_dir = dirs::home_dir()
        .context("HOME not set")?
        .join("Library")
        .join("LaunchAgents");
    std::fs::create_dir_all(&agent_dir).context("Failed to create LaunchAgents directory")?;

    let plist_path = agent_dir.join("com.haos-green.bot.plist");
    std::fs::write(&plist_path, &rendered)
        .with_context(|| format!("Failed to write {}", plist_path.display()))?;

    let status = std::process::Command::new("launchctl")
        .args(["load", "-w"])
        .arg(&plist_path)
        .status()
        .context("Failed to run launchctl load")?;
    if !status.success() {
        anyhow::bail!("launchctl load failed");
    }

    println!("✓ HaosGreen installed as a launchd agent");
    println!("  Status: launchctl list com.haos-green.bot");
    println!(
        "  Logs:   {}/Library/Logs/haos-green.log",
        dirs::home_dir().unwrap_or_default().display()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_launchd() -> Result<()> {
    let agent_dir = dirs::home_dir()
        .context("HOME not set")?
        .join("Library")
        .join("LaunchAgents");
    let plist_path = agent_dir.join("com.haos-green.bot.plist");
    let legacy_plist_path = agent_dir.join("com.rustfox.bot.plist");

    let _ = std::process::Command::new("launchctl")
        .args(["unload", "-w"])
        .arg(&plist_path)
        .status();
    let _ = std::process::Command::new("launchctl")
        .args(["unload", "-w"])
        .arg(&legacy_plist_path)
        .status();
    let _ = std::fs::remove_file(&plist_path);
    let _ = std::fs::remove_file(&legacy_plist_path);

    println!("✓ HaosGreen launchd agent removed");
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_windows_service(exe: &Path) -> Result<()> {
    use std::os::windows::process::CommandExt;

    let template = include_str!("../../scripts/services/install-service.bat.template");
    let rendered = render_template(template, exe);

    let tmp = std::env::temp_dir().join("haos-green-install-service.bat");
    std::fs::write(&tmp, &rendered).context("Failed to write install batch script")?;

    let status = std::process::Command::new("cmd")
        .arg("/c")
        .arg(&tmp)
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .status()
        .context("Failed to run install-service.bat")?;
    if !status.success() {
        anyhow::bail!("Service installation failed");
    }

    let _ = std::fs::remove_file(&tmp);
    println!("✓ HaosGreen installed as a Windows service");
    println!("  Manage: sc query HaosGreen");
    Ok(())
}

#[cfg(target_os = "windows")]
fn remove_windows_service() -> Result<()> {
    use std::os::windows::process::CommandExt;

    let template = include_str!("../../scripts/services/uninstall-service.bat.template");
    let rendered = render_template(template, &std::env::current_exe().unwrap_or_default());

    let tmp = std::env::temp_dir().join("haos-green-uninstall-service.bat");
    std::fs::write(&tmp, &rendered).context("Failed to write uninstall batch script")?;

    let status = std::process::Command::new("cmd")
        .arg("/c")
        .arg(&tmp)
        .creation_flags(0x08000000)
        .status()
        .context("Failed to run uninstall-service.bat")?;
    if !status.success() {
        anyhow::bail!("Service removal failed");
    }

    let _ = std::fs::remove_file(&tmp);
    println!("✓ HaosGreen Windows service removed");
    Ok(())
}

fn remove() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        remove_systemd()
    }
    #[cfg(target_os = "macos")]
    {
        remove_launchd()
    }
    #[cfg(target_os = "windows")]
    {
        remove_windows_service()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("Service removal is not supported on this platform")
    }
}

fn status() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let svc = if dirs::home_dir()
            .map(|h| h.join(".config/systemd/user/haos-green.service").exists())
            .unwrap_or(false)
        {
            "haos-green.service"
        } else {
            "rustfox.service"
        };
        let output = std::process::Command::new("systemctl")
            .args(["--user", "--no-pager", "status", svc])
            .output()
            .context("Failed to run systemctl status")?;
        print!("{}", String::from_utf8_lossy(&output.stdout));
        print!("{}", String::from_utf8_lossy(&output.stderr));
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let label = if dirs::home_dir()
            .map(|h| {
                h.join("Library/LaunchAgents/com.haos-green.bot.plist")
                    .exists()
            })
            .unwrap_or(false)
        {
            "com.haos-green.bot"
        } else {
            "com.rustfox.bot"
        };
        let output = std::process::Command::new("launchctl")
            .args(["list", label])
            .output()
            .context("Failed to run launchctl list")?;
        print!("{}", String::from_utf8_lossy(&output.stdout));
        print!("{}", String::from_utf8_lossy(&output.stderr));
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        let svc = if std::process::Command::new("sc")
            .args(["query", "HaosGreen"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            "HaosGreen"
        } else {
            "RustFox"
        };
        let output = std::process::Command::new("sc")
            .args(["query", svc])
            .output()
            .context("Failed to run sc query")?;
        print!("{}", String::from_utf8_lossy(&output.stdout));
        print!("{}", String::from_utf8_lossy(&output.stderr));
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("Service status is not supported on this platform")
    }
}

fn start() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let svc = if dirs::home_dir()
            .map(|h| h.join(".config/systemd/user/haos-green.service").exists())
            .unwrap_or(false)
        {
            "haos-green.service"
        } else {
            "rustfox.service"
        };
        let status = std::process::Command::new("systemctl")
            .args(["--user", "start", svc])
            .status()
            .context("Failed to start service")?;
        if !status.success() {
            anyhow::bail!("systemctl start failed");
        }
        println!("✓ Service started");
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let label = if dirs::home_dir()
            .map(|h| {
                h.join("Library/LaunchAgents/com.haos-green.bot.plist")
                    .exists()
            })
            .unwrap_or(false)
        {
            "com.haos-green.bot"
        } else {
            "com.rustfox.bot"
        };
        let status = std::process::Command::new("launchctl")
            .args(["start", label])
            .status()
            .context("Failed to start service")?;
        if !status.success() {
            anyhow::bail!("launchctl start failed");
        }
        println!("✓ Service started");
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        let svc = if std::process::Command::new("sc")
            .args(["query", "HaosGreen"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            "HaosGreen"
        } else {
            "RustFox"
        };
        let status = std::process::Command::new("sc")
            .args(["start", svc])
            .status()
            .context("Failed to start service")?;
        if !status.success() {
            anyhow::bail!("sc start failed");
        }
        println!("✓ Service started");
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("Starting services is not supported on this platform")
    }
}

fn stop() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let svc = if dirs::home_dir()
            .map(|h| h.join(".config/systemd/user/haos-green.service").exists())
            .unwrap_or(false)
        {
            "haos-green.service"
        } else {
            "rustfox.service"
        };
        let status = std::process::Command::new("systemctl")
            .args(["--user", "stop", svc])
            .status()
            .context("Failed to stop service")?;
        if !status.success() {
            anyhow::bail!("systemctl stop failed");
        }
        println!("✓ Service stopped");
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let label = if dirs::home_dir()
            .map(|h| {
                h.join("Library/LaunchAgents/com.haos-green.bot.plist")
                    .exists()
            })
            .unwrap_or(false)
        {
            "com.haos-green.bot"
        } else {
            "com.rustfox.bot"
        };
        let status = std::process::Command::new("launchctl")
            .args(["stop", label])
            .status()
            .context("Failed to stop service")?;
        if !status.success() {
            anyhow::bail!("launchctl stop failed");
        }
        println!("✓ Service stopped");
        Ok(())
    }
    #[cfg(target_os = "windows")]
    {
        let svc = if std::process::Command::new("sc")
            .args(["query", "HaosGreen"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            "HaosGreen"
        } else {
            "RustFox"
        };
        let status = std::process::Command::new("sc")
            .args(["stop", svc])
            .status()
            .context("Failed to stop service")?;
        if !status.success() {
            anyhow::bail!("sc stop failed");
        }
        println!("✓ Service stopped");
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        anyhow::bail!("Stopping services is not supported on this platform")
    }
}

// ── Tests ──

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_render_template_replaces_placeholders() {
        let template = "bin={{HAOS_GREEN_BIN}}\nconfig={{HAOS_GREEN_CONFIG}}\nhome={{HAOS_GREEN_HOME}}\npath={{HAOS_GREEN_PATH}}\n";
        let bin_path = Path::new("/usr/local/bin/haos-green");
        let result = render_template(template, bin_path);
        assert!(result.contains("/usr/local/bin/haos-green"));
        assert!(
            result.contains(".haos-green/config.toml") || result.contains(".rustfox/config.toml")
        );
        assert!(result.contains(".haos-green\n") || result.contains(".rustfox\n"));
        assert!(
            result.contains('/'),
            "PATH must be populated in rendered template, got: {}",
            result
        );
        assert!(!result.contains("{{HAOS_GREEN_BIN}}"));
        assert!(!result.contains("{{HAOS_GREEN_CONFIG}}"));
        assert!(!result.contains("{{HAOS_GREEN_HOME}}"));
        assert!(!result.contains("{{HAOS_GREEN_PATH}}"));
    }

    #[test]
    fn test_render_template_empty_home_does_not_panic() {
        let template = "{{HAOS_GREEN_HOME}}";
        let bin_path = Path::new("/usr/local/bin/haos-green");
        let result = render_template(template, bin_path);
        assert!(!result.contains("{{"));
    }
}
