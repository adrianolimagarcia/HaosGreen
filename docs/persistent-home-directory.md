# Persistent Home Directory (`~/.haos-green`)

HaosGreen stores all of its state under a single **home directory**, by default
`~/.haos-green`. This survives reboots, keeps secrets out of the LLM sandbox, and
makes it easy to run several isolated instances on one machine.

## Layout

```
~/.haos-green/
  config.toml       # secrets (bot token, API keys) — OUTSIDE the sandbox
  haos-green.db     # SQLite memory + embeddings     — OUTSIDE the sandbox
  skills/           # skills (seeded on first run, editable)
  agents/           # agents (seeded on first run, editable)
  workspace/        # THE SANDBOX — durable scratch space for the LLM
  artifacts/        # supervisor artifacts
  user_model.md     # learned user model
```

Only `workspace/` is reachable by the file and command tools. `config.toml`
and `haos-green.db` live above it and cannot be read or written by the LLM.

## Choosing where the home lives

Resolution order (first match wins):

1. `HAOS_GREEN_HOME` environment variable (must be an absolute path)
2. `[general].home` in `config.toml` (absolute path)
3. `~/.haos-green` (default)

Each individual path can still be pinned independently in `config.toml`
(e.g. `[memory].database_path`). An absolute value is used verbatim; an unset
value falls back to the home default.

## Migrating existing data

If you previously ran HaosGreen from a project directory (with `./haos-green.db`,
`./skills`, etc.), HaosGreen will **not** move your files automatically. On
startup it prints an actionable warning for each legacy path. To migrate:

HaosGreen auto-creates the home subdirectories on startup, so use `cp -rT`
(merge into the existing destination directory) rather than plain `cp -r`,
which would nest (e.g. `~/.haos-green/skills/skills`). Each command copies only
that one path — never your whole project.

```bash
mkdir -p ~/.haos-green
cp     ./haos-green.db        ~/.haos-green/haos-green.db
cp -rT ./skills               ~/.haos-green/skills
cp -rT ./agents               ~/.haos-green/agents
cp -rT ./supervisor/artifacts ~/.haos-green/artifacts        # if you used the supervisor
cp     ./memory/USER.md       ~/.haos-green/user_model.md    # if present
# Move your old sandbox contents into the new persistent workspace:
cp -rT /tmp/haos-green-sandbox ~/.haos-green/workspace       # adjust to your old sandbox
```

Then remove any path overrides from `config.toml` so HaosGreen uses the home
defaults, and place your `config.toml` at `~/.haos-green/config.toml` (or keep
passing it as the first CLI argument).

## Keeping the old location instead

If you prefer your current layout, pin the paths explicitly in `config.toml`:

```toml
[sandbox]
allowed_directory = "/abs/path/to/old/sandbox"
[memory]
database_path = "/abs/path/to/haos-green.db"
[skills]
directory = "/abs/path/to/skills"
```

Absolute paths are always honored unchanged.

## Starting fresh

Doing nothing is the "start fresh" path: HaosGreen creates an empty
`~/.haos-green/workspace`, a new database, and seeds skills/agents from the bundled
copies. Your old project-directory files are left untouched.

## Running multiple instances

Give each instance its own home:

```bash
# Default personal instance
cargo run

# A separate work instance, fully isolated
HAOS_GREEN_HOME="$HOME/.haos-green-work" cargo run
```

Each home has independent skills, agents, workspace, database, and artifacts.

## Updating bundled skills

The instance `skills/` and `agents/` directories are seeded once on first run.
To pull in newer bundled versions later, send the bot `/update-skills`:

- Skills you have not modified are overwritten with the new bundled version.
- Skills you edited locally are backed up to `<skill>/SKILL.md.bak` before being
  updated, so your changes are never silently lost.
- Skills you created yourself (not part of the bundle) are never touched.
