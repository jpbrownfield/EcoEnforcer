# EcoEnforcer

A Windows system-tray daemon that governs CPU priority and Efficiency Mode
(EcoQoS) for other processes based on window visibility and audio activity.

## Behavior

| Window state                     | CPU priority | EcoQoS (Efficiency Mode) |
|-----------------------------------|--------------|---------------------------|
| Foreground (active window)         | Normal       | Off                       |
| Hidden, playing audio              | Normal       | On                        |
| Hidden, silent                     | Idle         | On                        |

Shell/system-critical processes (`explorer.exe`, `ShellExperienceHost.exe`,
`SearchHost.exe`, `Taskmgr.exe`, `dwm.exe`, `audiodg.exe`, `csrss.exe`,
`wininit.exe`, `winlogon.exe`, `services.exe`, `lsass.exe`, `smss.exe`,
`svchost.exe`, and the kernel/idle/registry/memory-compression processes) are
never throttled.

Processes that have owned a titled top-level window are governed by the
table above. Once a window has been observed, its process keeps being
governed (based on foreground/audio state) even after that window is
minimized, moved to another desktop, or hidden to the tray — it's only
dropped once the process exits.

Processes with **no known window** (background services, helpers, etc.) are
never touched via CPU priority — a wrong guess there could starve something
important. Instead, if such a process stays below 5% CPU usage for three
consecutive checks, only its EcoQoS flag is switched on (nothing else). If it
becomes busy again, EcoQoS is switched back off. This whole-system scan runs
much less often than the windowed-app loop (every ~10th cycle) since
enumerating every process on the machine has its own small CPU cost.

### Tenacity

Priority class and EcoQoS are plain process attributes — Windows has no way
to "lock" them, so the process itself, another admin tool, or a user action
(e.g. Task Manager) can silently overwrite them at any time. To defend
against that, EcoEnforcer re-applies the target state on every check rather
than only when its own bookkeeping says the tier changed: every ~3s for
windowed apps, and on every background scan pass (~30s) for EcoQoS-only
processes. The known-window set is small, so the extra syscalls are
negligible and don't meaningfully offset the power savings.

NORMAL is never re-enforced — it's the default state, so once a foreground
process is set back to Normal it's free to raise its own priority further;
EcoEnforcer doesn't fight it. For non-NORMAL tiers, if a process keeps
resetting the same eco tier 10 cycles in a row, EcoEnforcer stops
re-applying it rather than fighting forever — it goes back to being actively
enforced only once the decision actually changes (e.g. it goes to the
foreground, or its audio state changes).

## Requirements

- Windows 10/11
- Python 3.10+

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\pip install -r requirements-dev.txt
```

## Running

```powershell
.\.venv\Scripts\python eco_enforcer.py
```

The app runs from the system tray. Right-clicking the icon shows the current
status and Eco process count as the first two (unclickable) lines, followed
by:

- **Pause/Resume** — manually pause (restores all managed processes to
  Normal priority and switches off background EcoQoS) or resume. If
  enforcement is currently auto-paused due to AC power or the active power
  plan, this instead reads "Resume" and clicking it manually overrides that
  auto-pause without changing the underlying settings. The override lasts
  only until the triggering condition itself clears and comes back (e.g.
  unplug/replug, or switching power plans away and back) — auto-pause
  reasserts itself at that point.
- **Disable when Plugged In** — auto-pauses enforcement while on AC power
  (with a battery present).
- **Use With Power Plans** — per-plan checkboxes controlling whether
  enforcement is active under each Windows power plan.
- **Quit**.

## Logging and crash recovery

EcoEnforcer logs every priority/EcoQoS change (and whether it succeeded) to
the console and to a rotating log file at
`%LOCALAPPDATA%\EcoEnforcer\eco_enforcer.log`.

While any processes are throttled (including background processes with
EcoQoS-only applied), their pid/name/tier are snapshotted to
`%LOCALAPPDATA%\EcoEnforcer\managed_state.json`. On startup, if that file is
non-empty (e.g. the app crashed instead of exiting via Quit), EcoEnforcer
restores any still-running process whose pid and executable name still match:
windowed-app entries go back to Normal priority, and background EcoQoS-only
entries just have EcoQoS switched off, before resuming normal operation.

## Testing

```powershell
.\.venv\Scripts\python -m pytest --cov=eco_enforcer --cov-report=term-missing
```

Win32 APIs (`kernel32`, `user32`), `psutil`, and `pycaw` are mocked in tests,
so the suite runs without needing elevated privileges or real audio sessions.

## Building a standalone executable

A GitHub Actions workflow ([.github/workflows/build.yml](.github/workflows/build.yml))
builds a single-file executable with PyInstaller and attaches it to a GitHub
release. Every push to `main` (after tests pass) auto-bumps a patch version
tag (`v*`), which re-triggers the workflow to build and publish that release —
no manual tagging needed. To build locally:

```powershell
pip install -r requirements.txt
pyinstaller --onefile --noconsole --name EcoEnforcer eco_enforcer.py
```

The resulting executable is at `dist/EcoEnforcer.exe`.

## Notes

- Only one instance of EcoEnforcer can run at a time (enforced via a named
  Windows mutex) to avoid two daemons fighting over the same processes'
  priority/EcoQoS state.
- Changing another process's priority class or power-throttling state does
  not require administrator privileges for processes owned by the same user;
  elevated or protected processes will simply be skipped.
