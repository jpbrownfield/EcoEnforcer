# EcoEnforcer

A Windows system-tray daemon that governs CPU priority and Efficiency Mode
(EcoQoS) for other processes based on window visibility and audio activity.

## Behavior

| Window state                     | CPU priority | EcoQoS (Efficiency Mode) |
|-----------------------------------|--------------|---------------------------|
| Foreground (active window)         | Normal       | Off                       |
| Hidden, playing audio              | Normal       | On                        |
| Hidden, silent                     | Idle         | On                        |

Shell processes (`explorer.exe`, `ShellExperienceHost.exe`, `SearchHost.exe`,
`Taskmgr.exe`) are never throttled.

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

The app runs from the system tray. Right-click the icon for "Pause Handler" /
"Resume Handler" (pausing restores all managed processes to Normal) and "Quit".

## Logging and crash recovery

EcoEnforcer logs every priority/EcoQoS change (and whether it succeeded) to
the console and to a rotating log file at
`%LOCALAPPDATA%\EcoEnforcer\eco_enforcer.log`.

While any processes are throttled, their pid/name/tier are snapshotted to
`%LOCALAPPDATA%\EcoEnforcer\managed_state.json`. On startup, if that file is
non-empty (e.g. the app crashed instead of exiting via Quit), EcoEnforcer
restores any still-running process whose pid and executable name still match
back to Normal priority before resuming normal operation.

## Testing

```powershell
.\.venv\Scripts\python -m pytest --cov=eco_enforcer --cov-report=term-missing
```

Win32 APIs (`kernel32`, `user32`), `psutil`, and `pycaw` are mocked in tests,
so the suite runs without needing elevated privileges or real audio sessions.

## Building a standalone executable

A GitHub Actions workflow ([.github/workflows/build.yml](.github/workflows/build.yml))
builds a single-file executable with PyInstaller on every push to a `v*` tag,
and uploads it as a build artifact / attaches it to a GitHub release. To build
locally:

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
