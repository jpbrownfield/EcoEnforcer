"""EcoEnforcer: a Windows tray daemon that governs CPU priority and Efficiency
Mode (EcoQoS) for processes based on window visibility and audio activity.

Tiers (windowed apps, i.e. processes that have owned a titled top-level window):
    NORMAL     - foreground window: normal priority, EcoQoS off.
    ECO_AUDIO  - hidden window playing audio: normal priority, EcoQoS on.
    ECO_MAX    - hidden window, silent: idle priority, EcoQoS on.

Background processes with no known window are never touched via priority class -- a
wrong guess there could starve something important. Instead, once such a process stays
below BACKGROUND_CPU_THRESHOLD_PERCENT CPU usage for BACKGROUND_LOW_USAGE_CYCLES
consecutive checks, only its EcoQoS flag is enabled (tagged "ECO_QOS_ONLY" in logs and
the crash-recovery state file). This whole-system scan runs far less often than the
windowed-app loop since enumerating every process has its own (small) CPU cost.
"""

import os
import sys
import json
import re
import shutil
import subprocess
import time
import logging
import threading
import ctypes
import winreg
import urllib.request
import urllib.error
import tkinter as tk
from tkinter import ttk
from ctypes import wintypes
from enum import Enum, auto
from pathlib import Path
from logging.handlers import RotatingFileHandler

from PIL import Image, ImageDraw, ImageTk
import pystray
import psutil
import comtypes

from pycaw.pycaw import AudioUtilities

# --- Win32 API constants ---
PROCESS_SET_INFORMATION = 0x0200
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

IDLE_PRIORITY_CLASS = 0x00000040
BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
NORMAL_PRIORITY_CLASS = 0x00000020
ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
HIGH_PRIORITY_CLASS = 0x00000080
REALTIME_PRIORITY_CLASS = 0x00000100

# Ordered low -> high so a NORMAL restore can be capped at a process's own natural
# priority instead of always jumping to NORMAL_PRIORITY_CLASS.
PRIORITY_CLASS_RANK = {
    IDLE_PRIORITY_CLASS: 0,
    BELOW_NORMAL_PRIORITY_CLASS: 1,
    NORMAL_PRIORITY_CLASS: 2,
    ABOVE_NORMAL_PRIORITY_CLASS: 3,
    HIGH_PRIORITY_CLASS: 4,
    REALTIME_PRIORITY_CLASS: 5,
}

ProcessPowerThrottling = 4
PROCESS_POWER_THROTTLING_CURRENT_VERSION = 1
PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1


class PROCESS_POWER_THROTTLING_STATE(ctypes.Structure):
    _fields_ = [
        ("Version", wintypes.ULONG),
        ("ControlMask", wintypes.ULONG),
        ("StateMask", wintypes.ULONG),
    ]


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class SYSTEM_POWER_STATUS(ctypes.Structure):
    _fields_ = [
        ("ACLineStatus", ctypes.c_ubyte),
        ("BatteryFlag", ctypes.c_ubyte),
        ("BatteryLifePercent", ctypes.c_ubyte),
        ("SystemStatusFlag", ctypes.c_ubyte),
        ("BatteryLifeTime", wintypes.DWORD),
        ("BatteryFullLifeTime", wintypes.DWORD),
    ]


# GUIDs of the built-in "High performance" and "Ultimate Performance" power plans.
HIGH_PERFORMANCE_PLAN_GUIDS = {
    "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
    "e1f0163f-a03a-4b7b-a133-0955ab5484d3",
}
# GUIDs of the built-in "Balanced" and "Power saver" plans -- these default to enabled
# since they already aim for power efficiency; High performance and any custom plan
# default to disabled.
BALANCED_OR_POWER_SAVER_PLAN_GUIDS = {
    "381b4222-f694-41f0-9685-ff5bb260df2e",
    "a1841308-3541-4fab-bc81-f71556f20b4a",
}
NO_SYSTEM_BATTERY_FLAG = 0x80

POWER_SCHEME_RE = re.compile(r"Power Scheme GUID:\s*([0-9a-fA-F-]{36})\s*\(([^)]*)\)")

kernel32 = ctypes.windll.kernel32 if sys.platform == "win32" else None
user32 = ctypes.windll.user32 if sys.platform == "win32" else None
powrprof = ctypes.windll.powrprof if sys.platform == "win32" else None
shell32 = ctypes.windll.shell32 if sys.platform == "win32" else None
version_dll = ctypes.windll.version if sys.platform == "win32" else None

if kernel32 is not None:
    # Explicit prototypes prevent HANDLE/pointer truncation on 64-bit Windows.
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.SetPriorityClass.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel32.SetPriorityClass.restype = wintypes.BOOL
    kernel32.SetProcessPriorityBoost.argtypes = [wintypes.HANDLE, wintypes.BOOL]
    kernel32.SetProcessPriorityBoost.restype = wintypes.BOOL
    kernel32.SetProcessInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
    ]
    kernel32.SetProcessInformation.restype = wintypes.BOOL
    kernel32.GetProcessInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD
    ]
    kernel32.GetProcessInformation.restype = wintypes.BOOL
    kernel32.GetPriorityClass.argtypes = [wintypes.HANDLE]
    kernel32.GetPriorityClass.restype = wintypes.DWORD
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE

    user32.EnumWindows.argtypes = [ctypes.c_void_p, wintypes.LPARAM]
    user32.EnumWindows.restype = wintypes.BOOL
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, wintypes.LPDWORD]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.GetForegroundWindow.argtypes = []
    user32.GetForegroundWindow.restype = wintypes.HWND
    user32.SystemParametersInfoW.argtypes = [wintypes.UINT, wintypes.UINT, ctypes.c_void_p, wintypes.UINT]
    user32.SystemParametersInfoW.restype = wintypes.BOOL

    kernel32.GetSystemPowerStatus.argtypes = [ctypes.POINTER(SYSTEM_POWER_STATUS)]
    kernel32.GetSystemPowerStatus.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [wintypes.HANDLE]
    kernel32.LocalFree.restype = wintypes.HANDLE
    powrprof.PowerGetActiveScheme.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.POINTER(GUID))]
    powrprof.PowerGetActiveScheme.restype = wintypes.DWORD

if version_dll is not None:
    version_dll.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
    version_dll.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    version_dll.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
    version_dll.GetFileVersionInfoW.restype = wintypes.BOOL
    version_dll.VerQueryValueW.argtypes = [
        wintypes.LPCVOID, wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(wintypes.UINT)
    ]
    version_dll.VerQueryValueW.restype = wintypes.BOOL

ERROR_ALREADY_EXISTS = 183

logger = logging.getLogger("EcoEnforcer")

# %LOCALAPPDATA%\EcoEnforcer holds the rotating log file and the crash-recovery state file.
APP_DATA_DIR = Path(os.getenv("LOCALAPPDATA") or os.path.expanduser("~")) / "EcoEnforcer"
LOG_FILE = APP_DATA_DIR / "eco_enforcer.log"
STATE_FILE = APP_DATA_DIR / "managed_state.json"
SETTINGS_FILE = APP_DATA_DIR / "settings.json"


def configure_logging() -> None:
    """Logs to the console and to a rotating file under %LOCALAPPDATA%\\EcoEnforcer."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)

    logger.setLevel(logging.INFO)
    logger.addHandler(file_handler)

    # The --noconsole build has no real console: PyInstaller's bootloader sets sys.stdout/
    # stderr to None in that case, so a StreamHandler would raise (silently, but not for
    # free) on every single log call. Only attach it when a real stream exists to write to.
    if sys.stderr is not None:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)


# Shell/system processes that should never be throttled. Widened beyond the tray-app
# set because EcoQoS-only management (below) reaches every process on the system.
PROTECTED_PROCESSES = {
    "explorer.exe",
    "shellexperiencehost.exe",
    "searchhost.exe",
    "taskmgr.exe",
    "dwm.exe",
    "audiodg.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "smss.exe",
    "svchost.exe",
    "system",
    "system idle process",
    "registry",
    "memcompression",
}

# A process outside our normal window-tracked set is only nudged to EcoQoS-only after
# staying below this CPU usage for this many consecutive enforce_step cycles.
BACKGROUND_CPU_THRESHOLD_PERCENT = 5.0
BACKGROUND_LOW_USAGE_CYCLES = 3
ECO_QOS_ONLY_TAG = "ECO_QOS_ONLY"

# How often the daemon's main loop wakes up to re-check foreground/audio state and
# reassert priority/EcoQoS. Also governs audio-transition latency (a process can take up
# to this long to be recognized as having started/stopped playing audio).
ENFORCE_LOOP_INTERVAL_SECONDS = 3.0

# Scanning every process on the system costs CPU too, so it runs far less often than
# the windowed-app enforcement loop (every Nth enforce_step cycle, ~30s at the 3s poll rate).
BACKGROUND_SCAN_EVERY_N_CYCLES = 10

# If something keeps fighting us and resetting the same non-NORMAL tier, we keep
# re-applying forever (a SetPriorityClass/EcoQoS call is cheap), just logging a reminder
# every this many consecutive overwrites so persistent fights are still visible.
OVERWRITE_LOG_INTERVAL_CYCLES = 20

# A newly-detected process is left completely untouched for this long so we can read its
# natural priority/EcoQoS before ever overwriting it. Skipped at daemon startup, since
# already-running processes have long since settled into whatever state they're going to be in.
BASELINE_SETTLE_SECONDS = 5.0


class ThrottleTier(Enum):
    NORMAL = auto()     # Foreground: normal priority, EcoQoS off, dynamic boost on
    ECO_AUDIO = auto()  # Background + audio: normal priority, EcoQoS on, dynamic boost on
    ECO_MAX = auto()    # Background + silent: idle priority, EcoQoS on, dynamic boost off


def _set_ecoqos(h_process, enabled: bool) -> bool:
    """Toggles EcoQoS (execution-speed throttling) on an already-open process handle."""
    throttle_state = PROCESS_POWER_THROTTLING_STATE()
    throttle_state.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION
    throttle_state.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED
    throttle_state.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED if enabled else 0
    return bool(kernel32.SetProcessInformation(
        h_process,
        ProcessPowerThrottling,
        ctypes.byref(throttle_state),
        ctypes.sizeof(throttle_state)
    ))


def apply_throttle_tier(pid: int, tier: ThrottleTier, natural_baseline: dict | None = None) -> bool:
    """Applies the specified CPU priority and EcoQoS profile to a process.

    natural_baseline (from capture_natural_baseline) caps a NORMAL restore so it never
    raises priority or disables EcoQoS above whatever the process/Windows already chose
    for itself; it's ignored for the ECO_AUDIO/ECO_MAX tiers, which are our own throttling.
    """
    if pid in (0, 4, os.getpid()):
        return False

    h_process = kernel32.OpenProcess(
        PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        pid
    )
    if not h_process:
        return False

    try:
        if tier == ThrottleTier.NORMAL:
            priority = NORMAL_PRIORITY_CLASS
            eco_enabled = False
            if natural_baseline:
                baseline_priority = natural_baseline.get("priority")
                if PRIORITY_CLASS_RANK.get(baseline_priority, PRIORITY_CLASS_RANK[NORMAL_PRIORITY_CLASS]) \
                        < PRIORITY_CLASS_RANK[NORMAL_PRIORITY_CLASS]:
                    priority = baseline_priority
                if natural_baseline.get("ecoqos"):
                    eco_enabled = True
        else:
            priority = IDLE_PRIORITY_CLASS if tier == ThrottleTier.ECO_MAX else NORMAL_PRIORITY_CLASS
            eco_enabled = True

        kernel32.SetPriorityClass(h_process, priority)

        # ECO_MAX also disables dynamic priority boosts so background/wait-boosted threads
        # can't briefly out-schedule other work, matching Task Manager's Efficiency Mode.
        kernel32.SetProcessPriorityBoost(h_process, tier == ThrottleTier.ECO_MAX)

        return _set_ecoqos(h_process, eco_enabled)
    finally:
        kernel32.CloseHandle(h_process)


def apply_ecoqos_only(pid: int, enabled: bool) -> bool:
    """Toggles EcoQoS on a process without touching its priority class or boost setting.

    Used for processes we don't otherwise manage (no known window), so a wrong guess
    can never leave them starved -- worst case they just don't get Turbo/P-cores.
    """
    if pid in (0, 4, os.getpid()):
        return False

    h_process = kernel32.OpenProcess(
        PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        pid
    )
    if not h_process:
        return False

    try:
        return _set_ecoqos(h_process, enabled)
    finally:
        kernel32.CloseHandle(h_process)


def capture_natural_baseline(pid: int) -> dict | None:
    """Reads a process's current priority class and EcoQoS state, untouched by us.

    Used so a later restore to NORMAL never raises priority or disables EcoQoS above
    whatever the process or Windows already chose for itself.
    """
    if pid in (0, 4, os.getpid()):
        return None

    h_process = kernel32.OpenProcess(
        PROCESS_SET_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION,
        False,
        pid
    )
    if not h_process:
        return None

    try:
        priority = kernel32.GetPriorityClass(h_process)
        throttle_state = PROCESS_POWER_THROTTLING_STATE()
        throttle_state.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION
        ecoqos = False
        if kernel32.GetProcessInformation(
            h_process, ProcessPowerThrottling, ctypes.byref(throttle_state), ctypes.sizeof(throttle_state)
        ):
            ecoqos = bool(throttle_state.ControlMask & throttle_state.StateMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED)
        return {"priority": priority, "ecoqos": ecoqos}
    finally:
        kernel32.CloseHandle(h_process)


# --- System inspection helpers ---

def get_active_audio_pids() -> set[int]:
    """Returns PIDs of applications actively outputting audio."""
    active_pids = set()
    try:
        # AudioSessionStateActive == 1
        sessions = AudioUtilities.GetAllSessions()
        for session in sessions:
            if session.State == 1 and session.Process:
                active_pids.add(session.Process.pid)
    except Exception:
        pass
    return active_pids


def get_visible_window_pids() -> set[int]:
    """Enumerates visible desktop application windows."""
    visible_pids = set()

    def enum_windows_callback(hwnd, extra):
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:  # Has a visible window title
                pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                if pid.value > 0:
                    visible_pids.add(pid.value)
        return True

    ENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user32.EnumWindows(ENUMPROC(enum_windows_callback), 0)
    return visible_pids


def get_foreground_pid() -> int:
    """Returns the PID of the active foreground window."""
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return 0
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def is_protected(pid: int, excluded_processes: frozenset[str] = frozenset()) -> bool:
    """Returns True if the pid belongs to a protected/user-excluded process, is our own, or no longer exists."""
    if pid == os.getpid():
        return True
    try:
        name = psutil.Process(pid).name().lower()
        return name in PROTECTED_PROCESSES or name in excluded_processes
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return True


def get_friendly_name(exe_path: str) -> str | None:
    """Reads the FileDescription field from an executable's version resource, if present."""
    if version_dll is None or not exe_path:
        return None
    try:
        size = version_dll.GetFileVersionInfoSizeW(exe_path, None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not version_dll.GetFileVersionInfoW(exe_path, 0, size, buf):
            return None

        trans_ptr = ctypes.c_void_p()
        trans_len = wintypes.UINT()
        if not version_dll.VerQueryValueW(
            buf, "\\VarFileInfo\\Translation", ctypes.byref(trans_ptr), ctypes.byref(trans_len)
        ) or trans_len.value < 4:
            return None
        lang, codepage = ctypes.cast(trans_ptr, ctypes.POINTER(ctypes.c_uint16 * 2)).contents

        desc_ptr = ctypes.c_void_p()
        desc_len = wintypes.UINT()
        subblock = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\FileDescription"
        if not version_dll.VerQueryValueW(
            buf, subblock, ctypes.byref(desc_ptr), ctypes.byref(desc_len)
        ) or not desc_len.value:
            return None
        return ctypes.wstring_at(desc_ptr, desc_len.value - 1).strip() or None
    except OSError:
        return None


def collect_process_rows() -> list[dict]:
    """One-time snapshot of every running process, grouped by executable name.

    Includes a short CPU sample (blocks briefly to get a real reading, since psutil's
    first cpu_percent() call is always meaningless) -- used to populate the Excluded
    Processes window. Excludes always-protected system processes and ourselves.
    """
    own_name = (get_process_name(os.getpid()) or "").lower()
    procs = []
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if not name:
            continue
        lname = name.lower()
        if lname in PROTECTED_PROCESSES or lname == own_name:
            continue
        try:
            proc.cpu_percent(None)  # prime the sample; first call is meaningless
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        procs.append(proc)

    time.sleep(0.2)

    rows: dict[str, dict] = {}
    for proc in procs:
        try:
            name = proc.info['name']
            exe_path = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            exe_path = ""
        try:
            cpu = proc.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        lname = name.lower()
        row = rows.setdefault(lname, {"name": name, "path": exe_path, "cpu": 0.0})
        row["cpu"] += cpu
        if not row["path"] and exe_path:
            row["path"] = exe_path

    for row in rows.values():
        row["friendly"] = get_friendly_name(row["path"]) or row["name"]

    return sorted(rows.values(), key=lambda r: r["friendly"].lower())


def is_running_as_admin() -> bool:
    """Returns True if this process has an elevated (administrator) token."""
    if shell32 is None:
        return False
    try:
        return bool(shell32.IsUserAnAdmin())
    except OSError:
        return False


_SPI_GETWORKAREA = 0x0030


def get_work_area() -> tuple[int, int, int, int] | None:
    """Returns (left, top, right, bottom) of the screen area excluding the taskbar, or None."""
    if user32 is None:
        return None
    try:
        rect = wintypes.RECT()
        if user32.SystemParametersInfoW(_SPI_GETWORKAREA, 0, ctypes.byref(rect), 0):
            return (rect.left, rect.top, rect.right, rect.bottom)
    except OSError:
        pass
    return None


def get_process_name(pid: int) -> str | None:
    """Returns the executable name for a pid, or None if it can't be determined."""
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


def describe_pid(pid: int) -> str:
    """Best-effort human-readable label for a pid, used only for logging."""
    name = get_process_name(pid)
    return f"{name} (pid {pid})" if name else f"pid {pid}"


def persist_managed_state(managed_pids: dict[int, "ThrottleTier"], eco_qos_pids: set[int] = frozenset()) -> None:
    """Snapshots throttled processes to disk so a crash can be recovered from on next launch."""
    entries = {
        str(pid): {"name": get_process_name(pid), "tier": tier.name}
        for pid, tier in managed_pids.items()
        if tier != ThrottleTier.NORMAL
    }
    entries.update({
        str(pid): {"name": get_process_name(pid), "tier": ECO_QOS_ONLY_TAG}
        for pid in eco_qos_pids
    })
    try:
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(entries), encoding="utf-8")
    except OSError:
        logger.debug("Failed to persist managed state", exc_info=True)


def recover_previous_session() -> None:
    """Restores processes left throttled by a previous run that didn't shut down cleanly."""
    if not STATE_FILE.exists():
        return
    try:
        entries = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        entries = {}

    for pid_str, info in entries.items():
        pid = int(pid_str)
        recorded_name = info.get("name")
        if not recorded_name or get_process_name(pid) != recorded_name:
            continue
        if info.get("tier") == ECO_QOS_ONLY_TAG:
            if apply_ecoqos_only(pid, False):
                logger.warning("Recovered from previous session/crash: %s -> EcoQoS off", describe_pid(pid))
        # This runs once at startup before the daemon loop begins, so there's no need to
        # wait -- read whatever natural state exists right now and cap the restore at it.
        elif apply_throttle_tier(pid, ThrottleTier.NORMAL, capture_natural_baseline(pid)):
            logger.warning("Recovered from previous session/crash: %s -> NORMAL", describe_pid(pid))

    try:
        STATE_FILE.unlink(missing_ok=True)
    except OSError:
        logger.debug("Failed to remove stale managed state file", exc_info=True)


def decide_tier(pid: int, foreground_pid: int, audio_pids: set[int]) -> ThrottleTier:
    """Pure decision function: maps a visible pid to its target tier."""
    if pid == foreground_pid:
        return ThrottleTier.NORMAL
    if pid in audio_pids:
        return ThrottleTier.ECO_AUDIO
    return ThrottleTier.ECO_MAX


def get_descendant_pids(pid: int) -> set[int]:
    """Returns all descendant pids of a process (e.g. helper/renderer processes).

    Windows only boosts the specific pid that owns the focused window -- child
    processes of a multi-process app are left at whatever tier they were assigned,
    so we govern them the same as their nearest tracked ancestor.
    """
    try:
        return {child.pid for child in psutil.Process(pid).children(recursive=True)}
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return set()


def get_descendants_bulk(owner_pids: set[int]) -> dict[int, set[int]]:
    """Returns {owner_pid: descendant pids} for many owners in a single process scan.

    psutil.Process.children(recursive=True) takes its own system-wide process snapshot
    on every call, so calling get_descendant_pids() once per owner_pid (as enforce_step
    used to) re-scans every process on the machine once per tracked window -- wasteful
    when several windowed apps are visible at once. This builds one pid->children map
    from a single psutil.process_iter() pass and reuses it for every owner.
    """
    if not owner_pids:
        return {}
    children_of: dict[int, set[int]] = {}
    try:
        for proc in psutil.process_iter(['pid', 'ppid']):
            ppid = proc.info['ppid']
            if ppid is not None:
                children_of.setdefault(ppid, set()).add(proc.info['pid'])
    except OSError:
        return {}

    def descendants(root: int) -> set[int]:
        result: set[int] = set()
        stack = list(children_of.get(root, ()))
        while stack:
            child_pid = stack.pop()
            if child_pid in result:
                continue
            result.add(child_pid)
            stack.extend(children_of.get(child_pid, ()))
        return result

    return {owner: descendants(owner) for owner in owner_pids}


def get_active_power_plan_guid() -> str | None:
    """Returns the lowercase GUID of the currently active Windows power plan, or None."""
    guid_ptr = ctypes.POINTER(GUID)()
    if powrprof.PowerGetActiveScheme(None, ctypes.byref(guid_ptr)) != 0 or not guid_ptr:
        return None
    try:
        guid = guid_ptr.contents
        data4 = bytes(guid.Data4)
        guid_str = "%08x-%04x-%04x-%s-%s" % (
            guid.Data1, guid.Data2, guid.Data3, data4[:2].hex(), data4[2:].hex(),
        )
    finally:
        kernel32.LocalFree(guid_ptr)
    return guid_str.lower()


def list_power_plans() -> list[tuple[str, str]]:
    """Returns (guid, friendly_name) for every power plan installed on this machine.

    Shells out to `powercfg /list` rather than the raw Win32 enumeration API, since
    parsing its fixed, well-known output format is far simpler and less error-prone.
    """
    try:
        result = subprocess.run(
            ["powercfg", "/list"], capture_output=True, text=True, timeout=5, check=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return [
        (match.group(1).lower(), match.group(2).strip())
        for match in POWER_SCHEME_RE.finditer(result.stdout)
    ]


def default_power_plan_enabled(guid: str) -> bool:
    """Balanced/Power saver default to enforcement enabled; High performance and any
    custom (non-built-in) plan default to disabled."""
    return guid.lower() in BALANCED_OR_POWER_SAVER_PLAN_GUIDS


def is_on_ac_with_battery() -> bool:
    """Returns True only for a laptop (has a battery) currently plugged into AC power.

    Desktops report "always on AC" with no battery present, which would otherwise
    disable enforcement permanently, so machines with no battery are excluded.
    """
    status = SYSTEM_POWER_STATUS()
    if not kernel32.GetSystemPowerStatus(ctypes.byref(status)):
        return False
    has_battery = not (status.BatteryFlag & NO_SYSTEM_BATTERY_FLAG)
    return has_battery and status.ACLineStatus == 1


def load_settings() -> dict:
    """Loads user-configurable settings (power plan / AC checkboxes) from disk."""
    if not SETTINGS_FILE.exists():
        return {}
    try:
        return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_settings(
    disable_on_ac: bool, power_plan_enabled: dict[str, bool], excluded_processes: list[str] = (),
) -> None:
    """Persists user-configurable settings so tray checkbox choices survive a restart."""
    try:
        APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
        SETTINGS_FILE.write_text(
            json.dumps({
                "disable_on_ac": disable_on_ac,
                "power_plan_enabled": power_plan_enabled,
                "excluded_processes": list(excluded_processes),
            }),
            encoding="utf-8",
        )
    except OSError:
        logger.debug("Failed to persist settings", exc_info=True)


STARTUP_REGISTRY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
STARTUP_VALUE_NAME = "EcoEnforcer"
STARTUP_TASK_NAME = "EcoEnforcer"


def _get_startup_command() -> str:
    """Builds the command line to register in the startup registry key."""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}"'
    return f'"{sys.executable}" "{os.path.abspath(__file__)}"'


def _scheduled_task_exists() -> bool:
    """Checks whether the elevated Task Scheduler startup entry is registered."""
    try:
        result = subprocess.run(
            ["schtasks", "/Query", "/TN", STARTUP_TASK_NAME],
            capture_output=True, timeout=5, check=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        return result.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _create_scheduled_task() -> None:
    """Registers a Task Scheduler entry that (re)launches EcoEnforcer elevated at logon.

    The HKCU Run key always launches non-elevated regardless of the privilege level it
    was toggled on with, so an admin-mode run needs Task Scheduler's /RL HIGHEST instead
    to actually come back up elevated next logon.
    """
    try:
        subprocess.run(
            ["schtasks", "/Create", "/TN", STARTUP_TASK_NAME, "/TR", _get_startup_command(),
             "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"],
            capture_output=True, timeout=5, check=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        logger.debug("Failed to create elevated startup task", exc_info=True)


def _delete_scheduled_task() -> None:
    """Removes the elevated Task Scheduler startup entry, if any."""
    try:
        subprocess.run(
            ["schtasks", "/Delete", "/TN", STARTUP_TASK_NAME, "/F"],
            capture_output=True, timeout=5, check=False,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        logger.debug("Failed to delete elevated startup task", exc_info=True)


def is_startup_enabled() -> bool:
    """Checks whether EcoEnforcer is registered to launch at Windows logon, via either
    the registry Run entry or (when last enabled while elevated) the Task Scheduler entry."""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_REGISTRY_KEY, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, STARTUP_VALUE_NAME)
        return True
    except OSError:
        pass
    return _scheduled_task_exists()


def set_startup_enabled(enabled: bool) -> None:
    """Registers/unregisters EcoEnforcer to launch at Windows logon.

    The Run registry key always launches non-elevated, so if we're currently running as
    admin, a Task Scheduler entry (/RL HIGHEST) is used instead -- otherwise a startup
    launch would silently drop back to unelevated and "Manage All Processes" wouldn't
    hold across a reboot. Only one of the two is ever kept registered at a time.
    """
    use_task = enabled and is_running_as_admin()
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, STARTUP_REGISTRY_KEY, 0, winreg.KEY_WRITE) as key:
            if enabled and not use_task:
                winreg.SetValueEx(key, STARTUP_VALUE_NAME, 0, winreg.REG_SZ, _get_startup_command())
            else:
                try:
                    winreg.DeleteValue(key, STARTUP_VALUE_NAME)
                except FileNotFoundError:
                    pass
    except OSError:
        logger.debug("Failed to update startup registry entry", exc_info=True)

    if use_task:
        _create_scheduled_task()
    else:
        _delete_scheduled_task()


# --- Self-update ---

GITHUB_REPO = "jpbrownfield/EcoEnforcer"
GITHUB_LATEST_RELEASE_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
UPDATE_ASSET_NAME = "EcoEnforcer.exe"
# Thumbprint of the self-signed code-signing cert used to sign release builds (see
# .github/workflows/build.yml). Pinned here so a downloaded update is only ever applied
# if it was signed with our own key -- not just any Authenticode-signed binary.
UPDATE_SIGNING_THUMBPRINT = "6789EE263EB2F64D61AC10AAA9456320EFCEA889"


def get_current_version() -> str:
    """Returns this build's version, stamped into version.txt at build time by CI."""
    if getattr(sys, "frozen", False):
        try:
            return (Path(sys._MEIPASS) / "version.txt").read_text(encoding="utf-8").strip()
        except OSError:
            pass
    return "0.0.0-dev"


def _parse_version(version: str) -> tuple[int, ...]:
    """Parses a (possibly 'v'-prefixed) dotted version into a comparable tuple."""
    return tuple(int(part) for part in re.findall(r"\d+", version)) or (0,)


def check_for_update() -> tuple[str, str] | None:
    """Checks the latest GitHub release; returns (version, download_url) if it's newer."""
    try:
        request = urllib.request.Request(
            GITHUB_LATEST_RELEASE_API,
            headers={"Accept": "application/vnd.github+json", "User-Agent": "EcoEnforcer"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError):
        return None

    latest_tag = data.get("tag_name") or ""
    if not latest_tag or _parse_version(latest_tag) <= _parse_version(get_current_version()):
        return None

    for asset in data.get("assets", []):
        if asset.get("name") == UPDATE_ASSET_NAME and asset.get("browser_download_url"):
            return latest_tag, asset["browser_download_url"]
    return None


def _download_update(url: str, dest: Path) -> bool:
    """Downloads the release asset to dest; returns False on any failure."""
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "EcoEnforcer"})
        with urllib.request.urlopen(request, timeout=60) as response, dest.open("wb") as out_file:
            shutil.copyfileobj(response, out_file)
        return True
    except OSError:
        return False


def _verify_update_signature(exe_path: Path) -> bool:
    """Confirms exe_path is Authenticode-signed with our pinned certificate thumbprint."""
    try:
        result = subprocess.run(
            [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                f"(Get-AuthenticodeSignature -FilePath '{exe_path}').SignerCertificate.Thumbprint",
            ],
            capture_output=True, text=True, timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    thumbprint = result.stdout.strip()
    return bool(thumbprint) and thumbprint.upper() == UPDATE_SIGNING_THUMBPRINT.upper()


def apply_update(new_exe_path: Path) -> None:
    """Launches a detached helper .bat that waits for this process to exit, replaces the
    running executable (wherever it's installed) with new_exe_path, relaunches it, then
    deletes itself. Windows won't let a running exe overwrite its own file, hence the helper.
    """
    current_exe = Path(sys.executable)
    pid = os.getpid()
    update_dir = APP_DATA_DIR / "update"
    update_dir.mkdir(parents=True, exist_ok=True)
    bat_path = update_dir / "apply_update.bat"
    bat_path.write_text(
        "@echo off\r\n"
        ":wait\r\n"
        f'tasklist /fi "PID eq {pid}" | findstr /i "{pid}" >nul\r\n'
        "if %errorlevel%==0 (\r\n"
        "  timeout /t 1 /nobreak >nul\r\n"
        "  goto wait\r\n"
        ")\r\n"
        f'move /y "{new_exe_path}" "{current_exe}" >nul\r\n'
        f'start "" "{current_exe}"\r\n'
        '(goto) 2>nul & del "%~f0"\r\n',
        encoding="utf-8",
    )
    subprocess.Popen(
        ["cmd", "/c", str(bat_path)],
        creationflags=subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP,
        close_fds=True,
    )


# --- Daemon engine ---

class EcoEnforcerDaemon:
    def __init__(self):
        self.running = True
        self.paused = False
        # Tracks current tier: {pid: ThrottleTier}
        self.managed_pids: dict[int, ThrottleTier] = {}
        # Consecutive same-tier reassertions per pid; used only to throttle the log spam
        # for a process that keeps resetting its own eco tier (see OVERWRITE_LOG_INTERVAL_CYCLES).
        self.overwrite_streak: dict[int, int] = {}
        # Pids that have ever owned a titled window; kept governed even after the window
        # is hidden (e.g. closed to tray), until the process actually exits.
        self.known_pids: set[int] = set()
        # EcoQoS-only bookkeeping for processes with no known window (priority never touched).
        self.background_procs: dict[int, psutil.Process] = {}
        self.background_low_streak: dict[int, int] = {}
        self.eco_qos_pids: set[int] = set()
        # Scanning every process on the system is itself not free, so it only runs every
        # BACKGROUND_SCAN_EVERY_N_CYCLES enforce_step calls rather than on every cycle.
        self._enforce_cycle_count = 0
        # Descendant pids (e.g. helper/renderer processes) currently governed via an
        # ancestor's tier; recomputed every cycle, excluded from the background scan.
        self._governed_descendant_pids: set[int] = set()
        # Natural (untouched) priority/EcoQoS per pid, captured once and never re-read;
        # caps how far a NORMAL restore can go (see _get_baseline/BASELINE_SETTLE_SECONDS).
        self.natural_baseline: dict[int, dict] = {}
        self._pending_baseline_since: dict[int, float] = {}
        # None means enforcement is active; otherwise the reason it's auto-paused.
        self.power_pause_reason: str | None = None
        # True once the user manually resumes despite an active power_pause_reason;
        # cleared as soon as that reason itself clears, so the next occurrence auto-pauses again.
        self.power_override_active = False
        self._was_active = False
        # User-configurable via tray checkboxes; loaded once at startup and persisted on change.
        settings = load_settings()
        self.disable_on_ac: bool = settings.get("disable_on_ac", True)
        self.power_plan_enabled: dict[str, bool] = dict(settings.get("power_plan_enabled", {}))
        # Process names (lowercase) the user has chosen to never throttle/EcoQoS at all.
        self.excluded_processes: set[str] = {
            name.lower() for name in settings.get("excluded_processes", [])
        }
        # Guards managed_pids/known_pids since the worker thread and quit/pause handlers touch them concurrently
        self._lock = threading.Lock()

    def run(self):
        # Initialize COM library for Windows Audio APIs on this worker thread
        comtypes.CoInitialize()
        try:
            while self.running:
                self.power_pause_reason = self._get_power_pause_reason()
                if self.power_pause_reason is None:
                    self.power_override_active = False
                active = not self.paused and (self.power_pause_reason is None or self.power_override_active)
                if active:
                    self.enforce_step()
                elif self._was_active:
                    self.restore_all()
                self._was_active = active
                time.sleep(ENFORCE_LOOP_INTERVAL_SECONDS)
        finally:
            comtypes.CoUninitialize()

    def _get_power_pause_reason(self) -> str | None:
        """Returns why enforcement should be auto-paused given current settings/power state."""
        if self.disable_on_ac and is_on_ac_with_battery():
            return "ac"
        guid = get_active_power_plan_guid()
        if guid is not None and not self.power_plan_enabled.get(guid, default_power_plan_enabled(guid)):
            return "power_plan"
        return None

    def get_status_text(self) -> str:
        """Human-readable enforcement state, shown as the first line of the tray tooltip."""
        if self.paused:
            return "EcoEnforcer Paused Manually"
        if self.power_pause_reason and self.power_override_active:
            return "EcoEnforcer Active (Manual Override)"
        if self.power_pause_reason == "power_plan":
            return "EcoEnforcer Paused due to Power Plan"
        if self.power_pause_reason == "ac":
            return "EcoEnforcer Paused on AC"
        return "EcoEnforcer Active"

    def _get_baseline(self, pid: int) -> dict | None:
        """Returns a pid's natural priority/EcoQoS baseline, or None while still settling.

        Captured immediately during the daemon's first cycle (already-running processes
        have long since settled), but a process newly detected afterward is left alone
        for BASELINE_SETTLE_SECONDS first so we read its own state rather than a
        transient one from just having launched.
        """
        if pid in self.natural_baseline:
            return self.natural_baseline[pid]

        if self._enforce_cycle_count == 0:
            baseline = capture_natural_baseline(pid) or {}
            self.natural_baseline[pid] = baseline
            return baseline

        first_seen = self._pending_baseline_since.setdefault(pid, time.monotonic())
        if time.monotonic() - first_seen < BASELINE_SETTLE_SECONDS:
            return None

        baseline = capture_natural_baseline(pid) or {}
        self.natural_baseline[pid] = baseline
        self._pending_baseline_since.pop(pid, None)
        return baseline

    def enforce_step(self):
        foreground_pid = get_foreground_pid()
        audio_pids = get_active_audio_pids()
        visible_pids = get_visible_window_pids()

        with self._lock:
            # Snapshotted so persist_managed_state (a disk write) only runs when this
            # cycle actually changed something, instead of unconditionally every cycle.
            state_before = (dict(self.managed_pids), frozenset(self.eco_qos_pids))

            self.known_pids |= visible_pids - {os.getpid()}

            # Stop tracking any pid that no longer exists, wherever it came from
            # (a known window owner or a governed descendant).
            for pid in list(self.known_pids | set(self.managed_pids)):
                if not psutil.pid_exists(pid):
                    self.known_pids.discard(pid)
                    self.managed_pids.pop(pid, None)
                    self.overwrite_streak.pop(pid, None)
                    self.natural_baseline.pop(pid, None)
                    self._pending_baseline_since.pop(pid, None)

            target_states: dict[int, ThrottleTier] = {
                pid: decide_tier(pid, foreground_pid, audio_pids)
                for pid in self.known_pids
                if not is_protected(pid, self.excluded_processes)
            }

            # Windows only boosts the specific pid that owns the focused window, so a
            # multi-process app's helper/renderer children would otherwise stay stuck at
            # whatever tier they last had. Govern them the same as their tracked ancestor.
            descendant_targets: dict[int, ThrottleTier] = {}
            descendants_by_owner = get_descendants_bulk(set(target_states.keys()))
            for owner_pid, tier in target_states.items():
                for child_pid in descendants_by_owner.get(owner_pid, ()):
                    if child_pid in self.known_pids or is_protected(child_pid, self.excluded_processes):
                        continue
                    descendant_targets.setdefault(child_pid, tier)
            for pid, tier in descendant_targets.items():
                target_states.setdefault(pid, tier)
            self._governed_descendant_pids = set(descendant_targets.keys())

            # Reassert every cycle rather than only on transitions: priority class and EcoQoS
            # are plain attributes anyone can overwrite (the process itself, another admin
            # tool, etc.), so trusting our own bookkeeping alone would let external changes
            # silently stick. The known_pids set is small, so re-applying is cheap.
            # NORMAL is never fought for -- it's the default state, so the process is free to
            # raise its own priority while foreground. Non-NORMAL tiers are re-applied forever,
            # never giving up, since a process resetting itself doesn't mean we should stop
            # correcting it back.
            for pid, target_tier in target_states.items():
                # A newly-detected process is left untouched until we've read its natural
                # state, so we never overwrite it -- in either direction -- before then.
                baseline = self._get_baseline(pid)
                if baseline is None:
                    continue

                current_tier = self.managed_pids.get(pid, ThrottleTier.NORMAL)
                is_transition = target_tier != current_tier

                if not is_transition and target_tier == ThrottleTier.NORMAL:
                    continue

                if apply_throttle_tier(pid, target_tier, baseline):
                    if is_transition:
                        logger.info("%s -> %s", describe_pid(pid), target_tier.name)
                        self.overwrite_streak[pid] = 0
                    elif target_tier != ThrottleTier.NORMAL:
                        self.overwrite_streak[pid] = self.overwrite_streak.get(pid, 0) + 1
                        if self.overwrite_streak[pid] % OVERWRITE_LOG_INTERVAL_CYCLES == 0:
                            logger.info(
                                "%s still resetting %s -- continuing to re-enforce it",
                                describe_pid(pid), target_tier.name)
                    self.managed_pids[pid] = target_tier
                else:
                    logger.warning("%s -> %s FAILED", describe_pid(pid), target_tier.name)
                    # Failed to open or modify (process died/elevated)
                    self.managed_pids.pop(pid, None)
                    self.overwrite_streak.pop(pid, None)

            self._enforce_cycle_count += 1
            if self._enforce_cycle_count % BACKGROUND_SCAN_EVERY_N_CYCLES == 0:
                self._manage_background_processes()

            state_after = (self.managed_pids, frozenset(self.eco_qos_pids))
            if state_after != state_before:
                persist_managed_state(self.managed_pids, self.eco_qos_pids)

    def _manage_background_processes(self):
        """EcoQoS-only pass over processes with no known window (never touches priority)."""
        try:
            candidates = {p.pid for p in psutil.process_iter(['pid'])} - self.known_pids - self._governed_descendant_pids
        except OSError:
            return
        candidates.discard(os.getpid())

        # Stop tracking anything that vanished or is no longer a background candidate.
        for pid in list(self.background_procs):
            if pid not in candidates:
                self.background_procs.pop(pid, None)
                self.background_low_streak.pop(pid, None)
                self.eco_qos_pids.discard(pid)

        for pid in candidates:
            if is_protected(pid, self.excluded_processes):
                continue

            proc = self.background_procs.get(pid)
            if proc is None:
                try:
                    proc = psutil.Process(pid)
                    proc.cpu_percent(None)  # prime the sample; first call is meaningless
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                self.background_procs[pid] = proc
                self.background_low_streak[pid] = 0
                continue

            try:
                usage = proc.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self.background_procs.pop(pid, None)
                self.background_low_streak.pop(pid, None)
                self.eco_qos_pids.discard(pid)
                continue

            if usage < BACKGROUND_CPU_THRESHOLD_PERCENT:
                self.background_low_streak[pid] = self.background_low_streak.get(pid, 0) + 1
            else:
                self.background_low_streak[pid] = 0

            should_enable = self.background_low_streak[pid] >= BACKGROUND_LOW_USAGE_CYCLES
            already_enabled = pid in self.eco_qos_pids
            # Reassert on every scan pass (not just on the enable/disable edge) so an
            # external reset of EcoQoS can't silently stick between scans.
            if should_enable:
                if apply_ecoqos_only(pid, True):
                    if not already_enabled:
                        logger.info("%s -> EcoQoS on (background, low usage)", describe_pid(pid))
                    self.eco_qos_pids.add(pid)
            elif already_enabled:
                if apply_ecoqos_only(pid, False):
                    logger.info("%s -> EcoQoS off (usage resumed)", describe_pid(pid))
                    self.eco_qos_pids.discard(pid)

    def restore_all(self):
        """Restores every managed process back to NORMAL and disables background EcoQoS."""
        with self._lock:
            for pid, tier in list(self.managed_pids.items()):
                if tier != ThrottleTier.NORMAL:
                    if apply_throttle_tier(pid, ThrottleTier.NORMAL, self.natural_baseline.get(pid)):
                        logger.info("%s -> NORMAL (restore)", describe_pid(pid))
                    else:
                        logger.warning("%s -> NORMAL (restore) FAILED", describe_pid(pid))
            self.managed_pids.clear()
            self.overwrite_streak.clear()

            for pid in list(self.eco_qos_pids):
                if apply_ecoqos_only(pid, False):
                    logger.info("%s -> EcoQoS off (restore)", describe_pid(pid))
                else:
                    logger.warning("%s -> EcoQoS off (restore) FAILED", describe_pid(pid))
            self.eco_qos_pids.clear()
            self.background_procs.clear()
            self.background_low_streak.clear()

            persist_managed_state(self.managed_pids, self.eco_qos_pids)

    def restore_process_name(self, name: str) -> None:
        """Restores every currently-managed pid matching this executable name to NORMAL.

        Called right when the user excludes a process that's already throttled, so the
        exclusion takes effect immediately rather than waiting for the process to exit.
        """
        lname = name.lower()
        with self._lock:
            for pid in [p for p in self.managed_pids if (get_process_name(p) or "").lower() == lname]:
                tier = self.managed_pids.pop(pid)
                self.overwrite_streak.pop(pid, None)
                if tier != ThrottleTier.NORMAL and apply_throttle_tier(
                    pid, ThrottleTier.NORMAL, self.natural_baseline.get(pid)
                ):
                    logger.info("%s -> NORMAL (excluded)", describe_pid(pid))
            for pid in [p for p in self.eco_qos_pids if (get_process_name(p) or "").lower() == lname]:
                if apply_ecoqos_only(pid, False):
                    logger.info("%s -> EcoQoS off (excluded)", describe_pid(pid))
                self.eco_qos_pids.discard(pid)
            persist_managed_state(self.managed_pids, self.eco_qos_pids)

    def get_stats(self) -> int:
        """Returns the number of processes currently throttled into any eco tier."""
        with self._lock:
            return sum(1 for t in self.managed_pids.values() if t != ThrottleTier.NORMAL) + len(self.eco_qos_pids)


# --- System tray application ---

# Outline of the Material Design Icons "leaf" glyph (Apache License 2.0,
# https://github.com/Templarian/MaterialDesign), flattened from its SVG bezier path and
# scaled from a 24x24 viewBox to this app's 64x64 icon canvas.
_LEAF_POLYGON_POINTS = (
    (44.1, 22.3), (40.2, 23.4), (36.7, 24.6), (33.5, 26.0), (30.6, 27.7), (28.1, 29.4),
    (25.8, 31.4), (23.7, 33.4), (21.9, 35.6), (20.2, 37.8), (18.8, 40.2), (17.5, 42.5),
    (16.3, 44.9), (15.2, 47.4), (14.2, 49.8), (13.2, 52.2), (12.2, 54.6), (16.8, 56.2),
    (19.1, 50.6), (19.3, 50.7), (19.5, 50.8), (19.8, 50.8), (20.0, 50.9), (20.2, 51.0),
    (20.4, 51.0), (20.6, 51.1), (20.8, 51.1), (21.0, 51.2), (21.2, 51.2), (21.4, 51.2),
    (21.6, 51.3), (21.8, 51.3), (22.0, 51.3), (22.2, 51.3), (22.3, 51.3), (27.1, 50.9),
    (31.4, 49.6), (35.3, 47.5), (38.8, 44.9), (42.0, 41.8), (44.7, 38.3), (47.1, 34.6),
    (49.2, 30.8), (51.0, 27.0), (52.5, 23.2), (53.7, 19.8), (54.6, 16.7), (55.3, 14.0),
    (55.8, 12.0), (56.1, 10.7), (56.2, 10.2), (55.5, 11.1), (54.6, 11.9), (53.4, 12.6),
    (51.9, 13.2), (50.2, 13.7), (48.4, 14.2), (46.3, 14.7), (44.1, 15.1), (41.8, 15.5),
    (39.4, 15.8), (36.9, 16.2), (34.4, 16.5), (31.9, 16.9), (29.5, 17.3), (27.1, 17.7),
    (24.8, 18.1), (22.6, 18.6), (20.6, 19.4), (18.7, 20.2), (17.0, 21.2), (15.5, 22.3),
    (14.1, 23.4), (12.9, 24.7), (11.8, 26.0), (10.8, 27.3), (10.0, 28.6), (9.3, 29.9),
    (8.8, 31.2), (8.4, 32.4), (8.1, 33.6), (7.9, 34.7), (7.8, 35.6), (7.9, 36.5),
    (8.0, 37.4), (8.2, 38.3), (8.5, 39.1), (8.8, 39.9), (9.2, 40.6), (9.6, 41.3),
    (9.9, 42.0), (10.3, 42.6), (10.7, 43.1), (11.1, 43.6), (11.4, 44.0), (11.7, 44.3),
    (11.9, 44.5), (12.0, 44.6), (12.1, 44.7), (13.7, 40.8), (15.7, 37.3), (17.9, 34.3),
    (20.4, 31.8), (23.0, 29.6), (25.6, 27.8), (28.3, 26.3), (31.0, 25.1), (33.6, 24.2),
    (36.0, 23.5), (38.2, 23.0), (40.2, 22.7), (41.8, 22.5), (43.0, 22.4), (43.8, 22.3),
)


def create_tray_icon_image(color: str, size: int = 64):
    """Draws a leaf glyph (see _LEAF_POLYGON_POINTS) -- green while active, yellow while paused."""
    scale = size / 64
    points = tuple((x * scale, y * scale) for x, y in _LEAF_POLYGON_POINTS)
    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    ImageDraw.Draw(image).polygon(points, fill=color)
    return image


def acquire_single_instance_lock():
    """Prevents multiple daemons from fighting over process priorities."""
    mutex = kernel32.CreateMutexW(None, False, "Global\\EcoEnforcerSingleInstance")
    if not mutex or kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
        return None
    return mutex


_CHECKBOX_CHECKED = "\u2611"
_CHECKBOX_UNCHECKED = "\u2610"


def _open_excluded_processes_window(daemon: "EcoEnforcerDaemon") -> None:  # pragma: no cover -- real Tk GUI
    """Builds and runs a scrollable, searchable window for managing excluded processes.

    Runs its own Tk() + mainloop() on the calling (dedicated) thread, so it's self-contained
    and doesn't interfere with the pystray icon's own thread. The process/CPU snapshot is
    taken once at open time rather than kept live, per the window's purpose as a picker.
    """
    rows = collect_process_rows()

    root = tk.Tk()
    root.title("EcoEnforcer - Excluded Processes")

    width, height = 700, 440
    work_area = get_work_area()
    if work_area:
        left, top, right, bottom = work_area
        # Clamp the window to the work area (screen minus taskbar) so it never draws
        # underneath the taskbar; center it within that area instead of the full screen.
        height = min(height, bottom - top)
        x = left + max(0, ((right - left) - width) // 2)
        y = top + max(0, ((bottom - top) - height) // 2)
        root.geometry(f"{width}x{height}+{x}+{y}")
    else:
        root.geometry(f"{width}x{height}")

    # Reuse the tray's green leaf icon instead of the default Tk/Python one; the
    # PhotoImage reference must be kept alive on the widget or it gets garbage collected.
    icon_photo = ImageTk.PhotoImage(create_tray_icon_image("#22C55E"))
    root.iconphoto(True, icon_photo)
    root._icon_photo = icon_photo

    if not is_running_as_admin():
        ttk.Label(
            root, text="Run in Admin Mode to Manage All Processes",
            foreground="#B45309", padding=(8, 8, 8, 0),
        ).pack(fill="x")

    search_frame = ttk.Frame(root, padding=(8, 8, 8, 0))
    search_frame.pack(fill="x")
    ttk.Label(search_frame, text="Search:").pack(side="left")
    search_var = tk.StringVar()
    ttk.Entry(search_frame, textvariable=search_var).pack(side="left", fill="x", expand=True, padx=(6, 0))

    tree_frame = ttk.Frame(root, padding=8)
    tree_frame.pack(fill="both", expand=True)

    columns = ("check", "friendly", "exe", "path", "cpu")
    column_headings = {
        "check": "", "friendly": "Friendly Name", "exe": "Executable", "path": "Path", "cpu": "CPU %",
    }
    tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="none")
    for col, width, anchor in (
        ("check", 28, "center"),
        ("friendly", 170, "w"),
        ("exe", 130, "w"),
        ("path", 280, "w"),
        ("cpu", 60, "e"),
    ):
        tree.column(col, width=width, anchor=anchor, stretch=(col == "path"))

    scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    def checkbox_for(lname: str) -> str:
        return _CHECKBOX_CHECKED if lname in daemon.excluded_processes else _CHECKBOX_UNCHECKED

    # Sorting: "check" puts every currently-excluded process at the top when ascending.
    sort_key_funcs = {
        "check": lambda row: row["name"].lower() not in daemon.excluded_processes,
        "friendly": lambda row: row["friendly"].lower(),
        "exe": lambda row: row["name"].lower(),
        "path": lambda row: (row["path"] or "").lower(),
        "cpu": lambda row: row["cpu"],
    }
    sort_state = {"column": "friendly", "reverse": False}

    def update_headings() -> None:
        for col, text in column_headings.items():
            arrow = ""
            if col == sort_state["column"]:
                arrow = " \u25bc" if sort_state["reverse"] else " \u25b2"
            tree.heading(col, text=f"{text}{arrow}", command=lambda c=col: sort_by(c))

    def sort_by(column: str) -> None:
        if sort_state["column"] == column:
            sort_state["reverse"] = not sort_state["reverse"]
        else:
            sort_state["column"] = column
            sort_state["reverse"] = False
        update_headings()
        populate(search_var.get())

    def populate(filter_text: str = "") -> None:
        tree.delete(*tree.get_children())
        needle = filter_text.strip().lower()
        filtered = [
            row for row in rows
            if not needle or needle in row["friendly"].lower() or needle in row["name"].lower()
        ]
        filtered.sort(key=sort_key_funcs[sort_state["column"]], reverse=sort_state["reverse"])
        for row in filtered:
            lname = row["name"].lower()
            tree.insert("", "end", iid=lname, values=(
                checkbox_for(lname), row["friendly"], row["name"], row["path"], f'{row["cpu"]:.1f}',
            ))

    def on_search_change(*_args) -> None:
        populate(search_var.get())

    search_var.trace_add("write", on_search_change)

    def on_click(event) -> None:
        if tree.identify_region(event.x, event.y) != "cell" or tree.identify_column(event.x) != "#1":
            return
        lname = tree.identify_row(event.y)
        if not lname:
            return
        if lname in daemon.excluded_processes:
            daemon.excluded_processes.discard(lname)
        else:
            daemon.excluded_processes.add(lname)
            daemon.restore_process_name(lname)
        save_settings(daemon.disable_on_ac, daemon.power_plan_enabled, daemon.excluded_processes)
        tree.set(lname, "check", checkbox_for(lname))

    tree.bind("<Button-1>", on_click)

    update_headings()
    populate()
    root.mainloop()


_TopAlignedTrayIcon = pystray.Icon
if sys.platform == "win32":
    try:
        from pystray._util import win32 as _pystray_win32

        class _TopAlignedTrayIcon(pystray.Icon):  # noqa: F811 -- intentional win32-only override
            """pystray's win32 backend anchors the popup menu's bottom edge to the raw
            cursor position, which sits inside the taskbar for a tray-icon click --
            letting the menu's bottom rows render underneath the taskbar. Clamping the
            anchor y-coordinate to the work area's bottom (the taskbar's top edge)
            guarantees the whole menu draws above it.
            """

            def _on_notify(self, wparam, lparam):
                if not (self._menu_handle and lparam == _pystray_win32.WM_RBUTTONUP):
                    return super()._on_notify(wparam, lparam)

                _pystray_win32.SetForegroundWindow(self._hwnd)

                point = wintypes.POINT()
                _pystray_win32.GetCursorPos(ctypes.byref(point))
                work_area = get_work_area()
                if work_area:
                    point.y = min(point.y, work_area[3])

                hmenu, descriptors = self._menu_handle
                index = _pystray_win32.TrackPopupMenuEx(
                    hmenu,
                    _pystray_win32.TPM_RIGHTALIGN | _pystray_win32.TPM_BOTTOMALIGN
                    | _pystray_win32.TPM_RETURNCMD,
                    point.x, point.y, self._menu_hwnd, None)
                if index > 0:
                    descriptors[index - 1](self)
    except ImportError:
        # pystray is stubbed out (e.g. under test on a non-Windows runner); keep the
        # plain pystray.Icon fallback assigned above.
        pass


def main():  # pragma: no cover -- tray/GUI wiring; requires a real Windows session to run
    configure_logging()

    if sys.platform != "win32":
        print("EcoEnforcer only supports Windows.", file=sys.stderr)
        sys.exit(1)

    lock = acquire_single_instance_lock()
    if lock is None:
        print("EcoEnforcer is already running.", file=sys.stderr)
        sys.exit(1)

    recover_previous_session()

    daemon = EcoEnforcerDaemon()
    worker_thread = threading.Thread(target=daemon.run, daemon=True)
    worker_thread.start()

    icon_green = create_tray_icon_image("#22C55E")
    icon_yellow = create_tray_icon_image("#EAB308")

    def toggle_pause(icon, item):
        if daemon.paused:
            daemon.paused = False
            logger.info("Resumed")
        elif daemon.power_pause_reason:
            daemon.power_override_active = not daemon.power_override_active
            if daemon.power_override_active:
                logger.info("Manually resumed despite power/AC pause condition")
            else:
                logger.info("Manual override cancelled; auto-pause re-engaged")
                daemon.restore_all()
        else:
            daemon.paused = True
            logger.info("Paused: restoring all managed processes to NORMAL")
            daemon.restore_all()
        refresh_status()

    def on_quit(icon, item):
        logger.info("Quitting: restoring all managed processes to NORMAL")
        daemon.running = False
        worker_thread.join(timeout=5)  # ensure enforce_step isn't mid-run before the final restore
        daemon.restore_all()
        icon.stop()

    def toggle_disable_on_ac(icon, item):
        daemon.disable_on_ac = not daemon.disable_on_ac
        save_settings(daemon.disable_on_ac, daemon.power_plan_enabled, daemon.excluded_processes)

    def make_toggle_plan(guid):
        def toggle_plan(icon, item):
            current = daemon.power_plan_enabled.get(guid, default_power_plan_enabled(guid))
            daemon.power_plan_enabled[guid] = not current
            save_settings(daemon.disable_on_ac, daemon.power_plan_enabled, daemon.excluded_processes)
        return toggle_plan

    def make_plan_checked(guid):
        return lambda item: daemon.power_plan_enabled.get(guid, default_power_plan_enabled(guid))

    # Cached rather than re-derived on every menu refresh (every 2s): is_startup_enabled()
    # can shell out to schtasks, which is wasted work when nothing has changed since the
    # last check/toggle.
    startup_enabled = is_startup_enabled()

    def toggle_run_on_startup(icon, item):
        nonlocal startup_enabled
        startup_enabled = not startup_enabled
        set_startup_enabled(startup_enabled)

    # Guards against opening a second window while one is already up.
    _excluded_window_open = threading.Event()

    def open_excluded_processes_window(icon, item):
        if _excluded_window_open.is_set():
            return
        _excluded_window_open.set()

        def worker():
            try:
                _open_excluded_processes_window(daemon)
            finally:
                _excluded_window_open.clear()

        threading.Thread(target=worker, daemon=True).start()

    def check_and_apply_update(icon, item):
        def worker():
            result = check_for_update()
            if result is None:
                icon.notify("You're running the latest version.", "EcoEnforcer")
                return
            new_version, download_url = result
            if not getattr(sys, "frozen", False):
                icon.notify(f"Update {new_version} available, but auto-update only "
                            "works from the built executable.", "EcoEnforcer")
                return

            icon.notify(f"Downloading EcoEnforcer {new_version}...", "EcoEnforcer")
            update_dir = APP_DATA_DIR / "update"
            update_dir.mkdir(parents=True, exist_ok=True)
            new_exe_path = update_dir / "EcoEnforcer.new.exe"
            if not _download_update(download_url, new_exe_path):
                icon.notify("Update download failed.", "EcoEnforcer")
                return
            if not _verify_update_signature(new_exe_path):
                new_exe_path.unlink(missing_ok=True)
                logger.warning("Downloaded update failed signature verification; discarding")
                icon.notify("Update signature verification failed -- discarded for safety.", "EcoEnforcer")
                return

            logger.info("Update %s verified; applying and restarting", new_version)
            apply_update(new_exe_path)
            on_quit(icon, item)

        threading.Thread(target=worker, daemon=True).start()

    power_plans = list_power_plans()
    if power_plans:
        plan_menu_items = [
            pystray.MenuItem(name, make_toggle_plan(guid), checked=make_plan_checked(guid))
            for guid, name in power_plans
        ]
    else:
        plan_menu_items = [pystray.MenuItem("(no power plans found)", None, enabled=False)]

    menu = pystray.Menu(
        pystray.MenuItem(lambda item: daemon.get_status_text(), None, enabled=False),
        pystray.MenuItem(lambda item: f"Eco Mode Processes: {daemon.get_stats()}", None, enabled=False),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem(
            lambda item: "Pause" if not daemon.paused and (
                daemon.power_pause_reason is None or daemon.power_override_active
            ) else "Resume",
            toggle_pause,
        ),
        pystray.MenuItem(
            "Disable when Plugged In", toggle_disable_on_ac, checked=lambda item: daemon.disable_on_ac,
        ),
        pystray.MenuItem("Use With Power Plans:", pystray.Menu(*plan_menu_items)),
        pystray.MenuItem("Manage Excluded Processes...", open_excluded_processes_window),
        pystray.MenuItem("Run on Startup", toggle_run_on_startup, checked=lambda item: startup_enabled),
        pystray.MenuItem("Check for Updates", check_and_apply_update),
        pystray.MenuItem("Quit", on_quit)
    )

    tray_icon = _TopAlignedTrayIcon("EcoEnforcer", icon_green, "EcoEnforcer", menu)

    def refresh_status():
        status_text = daemon.get_status_text()
        tray_icon.icon = icon_green if status_text.startswith("EcoEnforcer Active") else icon_yellow
        tray_icon.title = f"{status_text}\nEco Mode Processes: {daemon.get_stats()}"
        # pystray caches the rendered menu (status line, process count, Pause/Resume label)
        # and only recomputes it on an explicit update_menu() call, not on every popup --
        # without this, those dynamic labels go stale until some menu item is clicked.
        tray_icon.update_menu()

    def update_tooltip():
        while daemon.running:
            refresh_status()
            time.sleep(2.0)

    tooltip_thread = threading.Thread(target=update_tooltip, daemon=True)
    tooltip_thread.start()

    tray_icon.run()


if __name__ == "__main__":  # pragma: no cover
    main()
