"""EcoEnforcer: a Windows tray daemon that governs CPU priority and Efficiency
Mode (EcoQoS) for processes based on window visibility and audio activity.

Tiers:
    NORMAL     - foreground window: normal priority, EcoQoS off.
    ECO_AUDIO  - hidden window playing audio: normal priority, EcoQoS on.
    ECO_MAX    - hidden window, silent: idle priority, EcoQoS on.
"""

import os
import sys
import json
import time
import logging
import threading
import ctypes
from ctypes import wintypes
from enum import Enum, auto
from pathlib import Path
from logging.handlers import RotatingFileHandler

from PIL import Image, ImageDraw
import pystray
import psutil
import comtypes

from pycaw.pycaw import AudioUtilities

# --- Win32 API constants ---
PROCESS_SET_INFORMATION = 0x0200
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

IDLE_PRIORITY_CLASS = 0x00000040
NORMAL_PRIORITY_CLASS = 0x00000020

ProcessPowerThrottling = 4
PROCESS_POWER_THROTTLING_CURRENT_VERSION = 1
PROCESS_POWER_THROTTLING_EXECUTION_SPEED = 0x1


class PROCESS_POWER_THROTTLING_STATE(ctypes.Structure):
    _fields_ = [
        ("Version", wintypes.ULONG),
        ("ControlMask", wintypes.ULONG),
        ("StateMask", wintypes.ULONG),
    ]


kernel32 = ctypes.windll.kernel32 if sys.platform == "win32" else None
user32 = ctypes.windll.user32 if sys.platform == "win32" else None

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

ERROR_ALREADY_EXISTS = 183

logger = logging.getLogger("EcoEnforcer")

# %LOCALAPPDATA%\EcoEnforcer holds the rotating log file and the crash-recovery state file.
APP_DATA_DIR = Path(os.getenv("LOCALAPPDATA") or os.path.expanduser("~")) / "EcoEnforcer"
LOG_FILE = APP_DATA_DIR / "eco_enforcer.log"
STATE_FILE = APP_DATA_DIR / "managed_state.json"


def configure_logging() -> None:
    """Logs to the console and to a rotating file under %LOCALAPPDATA%\\EcoEnforcer."""
    APP_DATA_DIR.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    file_handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    file_handler.setFormatter(formatter)

    logger.setLevel(logging.INFO)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)


# Shell/system processes that should never be throttled.
PROTECTED_PROCESSES = {
    "explorer.exe",
    "shellexperiencehost.exe",
    "searchhost.exe",
    "taskmgr.exe",
}


class ThrottleTier(Enum):
    NORMAL = auto()     # Foreground: normal priority, EcoQoS off, dynamic boost on
    ECO_AUDIO = auto()  # Background + audio: normal priority, EcoQoS on, dynamic boost on
    ECO_MAX = auto()    # Background + silent: idle priority, EcoQoS on, dynamic boost off


def apply_throttle_tier(pid: int, tier: ThrottleTier) -> bool:
    """Applies the specified CPU priority and EcoQoS profile to a process."""
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
        priority = IDLE_PRIORITY_CLASS if tier == ThrottleTier.ECO_MAX else NORMAL_PRIORITY_CLASS
        kernel32.SetPriorityClass(h_process, priority)

        # ECO_MAX also disables dynamic priority boosts so background/wait-boosted threads
        # can't briefly out-schedule other work, matching Task Manager's Efficiency Mode.
        kernel32.SetProcessPriorityBoost(h_process, tier == ThrottleTier.ECO_MAX)

        eco_enabled = tier in (ThrottleTier.ECO_AUDIO, ThrottleTier.ECO_MAX)
        throttle_state = PROCESS_POWER_THROTTLING_STATE()
        throttle_state.Version = PROCESS_POWER_THROTTLING_CURRENT_VERSION
        throttle_state.ControlMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED
        throttle_state.StateMask = PROCESS_POWER_THROTTLING_EXECUTION_SPEED if eco_enabled else 0

        success = kernel32.SetProcessInformation(
            h_process,
            ProcessPowerThrottling,
            ctypes.byref(throttle_state),
            ctypes.sizeof(throttle_state)
        )
        return bool(success)
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


def is_protected(pid: int) -> bool:
    """Returns True if the pid belongs to a protected shell process or no longer exists."""
    try:
        return psutil.Process(pid).name().lower() in PROTECTED_PROCESSES
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return True


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


def persist_managed_state(managed_pids: dict[int, "ThrottleTier"]) -> None:
    """Snapshots non-NORMAL managed processes to disk so a crash can be recovered from on next launch."""
    entries = {
        str(pid): {"name": get_process_name(pid), "tier": tier.name}
        for pid, tier in managed_pids.items()
        if tier != ThrottleTier.NORMAL
    }
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
        if recorded_name and get_process_name(pid) == recorded_name:
            if apply_throttle_tier(pid, ThrottleTier.NORMAL):
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


# --- Daemon engine ---

class EcoEnforcerDaemon:
    def __init__(self):
        self.running = True
        self.paused = False
        # Tracks current tier: {pid: ThrottleTier}
        self.managed_pids: dict[int, ThrottleTier] = {}
        # Guards managed_pids since the worker thread and quit/pause handlers touch it concurrently
        self._lock = threading.Lock()

    def run(self):
        # Initialize COM library for Windows Audio APIs on this worker thread
        comtypes.CoInitialize()
        try:
            while self.running:
                if not self.paused:
                    self.enforce_step()
                time.sleep(1.5)
        finally:
            comtypes.CoUninitialize()

    def enforce_step(self):
        foreground_pid = get_foreground_pid()
        audio_pids = get_active_audio_pids()
        visible_pids = get_visible_window_pids()

        target_states: dict[int, ThrottleTier] = {
            pid: decide_tier(pid, foreground_pid, audio_pids)
            for pid in visible_pids
            if not is_protected(pid)
        }

        # Apply transitions only when state changes
        with self._lock:
            for pid, target_tier in target_states.items():
                current_tier = self.managed_pids.get(pid, ThrottleTier.NORMAL)
                if target_tier != current_tier:
                    if apply_throttle_tier(pid, target_tier):
                        logger.info("%s -> %s", describe_pid(pid), target_tier.name)
                        self.managed_pids[pid] = target_tier
                    else:
                        logger.warning("%s -> %s FAILED", describe_pid(pid), target_tier.name)
                        # Failed to open or modify (process died/elevated)
                        self.managed_pids.pop(pid, None)

            # Restore any process that was throttled but whose window was closed
            orphaned_pids = set(self.managed_pids.keys()) - set(target_states.keys())
            for pid in orphaned_pids:
                if self.managed_pids[pid] != ThrottleTier.NORMAL:
                    if apply_throttle_tier(pid, ThrottleTier.NORMAL):
                        logger.info("%s -> NORMAL (window closed)", describe_pid(pid))
                    else:
                        logger.warning("%s -> NORMAL (window closed) FAILED", describe_pid(pid))
                self.managed_pids.pop(pid, None)

            persist_managed_state(self.managed_pids)

    def restore_all(self):
        """Restores every managed process back to NORMAL."""
        with self._lock:
            for pid, tier in list(self.managed_pids.items()):
                if tier != ThrottleTier.NORMAL:
                    if apply_throttle_tier(pid, ThrottleTier.NORMAL):
                        logger.info("%s -> NORMAL (restore)", describe_pid(pid))
                    else:
                        logger.warning("%s -> NORMAL (restore) FAILED", describe_pid(pid))
            self.managed_pids.clear()
            persist_managed_state(self.managed_pids)

    def get_stats(self) -> int:
        """Returns the number of processes currently throttled into any eco tier."""
        with self._lock:
            return sum(1 for t in self.managed_pids.values() if t != ThrottleTier.NORMAL)


# --- System tray application ---

def create_tray_icon_image(color: str):
    image = Image.new('RGBA', (64, 64), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    draw.ellipse((8, 8, 56, 56), fill=color)
    return image


def acquire_single_instance_lock():
    """Prevents multiple daemons from fighting over process priorities."""
    mutex = kernel32.CreateMutexW(None, False, "Global\\EcoEnforcerSingleInstance")
    if not mutex or kernel32.GetLastError() == ERROR_ALREADY_EXISTS:
        return None
    return mutex


def main():
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
        daemon.paused = not daemon.paused
        if daemon.paused:
            logger.info("Paused: restoring all managed processes to NORMAL")
            daemon.restore_all()
            icon.icon = icon_yellow
            icon.title = "EcoEnforcer (Paused)"
        else:
            logger.info("Resumed")
            icon.icon = icon_green

    def on_quit(icon, item):
        logger.info("Quitting: restoring all managed processes to NORMAL")
        daemon.running = False
        worker_thread.join(timeout=5)  # ensure enforce_step isn't mid-run before the final restore
        daemon.restore_all()
        icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem(
            lambda item: "Resume Eco Handler" if daemon.paused else "Pause Eco Handler",
            toggle_pause,
        ),
        pystray.MenuItem("Quit", on_quit)
    )

    tray_icon = pystray.Icon("EcoEnforcer", icon_green, "EcoEnforcer (Active)", menu)

    def update_tooltip():
        while daemon.running:
            if not daemon.paused:
                tray_icon.title = f"EcoEnforcer | Eco Processes: {daemon.get_stats()}"
            time.sleep(2.0)

    tooltip_thread = threading.Thread(target=update_tooltip, daemon=True)
    tooltip_thread.start()

    tray_icon.run()


if __name__ == "__main__":
    main()
