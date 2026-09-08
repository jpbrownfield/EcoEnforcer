import sys
import types
from unittest.mock import MagicMock, patch

import pytest

# pycaw/comtypes/pystray only import cleanly on Windows; stub them out so the
# module can be imported and unit tested on any platform in CI.
for _name in ("pystray", "comtypes"):
    sys.modules.setdefault(_name, MagicMock())

if "pycaw" not in sys.modules:
    pycaw_pkg = types.ModuleType("pycaw")
    pycaw_mod = types.ModuleType("pycaw.pycaw")
    pycaw_mod.AudioUtilities = MagicMock()
    pycaw_pkg.pycaw = pycaw_mod
    sys.modules["pycaw"] = pycaw_pkg
    sys.modules["pycaw.pycaw"] = pycaw_mod

import eco_enforcer as ee


@pytest.fixture(autouse=True)
def isolate_app_data_dir(tmp_path, monkeypatch):
    """Prevents tests from reading/writing the real %LOCALAPPDATA%\\EcoEnforcer."""
    monkeypatch.setattr(ee, "APP_DATA_DIR", tmp_path)
    monkeypatch.setattr(ee, "STATE_FILE", tmp_path / "managed_state.json")
    monkeypatch.setattr(ee, "LOG_FILE", tmp_path / "eco_enforcer.log")


class TestDecideTier:
    def test_foreground_pid_is_normal(self):
        assert ee.decide_tier(pid=10, foreground_pid=10, audio_pids=set()) == ee.ThrottleTier.NORMAL

    def test_background_with_audio_is_eco_audio(self):
        assert ee.decide_tier(pid=10, foreground_pid=99, audio_pids={10}) == ee.ThrottleTier.ECO_AUDIO

    def test_background_silent_is_eco_max(self):
        assert ee.decide_tier(pid=10, foreground_pid=99, audio_pids=set()) == ee.ThrottleTier.ECO_MAX

    def test_foreground_wins_over_audio(self):
        assert ee.decide_tier(pid=10, foreground_pid=10, audio_pids={10}) == ee.ThrottleTier.NORMAL


class TestIsProtected:
    def test_protected_process_name(self):
        with patch("eco_enforcer.psutil.Process") as mock_process:
            mock_process.return_value.name.return_value = "explorer.exe"
            assert ee.is_protected(123) is True

    def test_unprotected_process_name(self):
        with patch("eco_enforcer.psutil.Process") as mock_process:
            mock_process.return_value.name.return_value = "notepad.exe"
            assert ee.is_protected(123) is False

    def test_no_such_process_is_treated_as_protected(self):
        import psutil
        with patch("eco_enforcer.psutil.Process", side_effect=psutil.NoSuchProcess(123)):
            assert ee.is_protected(123) is True


class TestDescribePid:
    def test_includes_process_name_when_available(self):
        with patch("eco_enforcer.psutil.Process") as mock_process:
            mock_process.return_value.name.return_value = "notepad.exe"
            assert ee.describe_pid(123) == "notepad.exe (pid 123)"

    def test_falls_back_to_pid_when_process_unavailable(self):
        import psutil
        with patch("eco_enforcer.psutil.Process", side_effect=psutil.NoSuchProcess(123)):
            assert ee.describe_pid(123) == "pid 123"


class TestGetProcessName:
    def test_returns_name_when_process_exists(self):
        with patch("eco_enforcer.psutil.Process") as mock_process:
            mock_process.return_value.name.return_value = "notepad.exe"
            assert ee.get_process_name(123) == "notepad.exe"

    def test_returns_none_when_process_missing(self):
        import psutil
        with patch("eco_enforcer.psutil.Process", side_effect=psutil.NoSuchProcess(123)):
            assert ee.get_process_name(123) is None


class TestPersistManagedState:
    def test_writes_only_non_normal_entries(self, tmp_path):
        state_file = tmp_path / "managed_state.json"
        managed_pids = {
            1: ee.ThrottleTier.ECO_MAX,
            2: ee.ThrottleTier.NORMAL,
            3: ee.ThrottleTier.ECO_AUDIO,
        }
        with patch("eco_enforcer.STATE_FILE", state_file), \
             patch("eco_enforcer.APP_DATA_DIR", tmp_path), \
             patch("eco_enforcer.get_process_name", return_value="test.exe"):
            ee.persist_managed_state(managed_pids)

        import json
        saved = json.loads(state_file.read_text(encoding="utf-8"))
        assert set(saved.keys()) == {"1", "3"}
        assert saved["1"] == {"name": "test.exe", "tier": "ECO_MAX"}

    def test_swallows_write_errors(self, tmp_path):
        # A path that can't exist as a directory (its parent is a file) forces a write failure.
        bogus_dir = tmp_path / "not_a_dir"
        bogus_dir.write_text("x")
        with patch("eco_enforcer.STATE_FILE", bogus_dir / "state.json"), \
             patch("eco_enforcer.APP_DATA_DIR", bogus_dir):
            ee.persist_managed_state({1: ee.ThrottleTier.ECO_MAX})  # should not raise


class TestRecoverPreviousSession:
    def test_no_state_file_is_a_no_op(self, tmp_path):
        with patch("eco_enforcer.STATE_FILE", tmp_path / "missing.json"), \
             patch("eco_enforcer.apply_throttle_tier") as mock_apply:
            ee.recover_previous_session()
            mock_apply.assert_not_called()

    def test_restores_matching_process_and_clears_file(self, tmp_path):
        import json
        state_file = tmp_path / "managed_state.json"
        state_file.write_text(json.dumps({"5": {"name": "stale.exe", "tier": "ECO_MAX"}}), encoding="utf-8")
        with patch("eco_enforcer.STATE_FILE", state_file), \
             patch("eco_enforcer.get_process_name", return_value="stale.exe"), \
             patch("eco_enforcer.apply_throttle_tier", return_value=True) as mock_apply:
            ee.recover_previous_session()
            mock_apply.assert_called_once_with(5, ee.ThrottleTier.NORMAL)
        assert not state_file.exists()

    def test_skips_pid_whose_name_no_longer_matches(self, tmp_path):
        import json
        state_file = tmp_path / "managed_state.json"
        state_file.write_text(json.dumps({"5": {"name": "stale.exe", "tier": "ECO_MAX"}}), encoding="utf-8")
        with patch("eco_enforcer.STATE_FILE", state_file), \
             patch("eco_enforcer.get_process_name", return_value="unrelated.exe"), \
             patch("eco_enforcer.apply_throttle_tier") as mock_apply:
            ee.recover_previous_session()
            mock_apply.assert_not_called()

    def test_handles_corrupt_state_file(self, tmp_path):
        state_file = tmp_path / "managed_state.json"
        state_file.write_text("{not valid json", encoding="utf-8")
        with patch("eco_enforcer.STATE_FILE", state_file), \
             patch("eco_enforcer.apply_throttle_tier") as mock_apply:
            ee.recover_previous_session()
            mock_apply.assert_not_called()
        assert not state_file.exists()


class TestConfigureLogging:
    def test_creates_app_data_dir_and_attaches_handlers(self, tmp_path):
        log_file = tmp_path / "eco_enforcer.log"
        fresh_logger = ee.logging.getLogger("EcoEnforcerTest")
        with patch("eco_enforcer.APP_DATA_DIR", tmp_path), \
             patch("eco_enforcer.LOG_FILE", log_file), \
             patch("eco_enforcer.logger", fresh_logger):
            ee.configure_logging()
        assert tmp_path.exists()
        assert len(fresh_logger.handlers) == 2
        for handler in fresh_logger.handlers:
            handler.close()


class TestApplyThrottleTier:
    def test_skips_system_and_self_pids(self):
        with patch("eco_enforcer.kernel32") as mock_kernel32:
            assert ee.apply_throttle_tier(0, ee.ThrottleTier.NORMAL) is False
            assert ee.apply_throttle_tier(4, ee.ThrottleTier.NORMAL) is False
            mock_kernel32.OpenProcess.assert_not_called()

    def test_returns_false_when_open_process_fails(self):
        with patch("eco_enforcer.kernel32") as mock_kernel32:
            mock_kernel32.OpenProcess.return_value = 0
            assert ee.apply_throttle_tier(1234, ee.ThrottleTier.NORMAL) is False

    def test_eco_max_uses_idle_priority(self):
        with patch("eco_enforcer.kernel32") as mock_kernel32:
            mock_kernel32.OpenProcess.return_value = 42
            mock_kernel32.SetProcessInformation.return_value = True
            result = ee.apply_throttle_tier(1234, ee.ThrottleTier.ECO_MAX)
            assert result is True
            mock_kernel32.SetPriorityClass.assert_called_once_with(42, ee.IDLE_PRIORITY_CLASS)
            mock_kernel32.CloseHandle.assert_called_once_with(42)

    def test_eco_max_disables_dynamic_priority_boost(self):
        with patch("eco_enforcer.kernel32") as mock_kernel32:
            mock_kernel32.OpenProcess.return_value = 42
            mock_kernel32.SetProcessInformation.return_value = True
            ee.apply_throttle_tier(1234, ee.ThrottleTier.ECO_MAX)
            mock_kernel32.SetProcessPriorityBoost.assert_called_once_with(42, True)

    def test_eco_audio_uses_normal_priority(self):
        with patch("eco_enforcer.kernel32") as mock_kernel32:
            mock_kernel32.OpenProcess.return_value = 42
            mock_kernel32.SetProcessInformation.return_value = True
            ee.apply_throttle_tier(1234, ee.ThrottleTier.ECO_AUDIO)
            mock_kernel32.SetPriorityClass.assert_called_once_with(42, ee.NORMAL_PRIORITY_CLASS)

    def test_eco_audio_keeps_dynamic_priority_boost_enabled(self):
        with patch("eco_enforcer.kernel32") as mock_kernel32:
            mock_kernel32.OpenProcess.return_value = 42
            mock_kernel32.SetProcessInformation.return_value = True
            ee.apply_throttle_tier(1234, ee.ThrottleTier.ECO_AUDIO)
            mock_kernel32.SetProcessPriorityBoost.assert_called_once_with(42, False)

    def test_normal_tier_keeps_dynamic_priority_boost_enabled(self):
        with patch("eco_enforcer.kernel32") as mock_kernel32:
            mock_kernel32.OpenProcess.return_value = 42
            mock_kernel32.SetProcessInformation.return_value = True
            ee.apply_throttle_tier(1234, ee.ThrottleTier.NORMAL)
            mock_kernel32.SetProcessPriorityBoost.assert_called_once_with(42, False)

    def test_normal_tier_uses_normal_priority_and_disables_ecoqos(self):
        captured = {}

        def _capture_state(handle, info_class, state_ptr, size):
            # Copy the StateMask out of the struct before it goes out of scope.
            captured["state_mask"] = state_ptr._obj.StateMask
            return True

        with patch("eco_enforcer.kernel32") as mock_kernel32:
            mock_kernel32.OpenProcess.return_value = 42
            mock_kernel32.SetProcessInformation.side_effect = _capture_state
            ee.apply_throttle_tier(1234, ee.ThrottleTier.NORMAL)
            mock_kernel32.SetPriorityClass.assert_called_once_with(42, ee.NORMAL_PRIORITY_CLASS)
            # StateMask must be cleared (0) when EcoQoS is disabled.
            assert captured["state_mask"] == 0

    def test_handle_is_closed_even_if_set_process_information_raises(self):
        with patch("eco_enforcer.kernel32") as mock_kernel32:
            mock_kernel32.OpenProcess.return_value = 42
            mock_kernel32.SetProcessInformation.side_effect = OSError("boom")
            with pytest.raises(OSError):
                ee.apply_throttle_tier(1234, ee.ThrottleTier.ECO_MAX)
            mock_kernel32.CloseHandle.assert_called_once_with(42)


class TestEcoEnforcerDaemonEnforceStep:
    def _make_daemon(self):
        return ee.EcoEnforcerDaemon()

    def test_foreground_window_set_to_normal(self):
        daemon = self._make_daemon()
        with patch("eco_enforcer.get_foreground_pid", return_value=1), \
             patch("eco_enforcer.get_active_audio_pids", return_value=set()), \
             patch("eco_enforcer.get_visible_window_pids", return_value={1}), \
             patch("eco_enforcer.is_protected", return_value=False), \
             patch("eco_enforcer.apply_throttle_tier", return_value=True) as mock_apply:
            daemon.managed_pids[1] = ee.ThrottleTier.ECO_MAX
            daemon.enforce_step()
            mock_apply.assert_called_once_with(1, ee.ThrottleTier.NORMAL)
            assert daemon.managed_pids[1] == ee.ThrottleTier.NORMAL

    def test_hidden_audio_window_set_to_eco_audio(self):
        daemon = self._make_daemon()
        with patch("eco_enforcer.get_foreground_pid", return_value=99), \
             patch("eco_enforcer.get_active_audio_pids", return_value={2}), \
             patch("eco_enforcer.get_visible_window_pids", return_value={2}), \
             patch("eco_enforcer.is_protected", return_value=False), \
             patch("eco_enforcer.apply_throttle_tier", return_value=True) as mock_apply:
            daemon.enforce_step()
            mock_apply.assert_called_once_with(2, ee.ThrottleTier.ECO_AUDIO)
            assert daemon.managed_pids[2] == ee.ThrottleTier.ECO_AUDIO

    def test_hidden_silent_window_set_to_eco_max(self):
        daemon = self._make_daemon()
        with patch("eco_enforcer.get_foreground_pid", return_value=99), \
             patch("eco_enforcer.get_active_audio_pids", return_value=set()), \
             patch("eco_enforcer.get_visible_window_pids", return_value={3}), \
             patch("eco_enforcer.is_protected", return_value=False), \
             patch("eco_enforcer.apply_throttle_tier", return_value=True) as mock_apply:
            daemon.enforce_step()
            mock_apply.assert_called_once_with(3, ee.ThrottleTier.ECO_MAX)
            assert daemon.managed_pids[3] == ee.ThrottleTier.ECO_MAX

    def test_protected_processes_are_skipped(self):
        daemon = self._make_daemon()
        with patch("eco_enforcer.get_foreground_pid", return_value=99), \
             patch("eco_enforcer.get_active_audio_pids", return_value=set()), \
             patch("eco_enforcer.get_visible_window_pids", return_value={4}), \
             patch("eco_enforcer.is_protected", return_value=True), \
             patch("eco_enforcer.apply_throttle_tier") as mock_apply:
            daemon.enforce_step()
            mock_apply.assert_not_called()
            assert 4 not in daemon.managed_pids

    def test_no_op_when_tier_unchanged(self):
        daemon = self._make_daemon()
        daemon.managed_pids[5] = ee.ThrottleTier.ECO_MAX
        with patch("eco_enforcer.get_foreground_pid", return_value=99), \
             patch("eco_enforcer.get_active_audio_pids", return_value=set()), \
             patch("eco_enforcer.get_visible_window_pids", return_value={5}), \
             patch("eco_enforcer.is_protected", return_value=False), \
             patch("eco_enforcer.apply_throttle_tier") as mock_apply:
            daemon.enforce_step()
            mock_apply.assert_not_called()

    def test_orphaned_pid_restored_to_normal(self):
        daemon = self._make_daemon()
        daemon.managed_pids[6] = ee.ThrottleTier.ECO_MAX
        with patch("eco_enforcer.get_foreground_pid", return_value=99), \
             patch("eco_enforcer.get_active_audio_pids", return_value=set()), \
             patch("eco_enforcer.get_visible_window_pids", return_value=set()), \
             patch("eco_enforcer.is_protected", return_value=False), \
             patch("eco_enforcer.apply_throttle_tier", return_value=True) as mock_apply:
            daemon.enforce_step()
            mock_apply.assert_called_once_with(6, ee.ThrottleTier.NORMAL)
            assert 6 not in daemon.managed_pids

    def test_failed_apply_drops_pid_from_managed_state(self):
        daemon = self._make_daemon()
        with patch("eco_enforcer.get_foreground_pid", return_value=99), \
             patch("eco_enforcer.get_active_audio_pids", return_value=set()), \
             patch("eco_enforcer.get_visible_window_pids", return_value={7}), \
             patch("eco_enforcer.is_protected", return_value=False), \
             patch("eco_enforcer.apply_throttle_tier", return_value=False):
            daemon.enforce_step()
            assert 7 not in daemon.managed_pids

    def test_successful_tier_change_is_logged(self, caplog):
        daemon = self._make_daemon()
        with caplog.at_level("INFO", logger="EcoEnforcer"), \
             patch("eco_enforcer.get_foreground_pid", return_value=99), \
             patch("eco_enforcer.get_active_audio_pids", return_value=set()), \
             patch("eco_enforcer.get_visible_window_pids", return_value={8}), \
             patch("eco_enforcer.is_protected", return_value=False), \
             patch("eco_enforcer.describe_pid", return_value="test.exe (pid 8)"), \
             patch("eco_enforcer.apply_throttle_tier", return_value=True):
            daemon.enforce_step()
        assert "test.exe (pid 8) -> ECO_MAX" in caplog.text

    def test_failed_tier_change_is_logged_as_warning(self, caplog):
        daemon = self._make_daemon()
        with caplog.at_level("WARNING", logger="EcoEnforcer"), \
             patch("eco_enforcer.get_foreground_pid", return_value=99), \
             patch("eco_enforcer.get_active_audio_pids", return_value=set()), \
             patch("eco_enforcer.get_visible_window_pids", return_value={9}), \
             patch("eco_enforcer.is_protected", return_value=False), \
             patch("eco_enforcer.describe_pid", return_value="test.exe (pid 9)"), \
             patch("eco_enforcer.apply_throttle_tier", return_value=False):
            daemon.enforce_step()
        assert "test.exe (pid 9) -> ECO_MAX FAILED" in caplog.text


class TestGetActiveAudioPids:
    def test_collects_pids_with_active_state(self):
        session_active = MagicMock(State=1, Process=MagicMock(pid=10))
        session_inactive = MagicMock(State=0, Process=MagicMock(pid=20))
        session_no_process = MagicMock(State=1, Process=None)
        with patch("eco_enforcer.AudioUtilities") as mock_audio:
            mock_audio.GetAllSessions.return_value = [session_active, session_inactive, session_no_process]
            assert ee.get_active_audio_pids() == {10}

    def test_swallows_exceptions_and_returns_empty_set(self):
        with patch("eco_enforcer.AudioUtilities") as mock_audio:
            mock_audio.GetAllSessions.side_effect = OSError("no audio device")
            assert ee.get_active_audio_pids() == set()


class TestGetVisibleWindowPids:
    def test_enumerates_only_visible_titled_windows(self):
        def fake_enum_windows(proc, lparam):
            # Simulate three windows: visible+titled, hidden, visible+untitled.
            proc(1, 0)
            proc(2, 0)
            proc(3, 0)
            return True

        def fake_is_visible(hwnd):
            return hwnd in (1, 2)

        def fake_text_length(hwnd):
            return {1: 5, 2: 0}.get(hwnd, 0)

        def fake_get_pid(hwnd, pid_ref):
            pid_ref._obj.value = {1: 111}.get(hwnd, 0)

        with patch("eco_enforcer.user32") as mock_user32:
            mock_user32.EnumWindows.side_effect = fake_enum_windows
            mock_user32.IsWindowVisible.side_effect = fake_is_visible
            mock_user32.GetWindowTextLengthW.side_effect = fake_text_length
            mock_user32.GetWindowThreadProcessId.side_effect = fake_get_pid
            assert ee.get_visible_window_pids() == {111}


class TestGetForegroundPid:
    def test_returns_zero_when_no_foreground_window(self):
        with patch("eco_enforcer.user32") as mock_user32:
            mock_user32.GetForegroundWindow.return_value = 0
            assert ee.get_foreground_pid() == 0

    def test_returns_pid_of_foreground_window(self):
        def fake_get_pid(hwnd, pid_ref):
            pid_ref._obj.value = 555

        with patch("eco_enforcer.user32") as mock_user32:
            mock_user32.GetForegroundWindow.return_value = 7
            mock_user32.GetWindowThreadProcessId.side_effect = fake_get_pid
            assert ee.get_foreground_pid() == 555


class TestAcquireSingleInstanceLock:
    def test_returns_handle_when_no_existing_instance(self):
        with patch("eco_enforcer.kernel32") as mock_kernel32:
            mock_kernel32.CreateMutexW.return_value = 99
            mock_kernel32.GetLastError.return_value = 0
            assert ee.acquire_single_instance_lock() == 99

    def test_returns_none_when_already_running(self):
        with patch("eco_enforcer.kernel32") as mock_kernel32:
            mock_kernel32.CreateMutexW.return_value = 99
            mock_kernel32.GetLastError.return_value = ee.ERROR_ALREADY_EXISTS
            assert ee.acquire_single_instance_lock() is None


class TestEcoEnforcerDaemonMisc:
    def test_restore_all_resets_non_normal_processes(self):
        daemon = ee.EcoEnforcerDaemon()
        daemon.managed_pids = {1: ee.ThrottleTier.ECO_MAX, 2: ee.ThrottleTier.NORMAL}
        with patch("eco_enforcer.apply_throttle_tier", return_value=True) as mock_apply:
            daemon.restore_all()
            mock_apply.assert_called_once_with(1, ee.ThrottleTier.NORMAL)
        assert daemon.managed_pids == {}

    def test_restore_all_logs_each_restoration(self, caplog):
        daemon = ee.EcoEnforcerDaemon()
        daemon.managed_pids = {1: ee.ThrottleTier.ECO_MAX}
        with caplog.at_level("INFO", logger="EcoEnforcer"), \
             patch("eco_enforcer.describe_pid", return_value="test.exe (pid 1)"), \
             patch("eco_enforcer.apply_throttle_tier", return_value=True):
            daemon.restore_all()
        assert "test.exe (pid 1) -> NORMAL (restore)" in caplog.text

    def test_get_stats_counts_all_non_normal_tiers(self):
        daemon = ee.EcoEnforcerDaemon()
        daemon.managed_pids = {
            1: ee.ThrottleTier.ECO_MAX,
            2: ee.ThrottleTier.ECO_MAX,
            3: ee.ThrottleTier.ECO_AUDIO,
            4: ee.ThrottleTier.NORMAL,
        }
        assert daemon.get_stats() == 3

    def test_run_invokes_enforce_step_until_stopped(self):
        daemon = ee.EcoEnforcerDaemon()
        call_count = {"n": 0}

        def fake_enforce_step():
            call_count["n"] += 1
            daemon.running = False  # stop after first iteration

        with patch("eco_enforcer.comtypes") as mock_comtypes, \
             patch("eco_enforcer.time.sleep") as mock_sleep, \
             patch.object(daemon, "enforce_step", side_effect=fake_enforce_step):
            daemon.run()
            mock_comtypes.CoInitialize.assert_called_once()
            mock_comtypes.CoUninitialize.assert_called_once()
            mock_sleep.assert_called_once_with(1.5)
        assert call_count["n"] == 1


class TestCreateTrayIconImage:
    def test_returns_rgba_image_of_expected_size(self):
        image = ee.create_tray_icon_image("#22C55E")
        assert image.size == (64, 64)
        assert image.mode == "RGBA"
