#!/usr/bin/env python3
"""
VPS Guardian - Real Process Tests (CRITICAL)
Tests with REAL processes to ensure no zombies are left behind.

These tests create actual child processes and verify they are properly
terminated without leaving defunct/zombie processes.

Run with: pytest tests/test_real_process.py -v
"""

import os
import sys
import time
import signal
import subprocess
import psutil
import pytest

# Add guardian to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from guardian.modules.response import ResponseHandler


@pytest.fixture
def real_config(tmp_path):
    """Real config for testing."""
    quarantine = tmp_path / 'quarantine'
    quarantine.mkdir()
    return {
        'response': {
            'quarantine_dir': str(quarantine),
            'log_file': str(tmp_path / 'incidents.jsonl'),
            'telegram': {
                'enabled': False,
                'webhook_url': None,
                'chat_id': None
            }
        }
    }


class TestRealProcessKill:
    """Tests that use REAL processes to verify zombie prevention."""

    def test_kill_real_process_no_zombie(self, real_config):
        """
        CRITICAL TEST: Kill a real process and verify NO zombie is created.

        This test:
        1. Spawns a real child process (sleep)
        2. Verifies it's running
        3. Kills it using our ResponseHandler
        4. Verifies it's dead
        5. Verifies NO zombie/defunct state
        """
        handler = ResponseHandler(real_config)

        # 1. Spawn a real process
        proc = subprocess.Popen(
            ['sleep', '60'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        pid = proc.pid

        # 2. Verify it's running
        assert psutil.pid_exists(pid), "Process should be running"
        ps = psutil.Process(pid)
        assert ps.status() != psutil.STATUS_ZOMBIE, "Should not be zombie initially"

        # 3. Kill using our handler
        result = handler._kill_process(pid)

        # 4. Verify kill was successful
        assert result is True, "Kill should succeed"

        # 5. Wait a moment and verify no zombie
        time.sleep(0.5)

        # Check if process exists
        if psutil.pid_exists(pid):
            try:
                ps = psutil.Process(pid)
                status = ps.status()
                assert status != psutil.STATUS_ZOMBIE, \
                    f"Process {pid} became ZOMBIE! Status: {status}"
                assert status != psutil.STATUS_DEAD, \
                    f"Process {pid} is DEAD (defunct)! Status: {status}"
            except psutil.NoSuchProcess:
                pass  # Process is gone, which is correct

        # Clean up just in case
        try:
            proc.kill()
            proc.wait()
        except:
            pass

    def test_kill_real_process_with_children_no_zombies(self, real_config):
        """
        CRITICAL TEST: Kill a process with children and verify NO zombies.

        This test spawns a parent process that creates children,
        then kills the parent and verifies no zombies remain.
        """
        handler = ResponseHandler(real_config)

        # 1. Spawn a parent process that creates children using bash
        # This creates a parent with 2 children
        parent = subprocess.Popen(
            ['bash', '-c', 'sleep 60 & sleep 60 & wait'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        parent_pid = parent.pid

        # Give children time to spawn
        time.sleep(0.5)

        # 2. Verify parent is running and has children
        assert psutil.pid_exists(parent_pid), "Parent should be running"
        ps_parent = psutil.Process(parent_pid)
        children = ps_parent.children(recursive=True)

        # Collect all PIDs (parent + children)
        all_pids = [parent_pid] + [c.pid for c in children]

        # 3. Kill using our handler
        result = handler._kill_process(parent_pid)

        # 4. Verify kill was successful
        assert result is True, "Kill should succeed"

        # 5. Wait and verify NO zombies in any of the processes
        time.sleep(1.0)

        zombies_found = []
        for pid in all_pids:
            if psutil.pid_exists(pid):
                try:
                    ps = psutil.Process(pid)
                    if ps.status() == psutil.STATUS_ZOMBIE:
                        zombies_found.append(pid)
                except psutil.NoSuchProcess:
                    pass  # Good - process is gone

        assert len(zombies_found) == 0, \
            f"ZOMBIE processes found! PIDs: {zombies_found}"

        # Clean up
        for pid in all_pids:
            try:
                os.kill(pid, signal.SIGKILL)
            except:
                pass

    def test_kill_stubborn_process_sigkill(self, real_config):
        """
        Test killing a process that ignores SIGTERM (requires SIGKILL).

        This verifies our SIGTERM -> SIGKILL escalation works.
        """
        handler = ResponseHandler(real_config)

        # Create a script that ignores SIGTERM
        script = """
import signal
import time

# Ignore SIGTERM
signal.signal(signal.SIGTERM, signal.SIG_IGN)

# Sleep forever
while True:
    time.sleep(1)
"""

        # 1. Spawn process that ignores SIGTERM
        proc = subprocess.Popen(
            [sys.executable, '-c', script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        pid = proc.pid

        # 2. Verify running
        assert psutil.pid_exists(pid), "Process should be running"

        # 3. Kill (should escalate to SIGKILL)
        result = handler._kill_process(pid)

        # 4. Should succeed (via SIGKILL)
        assert result is True, "Kill should succeed even for stubborn process"

        # 5. Verify dead and no zombie
        time.sleep(0.5)

        if psutil.pid_exists(pid):
            try:
                ps = psutil.Process(pid)
                assert ps.status() != psutil.STATUS_ZOMBIE, \
                    "Stubborn process became zombie!"
            except psutil.NoSuchProcess:
                pass

        # Cleanup
        try:
            proc.kill()
            proc.wait()
        except:
            pass

    def test_verify_wait_prevents_zombie(self, real_config):
        """
        Verify that our wait() call prevents zombies.

        Zombies are created when a parent doesn't call wait() on dead children.
        This test proves our implementation prevents that.
        """
        handler = ResponseHandler(real_config)

        # 1. Spawn process
        proc = subprocess.Popen(
            ['sleep', '60'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        pid = proc.pid

        # 2. Kill it
        handler._kill_process(pid)

        # 3. Wait a bit
        time.sleep(0.5)

        # 4. Count zombies in the system from our test
        current_zombies = []
        for p in psutil.process_iter(['pid', 'status', 'ppid']):
            try:
                if p.info['status'] == psutil.STATUS_ZOMBIE:
                    # Only count if it's related to our test (same parent)
                    if p.info['ppid'] == os.getpid():
                        current_zombies.append(p.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        assert len(current_zombies) == 0, \
            f"Found zombie children of our process: {current_zombies}"

    def test_multiple_kills_in_sequence(self, real_config):
        """
        Test killing multiple processes in sequence - no zombie accumulation.
        """
        handler = ResponseHandler(real_config)

        pids = []

        # 1. Spawn 5 processes
        for _ in range(5):
            proc = subprocess.Popen(
                ['sleep', '60'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            pids.append(proc.pid)

        # 2. Kill them all
        for pid in pids:
            handler._kill_process(pid)

        # 3. Wait
        time.sleep(1.0)

        # 4. Verify no zombies
        for pid in pids:
            if psutil.pid_exists(pid):
                try:
                    ps = psutil.Process(pid)
                    assert ps.status() != psutil.STATUS_ZOMBIE, \
                        f"PID {pid} is zombie after sequential kills!"
                except psutil.NoSuchProcess:
                    pass

    def test_orphan_children_not_zombies(self, real_config):
        """
        When we kill a parent, children should be orphaned to init, not zombies.
        """
        handler = ResponseHandler(real_config)

        # Spawn parent with a long-running child
        parent = subprocess.Popen(
            ['bash', '-c', 'sleep 120 & echo $!; wait'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )
        parent_pid = parent.pid

        time.sleep(0.5)

        # Get children before killing parent
        try:
            ps_parent = psutil.Process(parent_pid)
            children = ps_parent.children(recursive=True)
            child_pids = [c.pid for c in children]
        except psutil.NoSuchProcess:
            child_pids = []

        # Kill parent only (not children, to test orphan handling)
        handler._kill_process(parent_pid)

        time.sleep(0.5)

        # Children should be orphaned to init (ppid=1), not zombies
        for child_pid in child_pids:
            if psutil.pid_exists(child_pid):
                try:
                    ps = psutil.Process(child_pid)
                    assert ps.status() != psutil.STATUS_ZOMBIE, \
                        f"Orphaned child {child_pid} became zombie!"
                    # Orphans get adopted by init (pid 1) or systemd
                    # Their ppid should change
                except psutil.NoSuchProcess:
                    pass

        # Cleanup children
        for child_pid in child_pids:
            try:
                os.kill(child_pid, signal.SIGKILL)
            except:
                pass


class TestRealQuarantine:
    """Tests with real files."""

    def test_quarantine_real_file(self, real_config, tmp_path):
        """Quarantine a real file and verify it's moved correctly."""
        handler = ResponseHandler(real_config)

        # Create a fake malware file
        malware = tmp_path / 'xmrig_miner'
        malware.write_bytes(b'\x7fELF' + b'\x00' * 100)  # Fake ELF header
        original_content = malware.read_bytes()

        assert malware.exists()

        # Quarantine it
        result = handler._quarantine_file(str(malware))

        assert result is True
        assert not malware.exists(), "Original file should be gone"

        # Verify it's in quarantine
        quarantine_dir = tmp_path / 'quarantine'
        quarantined = list(quarantine_dir.glob('*xmrig_miner'))
        assert len(quarantined) == 1, "Should be exactly one quarantined file"

        # Verify permissions were removed (000)
        assert os.stat(quarantined[0]).st_mode & 0o777 == 0

        # Temporarily restore permissions to verify content
        os.chmod(quarantined[0], 0o400)
        assert quarantined[0].read_bytes() == original_content
        os.chmod(quarantined[0], 0o000)  # Restore locked state


if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
