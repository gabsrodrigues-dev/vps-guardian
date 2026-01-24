#!/usr/bin/env python3
"""
VPS Guardian - Auditd Monitor Tests
Tests auditd log parsing and event detection.
"""

import pytest
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch, mock_open
from guardian.modules.auditd import AuditdMonitor, AuditEvent


class TestAuditdMonitor:
    """Test suite for the AuditdMonitor module."""

    @pytest.fixture
    def auditd_config(self, tmp_path):
        """Auditd monitor configuration."""
        log_path = tmp_path / 'audit.log'
        log_path.touch()

        return {
            'auditd': {
                'enabled': True,
                'install_rules': True,
                'log_path': str(log_path)
            }
        }

    @pytest.fixture
    def disabled_auditd_config(self):
        """Disabled auditd configuration."""
        return {
            'auditd': {
                'enabled': False,
                'install_rules': False,
                'log_path': '/var/log/audit/audit.log'
            }
        }

    def test_auditd_disabled_by_config(self, disabled_auditd_config):
        """Should respect disabled flag in config."""
        monitor = AuditdMonitor(disabled_auditd_config)
        assert monitor.enabled is False

    def test_auditd_enabled_by_config(self, auditd_config):
        """Should respect enabled flag in config."""
        monitor = AuditdMonitor(auditd_config)
        assert monitor.enabled is True

    @patch('subprocess.run')
    def test_check_auditd_available_installed(self, mock_run, auditd_config):
        """Should detect when auditd is installed and running."""
        # Mock auditctl command exists and service is active
        mock_run.side_effect = [
            Mock(returncode=0),  # which auditctl
            Mock(returncode=0)   # systemctl is-active auditd
        ]

        monitor = AuditdMonitor(auditd_config)
        assert monitor.check_auditd_available() is True

    @patch('subprocess.run')
    def test_check_auditd_available_not_installed(self, mock_run, auditd_config):
        """Should detect when auditd is not installed."""
        mock_run.return_value = Mock(returncode=1)  # which auditctl fails

        monitor = AuditdMonitor(auditd_config)
        assert monitor.check_auditd_available() is False

    @patch('subprocess.run')
    def test_get_installed_rules(self, mock_run, auditd_config):
        """Should retrieve currently installed audit rules."""
        mock_run.return_value = Mock(
            returncode=0,
            stdout='-a always,exit -F arch=b64 -S execve -F dir=/tmp -k guardian_tmp\n'
                   '-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k guardian_shm\n'
        )

        monitor = AuditdMonitor(auditd_config)
        rules = monitor.get_installed_rules()

        assert len(rules) == 2
        assert 'guardian_tmp' in rules[0]
        assert 'guardian_shm' in rules[1]

    def test_generate_rules(self, auditd_config):
        """Should generate audit rules for guardian monitoring."""
        monitor = AuditdMonitor(auditd_config)
        rules = monitor.generate_rules()

        assert 'guardian_tmp' in rules
        assert 'guardian_shm' in rules
        assert 'guardian_vartmp' in rules
        assert '/tmp' in rules
        assert '/dev/shm' in rules
        assert '/var/tmp' in rules

    def test_parse_single_execve_event(self, auditd_config, tmp_path):
        """Should parse a single EXECVE event from audit log."""
        log_content = """type=SYSCALL msg=audit(1706000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=12345 uid=0
type=EXECVE msg=audit(1706000000.123:456): argc=3 a0="/tmp/malware" a1="-c" a2="payload"
type=CWD msg=audit(1706000000.123:456): cwd="/tmp"
type=PATH msg=audit(1706000000.123:456): item=0 name="/tmp/malware" key="guardian_tmp"
"""

        log_path = tmp_path / 'audit.log'
        log_path.write_text(log_content)

        auditd_config['auditd']['log_path'] = str(log_path)
        monitor = AuditdMonitor(auditd_config)

        events = monitor.parse_log(since_last=False)

        assert len(events) == 1
        assert events[0].pid == 12345
        assert events[0].ppid == 1
        assert events[0].uid == 0
        assert events[0].exe == '/tmp/malware'
        assert events[0].cmdline == ['/tmp/malware', '-c', 'payload']
        assert events[0].cwd == '/tmp'
        assert events[0].key == 'guardian_tmp'

    def test_parse_multiple_events(self, auditd_config, tmp_path):
        """Should parse multiple EXECVE events from audit log."""
        log_content = """type=SYSCALL msg=audit(1706000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=12345 uid=0
type=EXECVE msg=audit(1706000000.123:456): argc=2 a0="/tmp/script1" a1="arg1"
type=CWD msg=audit(1706000000.123:456): cwd="/tmp"
type=PATH msg=audit(1706000000.123:456): item=0 name="/tmp/script1" key="guardian_tmp"
type=SYSCALL msg=audit(1706000001.124:457): arch=c000003e syscall=59 success=yes exit=0 ppid=2 pid=12346 uid=1000
type=EXECVE msg=audit(1706000001.124:457): argc=1 a0="/dev/shm/miner"
type=CWD msg=audit(1706000001.124:457): cwd="/dev/shm"
type=PATH msg=audit(1706000001.124:457): item=0 name="/dev/shm/miner" key="guardian_shm"
"""

        log_path = tmp_path / 'audit.log'
        log_path.write_text(log_content)

        auditd_config['auditd']['log_path'] = str(log_path)
        monitor = AuditdMonitor(auditd_config)

        events = monitor.parse_log(since_last=False)

        assert len(events) == 2
        assert events[0].pid == 12345
        assert events[0].key == 'guardian_tmp'
        assert events[1].pid == 12346
        assert events[1].key == 'guardian_shm'

    def test_incremental_reading(self, auditd_config, tmp_path):
        """Should track file position for incremental reads."""
        log_path = tmp_path / 'audit.log'

        # Initial log content
        initial_content = """type=SYSCALL msg=audit(1706000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=12345 uid=0
type=EXECVE msg=audit(1706000000.123:456): argc=1 a0="/tmp/old"
type=CWD msg=audit(1706000000.123:456): cwd="/tmp"
type=PATH msg=audit(1706000000.123:456): item=0 name="/tmp/old" key="guardian_tmp"
"""
        log_path.write_text(initial_content)

        auditd_config['auditd']['log_path'] = str(log_path)
        monitor = AuditdMonitor(auditd_config)

        # First read - should get 1 event
        events1 = monitor.parse_log(since_last=True)
        assert len(events1) == 1
        assert events1[0].exe == '/tmp/old'

        # Append new content
        new_content = """type=SYSCALL msg=audit(1706000001.124:457): arch=c000003e syscall=59 success=yes exit=0 ppid=2 pid=12346 uid=1000
type=EXECVE msg=audit(1706000001.124:457): argc=1 a0="/tmp/new"
type=CWD msg=audit(1706000001.124:457): cwd="/tmp"
type=PATH msg=audit(1706000001.124:457): item=0 name="/tmp/new" key="guardian_tmp"
"""
        with open(log_path, 'a') as f:
            f.write(new_content)

        # Second read - should only get new event
        events2 = monitor.parse_log(since_last=True)
        assert len(events2) == 1
        assert events2[0].exe == '/tmp/new'

    def test_handle_log_rotation(self, auditd_config, tmp_path):
        """Should detect log rotation and reset position."""
        log_path = tmp_path / 'audit.log'

        # Write initial content
        log_path.write_text("type=SYSCALL msg=audit(1706000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=12345 uid=0\n" * 100)

        auditd_config['auditd']['log_path'] = str(log_path)
        monitor = AuditdMonitor(auditd_config)

        # First read to set position
        monitor.parse_log(since_last=True)
        old_position = monitor.last_position

        # Simulate log rotation (file gets smaller)
        log_path.write_text("type=SYSCALL msg=audit(1706000002.125:500): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=99999 uid=0\n")

        # Should detect rotation and reset position
        monitor.parse_log(since_last=True)
        assert monitor.last_position < old_position

    def test_filter_suspicious_events_by_exe_path(self, auditd_config):
        """Should identify events from suspicious paths."""
        monitor = AuditdMonitor(auditd_config)

        events = [
            AuditEvent(
                timestamp=datetime.now(),
                event_type='EXECVE',
                pid=1234,
                ppid=1,
                uid=0,
                exe='/tmp/suspicious',
                cmdline=['/tmp/suspicious'],
                cwd='/tmp',
                key='guardian_tmp',
                raw_record='...'
            ),
            AuditEvent(
                timestamp=datetime.now(),
                event_type='EXECVE',
                pid=5678,
                ppid=1,
                uid=0,
                exe='/usr/bin/legitimate',
                cmdline=['/usr/bin/legitimate'],
                cwd='/home/user',
                key='guardian_tmp',
                raw_record='...'
            )
        ]

        suspicious = monitor.get_suspicious_events(events)

        # Should flag /tmp execution but not /usr/bin
        assert len(suspicious) >= 1
        assert suspicious[0].exe == '/tmp/suspicious'

    def test_filter_suspicious_events_by_cmdline(self, auditd_config):
        """Should identify events with suspicious command patterns."""
        monitor = AuditdMonitor(auditd_config)

        events = [
            AuditEvent(
                timestamp=datetime.now(),
                event_type='EXECVE',
                pid=1234,
                ppid=1,
                uid=0,
                exe='/usr/local/bin/worker',
                cmdline=['/usr/local/bin/worker', '--pool', 'pool.minexmr.com'],
                cwd='/tmp',
                key='guardian_tmp',
                raw_record='...'
            )
        ]

        suspicious = monitor.get_suspicious_events(events)

        # Should flag mining pool in cmdline
        assert len(suspicious) == 1

    def test_handle_missing_auditd_gracefully(self, auditd_config):
        """Should handle missing auditd without crashing."""
        auditd_config['auditd']['log_path'] = '/nonexistent/audit.log'

        monitor = AuditdMonitor(auditd_config)

        # Should not crash, just return empty list
        events = monitor.parse_log(since_last=False)
        assert events == []

    def test_handle_permission_error_gracefully(self, auditd_config, tmp_path):
        """Should handle permission errors gracefully."""
        log_path = tmp_path / 'audit.log'
        log_path.touch()
        log_path.chmod(0o000)  # Remove all permissions

        auditd_config['auditd']['log_path'] = str(log_path)
        monitor = AuditdMonitor(auditd_config)

        # Should not crash
        events = monitor.parse_log(since_last=False)
        assert events == []

        # Cleanup
        log_path.chmod(0o644)

    def test_parse_timestamp(self, auditd_config, tmp_path):
        """Should correctly parse audit log timestamps."""
        log_content = """type=SYSCALL msg=audit(1706000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=12345 uid=0
type=EXECVE msg=audit(1706000000.123:456): argc=1 a0="/tmp/test"
type=CWD msg=audit(1706000000.123:456): cwd="/tmp"
type=PATH msg=audit(1706000000.123:456): item=0 name="/tmp/test" key="guardian_tmp"
"""

        log_path = tmp_path / 'audit.log'
        log_path.write_text(log_content)

        auditd_config['auditd']['log_path'] = str(log_path)
        monitor = AuditdMonitor(auditd_config)

        events = monitor.parse_log(since_last=False)

        assert len(events) == 1
        assert isinstance(events[0].timestamp, datetime)

    def test_skip_non_guardian_events(self, auditd_config, tmp_path):
        """Should skip events not tagged with guardian keys."""
        log_content = """type=SYSCALL msg=audit(1706000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=12345 uid=0
type=EXECVE msg=audit(1706000000.123:456): argc=1 a0="/bin/ls"
type=CWD msg=audit(1706000000.123:456): cwd="/home/user"
type=PATH msg=audit(1706000000.123:456): item=0 name="/bin/ls" key="other_key"
type=SYSCALL msg=audit(1706000001.124:457): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=12346 uid=0
type=EXECVE msg=audit(1706000001.124:457): argc=1 a0="/tmp/miner"
type=CWD msg=audit(1706000001.124:457): cwd="/tmp"
type=PATH msg=audit(1706000001.124:457): item=0 name="/tmp/miner" key="guardian_tmp"
"""

        log_path = tmp_path / 'audit.log'
        log_path.write_text(log_content)

        auditd_config['auditd']['log_path'] = str(log_path)
        monitor = AuditdMonitor(auditd_config)

        events = monitor.parse_log(since_last=False)

        # Should only get the guardian_tmp event
        assert len(events) == 1
        assert events[0].exe == '/tmp/miner'

    def test_default_config_values(self):
        """Should use default values when config sections are missing."""
        minimal_config = {}
        monitor = AuditdMonitor(minimal_config)

        assert monitor.enabled is False
        assert monitor.install_rules is True
        assert str(monitor.log_path) == '/var/log/audit/audit.log'
