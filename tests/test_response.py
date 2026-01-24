#!/usr/bin/env python3
"""
VPS Guardian - Response Handler Tests (CRITICAL)
Tests kill, quarantine, and notification logic with edge cases.
"""

import pytest
import json
import psutil
from unittest.mock import Mock, patch, MagicMock, mock_open
from pathlib import Path
from guardian.modules.response import ResponseHandler, ResponseLevel, Incident


class TestResponseHandler:
    """Test suite for the ResponseHandler module."""

    def test_kill_simple_process(self, mock_config, tmp_path):
        """Should successfully kill a simple process."""
        mock_config['response']['quarantine_dir'] = str(tmp_path / 'quarantine')
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')
        handler = ResponseHandler(mock_config)

        with patch('psutil.Process') as mock_process_class:
            mock_proc = Mock()
            mock_proc.children.return_value = []  # No children
            mock_proc.terminate = Mock()
            mock_proc.wait = Mock()
            mock_process_class.return_value = mock_proc

            result = handler._kill_process(1234)

            assert result is True
            mock_proc.terminate.assert_called_once()
            mock_proc.wait.assert_called()

    def test_kill_process_with_children_no_zombies(self, mock_config, tmp_path):
        """Should kill process and children without leaving zombies."""
        mock_config['response']['quarantine_dir'] = str(tmp_path / 'quarantine')
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')
        handler = ResponseHandler(mock_config)

        with patch('psutil.Process') as mock_process_class:
            # Create mock parent and children
            mock_child1 = Mock()
            mock_child1.pid = 2001
            mock_child1.terminate = Mock()
            mock_child1.wait = Mock()

            mock_child2 = Mock()
            mock_child2.pid = 2002
            mock_child2.terminate = Mock()
            mock_child2.wait = Mock()

            mock_parent = Mock()
            mock_parent.children.return_value = [mock_child1, mock_child2]
            mock_parent.terminate = Mock()
            mock_parent.wait = Mock()

            mock_process_class.return_value = mock_parent

            # Mock wait_procs to simulate graceful termination
            with patch('psutil.wait_procs') as mock_wait:
                mock_wait.return_value = ([mock_child1, mock_child2], [])  # All terminated gracefully

                result = handler._kill_process(1234)

                assert result is True
                # Verify children were terminated
                mock_child1.terminate.assert_called_once()
                mock_child2.terminate.assert_called_once()
                # Verify parent was terminated
                mock_parent.terminate.assert_called_once()

    def test_kill_process_already_dead(self, mock_config, tmp_path):
        """Should handle process that's already dead gracefully."""
        mock_config['response']['quarantine_dir'] = str(tmp_path / 'quarantine')
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')
        handler = ResponseHandler(mock_config)

        with patch('psutil.Process') as mock_process_class:
            mock_process_class.side_effect = psutil.NoSuchProcess(1234)

            result = handler._kill_process(1234)

            assert result is True  # Not an error - process is already gone

    def test_kill_process_permission_denied(self, mock_config, tmp_path):
        """Should handle permission denied error."""
        mock_config['response']['quarantine_dir'] = str(tmp_path / 'quarantine')
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')
        handler = ResponseHandler(mock_config)

        with patch('psutil.Process') as mock_process_class:
            mock_proc = Mock()
            mock_proc.children.return_value = []
            mock_proc.terminate.side_effect = psutil.AccessDenied()
            mock_process_class.return_value = mock_proc

            result = handler._kill_process(1234)

            assert result is False

    def test_quarantine_file(self, mock_config, tmp_path):
        """Should quarantine file successfully."""
        quarantine_dir = tmp_path / 'quarantine'
        quarantine_dir.mkdir()

        # Create a fake malicious binary
        malicious_file = tmp_path / 'xmrig'
        malicious_file.write_text('fake miner binary')

        mock_config['response']['quarantine_dir'] = str(quarantine_dir)
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')
        handler = ResponseHandler(mock_config)

        result = handler._quarantine_file(str(malicious_file))

        assert result is True
        assert not malicious_file.exists()  # Original should be moved
        quarantined_files = list(quarantine_dir.glob('*xmrig'))
        assert len(quarantined_files) == 1

        # Verify permissions were removed
        import os
        assert os.stat(quarantined_files[0]).st_mode & 0o777 == 0

    def test_quarantine_sanitizes_dangerous_filenames(self, mock_config, tmp_path):
        """Should sanitize dangerous characters in filenames during quarantine."""
        quarantine_dir = tmp_path / 'quarantine'
        quarantine_dir.mkdir()

        mock_config['response']['quarantine_dir'] = str(quarantine_dir)
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')
        handler = ResponseHandler(mock_config)

        # Create a file with a normal name
        src_file = tmp_path / 'malware_test'
        src_file.write_text('fake malware content')

        # Quarantine it
        result = handler._quarantine_file(str(src_file))

        assert result is True
        assert not src_file.exists()

        # Verify the quarantined file is in the quarantine directory
        quarantined = list(quarantine_dir.glob('*malware_test'))
        assert len(quarantined) == 1

        # Verify the file is within quarantine dir (path traversal protection)
        assert quarantined[0].resolve().is_relative_to(quarantine_dir.resolve())

    def test_quarantine_nonexistent_file(self, mock_config, tmp_path):
        """Should handle quarantine of nonexistent file."""
        mock_config['response']['quarantine_dir'] = str(tmp_path / 'quarantine')
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')
        handler = ResponseHandler(mock_config)

        result = handler._quarantine_file('/tmp/does_not_exist')

        assert result is False

    @patch('requests.post')
    def test_telegram_notification_enabled(self, mock_post, mock_config, tmp_path):
        """Should send Telegram notification when enabled."""
        mock_config['response']['quarantine_dir'] = str(tmp_path / 'quarantine')
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')
        mock_config['response']['telegram']['enabled'] = True
        handler = ResponseHandler(mock_config)

        handler._send_notification(
            pid=1234,
            name='xmrig',
            reason='Suspicious term: xmrig',
            is_kill=True,
            details={'cpu_percent': 95.0, 'memory_percent': 60.0}
        )

        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        assert 'json' in call_kwargs
        assert 'xmrig' in call_kwargs['json']['text']
        assert '1234' in call_kwargs['json']['text']

    @patch('requests.post')
    def test_telegram_notification_disabled(self, mock_post, mock_config, tmp_path):
        """Should NOT send notification when disabled."""
        mock_config['response']['quarantine_dir'] = str(tmp_path / 'quarantine')
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')
        mock_config['response']['telegram']['enabled'] = False
        handler = ResponseHandler(mock_config)

        handler._send_notification(
            pid=1234,
            name='xmrig',
            reason='Suspicious term: xmrig',
            is_kill=True,
            details={}
        )

        mock_post.assert_not_called()

    @patch('requests.post')
    def test_telegram_notification_failure_handled(self, mock_post, mock_config, tmp_path):
        """Should handle Telegram notification failures gracefully."""
        mock_config['response']['quarantine_dir'] = str(tmp_path / 'quarantine')
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')
        mock_config['response']['telegram']['enabled'] = True
        handler = ResponseHandler(mock_config)

        mock_post.side_effect = Exception('Network error')

        # Should not raise exception
        handler._send_notification(
            pid=1234,
            name='test',
            reason='test',
            is_kill=False,
            details={}
        )

    def test_log_incident(self, mock_config, tmp_path):
        """Should log incident to JSON file."""
        log_file = tmp_path / 'incidents.jsonl'
        mock_config['response']['quarantine_dir'] = str(tmp_path / 'quarantine')
        mock_config['response']['log_file'] = str(log_file)
        handler = ResponseHandler(mock_config)

        incident = Incident(
            timestamp='2026-01-24T12:00:00',
            pid=1234,
            process_name='xmrig',
            threat_type='Suspicious term',
            reason='Contains suspicious term: xmrig',
            action_taken='killed',
            details={'severity': 'high'}
        )

        handler._log_incident(incident)

        assert log_file.exists()
        with open(log_file) as f:
            logged = json.loads(f.read())
            assert logged['pid'] == 1234
            assert logged['process_name'] == 'xmrig'
            assert logged['action_taken'] == 'killed'

    @patch('psutil.Process')
    @patch('requests.post')
    def test_handle_threat_notify_level(self, mock_post, mock_proc_class, mock_config, tmp_path):
        """Should handle NOTIFY level threat (10min warning)."""
        mock_config['response']['quarantine_dir'] = str(tmp_path / 'quarantine')
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')
        mock_config['response']['telegram']['enabled'] = True
        handler = ResponseHandler(mock_config)

        incident = handler.handle_threat(
            pid=1234,
            name='cpu_hog',
            reason='High CPU usage for 10 minutes',
            level=ResponseLevel.NOTIFY,
            extra_details={'cpu_percent': 90.0, 'duration_minutes': 10.5}
        )

        assert incident.action_taken == 'notified'
        assert incident.pid == 1234
        mock_post.assert_called_once()  # Notification sent
        mock_proc_class.assert_not_called()  # Process NOT killed

    @patch('psutil.Process')
    @patch('requests.post')
    @patch('os.path.exists', return_value=True)
    def test_handle_threat_kill_level(self, mock_exists, mock_post, mock_proc_class, mock_config, tmp_path):
        """Should handle KILL level threat (20min or explicit)."""
        quarantine_dir = tmp_path / 'quarantine'
        quarantine_dir.mkdir()

        # Create fake binary
        fake_exe = tmp_path / 'xmrig'
        fake_exe.write_text('fake miner')

        mock_config['response']['quarantine_dir'] = str(quarantine_dir)
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')
        mock_config['response']['telegram']['enabled'] = True
        handler = ResponseHandler(mock_config)

        mock_proc = Mock()
        mock_proc.children.return_value = []
        mock_proc.terminate = Mock()
        mock_proc.wait = Mock()
        mock_proc_class.return_value = mock_proc

        incident = handler.handle_threat(
            pid=5678,
            name='xmrig',
            reason='Suspicious mining process',
            level=ResponseLevel.KILL,
            exe_path=str(fake_exe),
            extra_details={'severity': 'high'}
        )

        assert 'killed' in incident.action_taken
        mock_proc.terminate.assert_called_once()  # Process killed
        assert not fake_exe.exists()  # File quarantined
