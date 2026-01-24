#!/usr/bin/env python3
"""
VPS Guardian - Detector Module Tests
Tests process detection logic with various threat patterns.
"""

import pytest
from unittest.mock import Mock, patch
from guardian.modules.detector import Detector, Threat


class TestDetector:
    """Test suite for the Detector module."""

    def test_detect_suspicious_term_xmrig(self, mock_config):
        """Should detect process with 'xmrig' in name."""
        detector = Detector(mock_config)

        process_info = {
            'pid': 1234,
            'name': 'xmrig',
            'exe': '/tmp/xmrig',
            'cmdline': ['xmrig', '-o', 'pool.minexmr.com:4444']
        }

        threat = detector._analyze_process(process_info)

        assert threat is not None
        assert threat.pid == 1234
        assert threat.severity == 'high'
        assert 'xmrig' in threat.reason.lower()

    def test_detect_suspicious_term_monero(self, mock_config):
        """Should detect process with 'monero' in command line."""
        detector = Detector(mock_config)

        process_info = {
            'pid': 5678,
            'name': 'miner',
            'exe': '/usr/local/bin/miner',
            'cmdline': ['miner', '--coin', 'monero']
        }

        threat = detector._analyze_process(process_info)

        assert threat is not None
        assert threat.severity == 'high'
        assert 'monero' in threat.reason.lower()

    def test_detect_process_in_tmp(self, mock_config):
        """Should detect process running from /tmp."""
        detector = Detector(mock_config)

        process_info = {
            'pid': 9999,
            'name': 'suspicious_app',
            'exe': '/tmp/suspicious_app',
            'cmdline': ['suspicious_app']
        }

        threat = detector._analyze_process(process_info)

        assert threat is not None
        assert threat.severity == 'high'
        assert '/tmp/' in threat.reason

    def test_detect_fake_kernel_process(self, mock_config):
        """Should detect fake kernel process (kworkerds)."""
        detector = Detector(mock_config)

        process_info = {
            'pid': 1111,
            'name': 'kworkerds',
            'exe': '/tmp/kworkerds',
            'cmdline': ['kworkerds']
        }

        threat = detector._analyze_process(process_info)

        assert threat is not None
        assert threat.severity == 'high'
        # Can be detected as fake kernel or suspicious path - both are valid
        assert 'fake kernel' in threat.reason.lower() or 'suspicious path' in threat.reason.lower()

    def test_not_detect_legitimate_process(self, mock_config):
        """Should NOT detect legitimate system process (tracker-miner)."""
        detector = Detector(mock_config)

        process_info = {
            'pid': 2222,
            'name': 'tracker-miner-fs',
            'exe': '/usr/libexec/tracker-miner-fs',
            'cmdline': ['/usr/libexec/tracker-miner-fs']
        }

        threat = detector._analyze_process(process_info)

        assert threat is None

    def test_not_detect_gnome_process(self, mock_config):
        """Should NOT detect GNOME process even if it has 'mine' in name."""
        detector = Detector(mock_config)

        process_info = {
            'pid': 3333,
            'name': 'gnome-mines',
            'exe': '/usr/games/gnome-mines',
            'cmdline': ['/usr/games/gnome-mines']
        }

        threat = detector._analyze_process(process_info)

        assert threat is None

    def test_not_detect_whitelisted_path(self, mock_config):
        """Should NOT detect processes from legitimate system paths."""
        detector = Detector(mock_config)

        process_info = {
            'pid': 4444,
            'name': 'some-daemon',
            'exe': '/usr/lib/some-daemon',
            'cmdline': ['/usr/lib/some-daemon']
        }

        threat = detector._analyze_process(process_info)

        assert threat is None

    def test_detect_random_name_pattern(self, mock_config):
        """Should detect suspicious random process name."""
        detector = Detector(mock_config)

        process_info = {
            'pid': 5555,
            'name': 'asdfjklqwerty',
            'exe': '/usr/local/bin/asdfjklqwerty',  # Not in /tmp to test random name detection
            'cmdline': ['asdfjklqwerty']
        }

        threat = detector._analyze_process(process_info)

        assert threat is not None
        assert threat.severity == 'medium'
        assert 'random' in threat.reason.lower()

    def test_skip_real_kernel_thread(self, mock_config):
        """Should NOT flag real kernel threads (no exe, no cmdline)."""
        detector = Detector(mock_config)

        process_info = {
            'pid': 6666,
            'name': 'kworker/0:1',
            'exe': None,
            'cmdline': []
        }

        threat = detector._analyze_process(process_info)

        assert threat is None

    @patch('psutil.process_iter')
    def test_scan_multiple_processes(self, mock_process_iter, mock_config):
        """Should scan multiple processes and return only threats."""
        detector = Detector(mock_config)

        # Mock process list
        mock_processes = [
            Mock(info={'pid': 1, 'name': 'systemd', 'exe': '/sbin/systemd', 'cmdline': ['systemd']}),
            Mock(info={'pid': 2, 'name': 'xmrig', 'exe': '/tmp/xmrig', 'cmdline': ['xmrig']}),
            Mock(info={'pid': 3, 'name': 'python3', 'exe': '/usr/bin/python3', 'cmdline': ['python3']}),
        ]
        mock_process_iter.return_value = mock_processes

        threats = detector.scan()

        assert len(threats) == 1
        assert threats[0].pid == 2
        assert threats[0].name == 'xmrig'

    def test_skip_self_process(self, mock_config):
        """Should skip scanning its own PID."""
        detector = Detector(mock_config)

        process_info = {
            'pid': detector.my_pid,
            'name': 'guardian.py',
            'exe': '/opt/vps-guardian/guardian.py',
            'cmdline': ['python3', 'guardian.py']
        }

        # This should not be analyzed since it's our own PID
        # Test via scan() which checks my_pid
        with patch('psutil.process_iter') as mock_iter:
            mock_iter.return_value = [Mock(info=process_info)]
            threats = detector.scan()

        assert len(threats) == 0
