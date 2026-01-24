#!/usr/bin/env python3
"""
VPS Guardian - Shared Test Fixtures
Provides reusable test fixtures and configuration.
"""

import pytest
from pathlib import Path
from datetime import datetime


@pytest.fixture
def mock_config():
    """Standard configuration for tests."""
    return {
        'detection': {
            'suspicious_terms': ['xmrig', 'monero', 'stratum', 'nicehash'],
            'scan_interval_seconds': 5
        },
        'resources': {
            'cpu_threshold_percent': 80,
            'memory_threshold_percent': 50,
            'notify_after_minutes': 10,
            'kill_after_minutes': 20,
            'whitelist': ['python', 'systemd', 'dockerd']
        },
        'network': {
            'mining_pools_list': '/tmp/test_mining_pools.txt',
            'tor_nodes_list': '/tmp/test_tor_nodes.txt',
            'suspicious_ports': [3333, 4444, 5555, 14444, 45560]
        },
        'response': {
            'quarantine_dir': '/tmp/test_quarantine',
            'log_file': '/tmp/test_guardian.jsonl',
            'telegram': {
                'enabled': False,
                'webhook_url': 'https://api.telegram.org/bot123/sendMessage',
                'chat_id': '12345'
            }
        },
        'integrity': {
            'critical_binaries': ['/usr/bin/ls', '/usr/bin/ps'],
            'hash_db': '/tmp/test_hashes.json'
        },
        'filesystem': {
            'watch_dirs': ['/tmp', '/var/tmp'],
            'max_file_age_minutes': 30
        },
        'forensics': {
            'enabled': True,
            'storage_dir': '/tmp/test_forensics',
            'max_collection_time_seconds': 2,
            'include_environ': True,
            'include_open_files': True,
            'retention_days': 30
        },
        'auditd': {
            'enabled': False,
            'install_rules': True,
            'log_path': '/var/log/audit/audit.log'
        },
        'persistence': {
            'enabled': True,
            'scan_interval_seconds': 60,
            'crontab': {
                'system_paths': ['/etc/crontab'],
                'cron_d_path': '/etc/cron.d',
                'user_crontabs_path': '/var/spool/cron/crontabs',
                'periodic_paths': ['/etc/cron.daily', '/etc/cron.hourly']
            },
            'systemd': {
                'service_path': '/etc/systemd/system',
                'timer_path': '/etc/systemd/system'
            },
            'rc_scripts': {
                'paths': ['/etc/rc.local', '/etc/init.d']
            },
            'ssh_keys': {
                'authorized_keys_paths': ['/root/.ssh/authorized_keys', '/home/*/.ssh/authorized_keys'],
                'known_keys_db': '/var/lib/guardian/known_ssh_keys.json'
            }
        }
    }


@pytest.fixture
def mock_process_info():
    """Factory for creating mock process info dictionaries."""
    def _create(pid=1234, name='test_process', exe='/usr/bin/test',
                cmdline=None, cpu_percent=0, memory_percent=0):
        return {
            'pid': pid,
            'name': name,
            'exe': exe,
            'cmdline': cmdline or ['test_process'],
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent
        }
    return _create


@pytest.fixture
def temp_quarantine_dir(tmp_path):
    """Create temporary quarantine directory."""
    quarantine = tmp_path / "quarantine"
    quarantine.mkdir()
    return quarantine


@pytest.fixture
def temp_log_file(tmp_path):
    """Create temporary log file."""
    log_file = tmp_path / "incidents.jsonl"
    return log_file


@pytest.fixture
def mock_datetime(monkeypatch):
    """Mock datetime for consistent timestamps in tests."""
    class MockDateTime:
        @staticmethod
        def now():
            return datetime(2026, 1, 24, 12, 0, 0)

        @staticmethod
        def isoformat():
            return "2026-01-24T12:00:00"

    monkeypatch.setattr('guardian.modules.response.datetime', MockDateTime)
    return MockDateTime
