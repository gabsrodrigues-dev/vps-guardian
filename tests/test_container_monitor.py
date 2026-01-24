"""Tests for container resource monitoring."""
import pytest
from unittest.mock import Mock, patch, MagicMock
import time
import json

from guardian.modules.container_monitor import (
    ContainerMonitor, ContainerStats, ContainerAbuse
)


@pytest.fixture
def mock_config():
    return {
        'containers': {
            'resource_monitoring': {
                'enabled': True,
                'cpu_threshold_percent': 100,
                'kill_after_minutes': 15,
                'check_interval_seconds': 60,
                'action': 'stop',
                'whitelist': ['coolify.*', 'traefik.*'],
                'whitelist_labels': ['coolify.managed=true', 'guardian.ignore=true'],
            }
        }
    }


@pytest.fixture
def monitor(mock_config):
    return ContainerMonitor(mock_config)


class TestContainerMonitor:

    def test_init_with_defaults(self):
        """Test initialization with minimal config."""
        monitor = ContainerMonitor({})
        assert monitor.enabled is True
        assert monitor.cpu_threshold == 100
        assert monitor.kill_after_minutes == 15

    def test_init_with_config(self, monitor, mock_config):
        """Test initialization with full config."""
        assert monitor.enabled is True
        assert monitor.cpu_threshold == 100
        assert monitor.kill_after_minutes == 15
        assert 'coolify.*' in monitor.whitelist_patterns

    def test_whitelist_by_name(self, monitor):
        """Test container whitelisted by name pattern."""
        assert monitor._is_whitelisted('coolify-proxy', 'nginx:latest', {}) is True
        assert monitor._is_whitelisted('traefik', 'traefik:v2', {}) is True
        assert monitor._is_whitelisted('malicious-miner', 'ubuntu', {}) is False

    def test_whitelist_by_label(self, monitor):
        """Test container whitelisted by label."""
        labels = {'coolify.managed': 'true'}
        assert monitor._is_whitelisted('myapp', 'myapp:latest', labels) is True

        labels = {'guardian.ignore': 'true'}
        assert monitor._is_whitelisted('myapp', 'myapp:latest', labels) is True

        labels = {'random': 'label'}
        assert monitor._is_whitelisted('myapp', 'myapp:latest', labels) is False

    def test_check_detects_high_cpu(self, monitor):
        """Test detection of container with high CPU."""
        mock_stats = [
            {'id': 'abc123', 'name': 'miner', 'cpu_percent': 150.0, 'image': 'ubuntu'},
        ]

        with patch.object(monitor, '_get_container_stats', return_value=[
            {'id': 'abc123', 'name': 'miner', 'cpu_percent': 150.0, 'image': 'ubuntu'}
        ]):
            with patch.object(monitor, '_get_container_labels', return_value={}):
                # First check - starts tracking
                abusive = monitor.check()
                assert len(abusive) == 0  # Not abusive yet, just started
                assert 'abc123' in monitor._tracking
                assert monitor._tracking['abc123'].first_high_cpu_time is not None

    def test_check_kills_after_threshold(self, monitor):
        """Test container killed after exceeding time threshold."""
        with patch.object(monitor, '_get_container_stats', return_value=[
            {'id': 'abc123', 'name': 'miner', 'cpu_percent': 150.0, 'image': 'ubuntu'}
        ]):
            with patch.object(monitor, '_get_container_labels', return_value={}):
                # First check
                monitor.check()

                # Simulate 16 minutes passing
                monitor._tracking['abc123'].first_high_cpu_time = time.time() - (16 * 60)

                # Second check - should return as abusive
                abusive = monitor.check()
                assert len(abusive) == 1
                assert abusive[0].container_name == 'miner'
                assert abusive[0].duration_minutes >= 15

    def test_check_resets_on_cpu_drop(self, monitor):
        """Test tracking resets when CPU drops below threshold."""
        with patch.object(monitor, '_get_container_stats') as mock_stats:
            with patch.object(monitor, '_get_container_labels', return_value={}):
                # First check - high CPU
                mock_stats.return_value = [
                    {'id': 'abc123', 'name': 'app', 'cpu_percent': 150.0, 'image': 'ubuntu'}
                ]
                monitor.check()
                assert monitor._tracking['abc123'].first_high_cpu_time is not None

                # Second check - CPU normalized
                mock_stats.return_value = [
                    {'id': 'abc123', 'name': 'app', 'cpu_percent': 50.0, 'image': 'ubuntu'}
                ]
                monitor.check()
                assert monitor._tracking['abc123'].first_high_cpu_time is None

    def test_check_ignores_whitelisted(self, monitor):
        """Test whitelisted containers are never flagged."""
        with patch.object(monitor, '_get_container_stats', return_value=[
            {'id': 'abc123', 'name': 'coolify-proxy', 'cpu_percent': 200.0, 'image': 'coolify/proxy'}
        ]):
            with patch.object(monitor, '_get_container_labels', return_value={'coolify.managed': 'true'}):
                # Simulate 20 minutes of high CPU
                monitor.check()
                if 'abc123' in monitor._tracking:
                    monitor._tracking['abc123'].first_high_cpu_time = time.time() - (20 * 60)

                abusive = monitor.check()
                assert len(abusive) == 0  # Should not be flagged

    def test_stop_container_success(self, monitor):
        """Test successful container stop."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stderr='')
            result = monitor.stop_container('abc123def456')
            assert result is True
            mock_run.assert_called_with(
                ['docker', 'stop', 'abc123def456'],
                capture_output=True, text=True, timeout=30
            )

    def test_stop_container_failure(self, monitor):
        """Test failed container stop."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=1, stderr='Error')
            result = monitor.stop_container('abc123def456')
            assert result is False

    def test_disabled_returns_empty(self, mock_config):
        """Test disabled monitor returns empty list."""
        mock_config['containers']['resource_monitoring']['enabled'] = False
        monitor = ContainerMonitor(mock_config)
        assert monitor.check() == []

    def test_get_status(self, monitor):
        """Test status reporting."""
        status = monitor.get_status()
        assert 'enabled' in status
        assert 'threshold' in status
        assert 'tracking' in status


class TestContainerStats:
    """Test ContainerStats dataclass."""

    def test_container_stats_creation(self):
        """Test creating ContainerStats."""
        stats = ContainerStats(
            container_id='abc123',
            container_name='test-app',
            image='ubuntu:latest'
        )
        assert stats.container_id == 'abc123'
        assert stats.container_name == 'test-app'
        assert stats.first_high_cpu_time is None
        assert stats.consecutive_high_readings == 0
        assert stats.labels == {}


class TestContainerAbuse:
    """Test ContainerAbuse dataclass."""

    def test_container_abuse_creation(self):
        """Test creating ContainerAbuse."""
        abuse = ContainerAbuse(
            container_id='abc123',
            container_name='miner',
            image='ubuntu',
            cpu_percent=150.5,
            duration_minutes=16.2,
            labels={'test': 'label'}
        )
        assert abuse.container_id == 'abc123'
        assert abuse.cpu_percent == 150.5
        assert abuse.duration_minutes == 16.2


class TestDockerStatsIntegration:
    """Test docker stats command parsing."""

    def test_parse_docker_stats_output(self, monitor):
        """Test parsing real docker stats JSON output."""
        mock_output = '''{"id":"abc123","name":"test-app","cpu":"150.25%","image":"ubuntu:latest"}
{"id":"def456","name":"coolify","cpu":"5.10%","image":"coolify/proxy"}'''

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stderr='',
                stdout=mock_output
            )

            stats = monitor._get_container_stats()
            assert len(stats) == 2
            assert stats[0]['id'] == 'abc123'
            assert stats[0]['cpu_percent'] == 150.25
            assert stats[1]['cpu_percent'] == 5.10

    def test_handle_docker_stats_failure(self, monitor):
        """Test handling docker stats command failure."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stderr='Docker daemon not running',
                stdout=''
            )

            stats = monitor._get_container_stats()
            assert stats == []

    def test_handle_malformed_json(self, monitor):
        """Test handling malformed JSON from docker stats."""
        mock_output = '''{"id":"abc123","name":"test-app","cpu":"150.25%"}
invalid json line
{"id":"def456","name":"app2","cpu":"10%"}'''

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stderr='',
                stdout=mock_output
            )

            stats = monitor._get_container_stats()
            # Should parse valid lines, skip invalid
            assert len(stats) == 2
            assert stats[0]['id'] == 'abc123'
            assert stats[1]['id'] == 'def456'


class TestContainerLabels:
    """Test container label retrieval."""

    def test_get_container_labels_success(self, monitor):
        """Test successful label retrieval."""
        mock_labels = '{"coolify.managed":"true","app":"myapp"}'

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout=mock_labels
            )

            labels = monitor._get_container_labels('abc123')
            assert labels == {'coolify.managed': 'true', 'app': 'myapp'}

    def test_get_container_labels_no_labels(self, monitor):
        """Test container with no labels."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout='null'
            )

            labels = monitor._get_container_labels('abc123')
            assert labels == {}

    def test_get_container_labels_failure(self, monitor):
        """Test label retrieval failure."""
        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=1,
                stdout=''
            )

            labels = monitor._get_container_labels('abc123')
            assert labels == {}


class TestContainerWarnings:
    """Test early warning system for containers."""

    @patch('guardian.modules.container_monitor.subprocess.run')
    @patch('time.time')
    def test_get_warnings_at_5_minutes(self, mock_time, mock_run):
        """Should return warnings for containers at 5 minutes of high CPU."""
        config = {
            'containers': {
                'resource_monitoring': {
                    'enabled': True,
                    'cpu_threshold_percent': 100,
                    'warn_after_minutes': 5,
                    'kill_after_minutes': 15,
                    'whitelist': [],
                    'whitelist_labels': []
                }
            }
        }

        monitor = ContainerMonitor(config)

        # First check: container starts with high CPU
        mock_time.return_value = 1000.0
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"id":"abc123","name":"high-cpu","cpu":"150.5%","image":"test:latest"}\n'
        )

        abusive = monitor.check()
        warnings = monitor.get_warnings()
        assert len(abusive) == 0
        assert len(warnings) == 0  # Not yet at 5 minutes

        # Second check: 6 minutes later (should warn)
        mock_time.return_value = 1000.0 + (6 * 60)
        abusive = monitor.check()
        warnings = monitor.get_warnings()

        assert len(abusive) == 0  # Not yet at 15 minutes
        assert len(warnings) == 1
        assert warnings[0]['container_name'] == 'high-cpu'
        assert warnings[0]['cpu_percent'] == 150.5
        assert warnings[0]['duration_minutes'] >= 5

    @patch('guardian.modules.container_monitor.subprocess.run')
    @patch('time.time')
    def test_get_warnings_only_once(self, mock_time, mock_run):
        """Should only warn once per container."""
        config = {
            'containers': {
                'resource_monitoring': {
                    'enabled': True,
                    'cpu_threshold_percent': 100,
                    'warn_after_minutes': 5,
                    'kill_after_minutes': 15,
                    'whitelist': [],
                    'whitelist_labels': []
                }
            }
        }

        monitor = ContainerMonitor(config)

        # Setup container with 6 minutes of high CPU
        mock_time.return_value = 1000.0
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"id":"abc123","name":"high-cpu","cpu":"150.5%","image":"test:latest"}\n'
        )
        monitor.check()  # Start tracking

        mock_time.return_value = 1000.0 + (6 * 60)
        warnings = monitor.get_warnings()
        assert len(warnings) == 1

        # Call again - should not warn twice
        warnings = monitor.get_warnings()
        assert len(warnings) == 0  # Already warned

    @patch('guardian.modules.container_monitor.subprocess.run')
    @patch('time.time')
    def test_get_warnings_not_after_kill_threshold(self, mock_time, mock_run):
        """Should not warn after kill threshold is reached."""
        config = {
            'containers': {
                'resource_monitoring': {
                    'enabled': True,
                    'cpu_threshold_percent': 100,
                    'warn_after_minutes': 5,
                    'kill_after_minutes': 15,
                    'whitelist': [],
                    'whitelist_labels': []
                }
            }
        }

        monitor = ContainerMonitor(config)

        # Setup container with 16 minutes of high CPU
        mock_time.return_value = 1000.0
        mock_run.return_value = Mock(
            returncode=0,
            stdout='{"id":"abc123","name":"high-cpu","cpu":"150.5%","image":"test:latest"}\n'
        )
        monitor.check()

        mock_time.return_value = 1000.0 + (16 * 60)
        warnings = monitor.get_warnings()
        assert len(warnings) == 0  # Past kill threshold, don't warn


class TestMultipleContainers:
    """Test monitoring multiple containers simultaneously."""

    def test_track_multiple_containers(self, monitor):
        """Test tracking multiple containers at once."""
        with patch.object(monitor, '_get_container_stats', return_value=[
            {'id': 'abc123', 'name': 'app1', 'cpu_percent': 150.0, 'image': 'ubuntu'},
            {'id': 'def456', 'name': 'app2', 'cpu_percent': 120.0, 'image': 'ubuntu'},
            {'id': 'ghi789', 'name': 'app3', 'cpu_percent': 50.0, 'image': 'ubuntu'},
        ]):
            with patch.object(monitor, '_get_container_labels', return_value={}):
                monitor.check()

                # Should track high CPU containers
                assert 'abc123' in monitor._tracking
                assert 'def456' in monitor._tracking

                # Low CPU should be tracked but with no high CPU time
                assert 'ghi789' in monitor._tracking
                assert monitor._tracking['ghi789'].first_high_cpu_time is None

    def test_cleanup_stopped_containers(self, monitor):
        """Test cleanup of tracking for stopped containers."""
        with patch.object(monitor, '_get_container_stats') as mock_stats:
            with patch.object(monitor, '_get_container_labels', return_value={}):
                # First check - two containers
                mock_stats.return_value = [
                    {'id': 'abc123', 'name': 'app1', 'cpu_percent': 150.0, 'image': 'ubuntu'},
                    {'id': 'def456', 'name': 'app2', 'cpu_percent': 120.0, 'image': 'ubuntu'},
                ]
                monitor.check()
                assert len(monitor._tracking) == 2

                # Second check - one container stopped
                mock_stats.return_value = [
                    {'id': 'abc123', 'name': 'app1', 'cpu_percent': 150.0, 'image': 'ubuntu'},
                ]
                monitor.check()

                # Should only track running containers
                assert len(monitor._tracking) == 1
                assert 'abc123' in monitor._tracking
                assert 'def456' not in monitor._tracking
