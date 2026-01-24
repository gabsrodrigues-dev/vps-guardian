#!/usr/bin/env python3
"""
VPS Guardian - Integrity Checker Tests
Tests binary hash verification and rootkit detection.
"""

import pytest
import json
from pathlib import Path
from guardian.modules.integrity import IntegrityChecker, IntegrityViolation


class TestIntegrityChecker:
    """Test suite for the IntegrityChecker module."""

    @pytest.fixture
    def integrity_config(self, tmp_path):
        """Integrity checker configuration with test files."""
        # Create test binaries
        bin1 = tmp_path / 'bin1'
        bin1.write_text('original binary 1')

        bin2 = tmp_path / 'bin2'
        bin2.write_text('original binary 2')

        hash_db = tmp_path / 'hashes.json'

        return {
            'integrity': {
                'critical_binaries': [str(bin1), str(bin2)],
                'hash_db': str(hash_db)
            }
        }

    def test_initialize_hash_database(self, integrity_config, tmp_path):
        """Should initialize hash database with current binary hashes."""
        checker = IntegrityChecker(integrity_config)

        result = checker.initialize()

        assert result is True
        hash_db = Path(integrity_config['integrity']['hash_db'])
        assert hash_db.exists()

        with open(hash_db) as f:
            hashes = json.load(f)

        assert len(hashes) == 2
        for binary in integrity_config['integrity']['critical_binaries']:
            assert binary in hashes

    def test_detect_modified_binary(self, integrity_config, tmp_path):
        """Should detect when binary hash changes (rootkit)."""
        checker = IntegrityChecker(integrity_config)
        checker.initialize()

        # Modify one of the binaries
        bin1 = Path(integrity_config['integrity']['critical_binaries'][0])
        bin1.write_text('MALICIOUS ROOTKIT CODE')

        violations = checker.check()

        assert len(violations) == 1
        assert violations[0].path == str(bin1)
        assert violations[0].severity == 'critical'
        assert violations[0].actual_hash != violations[0].expected_hash

    def test_detect_missing_binary(self, integrity_config, tmp_path):
        """Should detect when critical binary is deleted."""
        checker = IntegrityChecker(integrity_config)
        checker.initialize()

        # Delete one binary
        bin1 = Path(integrity_config['integrity']['critical_binaries'][0])
        bin1.unlink()

        violations = checker.check()

        assert len(violations) == 1
        assert violations[0].path == str(bin1)
        assert violations[0].actual_hash == 'FILE_MISSING'

    def test_no_violations_when_unchanged(self, integrity_config, tmp_path):
        """Should return no violations when binaries are unchanged."""
        checker = IntegrityChecker(integrity_config)
        checker.initialize()

        violations = checker.check()

        assert len(violations) == 0

    def test_no_baseline_returns_empty(self, integrity_config, tmp_path):
        """Should return empty list when no baseline exists."""
        # Don't initialize, just check
        checker = IntegrityChecker(integrity_config)

        violations = checker.check()

        assert len(violations) == 0

    def test_hash_calculation_consistency(self, integrity_config, tmp_path):
        """Should calculate same hash for same file content."""
        checker = IntegrityChecker(integrity_config)

        bin1 = Path(integrity_config['integrity']['critical_binaries'][0])
        hash1 = checker._calculate_hash(str(bin1))
        hash2 = checker._calculate_hash(str(bin1))

        assert hash1 == hash2
        assert len(hash1) == 64  # SHA256 hex digest

    def test_handle_nonexistent_file_hash(self, integrity_config):
        """Should return None for nonexistent file."""
        checker = IntegrityChecker(integrity_config)

        hash_val = checker._calculate_hash('/tmp/does_not_exist_12345')

        assert hash_val is None

    def test_load_existing_hash_database(self, integrity_config, tmp_path):
        """Should load existing hash database on initialization."""
        # Create hash database manually
        hash_db = Path(integrity_config['integrity']['hash_db'])
        hash_db.parent.mkdir(parents=True, exist_ok=True)

        test_hashes = {
            '/usr/bin/test1': 'abc123',
            '/usr/bin/test2': 'def456'
        }

        with open(hash_db, 'w') as f:
            json.dump(test_hashes, f)

        checker = IntegrityChecker(integrity_config)

        assert checker.hashes == test_hashes

    def test_multiple_modifications_detected(self, integrity_config, tmp_path):
        """Should detect multiple modified binaries."""
        checker = IntegrityChecker(integrity_config)
        checker.initialize()

        # Modify both binaries
        for binary_path in integrity_config['integrity']['critical_binaries']:
            Path(binary_path).write_text('COMPROMISED')

        violations = checker.check()

        assert len(violations) == 2
        for violation in violations:
            assert violation.severity == 'critical'


class TestRootkitDetection:
    """Test suite for rootkit detection capabilities."""

    @pytest.fixture
    def rootkit_config(self, tmp_path):
        """Configuration for rootkit detection tests."""
        hash_db = tmp_path / 'hashes.json'
        return {
            'integrity': {
                'critical_binaries': [],
                'hash_db': str(hash_db),
                'rootkit_detection': {
                    'enabled': True,
                    'check_ld_preload': True,
                    'check_hidden_uid0': True,
                    'check_hugepages': True,
                    'check_hidden_processes': True,
                    'check_kernel_modules': True
                }
            }
        }

    def test_ld_preload_detection(self, rootkit_config, tmp_path):
        """Should detect library hijacking via ld.so.preload."""
        # Create fake ld.so.preload with malicious library
        ld_preload = tmp_path / 'ld.so.preload'
        ld_preload.write_text('/tmp/malicious.so\n')

        checker = IntegrityChecker(rootkit_config)

        # Monkeypatch the file path
        import guardian.modules.integrity as integrity_module
        original_path = '/etc/ld.so.preload'

        with pytest.MonkeyPatch().context() as m:
            m.setattr(integrity_module, 'LD_PRELOAD_PATH', str(ld_preload))
            indicators = checker.check_rootkits()

        # Should find LD_PRELOAD indicator
        ld_indicators = [i for i in indicators if i.check_name == 'ld_preload']
        assert len(ld_indicators) == 1
        assert ld_indicators[0].severity == 'critical'
        assert '/tmp/malicious.so' in ld_indicators[0].evidence.get('libraries', [])

    def test_ld_preload_no_threat_when_empty(self, rootkit_config, tmp_path):
        """Should not alert when ld.so.preload is empty."""
        ld_preload = tmp_path / 'ld.so.preload'
        ld_preload.write_text('')

        checker = IntegrityChecker(rootkit_config)

        import guardian.modules.integrity as integrity_module
        with pytest.MonkeyPatch().context() as m:
            m.setattr(integrity_module, 'LD_PRELOAD_PATH', str(ld_preload))
            indicators = checker.check_rootkits()

        ld_indicators = [i for i in indicators if i.check_name == 'ld_preload']
        assert len(ld_indicators) == 0

    def test_hidden_uid0_detection(self, rootkit_config, tmp_path):
        """Should detect backdoor users with UID 0."""
        # Create fake passwd file with hidden root account
        passwd = tmp_path / 'passwd'
        passwd.write_text(
            'root:x:0:0:root:/root:/bin/bash\n'
            'backdoor:x:0:0:Hidden Admin:/tmp:/bin/bash\n'
            'user:x:1000:1000:Normal User:/home/user:/bin/bash\n'
        )

        checker = IntegrityChecker(rootkit_config)

        import guardian.modules.integrity as integrity_module
        with pytest.MonkeyPatch().context() as m:
            m.setattr(integrity_module, 'PASSWD_PATH', str(passwd))
            indicators = checker.check_rootkits()

        uid0_indicators = [i for i in indicators if i.check_name == 'hidden_uid0']
        assert len(uid0_indicators) == 1
        assert uid0_indicators[0].severity == 'critical'
        assert 'backdoor' in uid0_indicators[0].evidence.get('suspicious_users', [])

    def test_hidden_uid0_no_threat_normal(self, rootkit_config, tmp_path):
        """Should not alert for normal passwd with only root UID 0."""
        passwd = tmp_path / 'passwd'
        passwd.write_text(
            'root:x:0:0:root:/root:/bin/bash\n'
            'user:x:1000:1000:Normal User:/home/user:/bin/bash\n'
        )

        checker = IntegrityChecker(rootkit_config)

        import guardian.modules.integrity as integrity_module
        with pytest.MonkeyPatch().context() as m:
            m.setattr(integrity_module, 'PASSWD_PATH', str(passwd))
            indicators = checker.check_rootkits()

        uid0_indicators = [i for i in indicators if i.check_name == 'hidden_uid0']
        assert len(uid0_indicators) == 0

    def test_hugepages_detection(self, rootkit_config, tmp_path):
        """Should detect suspicious HugePages usage (crypto miners)."""
        meminfo = tmp_path / 'meminfo'
        meminfo.write_text(
            'MemTotal:        8192000 kB\n'
            'MemFree:         4096000 kB\n'
            'HugePages_Total:     128\n'
            'HugePages_Free:       64\n'
        )

        checker = IntegrityChecker(rootkit_config)

        import guardian.modules.integrity as integrity_module
        with pytest.MonkeyPatch().context() as m:
            m.setattr(integrity_module, 'MEMINFO_PATH', str(meminfo))
            indicators = checker.check_rootkits()

        hugepages_indicators = [i for i in indicators if i.check_name == 'hugepages']
        assert len(hugepages_indicators) == 1
        assert hugepages_indicators[0].severity == 'high'
        assert hugepages_indicators[0].evidence.get('hugepages_total') == 128

    def test_hugepages_no_threat_when_zero(self, rootkit_config, tmp_path):
        """Should not alert when HugePages_Total is 0."""
        meminfo = tmp_path / 'meminfo'
        meminfo.write_text(
            'MemTotal:        8192000 kB\n'
            'HugePages_Total:       0\n'
        )

        checker = IntegrityChecker(rootkit_config)

        import guardian.modules.integrity as integrity_module
        with pytest.MonkeyPatch().context() as m:
            m.setattr(integrity_module, 'MEMINFO_PATH', str(meminfo))
            indicators = checker.check_rootkits()

        hugepages_indicators = [i for i in indicators if i.check_name == 'hugepages']
        assert len(hugepages_indicators) == 0

    def test_hidden_processes_detection(self, rootkit_config, tmp_path, monkeypatch):
        """Should detect processes hidden by rootkits."""
        # Mock /proc listing
        proc_pids = ['1', '2', '100', '200', '666']  # 666 is hidden

        # Mock ps output (missing PID 666)
        ps_output = """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169564 11424 ?        Ss   10:00   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    10:00   0:00 [kthreadd]
root       100  0.0  0.2 123456  1024 ?        S    10:01   0:00 /usr/bin/sshd
root       200  0.0  0.1  98765   512 ?        S    10:02   0:00 /usr/sbin/cron
"""

        checker = IntegrityChecker(rootkit_config)

        def mock_listdir(path):
            if str(path) == '/proc':
                return proc_pids + ['cpuinfo', 'meminfo', 'self']
            raise FileNotFoundError()

        def mock_isdir(path):
            path_str = str(path)
            if path_str.startswith('/proc/'):
                pid = path_str.split('/')[-1]
                return pid.isdigit()
            return False

        import subprocess
        def mock_run(*args, **kwargs):
            class Result:
                stdout = ps_output
                returncode = 0
            return Result()

        monkeypatch.setattr('os.listdir', mock_listdir)
        monkeypatch.setattr('pathlib.Path.is_dir', mock_isdir)
        monkeypatch.setattr('subprocess.run', mock_run)

        indicators = checker.check_rootkits()

        hidden_indicators = [i for i in indicators if i.check_name == 'hidden_processes']
        assert len(hidden_indicators) == 1
        assert hidden_indicators[0].severity == 'critical'
        assert 666 in hidden_indicators[0].evidence.get('hidden_pids', [])

    def test_kernel_modules_detection(self, rootkit_config, tmp_path):
        """Should detect known rootkit kernel modules."""
        modules = tmp_path / 'modules'
        modules.write_text(
            'ext4 1048576 1 - Live 0xffffffffc0000000\n'
            'diamorphine 16384 0 - Live 0xffffffffc0001000\n'
            'usbcore 270336 2 - Live 0xffffffffc0002000\n'
        )

        checker = IntegrityChecker(rootkit_config)

        import guardian.modules.integrity as integrity_module
        with pytest.MonkeyPatch().context() as m:
            m.setattr(integrity_module, 'MODULES_PATH', str(modules))
            indicators = checker.check_rootkits()

        module_indicators = [i for i in indicators if i.check_name == 'kernel_modules']
        assert len(module_indicators) == 1
        assert module_indicators[0].severity == 'critical'
        assert 'diamorphine' in module_indicators[0].evidence.get('suspicious_modules', [])

    def test_kernel_modules_no_threat_clean(self, rootkit_config, tmp_path):
        """Should not alert for clean kernel modules."""
        modules = tmp_path / 'modules'
        modules.write_text(
            'ext4 1048576 1 - Live 0xffffffffc0000000\n'
            'usbcore 270336 2 - Live 0xffffffffc0002000\n'
        )

        checker = IntegrityChecker(rootkit_config)

        import guardian.modules.integrity as integrity_module
        with pytest.MonkeyPatch().context() as m:
            m.setattr(integrity_module, 'MODULES_PATH', str(modules))
            indicators = checker.check_rootkits()

        module_indicators = [i for i in indicators if i.check_name == 'kernel_modules']
        assert len(module_indicators) == 0

    def test_rootkit_detection_disabled_returns_empty(self, rootkit_config):
        """Should return empty list when rootkit detection is disabled."""
        rootkit_config['integrity']['rootkit_detection']['enabled'] = False

        checker = IntegrityChecker(rootkit_config)
        indicators = checker.check_rootkits()

        assert len(indicators) == 0

    def test_individual_checks_can_be_disabled(self, rootkit_config, tmp_path):
        """Should skip checks that are disabled in config."""
        rootkit_config['integrity']['rootkit_detection']['check_hugepages'] = False

        meminfo = tmp_path / 'meminfo'
        meminfo.write_text('HugePages_Total:     128\n')

        checker = IntegrityChecker(rootkit_config)

        import guardian.modules.integrity as integrity_module
        with pytest.MonkeyPatch().context() as m:
            m.setattr(integrity_module, 'MEMINFO_PATH', str(meminfo))
            indicators = checker.check_rootkits()

        hugepages_indicators = [i for i in indicators if i.check_name == 'hugepages']
        assert len(hugepages_indicators) == 0

    def test_multiple_rootkit_indicators(self, rootkit_config, tmp_path):
        """Should detect multiple rootkit indicators simultaneously."""
        # Setup multiple threats
        ld_preload = tmp_path / 'ld.so.preload'
        ld_preload.write_text('/tmp/hack.so\n')

        passwd = tmp_path / 'passwd'
        passwd.write_text('root:x:0:0:root:/root:/bin/bash\nhacker:x:0:0::/tmp:/bin/sh\n')

        checker = IntegrityChecker(rootkit_config)

        import guardian.modules.integrity as integrity_module
        with pytest.MonkeyPatch().context() as m:
            m.setattr(integrity_module, 'LD_PRELOAD_PATH', str(ld_preload))
            m.setattr(integrity_module, 'PASSWD_PATH', str(passwd))
            indicators = checker.check_rootkits()

        # Should have at least 2 indicators
        assert len(indicators) >= 2
        check_names = {i.check_name for i in indicators}
        assert 'ld_preload' in check_names
        assert 'hidden_uid0' in check_names
