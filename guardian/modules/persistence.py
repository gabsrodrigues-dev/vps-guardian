#!/usr/bin/env python3
"""
VPS Guardian - Persistence Mechanism Detection Module
Detects malicious persistence mechanisms: cron jobs, systemd services, RC scripts, and SSH keys.
"""

import re
import json
import glob
import hashlib
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set
from pathlib import Path
from enum import Enum

logger = logging.getLogger('guardian.persistence')


class PersistenceType(Enum):
    """Types of persistence mechanisms."""
    CRONTAB = "crontab"
    SYSTEMD_SERVICE = "systemd_service"
    SYSTEMD_TIMER = "systemd_timer"
    RC_SCRIPT = "rc_script"
    SSH_KEY = "ssh_key"


@dataclass
class PersistenceThreat:
    """Single Responsibility: Data container for persistence threat."""
    type: PersistenceType
    path: str
    content_snippet: str  # First 200 chars or matched line
    matched_pattern: Optional[str]
    severity: str  # 'high', 'medium', 'low'
    details: Dict[str, Any] = field(default_factory=dict)


class PersistenceScanner:
    """Single Responsibility: Scan for and detect persistence mechanisms."""

    # Patterns that indicate malicious/suspicious behavior
    SUSPICIOUS_PATTERNS = [
        (r'wget\s+.*\|\s*(?:sh|bash)', 'Download and execute via wget'),
        (r'curl\s+.*\|\s*(?:sh|bash)', 'Download and execute via curl'),
        (r'/tmp/[^\s]+', 'Execute from /tmp'),
        (r'/dev/shm/[^\s]+', 'Execute from /dev/shm'),
        (r'/var/tmp/[^\s]+', 'Execute from /var/tmp'),
        (r'base64\s+.*-d', 'Base64 decode (obfuscation)'),
        (r'nohup\s+.*&', 'Background execution'),
        (r'\$\([^)]+\)', 'Command substitution'),
    ]

    # Known malicious service names
    MALICIOUS_SERVICE_NAMES = [
        'bot.service',
        'rondo.service',
        'rsyslo.service',
        'system-cleanup.service',
        'perfctl.service',
        'kdevtmpfsi.service',
        'kinsing.service',
    ]

    def __init__(self, config: dict):
        persistence_config = config.get('persistence', {})
        self.enabled = persistence_config.get('enabled', True)
        self.crontab_config = persistence_config.get('crontab', {})
        self.systemd_config = persistence_config.get('systemd', {})
        self.rc_config = persistence_config.get('rc_scripts', {})
        self.ssh_config = persistence_config.get('ssh_keys', {})
        self.logger = logging.getLogger('guardian.persistence')

        # Compile regex patterns once for performance
        self.compiled_patterns = [
            (re.compile(pattern, re.IGNORECASE), description)
            for pattern, description in self.SUSPICIOUS_PATTERNS
        ]

        # Load or initialize SSH key database
        self._known_ssh_keys: Optional[Dict[str, Any]] = None

    def scan(self) -> List[PersistenceThreat]:
        """Full scan of all persistence locations."""
        if not self.enabled:
            return []

        threats = []

        try:
            threats.extend(self.scan_crontabs())
            threats.extend(self.scan_systemd())
            threats.extend(self.scan_rc_scripts())
            threats.extend(self.scan_ssh_keys())
        except Exception as e:
            self.logger.error(f"Error during persistence scan: {e}")

        return threats

    def scan_crontabs(self) -> List[PersistenceThreat]:
        """Scan all crontab locations."""
        threats = []

        # System crontab
        system_paths = self.crontab_config.get('system_paths', ['/etc/crontab'])
        for path in system_paths:
            threats.extend(self._scan_file(path, PersistenceType.CRONTAB))

        # /etc/cron.d/*
        cron_d_path = self.crontab_config.get('cron_d_path', '/etc/cron.d')
        threats.extend(self._scan_directory(cron_d_path, PersistenceType.CRONTAB, pattern='*'))

        # Periodic crons (daily, hourly, weekly, monthly)
        periodic_paths = self.crontab_config.get('periodic_paths', [
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.weekly',
            '/etc/cron.monthly'
        ])
        for path in periodic_paths:
            threats.extend(self._scan_directory(path, PersistenceType.CRONTAB, pattern='*'))

        # User crontabs
        user_crontabs_path = self.crontab_config.get('user_crontabs_path', '/var/spool/cron/crontabs')
        threats.extend(self._scan_directory(user_crontabs_path, PersistenceType.CRONTAB, pattern='*'))

        return threats

    def scan_systemd(self) -> List[PersistenceThreat]:
        """Scan systemd services and timers."""
        threats = []

        # Systemd services
        service_path = self.systemd_config.get('service_path', '/etc/systemd/system')
        service_threats = self._scan_directory(service_path, PersistenceType.SYSTEMD_SERVICE, pattern='*.service')

        # Check for malicious service names
        for threat in service_threats:
            filename = Path(threat.path).name
            if filename in self.MALICIOUS_SERVICE_NAMES:
                threat.severity = 'high'
                threat.details['reason'] = f'Known malicious service name: {filename}'

        threats.extend(service_threats)

        # Systemd timers - scan and report all timers
        timer_path = self.systemd_config.get('timer_path', '/etc/systemd/system')
        timer_threats = self._scan_directory(timer_path, PersistenceType.SYSTEMD_TIMER, pattern='*.timer')

        # Also detect timer files even without suspicious content (timers are persistence mechanisms)
        dir_path = Path(timer_path)
        if dir_path.is_dir():
            for timer_file in dir_path.glob('*.timer'):
                if timer_file.is_file():
                    # Check if already detected
                    already_detected = any(t.path == str(timer_file) for t in timer_threats)
                    if not already_detected:
                        content = self._read_file_safely(str(timer_file))
                        timer_threats.append(PersistenceThreat(
                            type=PersistenceType.SYSTEMD_TIMER,
                            path=str(timer_file),
                            content_snippet=content[:200],
                            matched_pattern=None,
                            severity='medium',
                            details={'reason': 'Systemd timer (persistence mechanism)'}
                        ))

        threats.extend(timer_threats)

        return threats

    def scan_rc_scripts(self) -> List[PersistenceThreat]:
        """Scan RC scripts."""
        threats = []

        rc_paths = self.rc_config.get('paths', ['/etc/rc.local', '/etc/init.d'])
        for path_str in rc_paths:
            path = Path(path_str)
            if path.is_file():
                threats.extend(self._scan_file(str(path), PersistenceType.RC_SCRIPT))
            elif path.is_dir():
                threats.extend(self._scan_directory(str(path), PersistenceType.RC_SCRIPT, pattern='*'))

        return threats

    def scan_ssh_keys(self) -> List[PersistenceThreat]:
        """Scan for unauthorized SSH keys."""
        threats = []

        authorized_keys_paths = self.ssh_config.get('authorized_keys_paths', [
            '/root/.ssh/authorized_keys',
            '/home/*/.ssh/authorized_keys'
        ])

        # Load known keys database
        self._load_known_ssh_keys()

        current_keys: Dict[str, Dict[str, Any]] = {}

        # Scan all authorized_keys files
        for path_pattern in authorized_keys_paths:
            for path in glob.glob(path_pattern):
                if not Path(path).is_file():
                    continue

                try:
                    with open(path, 'r') as f:
                        for line_num, line in enumerate(f, 1):
                            line = line.strip()
                            if not line or line.startswith('#'):
                                continue

                            # Extract key fingerprint
                            fingerprint = self._get_key_fingerprint(line)
                            if not fingerprint:
                                continue

                            current_keys[fingerprint] = {
                                'path': path,
                                'line': line[:200],  # Limit snippet
                                'line_num': line_num
                            }

                            # Check if this is a new key
                            if fingerprint not in self._known_ssh_keys:
                                # New key detected
                                threats.append(PersistenceThreat(
                                    type=PersistenceType.SSH_KEY,
                                    path=path,
                                    content_snippet=line[:200],
                                    matched_pattern=None,
                                    severity='high',
                                    details={
                                        'fingerprint': fingerprint,
                                        'line_num': line_num,
                                        'reason': 'New SSH key added after baseline'
                                    }
                                ))

                except (IOError, OSError) as e:
                    self.logger.debug(f"Could not read SSH keys from {path}: {e}")

        # Update known keys database with current state
        self._update_known_ssh_keys(current_keys)

        return threats

    def _scan_file(self, path: str, persistence_type: PersistenceType) -> List[PersistenceThreat]:
        """Scan a single file for suspicious patterns."""
        threats = []

        if not Path(path).is_file():
            return threats

        try:
            content = self._read_file_safely(path)
            if not content:
                return threats

            # Check for suspicious patterns
            for line in content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                for pattern_re, description in self.compiled_patterns:
                    if pattern_re.search(line):
                        threats.append(PersistenceThreat(
                            type=persistence_type,
                            path=path,
                            content_snippet=line[:200],
                            matched_pattern=description,
                            severity='high',
                            details={'line_content': line[:300]}
                        ))
                        break  # Only report once per line

        except Exception as e:
            self.logger.debug(f"Error scanning file {path}: {e}")

        return threats

    def _scan_directory(self, directory: str, persistence_type: PersistenceType, pattern: str = '*') -> List[PersistenceThreat]:
        """Scan all files in a directory matching pattern."""
        threats = []

        dir_path = Path(directory)
        if not dir_path.is_dir():
            return threats

        try:
            for file_path in dir_path.glob(pattern):
                if file_path.is_file():
                    threats.extend(self._scan_file(str(file_path), persistence_type))
        except Exception as e:
            self.logger.debug(f"Error scanning directory {directory}: {e}")

        return threats

    def _read_file_safely(self, path: str, max_size: int = 1024 * 1024) -> str:
        """DRY: Read file content safely with size limit."""
        try:
            file_path = Path(path)
            if file_path.stat().st_size > max_size:
                self.logger.warning(f"File {path} exceeds max size, skipping")
                return ""

            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except (IOError, OSError) as e:
            self.logger.debug(f"Could not read file {path}: {e}")
            return ""

    def _get_key_fingerprint(self, key_line: str) -> Optional[str]:
        """Generate fingerprint for SSH key."""
        try:
            # Extract key data (format: "type key comment")
            parts = key_line.split()
            if len(parts) < 2:
                return None

            # Hash the key part for fingerprint
            key_data = parts[1] if len(parts) >= 2 else key_line
            return hashlib.sha256(key_data.encode()).hexdigest()[:16]
        except Exception:
            return None

    def _load_known_ssh_keys(self):
        """Load known SSH keys database."""
        if self._known_ssh_keys is not None:
            return  # Already loaded

        db_path = self.ssh_config.get('known_keys_db', '/var/lib/guardian/known_ssh_keys.json')
        db_file = Path(db_path)

        if db_file.is_file():
            try:
                with open(db_file, 'r') as f:
                    self._known_ssh_keys = json.load(f)
                self.logger.debug(f"Loaded {len(self._known_ssh_keys)} known SSH keys from {db_path}")
            except (json.JSONDecodeError, IOError) as e:
                self.logger.warning(f"Could not load SSH keys database: {e}")
                self._known_ssh_keys = {}
        else:
            # First run - initialize empty database
            self._known_ssh_keys = {}
            self.logger.info("SSH keys database not found, initializing baseline")

    def _update_known_ssh_keys(self, current_keys: Dict[str, Dict[str, Any]]):
        """Update known SSH keys database with current state."""
        db_path = self.ssh_config.get('known_keys_db', '/var/lib/guardian/known_ssh_keys.json')
        db_file = Path(db_path)

        # Merge current keys into known keys
        import time
        for fingerprint, key_info in current_keys.items():
            if fingerprint not in self._known_ssh_keys:
                self._known_ssh_keys[fingerprint] = {
                    'added_at': time.time(),
                    'path': key_info['path'],
                    'first_seen': time.time()
                }

        # Save database
        try:
            db_file.parent.mkdir(parents=True, exist_ok=True)
            with open(db_file, 'w') as f:
                json.dump(self._known_ssh_keys, f, indent=2)
            self.logger.debug(f"Updated SSH keys database: {len(self._known_ssh_keys)} keys")
        except (IOError, OSError) as e:
            self.logger.error(f"Could not save SSH keys database: {e}")
