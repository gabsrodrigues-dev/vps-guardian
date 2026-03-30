#!/usr/bin/env python3
"""
VPS Guardian - Integrity Checker Module
Verifies SHA256 hashes of critical system binaries.
Detects rootkits that replace system tools.
"""

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass

# System file paths (can be overridden in tests)
LD_PRELOAD_PATH = '/etc/ld.so.preload'
PASSWD_PATH = '/etc/passwd'
MEMINFO_PATH = '/proc/meminfo'
MODULES_PATH = '/proc/modules'

@dataclass
class IntegrityViolation:
    """Represents a binary integrity violation (possible rootkit)."""
    path: str
    expected_hash: str
    actual_hash: str
    severity: str = 'critical'


@dataclass
class RootkitIndicator:
    """Single Responsibility: Data container for rootkit indicators."""
    check_name: str
    severity: str  # 'critical', 'high', 'medium'
    description: str
    evidence: Dict[str, Any]

class IntegrityChecker:
    """Checks integrity of critical system binaries."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.binaries = config['integrity']['critical_binaries']
        self.hash_db_path = Path(config['integrity']['hash_db'])
        self.hashes: Dict[str, str] = {}

        self._load_hashes()

    def _load_hashes(self):
        """Load known hashes from database."""
        if self.hash_db_path.exists():
            with open(self.hash_db_path) as f:
                self.hashes = json.load(f)

    def _calculate_hash(self, path: str) -> str | None:
        """Calculate SHA256 hash of a file."""
        try:
            sha256 = hashlib.sha256()
            with open(path, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (IOError, OSError):
            return None

    def initialize(self) -> bool:
        """Initialize hash database with current binary hashes."""
        self.hashes = {}

        for binary in self.binaries:
            if Path(binary).exists():
                hash_val = self._calculate_hash(binary)
                if hash_val:
                    self.hashes[binary] = hash_val

        # Save to database
        self.hash_db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.hash_db_path, 'w') as f:
            json.dump(self.hashes, f, indent=2)

        return True

    def check(self) -> List[IntegrityViolation]:
        """Check all binaries against known hashes."""
        violations = []

        if not self.hashes:
            # No baseline - can't check
            return violations

        for binary, expected_hash in self.hashes.items():
            if not Path(binary).exists():
                violations.append(IntegrityViolation(
                    path=binary,
                    expected_hash=expected_hash,
                    actual_hash='FILE_MISSING',
                    severity='critical'
                ))
                continue

            actual_hash = self._calculate_hash(binary)
            if actual_hash and actual_hash != expected_hash:
                violations.append(IntegrityViolation(
                    path=binary,
                    expected_hash=expected_hash,
                    actual_hash=actual_hash,
                    severity='critical'
                ))

        return violations

    def check_rootkits(self) -> List[RootkitIndicator]:
        """Run all rootkit checks based on config, return list of indicators."""
        indicators = []

        rootkit_config = self.config.get('integrity', {}).get('rootkit_detection', {})
        if not rootkit_config.get('enabled', True):
            return indicators

        # Map config keys to check methods
        checks = [
            ('check_ld_preload', self._check_ld_preload),
            ('check_hidden_uid0', self._check_hidden_uid0),
            ('check_hugepages', self._check_hugepages),
            ('check_hidden_processes', self._check_hidden_processes),
            ('check_kernel_modules', self._check_kernel_modules),
        ]

        for config_key, check_method in checks:
            if rootkit_config.get(config_key, True):
                result = check_method()
                if result:
                    indicators.append(result)

        return indicators

    def _check_ld_preload(self) -> Optional[RootkitIndicator]:
        """Check for library hijacking via /etc/ld.so.preload."""
        try:
            if not Path(LD_PRELOAD_PATH).exists():
                return None

            with open(LD_PRELOAD_PATH, 'r') as f:
                content = f.read().strip()

            if not content:
                return None

            # Non-empty ld.so.preload is suspicious
            libraries = [line.strip() for line in content.split('\n') if line.strip()]

            return RootkitIndicator(
                check_name='ld_preload',
                severity='critical',
                description='LD_PRELOAD library hijacking detected',
                evidence={'libraries': libraries}
            )

        except (IOError, OSError):
            return None

    def _check_hidden_uid0(self) -> Optional[RootkitIndicator]:
        """Check for backdoor users with UID 0."""
        try:
            with open(PASSWD_PATH, 'r') as f:
                lines = f.readlines()

            suspicious_users = []
            for line in lines:
                if not line.strip() or line.startswith('#'):
                    continue

                fields = line.split(':')
                if len(fields) < 3:
                    continue

                username = fields[0]
                uid = fields[2]

                # UID 0 that's not root
                if uid == '0' and username != 'root':
                    suspicious_users.append(username)

            if not suspicious_users:
                return None

            return RootkitIndicator(
                check_name='hidden_uid0',
                severity='critical',
                description='Backdoor user(s) with UID 0 detected',
                evidence={'suspicious_users': suspicious_users}
            )

        except (IOError, OSError):
            return None

    def _check_hugepages(self) -> Optional[RootkitIndicator]:
        """Check for suspicious HugePages usage (crypto miners)."""
        try:
            with open(MEMINFO_PATH, 'r') as f:
                content = f.read()

            for line in content.split('\n'):
                if line.startswith('HugePages_Total:'):
                    value_str = line.split(':')[1].strip()
                    hugepages_total = int(value_str)

                    if hugepages_total > 0:
                        return RootkitIndicator(
                            check_name='hugepages',
                            severity='high',
                            description='Suspicious HugePages usage detected (possible crypto miner)',
                            evidence={'hugepages_total': hugepages_total}
                        )

            return None

        except (IOError, OSError, ValueError):
            return None

    def _check_hidden_processes(self) -> Optional[RootkitIndicator]:
        """Check for processes hidden by rootkits."""
        try:
            # Get PIDs from ps first (more stable)
            result = subprocess.run(
                ['ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=5
            )

            ps_pids = set()
            for line in result.stdout.split('\n')[1:]:  # Skip header
                if not line.strip():
                    continue
                fields = line.split()
                if len(fields) >= 2:
                    try:
                        ps_pids.add(int(fields[1]))
                    except ValueError:
                        continue

            # Get PIDs from /proc
            proc_pids = set()
            for entry in os.listdir('/proc'):
                if entry.isdigit():
                    proc_path = Path('/proc') / entry
                    if proc_path.is_dir():
                        proc_pids.add(int(entry))

            # Find PIDs in /proc but not in ps
            hidden_pids = proc_pids - ps_pids

            # Filter out false positives:
            # - PIDs <= 10 (kernel threads)
            # - Very short-lived processes (race condition)
            # Only alert if we have a significant number of hidden processes
            hidden_pids = [pid for pid in hidden_pids if pid > 10]

            # Require at least 5 hidden processes to reduce false positives
            # A real rootkit will hide multiple processes
            if len(hidden_pids) < 5:
                return None

            return RootkitIndicator(
                check_name='hidden_processes',
                severity='critical',
                description='Process hiding detected (possible rootkit)',
                evidence={'hidden_pids': hidden_pids, 'count': len(hidden_pids)}
            )

        except (IOError, OSError, subprocess.TimeoutExpired):
            return None

    def _check_kernel_modules(self) -> Optional[RootkitIndicator]:
        """Check for known rootkit kernel modules."""
        try:
            if not Path(MODULES_PATH).exists():
                return None

            with open(MODULES_PATH, 'r') as f:
                content = f.read()

            # Known rootkit module names
            rootkit_names = ['diamorphine', 'reptile', 'hiding', 'rootkit', 'hide']

            suspicious_modules = []
            for line in content.split('\n'):
                if not line.strip():
                    continue

                module_name = line.split()[0]
                for rootkit_name in rootkit_names:
                    if rootkit_name.lower() in module_name.lower():
                        suspicious_modules.append(module_name)
                        break

            if not suspicious_modules:
                return None

            return RootkitIndicator(
                check_name='kernel_modules',
                severity='critical',
                description='Suspicious kernel module(s) detected',
                evidence={'suspicious_modules': suspicious_modules}
            )

        except (IOError, OSError):
            return None
