#!/usr/bin/env python3
"""
VPS Guardian - Auditd Monitor Module
Parses auditd logs to detect short-lived processes escaping detection.
"""

import re
import logging
import subprocess
from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from pathlib import Path
from datetime import datetime

logger = logging.getLogger('guardian.auditd')


@dataclass
class AuditEvent:
    """Single Responsibility: Parsed audit event."""
    timestamp: datetime
    event_type: str
    pid: int
    ppid: int
    uid: int
    exe: str
    cmdline: List[str]
    cwd: str
    key: str
    raw_record: str


class AuditdMonitor:
    """Single Responsibility: Parse and monitor auditd logs."""

    # Guardian audit keys to filter events
    GUARDIAN_KEYS = ['guardian_tmp', 'guardian_shm', 'guardian_vartmp']

    # Directories monitored by guardian rules
    MONITORED_DIRS = ['/tmp', '/dev/shm', '/var/tmp']

    # Suspicious execution paths
    SUSPICIOUS_PATHS = ['/tmp/', '/dev/shm/', '/var/tmp/']

    # Suspicious terms in cmdline (mining pools, etc.)
    SUSPICIOUS_TERMS = [
        'pool.minexmr', 'supportxmr', 'nanopool', 'f2pool',
        'hashvault', 'nicehash', 'minergate', 'stratum',
        'xmrig', 'monero', 'cpuminer', 'ethminer'
    ]

    def __init__(self, config: Dict[str, Any]):
        auditd_config = config.get('auditd', {})
        self.enabled = auditd_config.get('enabled', False)
        self.install_rules = auditd_config.get('install_rules', True)
        self.log_path = Path(auditd_config.get('log_path', '/var/log/audit/audit.log'))
        self.last_position = 0
        self.logger = logging.getLogger('guardian.auditd')

    def check_auditd_available(self) -> bool:
        """Check if auditd is installed and running."""
        try:
            # Check if auditctl command exists
            result = subprocess.run(
                ['which', 'auditctl'],
                capture_output=True,
                timeout=5
            )
            if result.returncode != 0:
                self.logger.warning("auditctl not found - auditd not installed")
                return False

            # Check if auditd service is running
            result = subprocess.run(
                ['systemctl', 'is-active', 'auditd'],
                capture_output=True,
                timeout=5
            )
            if result.returncode != 0:
                self.logger.warning("auditd service not running")
                return False

            return True

        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            self.logger.warning(f"Failed to check auditd availability: {e}")
            return False

    def get_installed_rules(self) -> List[str]:
        """Get currently installed audit rules."""
        try:
            result = subprocess.run(
                ['auditctl', '-l'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Filter rules containing guardian keys
                rules = [
                    line.strip()
                    for line in result.stdout.splitlines()
                    if any(key in line for key in self.GUARDIAN_KEYS)
                ]
                return rules

            return []

        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            self.logger.warning(f"Failed to get installed rules: {e}")
            return []

    def generate_rules(self) -> str:
        """Generate audit rules for installation."""
        rules = []
        rules.append("# VPS Guardian - Auditd Rules")
        rules.append("# Monitor execve() syscalls in temporary directories")
        rules.append("")
        rules.append("-a always,exit -F arch=b64 -S execve -F dir=/tmp -k guardian_tmp")
        rules.append("-a always,exit -F arch=b64 -S execve -F dir=/dev/shm -k guardian_shm")
        rules.append("-a always,exit -F arch=b64 -S execve -F dir=/var/tmp -k guardian_vartmp")

        return '\n'.join(rules)

    def parse_log(self, since_last: bool = True) -> List[AuditEvent]:
        """Parse audit log for guardian-related events."""
        events = []

        try:
            if not self.log_path.exists():
                self.logger.warning(f"Audit log not found: {self.log_path}")
                return []

            # Check for log rotation (file shrank)
            current_size = self.log_path.stat().st_size
            if since_last and current_size < self.last_position:
                self.logger.info("Log rotation detected, resetting position")
                self.last_position = 0

            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                if since_last:
                    f.seek(self.last_position)

                content = f.read()
                self.last_position = f.tell()

            # Parse events from content
            events = self._parse_audit_records(content)

        except PermissionError:
            self.logger.warning(f"Permission denied reading audit log: {self.log_path}")
        except OSError as e:
            self.logger.warning(f"Error reading audit log: {e}")

        return events

    def _parse_audit_records(self, content: str) -> List[AuditEvent]:
        """Parse audit records from log content."""
        events = []

        # Group records by message ID (timestamp:sequence)
        # Pattern: msg=audit(1706000000.123:456)
        msg_pattern = re.compile(r'msg=audit\(([\d.]+):(\d+)\)')

        # Split into lines and group by message ID
        records_by_msg = {}
        current_msg_id = None

        for line in content.splitlines():
            match = msg_pattern.search(line)
            if match:
                msg_timestamp = match.group(1)
                msg_seq = match.group(2)
                current_msg_id = f"{msg_timestamp}:{msg_seq}"

                if current_msg_id not in records_by_msg:
                    records_by_msg[current_msg_id] = []

                records_by_msg[current_msg_id].append(line)

        # Parse each message group into an AuditEvent
        for msg_id, lines in records_by_msg.items():
            event = self._parse_event_group(msg_id, lines)
            if event:
                events.append(event)

        return events

    def _parse_event_group(self, msg_id: str, lines: List[str]) -> Optional[AuditEvent]:
        """Parse a group of audit records into an AuditEvent."""
        # Extract data from different record types
        syscall_data = {}
        execve_data = {}
        cwd_data = {}
        path_data = {}

        for line in lines:
            if 'type=SYSCALL' in line:
                syscall_data = self._parse_syscall_line(line)
            elif 'type=EXECVE' in line:
                execve_data = self._parse_execve_line(line)
            elif 'type=CWD' in line:
                cwd_data = self._parse_cwd_line(line)
            elif 'type=PATH' in line:
                path_data = self._parse_path_line(line)

        # Check if this event has a guardian key
        key = path_data.get('key', '')
        if key not in self.GUARDIAN_KEYS:
            return None

        # Ensure we have minimum required data
        if not syscall_data or not execve_data:
            return None

        # Parse timestamp from msg_id
        timestamp_str = msg_id.split(':')[0]
        timestamp = datetime.fromtimestamp(float(timestamp_str))

        return AuditEvent(
            timestamp=timestamp,
            event_type='EXECVE',
            pid=syscall_data.get('pid', 0),
            ppid=syscall_data.get('ppid', 0),
            uid=syscall_data.get('uid', 0),
            exe=execve_data.get('a0', ''),
            cmdline=execve_data.get('cmdline', []),
            cwd=cwd_data.get('cwd', ''),
            key=key,
            raw_record='\n'.join(lines)
        )

    def _extract_field(self, line: str, field: str, convert_fn=str) -> Any:
        """DRY: Extract a field value from audit log line."""
        pattern = rf'\b{field}=(\d+)' if convert_fn == int else rf'{field}="([^"]*)"'
        match = re.search(pattern, line)
        if match:
            return convert_fn(match.group(1))
        return None

    def _parse_syscall_line(self, line: str) -> Dict[str, Any]:
        """Parse SYSCALL record line."""
        data = {}

        # Extract pid, ppid, uid using DRY helper
        for field in ['pid', 'ppid', 'uid']:
            value = self._extract_field(line, field, int)
            if value is not None:
                data[field] = value

        return data

    def _parse_execve_line(self, line: str) -> Dict[str, Any]:
        """Parse EXECVE record line."""
        data = {}
        cmdline = []

        # Extract all arguments (a0="...", a1="...", etc.)
        arg_pattern = re.compile(r'a\d+="([^"]*)"')
        matches = arg_pattern.findall(line)

        if matches:
            cmdline = matches
            data['a0'] = matches[0]  # First argument is the executable
            data['cmdline'] = cmdline

        return data

    def _parse_cwd_line(self, line: str) -> Dict[str, Any]:
        """Parse CWD record line."""
        data = {}

        # Extract working directory using DRY helper
        cwd = self._extract_field(line, 'cwd', str)
        if cwd:
            data['cwd'] = cwd

        return data

    def _parse_path_line(self, line: str) -> Dict[str, Any]:
        """Parse PATH record line."""
        data = {}

        # Extract key and name using DRY helper
        key = self._extract_field(line, 'key', str)
        if key:
            data['key'] = key

        name = self._extract_field(line, 'name', str)
        if name:
            data['name'] = name

        return data

    def get_suspicious_events(self, events: List[AuditEvent]) -> List[AuditEvent]:
        """Filter events for suspicious activity."""
        suspicious = []

        for event in events:
            # Check if exe is from suspicious path
            is_suspicious_path = any(
                path in event.exe
                for path in self.SUSPICIOUS_PATHS
            )

            # Check if cmdline contains suspicious terms
            cmdline_str = ' '.join(event.cmdline).lower()
            has_suspicious_term = any(
                term.lower() in cmdline_str
                for term in self.SUSPICIOUS_TERMS
            )

            if is_suspicious_path or has_suspicious_term:
                suspicious.append(event)

        return suspicious
