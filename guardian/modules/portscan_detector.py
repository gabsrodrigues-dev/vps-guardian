#!/usr/bin/env python3
"""
VPS Guardian - Port Scan Detector Module
Detects port scanning activity and bans offending IPs.

Detection strategy:
- Tracks unique destination ports per source IP via iptables LOG entries.
- If a single IP hits more than N distinct ports within a time window, it's flagged.
- First offense: temporary ban (default 30 min).
- Repeat offense (caught again after temp ban expires): permanent ban.
- Bans are applied via a dedicated iptables chain (GUARDIAN_BANNED).
- Permanent bans are persisted to disk and restored on restart.
"""

import re
import os
import json
import time
import subprocess
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger('guardian.portscan')

# Chain name used exclusively by guardian for bans
IPTABLES_CHAIN = 'GUARDIAN_BANNED'
BAN_STATE_FILE = '/var/lib/guardian/portscan_bans.json'


@dataclass
class PortScanEvent:
    """Represents a detected port scan."""
    source_ip: str
    ports_hit: List[int]
    port_count: int
    first_seen: float
    last_seen: float
    duration_seconds: float
    scan_type: str  # 'sequential', 'common_ports', 'high_ports', 'mixed'
    action_taken: str  # 'temp_ban', 'permanent_ban'


@dataclass
class _IPTracking:
    """Internal tracking for a source IP."""
    ports: Set[int] = field(default_factory=set)
    first_seen: float = 0.0
    last_seen: float = 0.0
    syn_count: int = 0
    warned: bool = False


@dataclass
class _BanRecord:
    """Record of a banned IP."""
    ip: str
    banned_at: float
    expires_at: Optional[float]  # None = permanent
    offense_count: int
    reason: str
    permanent: bool


class PortScanDetector:
    """Detects port scanning and bans offending IPs via iptables.

    Ban strategy:
    - First scan detected → temp ban (configurable, default 30 min)
    - IP caught scanning again after temp ban expires → permanent ban
    - Permanent bans persisted to disk and restored on restart
    - Whitelist IPs/CIDRs are never banned
    """

    IPTABLES_LOG_PATTERN = re.compile(
        r'GUARDIAN_SYN:.*SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)'
    )

    GENERIC_DROP_PATTERN = re.compile(
        r'IN=\w+.*SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+).*(?:SYN|PROTO=TCP)'
    )

    def __init__(self, config: Dict[str, Any]):
        portscan_config = config.get('portscan_detection', {})

        self.enabled = portscan_config.get('enabled', True)
        self.port_threshold = portscan_config.get('port_threshold', 15)
        self.time_window_seconds = portscan_config.get('time_window_seconds', 60)
        self.cooldown_seconds = portscan_config.get('cooldown_seconds', 300)

        # Ban settings
        ban_config = portscan_config.get('ban', {})
        self.ban_enabled = ban_config.get('enabled', True)
        self.temp_ban_minutes = ban_config.get('temp_ban_minutes', 30)
        self.permanent_on_repeat = ban_config.get('permanent_on_repeat', True)
        self.ban_state_file = Path(ban_config.get('state_file', BAN_STATE_FILE))

        # IPs to NEVER ban (critical safety)
        self.whitelist_ips: Set[str] = set(portscan_config.get('whitelist_ips', [
            '127.0.0.1',
        ]))
        self.whitelist_cidrs: List[str] = portscan_config.get('whitelist_cidrs', [
            '10.0.0.0/8',
            '172.16.0.0/12',
            '192.168.0.0/16',
        ])

        self._tracking: Dict[str, _IPTracking] = defaultdict(_IPTracking)
        self._bans: Dict[str, _BanRecord] = {}
        # Track IPs that have been temp-banned before (for repeat detection)
        self._offense_history: Dict[str, int] = {}

        self._log_source = portscan_config.get('log_source', 'journalctl')
        self._kernlog_path = portscan_config.get('kernlog_path', '/var/log/kern.log')
        self._last_kernlog_position: int = 0
        self._install_iptables_rule = portscan_config.get('install_iptables_rule', True)

        if self.enabled:
            if self._install_iptables_rule:
                self._ensure_log_rule()
            if self.ban_enabled:
                self._ensure_ban_chain()
                self._load_persistent_bans()

    # ─── iptables setup ──────────────────────────────────────────────────

    def _ensure_log_rule(self):
        """Ensure iptables LOG rule exists for SYN tracking."""
        try:
            result = subprocess.run(
                ['iptables', '-C', 'INPUT', '-p', 'tcp', '--syn',
                 '-m', 'state', '--state', 'NEW',
                 '-m', 'limit', '--limit', '10/second', '--limit-burst', '50',
                 '-j', 'LOG', '--log-prefix', 'GUARDIAN_SYN: ', '--log-level', '4'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                subprocess.run(
                    ['iptables', '-A', 'INPUT', '-p', 'tcp', '--syn',
                     '-m', 'state', '--state', 'NEW',
                     '-m', 'limit', '--limit', '10/second', '--limit-burst', '50',
                     '-j', 'LOG', '--log-prefix', 'GUARDIAN_SYN: ', '--log-level', '4'],
                    capture_output=True, text=True, timeout=5
                )
                logger.info("Installed iptables LOG rule for port scan detection")
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            logger.warning(f"Could not install iptables LOG rule: {e}")

    def _ensure_ban_chain(self):
        """Create the GUARDIAN_BANNED chain and hook it into INPUT if needed."""
        try:
            # Create chain (ignore error if exists)
            subprocess.run(
                ['iptables', '-N', IPTABLES_CHAIN],
                capture_output=True, text=True, timeout=5
            )

            # Check if chain is already referenced in INPUT
            result = subprocess.run(
                ['iptables', '-C', 'INPUT', '-j', IPTABLES_CHAIN],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode != 0:
                # Insert at top of INPUT so bans are checked first
                subprocess.run(
                    ['iptables', '-I', 'INPUT', '1', '-j', IPTABLES_CHAIN],
                    capture_output=True, text=True, timeout=5
                )
                logger.info(f"Created and hooked {IPTABLES_CHAIN} chain into INPUT")

        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            logger.warning(f"Could not setup ban chain: {e}. Bans will not work.")
            self.ban_enabled = False

    # ─── Ban management ──────────────────────────────────────────────────

    def ban_ip(self, ip: str, permanent: bool = False, reason: str = '') -> bool:
        """Ban an IP via iptables DROP rule in GUARDIAN_BANNED chain.

        Args:
            ip: IP address to ban
            permanent: If True, ban never expires. If False, expires after temp_ban_minutes.
            reason: Human-readable reason for the ban.

        Returns:
            True if ban was applied successfully.
        """
        if self._is_whitelisted(ip):
            logger.warning(f"Refused to ban whitelisted IP: {ip}")
            return False

        if not self.ban_enabled:
            return False

        # Apply iptables rule
        try:
            # Check if already banned in chain
            check = subprocess.run(
                ['iptables', '-C', IPTABLES_CHAIN, '-s', ip, '-j', 'DROP'],
                capture_output=True, text=True, timeout=5
            )
            if check.returncode != 0:
                # Not yet banned, add rule
                subprocess.run(
                    ['iptables', '-A', IPTABLES_CHAIN, '-s', ip, '-j', 'DROP'],
                    capture_output=True, text=True, timeout=5
                )
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            logger.error(f"Failed to ban {ip}: {e}")
            return False

        # Track ban
        now = time.time()
        expires = None if permanent else now + (self.temp_ban_minutes * 60)

        # Update offense history
        self._offense_history[ip] = self._offense_history.get(ip, 0) + 1

        self._bans[ip] = _BanRecord(
            ip=ip,
            banned_at=now,
            expires_at=expires,
            offense_count=self._offense_history[ip],
            reason=reason,
            permanent=permanent
        )

        ban_type = "PERMANENT" if permanent else f"TEMPORARY ({self.temp_ban_minutes}min)"
        logger.warning(f"Banned {ip} [{ban_type}] - offense #{self._offense_history[ip]}: {reason}")

        # Persist permanent bans
        if permanent:
            self._save_persistent_bans()

        return True

    def unban_ip(self, ip: str) -> bool:
        """Remove ban for an IP."""
        try:
            subprocess.run(
                ['iptables', '-D', IPTABLES_CHAIN, '-s', ip, '-j', 'DROP'],
                capture_output=True, text=True, timeout=5
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError) as e:
            logger.error(f"Failed to unban {ip}: {e}")
            return False

        if ip in self._bans:
            was_permanent = self._bans[ip].permanent
            del self._bans[ip]
            if was_permanent:
                self._save_persistent_bans()

        logger.info(f"Unbanned {ip}")
        return True

    def _expire_temp_bans(self):
        """Check and remove expired temporary bans."""
        now = time.time()
        expired = []

        for ip, ban in self._bans.items():
            if not ban.permanent and ban.expires_at and now >= ban.expires_at:
                expired.append(ip)

        for ip in expired:
            logger.info(f"Temp ban expired for {ip} (offense #{self._offense_history.get(ip, 1)})")
            # Remove from iptables
            try:
                subprocess.run(
                    ['iptables', '-D', IPTABLES_CHAIN, '-s', ip, '-j', 'DROP'],
                    capture_output=True, text=True, timeout=5
                )
            except Exception as e:
                logger.error(f"Failed to remove expired ban for {ip}: {e}")

            del self._bans[ip]

    def _save_persistent_bans(self):
        """Save permanent bans to disk for restoration on restart."""
        try:
            self.ban_state_file.parent.mkdir(parents=True, exist_ok=True)

            persistent = {}
            for ip, ban in self._bans.items():
                if ban.permanent:
                    persistent[ip] = {
                        'banned_at': ban.banned_at,
                        'offense_count': ban.offense_count,
                        'reason': ban.reason,
                    }

            # Also save offense history so repeat detection survives restart
            state = {
                'permanent_bans': persistent,
                'offense_history': self._offense_history,
            }

            with open(self.ban_state_file, 'w') as f:
                json.dump(state, f, indent=2)

            logger.debug(f"Saved {len(persistent)} permanent bans to {self.ban_state_file}")

        except (PermissionError, OSError) as e:
            logger.error(f"Failed to save ban state: {e}")

    def _load_persistent_bans(self):
        """Load and restore permanent bans from disk."""
        if not self.ban_state_file.exists():
            return

        try:
            with open(self.ban_state_file, 'r') as f:
                state = json.load(f)

            # Restore offense history
            self._offense_history = state.get('offense_history', {})

            # Restore permanent bans
            permanent_bans = state.get('permanent_bans', {})
            restored = 0

            for ip, data in permanent_bans.items():
                if self._is_whitelisted(ip):
                    continue

                # Re-apply iptables rule
                try:
                    check = subprocess.run(
                        ['iptables', '-C', IPTABLES_CHAIN, '-s', ip, '-j', 'DROP'],
                        capture_output=True, text=True, timeout=5
                    )
                    if check.returncode != 0:
                        subprocess.run(
                            ['iptables', '-A', IPTABLES_CHAIN, '-s', ip, '-j', 'DROP'],
                            capture_output=True, text=True, timeout=5
                        )
                except Exception as e:
                    logger.error(f"Failed to restore ban for {ip}: {e}")
                    continue

                self._bans[ip] = _BanRecord(
                    ip=ip,
                    banned_at=data.get('banned_at', time.time()),
                    expires_at=None,
                    offense_count=data.get('offense_count', 1),
                    reason=data.get('reason', 'restored from disk'),
                    permanent=True
                )
                restored += 1

            if restored:
                logger.info(f"Restored {restored} permanent IP bans from {self.ban_state_file}")

        except (json.JSONDecodeError, PermissionError, OSError) as e:
            logger.error(f"Failed to load ban state: {e}")

    # ─── IP whitelist check ──────────────────────────────────────────────

    def _is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is whitelisted (never ban these)."""
        if ip in self.whitelist_ips:
            return True

        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            return False

        try:
            ip_int = (int(ip_parts[0]) << 24 | int(ip_parts[1]) << 16 |
                      int(ip_parts[2]) << 8 | int(ip_parts[3]))
        except ValueError:
            return False

        for cidr in self.whitelist_cidrs:
            try:
                network, prefix_len = cidr.split('/')
                prefix_len = int(prefix_len)
                net_parts = network.split('.')
                net_int = (int(net_parts[0]) << 24 | int(net_parts[1]) << 16 |
                           int(net_parts[2]) << 8 | int(net_parts[3]))
                mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF

                if (ip_int & mask) == (net_int & mask):
                    return True
            except (ValueError, IndexError):
                continue

        return False

    # ─── Log parsing ─────────────────────────────────────────────────────

    def _fetch_log_entries(self) -> List[str]:
        """Fetch new log entries from journalctl or kern.log."""
        if self._log_source == 'journalctl':
            return self._fetch_from_journalctl()
        return self._fetch_from_kernlog()

    def _fetch_from_journalctl(self) -> List[str]:
        """Fetch kernel log entries from journalctl."""
        try:
            cmd = ['journalctl', '-k', '--no-pager', '-o', 'short-iso',
                   '--since', '1 min ago', '-q']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return []
            return result.stdout.strip().split('\n') if result.stdout.strip() else []
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.debug(f"journalctl fetch failed: {e}")
            return []

    def _fetch_from_kernlog(self) -> List[str]:
        """Fetch new entries from /var/log/kern.log."""
        try:
            file_size = os.path.getsize(self._kernlog_path)
            if file_size < self._last_kernlog_position:
                self._last_kernlog_position = 0

            with open(self._kernlog_path, 'r') as f:
                f.seek(self._last_kernlog_position)
                lines = f.readlines()
                self._last_kernlog_position = f.tell()

            return [line.strip() for line in lines if line.strip()]
        except (FileNotFoundError, PermissionError) as e:
            logger.debug(f"kern.log read failed: {e}")
            return []

    def _parse_log_entries(self, lines: List[str]) -> List[tuple]:
        """Parse log lines and extract (source_ip, dest_port) tuples."""
        results = []
        for line in lines:
            match = self.IPTABLES_LOG_PATTERN.search(line)
            if match:
                results.append((match.group(1), int(match.group(2))))
                continue
            match = self.GENERIC_DROP_PATTERN.search(line)
            if match:
                results.append((match.group(1), int(match.group(2))))
        return results

    # ─── Scan classification ─────────────────────────────────────────────

    def _classify_scan(self, ports: Set[int]) -> str:
        """Classify the scan type based on port patterns."""
        port_list = sorted(ports)

        if len(port_list) > 5:
            sequential = sum(1 for i in range(1, len(port_list))
                            if port_list[i] - port_list[i-1] == 1)
            if sequential > len(port_list) * 0.5:
                return 'sequential'

        common_ports = {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                        445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443}
        common_hit = len(ports & common_ports)
        if common_hit > len(ports) * 0.5:
            return 'common_ports'

        high_ports = sum(1 for p in ports if p > 1024)
        if high_ports > len(ports) * 0.8:
            return 'high_ports'

        return 'mixed'

    # ─── Main check loop ─────────────────────────────────────────────────

    def _cleanup_expired(self, current_time: float):
        """Remove tracking entries outside the time window."""
        expired = [ip for ip, t in self._tracking.items()
                   if current_time - t.last_seen > self.time_window_seconds]
        for ip in expired:
            del self._tracking[ip]

    def check(self) -> List[PortScanEvent]:
        """Check for port scanning activity and ban offenders.

        Returns list of detected port scan events since last check.
        """
        if not self.enabled:
            return []

        current_time = time.time()
        events = []

        # Expire temporary bans
        if self.ban_enabled:
            self._expire_temp_bans()

        # Cleanup old tracking entries
        self._cleanup_expired(current_time)

        # Fetch and parse new log entries
        log_lines = self._fetch_log_entries()
        connections = self._parse_log_entries(log_lines)

        for src_ip, dst_port in connections:
            if self._is_whitelisted(src_ip):
                continue
            # Skip IPs already banned (they shouldn't generate logs but just in case)
            if src_ip in self._bans:
                continue

            tracking = self._tracking[src_ip]
            if tracking.first_seen == 0.0:
                tracking.first_seen = current_time
            tracking.last_seen = current_time
            tracking.ports.add(dst_port)
            tracking.syn_count += 1

        # Check thresholds and take action
        for ip, tracking in self._tracking.items():
            if tracking.warned:
                continue

            if len(tracking.ports) >= self.port_threshold:
                duration = tracking.last_seen - tracking.first_seen
                scan_type = self._classify_scan(tracking.ports)

                # Determine ban type: repeat offender → permanent
                previous_offenses = self._offense_history.get(ip, 0)
                is_repeat = previous_offenses > 0 and self.permanent_on_repeat
                action_taken = 'monitoring'

                if self.ban_enabled:
                    if is_repeat:
                        reason = (f"Repeat port scan: {len(tracking.ports)} ports "
                                  f"in {duration:.0f}s (offense #{previous_offenses + 1})")
                        if self.ban_ip(ip, permanent=True, reason=reason):
                            action_taken = 'permanent_ban'
                    else:
                        reason = (f"Port scan: {len(tracking.ports)} ports "
                                  f"in {duration:.0f}s ({scan_type})")
                        if self.ban_ip(ip, permanent=False, reason=reason):
                            action_taken = 'temp_ban'

                event = PortScanEvent(
                    source_ip=ip,
                    ports_hit=sorted(tracking.ports)[:50],
                    port_count=len(tracking.ports),
                    first_seen=tracking.first_seen,
                    last_seen=tracking.last_seen,
                    duration_seconds=duration,
                    scan_type=scan_type,
                    action_taken=action_taken
                )
                events.append(event)
                tracking.warned = True

                logger.warning(
                    f"Port scan from {ip}: {len(tracking.ports)} ports "
                    f"in {duration:.1f}s ({scan_type}) → {action_taken}"
                )

        return events

    # ─── Status & management ─────────────────────────────────────────────

    def get_banned_ips(self) -> Dict[str, Any]:
        """Get all currently banned IPs."""
        return {
            ip: {
                'permanent': ban.permanent,
                'banned_at': datetime.fromtimestamp(ban.banned_at).isoformat(),
                'expires_at': (datetime.fromtimestamp(ban.expires_at).isoformat()
                               if ban.expires_at else None),
                'offense_count': ban.offense_count,
                'reason': ban.reason,
            }
            for ip, ban in self._bans.items()
        }

    def get_status(self) -> Dict[str, Any]:
        """Get current detector status."""
        return {
            'enabled': self.enabled,
            'ban_enabled': self.ban_enabled,
            'port_threshold': self.port_threshold,
            'time_window_seconds': self.time_window_seconds,
            'temp_ban_minutes': self.temp_ban_minutes,
            'permanent_on_repeat': self.permanent_on_repeat,
            'tracking_ips': len(self._tracking),
            'active_bans': len(self._bans),
            'permanent_bans': sum(1 for b in self._bans.values() if b.permanent),
            'temp_bans': sum(1 for b in self._bans.values() if not b.permanent),
            'offense_history_count': len(self._offense_history),
        }
