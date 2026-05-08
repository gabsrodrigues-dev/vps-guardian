#!/usr/bin/env python3
"""
VPS Guardian - Network Monitor Module
Detects connections to known mining pools and TOR exit nodes.
"""

import os
import socket
import psutil
from typing import Dict, List, Any, Set, Optional
from dataclasses import dataclass
from pathlib import Path
from functools import lru_cache
import logging

logger = logging.getLogger('guardian.network')

# Set default socket timeout to prevent blocking
socket.setdefaulttimeout(0.5)

@dataclass
class NetworkThreat:
    """Represents a suspicious network connection."""
    pid: int
    name: str
    remote_ip: str
    remote_port: int
    reason: str

class NetworkMonitor:
    """Monitors network connections for suspicious destinations."""

    # Common mining pool ports
    MINING_PORTS = {3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 45700}

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.mining_pools_file = Path(config['network']['mining_pools_list'])
        self.tor_nodes_file = Path(config['network']['tor_nodes_list'])
        self.suspicious_ports = set(config['network']['suspicious_ports'])

        self.process_whitelist = set(config.get('resources', {}).get('whitelist', []))
        network_whitelist = config.get('network', {}).get('process_whitelist', [])
        self.process_whitelist.update(network_whitelist)

        # Load blocklists
        self.blocked_domains: Set[str] = set()
        self.blocked_ips: Set[str] = set()
        self._load_blocklists()

    def _load_blocklists(self):
        """Load blocklists from files."""
        # Load mining pools (domains)
        if self.mining_pools_file.exists():
            with open(self.mining_pools_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.blocked_domains.add(line.lower())

        # Load TOR exit nodes (IPs)
        if self.tor_nodes_file.exists():
            with open(self.tor_nodes_file) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.blocked_ips.add(line)

    def reload_blocklists(self):
        """Reload blocklists from disk."""
        self.blocked_domains.clear()
        self.blocked_ips.clear()
        self._load_blocklists()

    def scan(self) -> List[NetworkThreat]:
        """Scan all network connections for suspicious destinations."""
        threats = []
        my_pid = os.getpid()

        for conn in psutil.net_connections(kind='inet'):
            try:
                if conn.pid is None or conn.pid == my_pid:
                    continue

                if conn.status != 'ESTABLISHED' and conn.status != 'SYN_SENT':
                    continue

                if not conn.raddr:
                    continue

                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port

                # Get process info
                try:
                    proc = psutil.Process(conn.pid)
                    proc_name = proc.name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = 'unknown'

                threat = self._analyze_connection(conn.pid, proc_name, remote_ip, remote_port)
                if threat:
                    threats.append(threat)

            except Exception:
                continue

        return threats

    @lru_cache(maxsize=1000)
    def _reverse_dns_cached(self, ip: str) -> Optional[str]:
        """Cached reverse DNS lookup with timeout."""
        try:
            return socket.gethostbyaddr(ip)[0].lower()
        except (socket.herror, socket.gaierror, socket.timeout, OSError):
            return None

    def _analyze_connection(self, pid: int, name: str, ip: str, port: int) -> Optional[NetworkThreat]:
        """Analyze a single connection for threats."""

        if name in self.process_whitelist:
            return None

        # Check if connecting to mining port
        if port in self.suspicious_ports:
            return NetworkThreat(
                pid=pid, name=name, remote_ip=ip, remote_port=port,
                reason=f"Connection to known mining port: {port}"
            )

        # Check if connecting to TOR exit node
        if ip in self.blocked_ips:
            return NetworkThreat(
                pid=pid, name=name, remote_ip=ip, remote_port=port,
                reason="Connection to TOR exit node"
            )

        # Try reverse DNS lookup with cache (prevents blocking)
        hostname = self._reverse_dns_cached(ip)
        if hostname:
            for domain in self.blocked_domains:
                if domain in hostname:
                    return NetworkThreat(
                        pid=pid, name=name, remote_ip=ip, remote_port=port,
                        reason=f"Connection to blocked domain: {domain}"
                    )

        return None
