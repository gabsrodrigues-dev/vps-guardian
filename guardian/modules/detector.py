#!/usr/bin/env python3
"""
VPS Guardian - Process Detector Module
Detects suspicious processes by name, command line, and execution path.
"""

import os
import re
import psutil
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger('guardian.detector')

@dataclass
class Threat:
    """Represents a detected threat."""
    pid: int
    name: str
    exe: str
    cmdline: str
    reason: str
    severity: str  # 'high', 'medium', 'low'

class Detector:
    """Detects suspicious processes based on various patterns."""

    # Patterns that indicate random/obfuscated process names (common in malware)
    # Limit to 100 chars to prevent ReDoS attacks
    RANDOM_NAME_PATTERN = re.compile(r'^[a-z]{10,100}$|^[a-zA-Z0-9]{16,100}$')

    # Processes that masquerade as kernel workers
    FAKE_KERNEL_PATTERNS = ['kworkerds', 'kdevtmpfs', 'kthreaddi']

    # Build/development tools that legitimately run from /tmp during compilation
    BUILD_PROCESS_WHITELIST = [
        'maturin',      # Rust/Python build tool
        'cargo',        # Rust package manager
        'rustc',        # Rust compiler
        'cc1',          # GCC C compiler
        'cc1plus',      # GCC C++ compiler
        'as',           # GNU assembler
        'ld',           # GNU linker
        'pip',          # Python package installer
        'pip3',
        'npm',          # Node.js package manager
        'node',         # Node.js runtime
        'go',           # Go compiler
        'make',         # Build automation
        'cmake',        # CMake build system
        'ninja',        # Ninja build system
    ]

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.suspicious_terms = config['detection']['suspicious_terms']
        self.my_pid = os.getpid()
        # Load additional build whitelist from config if present
        self.build_whitelist = self.BUILD_PROCESS_WHITELIST.copy()
        if 'build_whitelist' in config.get('detection', {}):
            self.build_whitelist.extend(config['detection']['build_whitelist'])

    def scan(self) -> List[Threat]:
        """Scan all processes for suspicious patterns."""
        threats = []

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline']):
            try:
                if proc.info['pid'] == self.my_pid:
                    continue

                threat = self._analyze_process(proc.info)
                if threat:
                    threats.append(threat)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return threats

    def _analyze_process(self, info: Dict) -> Threat | None:
        """Analyze a single process for threats."""
        pid = info['pid']
        name = str(info['name'] or '')
        exe = str(info['exe'] or '')
        cmdline = ' '.join(info['cmdline'] or [])
        combined = (name + exe + cmdline).lower()

        # Skip legitimate kernel threads (they have no exe and appear in brackets in ps)
        # Real kernel threads will have exe=None/empty
        is_kernel_thread = (not exe and not cmdline)

        # Whitelist for legitimate system processes that might match our terms
        legitimate_whitelist = [
            'tracker-miner',  # GNOME file indexer
            'gnome-',
            '/usr/libexec/',
            '/usr/lib/',
        ]

        # Check if this is a legitimate process
        is_whitelisted = any(w.lower() in combined for w in legitimate_whitelist)

        # Check for known mining terms (skip whitelisted)
        if not is_whitelisted:
            for term in self.suspicious_terms:
                if term.lower() in combined:
                    return Threat(
                        pid=pid, name=name, exe=exe, cmdline=cmdline,
                        reason=f"Contains suspicious term: {term}",
                        severity='high'
                    )

        # Check for processes running from suspicious paths
        # But allow legitimate build tools that often run from /tmp during compilation
        if exe:
            is_build_tool = any(tool.lower() in name.lower() for tool in self.build_whitelist)
            if not is_build_tool:
                suspicious_paths = ['/tmp/', '/dev/shm/', '/var/tmp/', '/run/user/']
                for path in suspicious_paths:
                    if path in exe:
                        return Threat(
                            pid=pid, name=name, exe=exe, cmdline=cmdline,
                            reason=f"Executing from suspicious path: {path}",
                            severity='high'
                        )

        # Check for fake kernel process names (only if it's NOT a real kernel thread)
        if not is_kernel_thread:
            for fake_name in self.FAKE_KERNEL_PATTERNS:
                if fake_name in name.lower():
                    return Threat(
                        pid=pid, name=name, exe=exe, cmdline=cmdline,
                        reason=f"Fake kernel process pattern: {fake_name}",
                        severity='high'
                    )

        # Check for random/obfuscated names
        if self.RANDOM_NAME_PATTERN.match(name) and len(name) > 12:
            return Threat(
                pid=pid, name=name, exe=exe, cmdline=cmdline,
                reason="Suspicious random process name",
                severity='medium'
            )

        return None
