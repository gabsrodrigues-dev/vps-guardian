#!/usr/bin/env python3
"""
VPS Guardian - Forensics Module
Collects and stores forensic evidence from malicious processes before termination.

Single Responsibility: Evidence collection and retention.
"""

import json
import time
import logging
import subprocess
import psutil
from dataclasses import dataclass, asdict
from typing import Optional, List, Dict, Any
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger("guardian.forensics")


@dataclass
class ForensicsData:
    """Single Responsibility: Data container for forensic evidence."""

    pid: int
    timestamp: float
    ppid: Optional[int]
    uid: Optional[int]
    username: Optional[str]
    exe_path: Optional[str]
    cwd: Optional[str]
    cmdline: List[str]
    environ: Dict[str, str]
    open_files: List[Dict[str, Any]]
    connections: List[Dict[str, Any]]
    parent_chain: List[Dict[str, Any]]
    children: List[Dict[str, Any]]
    container_info: Optional[Dict[str, Any]] = None  # For Phase 3


class ForensicsCollector:
    """Single Responsibility: Collect and store forensic evidence."""

    def __init__(self, config: dict):
        """Initialize forensics collector with configuration."""
        # Extract config with defaults
        forensics_config = config.get("forensics", {})
        self.enabled = forensics_config.get("enabled", True)
        self.storage_dir = Path(
            forensics_config.get("storage_dir", "/var/lib/guardian/forensics")
        )
        self.max_collection_time = forensics_config.get(
            "max_collection_time_seconds", 2
        )
        self.include_environ = forensics_config.get("include_environ", True)
        self.include_open_files = forensics_config.get("include_open_files", True)
        self.retention_days = forensics_config.get("retention_days", 30)
        self.logger = logging.getLogger("guardian.forensics")

        # Ensure storage directory exists
        self._ensure_storage_dir()

    def _ensure_storage_dir(self):
        """Create storage directory if it doesn't exist."""
        try:
            self.storage_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            self.logger.warning(
                f"No permission to create {self.storage_dir}, will attempt on first use"
            )

    def collect(self, pid: int) -> Optional[ForensicsData]:
        """
        Main collection method - timeout protected.

        Collects comprehensive forensic data from a process including:
        - Process metadata (PID, PPID, UID, username)
        - Executable path and working directory
        - Command line arguments
        - Environment variables (if enabled)
        - Open files (if enabled)
        - Network connections
        - Parent process chain
        - Child processes

        Returns None if process doesn't exist or collection fails.
        """
        try:
            proc = psutil.Process(pid)

            # Collect basic metadata
            ppid = self._safe_collect(proc.ppid)
            uid = self._safe_collect(
                lambda: proc.uids().real if hasattr(proc.uids(), "real") else None
            )
            username = self._safe_collect(proc.username)
            exe_path = self._safe_collect(proc.exe)
            cwd = self._safe_collect(proc.cwd)
            cmdline = self._safe_collect(proc.cmdline, default=[])

            # Collect environment (optional)
            environ = {}
            if self.include_environ:
                environ = self._safe_collect(proc.environ, default={})

            # Collect open files (optional)
            open_files = []
            if self.include_open_files:
                raw_files = self._safe_collect(proc.open_files, default=[])
                open_files = self._format_open_files(raw_files)

            # Collect network connections
            raw_connections = self._safe_collect(proc.connections, default=[])
            connections = self._format_connections(raw_connections)

            # Collect parent chain
            parent_chain = self._collect_parent_chain(proc)

            # Collect children
            raw_children = self._safe_collect(proc.children, default=[])
            children = self._format_children(raw_children)

            # Detect container (Phase 3)
            container_info = self.detect_container(pid)

            # Add container processes if container detected
            if container_info:
                container_info['processes'] = self.get_container_processes(
                    container_info.get('container_id', '')
                )

            # Create forensic data object
            data = ForensicsData(
                pid=pid,
                timestamp=time.time(),
                ppid=ppid,
                uid=uid,
                username=username,
                exe_path=exe_path,
                cwd=cwd,
                cmdline=cmdline,
                environ=environ,
                open_files=open_files,
                connections=connections,
                parent_chain=parent_chain,
                children=children,
                container_info=container_info,
            )

            return data

        except psutil.NoSuchProcess:
            self.logger.warning(f"Process {pid} no longer exists")
            return None
        except Exception as e:
            self.logger.error(f"Failed to collect forensics for PID {pid}: {e}")
            return None

    def _safe_collect(self, func, default=None):
        """
        DRY helper: Safely call a psutil function with error handling.

        All psutil calls can raise AccessDenied or NoSuchProcess.
        This wrapper ensures we don't crash the entire collection.
        """
        try:
            if callable(func):
                return func()
            return func
        except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
            return default
        except Exception as e:
            self.logger.debug(f"Error collecting attribute: {e}")
            return default

    def _format_open_files(self, raw_files: List) -> List[Dict[str, Any]]:
        """Format open files into serializable dictionaries."""
        formatted = []
        for f in raw_files:
            try:
                formatted.append({"path": f.path, "fd": f.fd})
            except Exception as e:
                self.logger.debug(f"Error formatting open file: {e}")
        return formatted

    def _format_connections(self, raw_connections: List) -> List[Dict[str, Any]]:
        """Format network connections into serializable dictionaries."""
        formatted = []
        for conn in raw_connections:
            try:
                # Format addresses
                laddr = f"{conn.laddr[0]}:{conn.laddr[1]}" if conn.laddr else ""
                raddr = f"{conn.raddr[0]}:{conn.raddr[1]}" if conn.raddr else ""

                formatted.append(
                    {"laddr": laddr, "raddr": raddr, "status": conn.status}
                )
            except Exception as e:
                self.logger.debug(f"Error formatting connection: {e}")
        return formatted

    def _collect_parent_chain(self, proc: psutil.Process) -> List[Dict[str, Any]]:
        """Walk up the parent chain and collect information."""
        chain = []
        current = self._safe_collect(proc.parent)

        # Limit depth to prevent infinite loops
        max_depth = 10
        depth = 0

        while current and depth < max_depth:
            try:
                chain.append(
                    {
                        "pid": current.pid,
                        "name": self._safe_collect(current.name, default="unknown"),
                    }
                )
                current = self._safe_collect(current.parent)
                depth += 1
            except Exception as e:
                self.logger.debug(f"Error collecting parent: {e}")
                break

        return chain

    def _format_children(self, raw_children: List) -> List[Dict[str, Any]]:
        """Format child processes into serializable dictionaries."""
        formatted = []
        for child in raw_children:
            try:
                formatted.append(
                    {
                        "pid": child.pid,
                        "name": self._safe_collect(child.name, default="unknown"),
                    }
                )
            except Exception as e:
                self.logger.debug(f"Error formatting child: {e}")
        return formatted

    def detect_container(self, pid: int) -> Optional[Dict[str, Any]]:
        """Detect if process is running in a container.

        Returns:
            Dict with container info or None if not in container
            {
                'type': 'docker' | 'kubernetes' | 'containerd' | 'lxc',
                'container_id': str,  # First 12 chars of container ID
                'full_id': str,       # Full container ID
            }
        """
        try:
            cgroup_path = f"/proc/{pid}/cgroup"
            with open(cgroup_path, "r") as f:
                cgroup_content = f.read()

            # Check for container patterns
            for line in cgroup_content.split("\n"):
                if not line.strip():
                    continue

                # Docker container
                if "/docker/" in line:
                    container_id = self._extract_container_id(line, "/docker/")
                    if container_id:
                        return {
                            "type": "docker",
                            "container_id": container_id[:12],
                            "full_id": container_id,
                        }

                # Kubernetes pod
                elif "/kubepods/" in line:
                    container_id = self._extract_container_id(line, "/kubepods/")
                    if container_id:
                        return {
                            "type": "kubernetes",
                            "container_id": container_id[:12],
                            "full_id": container_id,
                        }

                # containerd
                elif "/containerd/" in line:
                    container_id = self._extract_container_id(line, "/containerd/")
                    if container_id:
                        return {
                            "type": "containerd",
                            "container_id": container_id[:12],
                            "full_id": container_id,
                        }

                # LXC container
                elif "/lxc/" in line:
                    container_id = self._extract_container_id(line, "/lxc/")
                    if container_id:
                        return {
                            "type": "lxc",
                            "container_id": container_id[:12],
                            "full_id": container_id,
                        }

            # No container detected
            return None

        except (FileNotFoundError, PermissionError, OSError) as e:
            self.logger.debug(f"Could not read cgroup for PID {pid}: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Error detecting container for PID {pid}: {e}")
            return None

    def _extract_container_id(self, cgroup_line: str, pattern: str) -> Optional[str]:
        """Extract container ID from cgroup line.

        Args:
            cgroup_line: A line from /proc/PID/cgroup
            pattern: The pattern to look for (e.g., '/docker/')

        Returns:
            Container ID (hex string) or None
        """
        try:
            # Split by pattern and get the part after it
            parts = cgroup_line.split(pattern)
            if len(parts) < 2:
                return None

            # Get the ID part (everything after the pattern until next /)
            id_part = parts[1].split("/")[0].strip()

            # For kubernetes, the last segment is usually the container ID
            if pattern == "/kubepods/":
                segments = parts[1].strip().split("/")
                if segments:
                    id_part = segments[-1]

            # Clean up the ID (remove any trailing characters)
            if id_part:
                return id_part

            return None

        except Exception as e:
            self.logger.debug(f"Error extracting container ID: {e}")
            return None

    def get_container_processes(self, container_id: str) -> List[Dict[str, Any]]:
        """Get list of processes running inside a container.

        Useful for post-incident analysis and baseline comparison.

        Args:
            container_id: Short or full container ID

        Returns:
            List of dictionaries with process info (pid, user, command, args)
        """
        try:
            result = subprocess.run(
                ['docker', 'top', container_id, '-eo', 'pid,user,comm,args'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')[1:]  # Skip header
                processes = []
                for line in lines:
                    parts = line.split(None, 3)
                    if len(parts) >= 3:
                        processes.append({
                            'pid': parts[0],
                            'user': parts[1],
                            'command': parts[2],
                            'args': parts[3] if len(parts) > 3 else ''
                        })
                return processes
        except Exception as e:
            self.logger.warning(f"Failed to get container processes: {e}")
        return []

    def save(self, data: ForensicsData) -> Path:
        """
        Save forensics to JSON file, return path.

        File format: {timestamp}_{pid}.json
        Location: {storage_dir}/{timestamp}_{pid}.json
        """
        try:
            # Generate filename
            timestamp_str = str(int(data.timestamp))
            filename = f"{timestamp_str}_{data.pid}.json"
            filepath = self.storage_dir / filename

            # Ensure directory exists
            self.storage_dir.mkdir(parents=True, exist_ok=True)

            # Write JSON
            with open(filepath, "w") as f:
                json.dump(asdict(data), f, indent=2)

            self.logger.info(f"Saved forensic evidence to {filepath}")
            return filepath

        except Exception as e:
            self.logger.error(f"Failed to save forensics: {e}")
            raise

    def to_summary(self, data: ForensicsData) -> str:
        """Generate human-readable summary for notifications."""
        lines = [
            "=== FORENSIC EVIDENCE ===",
            f"PID: {data.pid}",
            f"User: {data.username or 'unknown'} (UID: {data.uid})",
            f"Executable: {data.exe_path or 'unknown'}",
            f"Working Dir: {data.cwd or 'unknown'}",
            f"Command: {' '.join(data.cmdline) if data.cmdline else 'unknown'}",
        ]

        # Add parent info
        if data.parent_chain:
            parent_names = " -> ".join([p["name"] for p in data.parent_chain])
            lines.append(f"Parent Chain: {parent_names}")

        # Add children info
        if data.children:
            child_pids = ", ".join([str(c["pid"]) for c in data.children])
            lines.append(f"Children: {child_pids}")

        # Add network connections
        if data.connections:
            lines.append("Network Connections:")
            for conn in data.connections[:3]:  # Limit to first 3
                lines.append(f"  - {conn['raddr']} ({conn['status']})")

        # Add open files
        if data.open_files:
            lines.append(f"Open Files: {len(data.open_files)} file(s)")

        lines.append("=" * 25)
        return "\n".join(lines)

    def cleanup_old(self) -> int:
        """
        Remove evidence older than retention_days, return count deleted.

        Walks the storage directory and deletes JSON files older than
        the retention period.
        """
        try:
            if not self.storage_dir.exists():
                return 0

            cutoff_time = time.time() - (self.retention_days * 24 * 60 * 60)
            deleted_count = 0

            for filepath in self.storage_dir.glob("*.json"):
                try:
                    # Check file modification time
                    if filepath.stat().st_mtime < cutoff_time:
                        filepath.unlink()
                        deleted_count += 1
                        self.logger.debug(f"Deleted old evidence: {filepath}")
                except Exception as e:
                    self.logger.warning(f"Failed to delete {filepath}: {e}")

            if deleted_count > 0:
                self.logger.info(f"Cleaned up {deleted_count} old forensic files")

            return deleted_count

        except Exception as e:
            self.logger.error(f"Failed to cleanup old evidence: {e}")
            return 0
