#!/usr/bin/env python3
"""
VPS Guardian - Response Module
Handles threat response: kill processes, quarantine files, send notifications.
"""

import os
import shutil
import json
import signal
import subprocess
import psutil
import requests
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import logging

from guardian.modules.forensics import ForensicsCollector
from guardian.modules.webhook import WebhookNotifier

logger = logging.getLogger('guardian.response')

class ResponseLevel(Enum):
    """Response severity levels."""
    NOTIFY = 1      # Just notify (10min resource usage)
    KILL = 2        # Notify + Kill (20min resource usage OR explicit trigger)

@dataclass
class Incident:
    """Represents a security incident."""
    timestamp: str
    pid: int
    process_name: str
    threat_type: str
    reason: str
    action_taken: str
    details: Dict[str, Any]
    forensics_path: Optional[str] = None

class ResponseHandler:
    """Handles responses to detected threats."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.quarantine_dir = Path(config['response']['quarantine_dir'])
        self.log_file = Path(config['response']['log_file'])

        # Telegram config
        telegram_config = config['response']['telegram']
        self.telegram_enabled = telegram_config.get('enabled', False)
        self.telegram_webhook = telegram_config.get('webhook_url')
        self.telegram_chat_id = telegram_config.get('chat_id')

        # Forensics collector
        self.forensics = ForensicsCollector(config)

        # Webhook notifier
        self.webhook = WebhookNotifier(config)

        # Container config
        containers_config = config.get('containers', {})
        self.containers_enabled = containers_config.get('enabled', False)
        self.container_on_threat = containers_config.get('on_threat', 'notify_only')
        self.container_whitelist = containers_config.get('whitelist', [])

        # Ensure directories exist (gracefully handle permission errors)
        try:
            self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            logger.warning(f"No permission to create {self.quarantine_dir}, will attempt on first use")

        try:
            self.log_file.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            logger.warning(f"No permission to create {self.log_file.parent}, will attempt on first use")

    def handle_threat(self, pid: int, name: str, reason: str,
                      level: ResponseLevel, exe_path: str = None,
                      extra_details: Dict = None) -> Incident:
        """Handle a detected threat based on severity level."""

        details = extra_details or {}
        action = 'none'
        forensics_path = None
        forensics_summary = None

        if level == ResponseLevel.NOTIFY:
            action = 'notified'
            self._send_notification(pid, name, reason, is_kill=False, details=details)

        elif level == ResponseLevel.KILL:
            # Collect forensics BEFORE killing process
            forensics_data = self.forensics.collect(pid)
            if forensics_data:
                try:
                    evidence_path = self.forensics.save(forensics_data)
                    forensics_path = str(evidence_path)
                    forensics_summary = self.forensics.to_summary(forensics_data)
                    logger.info(f"Forensics collected: {forensics_path}")

                    # Handle container threat if detected
                    if forensics_data.container_info:
                        container_handled = self._handle_container_threat(forensics_data.container_info)
                        if container_handled:
                            action = 'container_stopped'
                            logger.info(f"Container {forensics_data.container_info['container_id']} handled")

                except Exception as e:
                    logger.error(f"Failed to save forensics: {e}")

            # Kill the process
            killed = self._kill_process(pid)
            action = 'killed' if killed else 'kill_failed'

            # Quarantine the binary if exists
            if exe_path and os.path.exists(exe_path):
                quarantined = self._quarantine_file(exe_path)
                if quarantined:
                    action += '+quarantined'

            # Send notification
            self._send_notification(pid, name, reason, is_kill=True,
                                  details=details, forensics_summary=forensics_summary)

        # Log the incident
        incident = Incident(
            timestamp=datetime.now().isoformat(),
            pid=pid,
            process_name=name,
            threat_type=reason.split(':')[0] if ':' in reason else 'unknown',
            reason=reason,
            action_taken=action,
            details=details,
            forensics_path=forensics_path
        )

        self._log_incident(incident)
        return incident

    def _kill_process(self, pid: int) -> bool:
        """Kill a process and its children, ensuring no zombies are left."""
        try:
            proc = psutil.Process(pid)

            # Get children first (before killing parent)
            children = proc.children(recursive=True)

            # Kill children first - use SIGTERM then SIGKILL
            for child in children:
                try:
                    child.terminate()  # SIGTERM first (graceful)
                except psutil.NoSuchProcess:
                    continue

            # Wait for children to terminate gracefully
            gone, alive = psutil.wait_procs(children, timeout=3)

            # Force kill any remaining children
            for child in alive:
                try:
                    child.kill()  # SIGKILL (force)
                    child.wait(timeout=2)  # Collect exit status to prevent zombie
                except psutil.NoSuchProcess:
                    pass
                except psutil.TimeoutExpired:
                    logger.warning(f"Child {child.pid} did not terminate, may become zombie")

            # Now kill main process - SIGTERM first, then SIGKILL
            try:
                proc.terminate()  # SIGTERM
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()  # SIGKILL
                proc.wait(timeout=2)  # Collect exit status

            logger.info(f"Killed process {pid} and {len(children)} children (no zombies)")
            return True

        except psutil.NoSuchProcess:
            logger.info(f"Process {pid} already dead")
            return True  # Not an error - process is gone
        except psutil.AccessDenied as e:
            logger.error(f"Access denied killing PID {pid}: {e}")
            return False
        except psutil.TimeoutExpired as e:
            logger.error(f"Timeout killing PID {pid}: {e}")
            return False

    def _quarantine_file(self, file_path: str) -> bool:
        """Move a file to quarantine directory safely."""
        try:
            src = Path(file_path).resolve()  # Resolve to absolute path
            if not src.exists():
                return False

            # Sanitize filename to prevent path traversal
            safe_name = src.name.replace('/', '_').replace('\\', '_').replace('..', '__')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            dst = self.quarantine_dir / f"{timestamp}_{safe_name}"

            # Verify destination is within quarantine directory (prevent path traversal)
            if not dst.resolve().is_relative_to(self.quarantine_dir.resolve()):
                logger.error(f"Path traversal attempt blocked: {file_path}")
                return False

            shutil.move(str(src), str(dst))
            os.chmod(str(dst), 0o000)  # Remove all permissions

            logger.info(f"Quarantined: {file_path} -> {dst}")
            return True

        except (IOError, OSError) as e:
            logger.error(f"Failed to quarantine {file_path}: {e}")
            return False

    def _send_notification(self, pid: int, name: str, reason: str,
                           is_kill: bool, details: Dict,
                           forensics_summary: Optional[str] = None):
        """Send notification via Telegram and Webhook."""
        self._send_webhook_notification(
            pid, name, reason, is_kill, details, forensics_summary
        )

        if not self.telegram_enabled or not self.telegram_webhook:
            return

        emoji = "☠️" if is_kill else "🔔"
        action_text = "PROCESSO ELIMINADO" if is_kill else "Monitorando"
        title = "[KILL]" if is_kill else "[ALERTA]"

        # Format details
        detail_lines = []
        if 'cpu_percent' in details:
            detail_lines.append(f"CPU: {details['cpu_percent']:.1f}%")
        if 'memory_percent' in details:
            detail_lines.append(f"RAM: {details['memory_percent']:.1f}%")
        if 'duration_minutes' in details:
            detail_lines.append(f"Duração: {details['duration_minutes']:.1f} min")
        if 'time_until_kill' in details and not is_kill:
            detail_lines.append(f"Kill em: {details['time_until_kill']:.1f} min")

        message_parts = [
            f"{emoji} {title} VPS Guardian",
            "━━━━━━━━━━━━━━━━━━━",
            f"Processo: {name} (PID {pid})",
            chr(10).join(detail_lines),
            f"Motivo: {reason}",
            f"Ação: {action_text}"
        ]

        # Add forensics summary if available
        if forensics_summary:
            message_parts.append("━━━━━━━━━━━━━━━━━━━")
            message_parts.append(forensics_summary)

        message_parts.append("━━━━━━━━━━━━━━━━━━━")
        message = chr(10).join(message_parts)

        try:
            # For Telegram Bot API
            if 'api.telegram.org' in self.telegram_webhook:
                requests.post(
                    self.telegram_webhook,
                    json={'chat_id': self.telegram_chat_id, 'text': message},
                    timeout=5
                )
            else:
                # Generic webhook
                requests.post(self.telegram_webhook, json={'text': message}, timeout=5)

        except Exception as e:
            logger.error(f"Failed to send notification: {e}")

    def _send_webhook_notification(self, pid: int, name: str, reason: str,
                                   is_kill: bool, details: Dict,
                                   forensics_summary: Optional[str] = None):
        """Send notification via Webhook."""
        if not self.webhook.enabled:
            return

        try:
            self.webhook.send_incident(
                pid=pid,
                name=name,
                reason=reason,
                is_kill=is_kill,
                details=details,
                forensics_summary=forensics_summary
            )
        except Exception as e:
            logger.error(f"Failed to send webhook notification: {e}")

    def _log_incident(self, incident: Incident):
        """Log incident to JSON file."""
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(asdict(incident)) + '\n')
        except IOError as e:
            logger.error(f"Failed to log incident: {e}")

    def _handle_container_threat(self, container_info: Dict[str, Any]) -> bool:
        """Handle threat in container based on config.

        Config options (containers.on_threat):
        - 'stop': docker stop {container_id}
        - 'kill': docker kill {container_id}
        - 'notify_only': just alert, don't take action

        Returns:
            True if action was taken or notify_only, False if disabled/whitelisted/failed
        """
        # Check if containers feature is enabled
        if not self.containers_enabled:
            logger.debug("Containers feature is disabled")
            return False

        container_id = container_info.get('container_id')
        if not container_id:
            logger.warning("Container info missing container_id")
            return False

        # Check whitelist
        if container_id in self.container_whitelist:
            logger.info(f"Container {container_id} is whitelisted, skipping action")
            return False

        # Handle based on configured action
        if self.container_on_threat == 'notify_only':
            logger.info(f"Container {container_id} detected (notify_only mode)")
            return True

        # Execute docker command
        container_type = container_info.get('type', 'docker')
        command = [container_type, self.container_on_threat, container_id]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                logger.info(
                    f"Container {container_id} {self.container_on_threat}ped successfully"
                )
                return True
            else:
                logger.error(
                    f"Failed to {self.container_on_threat} container {container_id}: "
                    f"{result.stderr}"
                )
                return False

        except subprocess.TimeoutExpired:
            logger.error(f"Timeout executing {command}")
            return False
        except Exception as e:
            logger.error(f"Error executing {command}: {e}")
            return False
