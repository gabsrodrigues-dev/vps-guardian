"""Container resource monitoring module.

Monitors Docker containers for excessive CPU usage and stops abusive containers.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from datetime import datetime
import subprocess
import logging
import json
import re


@dataclass
class ContainerStats:
    """CPU usage tracking for a container."""
    container_id: str
    container_name: str
    image: str
    first_high_cpu_time: Optional[float] = None
    consecutive_high_readings: int = 0
    last_cpu_percent: float = 0.0
    labels: Dict[str, str] = field(default_factory=dict)
    warning_sent: bool = False


@dataclass
class ContainerAbuse:
    """Container that exceeded CPU threshold for too long."""
    container_id: str
    container_name: str
    image: str
    cpu_percent: float
    duration_minutes: float
    labels: Dict[str, str]


class ContainerMonitor:
    """Monitor and control Docker container resource usage.

    Single Responsibility: Track container CPU usage and stop abusive containers.
    """

    def __init__(self, config: dict):
        container_config = config.get('containers', {})
        resource_config = container_config.get('resource_monitoring', {})

        self.enabled = resource_config.get('enabled', True)
        self.cpu_threshold = resource_config.get('cpu_threshold_percent', 100)
        self.warn_after_minutes = resource_config.get('warn_after_minutes', 5)
        self.kill_after_minutes = resource_config.get('kill_after_minutes', 15)
        self.check_interval = resource_config.get('check_interval_seconds', 60)
        self.action = resource_config.get('action', 'stop')  # stop or kill

        # Whitelist patterns (regex)
        self.whitelist_patterns = resource_config.get('whitelist', [
            r'coolify.*',           # All Coolify containers
            r'traefik.*',           # Traefik proxy
            r'.*postgres.*',        # Databases
            r'.*redis.*',           # Cache
            r'.*mysql.*',           # Databases
        ])

        # Label-based whitelist
        self.whitelist_labels = resource_config.get('whitelist_labels', [
            'coolify.managed=true',
            'guardian.ignore=true',
        ])

        self._compiled_patterns = [re.compile(p, re.I) for p in self.whitelist_patterns]
        self._tracking: Dict[str, ContainerStats] = {}
        self.logger = logging.getLogger('guardian.container_monitor')

    def _is_whitelisted(self, name: str, image: str, labels: Dict[str, str]) -> bool:
        """Check if container is whitelisted by name, image, or labels."""
        # Check name patterns
        for pattern in self._compiled_patterns:
            if pattern.match(name) or pattern.match(image):
                return True

        # Check labels
        for label_spec in self.whitelist_labels:
            if '=' in label_spec:
                key, value = label_spec.split('=', 1)
                if labels.get(key) == value:
                    return True
            elif label_spec in labels:
                return True

        return False

    def _get_container_stats(self) -> List[Dict[str, Any]]:
        """Get CPU stats for all running containers using docker stats."""
        try:
            # Get stats in JSON format
            result = subprocess.run(
                ['docker', 'stats', '--no-stream', '--format',
                 '{"id":"{{.ID}}","name":"{{.Name}}","cpu":"{{.CPUPerc}}","image":"{{.Image}}"}'],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode != 0:
                self.logger.warning(f"docker stats failed: {result.stderr}")
                return []

            containers = []
            for line in result.stdout.strip().split('\n'):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    # Parse CPU percentage (e.g., "150.25%" -> 150.25)
                    cpu_str = data.get('cpu', '0%').rstrip('%')
                    data['cpu_percent'] = float(cpu_str) if cpu_str else 0.0
                    containers.append(data)
                except (json.JSONDecodeError, ValueError) as e:
                    self.logger.debug(f"Failed to parse stats line: {line}, error: {e}")

            return containers

        except subprocess.TimeoutExpired:
            self.logger.error("docker stats timed out")
            return []
        except Exception as e:
            self.logger.error(f"Failed to get container stats: {e}")
            return []

    def _get_container_labels(self, container_id: str) -> Dict[str, str]:
        """Get labels for a specific container."""
        try:
            result = subprocess.run(
                ['docker', 'inspect', '--format', '{{json .Config.Labels}}', container_id],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return json.loads(result.stdout.strip()) or {}
        except Exception as e:
            self.logger.debug(f"Failed to get labels for {container_id}: {e}")
        return {}

    def check(self) -> List[ContainerAbuse]:
        """Check all containers for CPU abuse.

        Returns list of containers that exceeded threshold for kill_after_minutes.
        """
        if not self.enabled:
            return []

        import time
        current_time = time.time()
        abusive_containers = []

        stats = self._get_container_stats()
        seen_ids = set()

        for container in stats:
            container_id = container['id']
            container_name = container['name']
            image = container.get('image', '')
            cpu_percent = container['cpu_percent']

            seen_ids.add(container_id)

            # Get or create tracking entry
            if container_id not in self._tracking:
                labels = self._get_container_labels(container_id)
                self._tracking[container_id] = ContainerStats(
                    container_id=container_id,
                    container_name=container_name,
                    image=image,
                    labels=labels
                )

            tracking = self._tracking[container_id]
            tracking.last_cpu_percent = cpu_percent

            # Check whitelist
            if self._is_whitelisted(container_name, image, tracking.labels):
                # Reset tracking for whitelisted containers
                tracking.first_high_cpu_time = None
                tracking.consecutive_high_readings = 0
                continue

            # Check if CPU is above threshold
            if cpu_percent >= self.cpu_threshold:
                if tracking.first_high_cpu_time is None:
                    tracking.first_high_cpu_time = current_time
                    self.logger.info(
                        f"Container {container_name} ({container_id[:12]}) "
                        f"started high CPU usage: {cpu_percent:.1f}%"
                    )

                tracking.consecutive_high_readings += 1

                # Calculate duration
                duration_seconds = current_time - tracking.first_high_cpu_time
                duration_minutes = duration_seconds / 60

                # Check if exceeded time limit
                if duration_minutes >= self.kill_after_minutes:
                    abusive_containers.append(ContainerAbuse(
                        container_id=container_id,
                        container_name=container_name,
                        image=image,
                        cpu_percent=cpu_percent,
                        duration_minutes=duration_minutes,
                        labels=tracking.labels
                    ))
            else:
                # CPU dropped below threshold, reset tracking
                if tracking.first_high_cpu_time is not None:
                    self.logger.info(
                        f"Container {container_name} ({container_id[:12]}) "
                        f"CPU normalized: {cpu_percent:.1f}%"
                    )
                tracking.first_high_cpu_time = None
                tracking.consecutive_high_readings = 0

        # Clean up tracking for stopped containers
        for container_id in list(self._tracking.keys()):
            if container_id not in seen_ids:
                del self._tracking[container_id]

        return abusive_containers

    def stop_container(self, container_id: str) -> bool:
        """Stop an abusive container."""
        try:
            cmd = ['docker', self.action, container_id]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

            if result.returncode == 0:
                self.logger.warning(f"Container {container_id[:12]} stopped due to CPU abuse")
                # Remove from tracking
                if container_id in self._tracking:
                    del self._tracking[container_id]
                return True
            else:
                self.logger.error(f"Failed to stop container {container_id[:12]}: {result.stderr}")
                return False

        except Exception as e:
            self.logger.error(f"Error stopping container {container_id[:12]}: {e}")
            return False

    def get_warnings(self) -> List[Dict[str, Any]]:
        """Get containers that need warning (5+ min high CPU but not yet 15 min)."""
        warnings = []
        import time
        current_time = time.time()

        for container_id, tracking in self._tracking.items():
            if tracking.first_high_cpu_time is None:
                continue

            duration = (current_time - tracking.first_high_cpu_time) / 60

            # Between warn threshold and kill threshold, and not yet warned
            if self.warn_after_minutes <= duration < self.kill_after_minutes:
                if not tracking.warning_sent:
                    tracking.warning_sent = True
                    warnings.append({
                        'container_id': container_id,
                        'container_name': tracking.container_name,
                        'image': tracking.image,
                        'cpu_percent': tracking.last_cpu_percent,
                        'duration_minutes': duration,
                        'labels': tracking.labels,
                    })

        return warnings

    def get_status(self) -> Dict[str, Any]:
        """Get current monitoring status for debugging."""
        return {
            'enabled': self.enabled,
            'threshold': self.cpu_threshold,
            'warn_after_minutes': self.warn_after_minutes,
            'kill_after_minutes': self.kill_after_minutes,
            'tracking': {
                cid[:12]: {
                    'name': t.container_name,
                    'cpu': t.last_cpu_percent,
                    'high_since': t.first_high_cpu_time,
                    'readings': t.consecutive_high_readings
                }
                for cid, t in self._tracking.items()
            }
        }
