#!/usr/bin/env python3
"""
VPS Guardian - Anti-Cryptojacking Protection System
Main orchestrator that coordinates all detection modules.
"""

import os
import sys
import time
import yaml
import logging
from pathlib import Path

# Setup logging
def setup_logging():
    """Configure logging with fallback for non-root execution."""
    handlers = [logging.StreamHandler(sys.stdout)]

    # Try to write to /var/log, fallback to local log if not root
    try:
        handlers.append(logging.FileHandler('/var/log/guardian.log'))
    except PermissionError:
        log_dir = Path(__file__).parent / 'logs'
        log_dir.mkdir(exist_ok=True)
        handlers.append(logging.FileHandler(log_dir / 'guardian.log'))

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=handlers
    )

setup_logging()
logger = logging.getLogger('guardian')

# Paths
GUARDIAN_DIR = Path(__file__).parent
CONFIG_PATH = GUARDIAN_DIR / 'config.yaml'

def load_config():
    """Load configuration from YAML file."""
    try:
        with open(CONFIG_PATH, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {CONFIG_PATH}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logger.error(f"Invalid YAML configuration: {e}")
        sys.exit(1)

def clean_zombies():
    """
    Clean zombie processes safely.

    Zombies are processes that have exited but their parent hasn't called wait().
    We try to reap them with os.waitpid() first. Only if that fails AND the zombie
    persists for multiple cycles, we log a warning (but don't kill the parent,
    as that could cause cascading issues).
    """
    try:
        import psutil
        import os

        for proc in psutil.process_iter(['pid', 'status', 'ppid', 'name']):
            try:
                if proc.info['status'] == psutil.STATUS_ZOMBIE:
                    zombie_pid = proc.info['pid']
                    ppid = proc.info['ppid']

                    # Try to reap the zombie with waitpid (non-blocking)
                    try:
                        os.waitpid(zombie_pid, os.WNOHANG)
                        logger.debug(f"Reaped zombie PID {zombie_pid}")
                    except ChildProcessError:
                        # Not our child - can't reap it directly
                        # This is normal - the zombie's parent must reap it
                        pass
                    except OSError:
                        pass

                    # If zombie still exists after waitpid attempt, just log it
                    # Don't kill parent as it may cause more issues
                    if psutil.pid_exists(zombie_pid):
                        try:
                            z = psutil.Process(zombie_pid)
                            if z.status() == psutil.STATUS_ZOMBIE:
                                logger.warning(
                                    f"Zombie process detected: PID {zombie_pid} "
                                    f"(parent: {ppid}, name: {proc.info['name']}). "
                                    f"Parent should reap it."
                                )
                        except psutil.NoSuchProcess:
                            pass  # Zombie was reaped

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    except ImportError:
        logger.warning("psutil not installed. Zombie cleanup disabled.")

def main():
    """Main loop - orchestrates all detection modules."""
    my_pid = os.getpid()
    logger.info(f"VPS Guardian started (PID {my_pid})")

    try:
        config = load_config()
        logger.info("Configuration loaded successfully")
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        sys.exit(1)

    # Import detection modules
    try:
        from guardian.modules import (
            Detector, ResourceMonitor, NetworkMonitor,
            IntegrityChecker, FilesystemMonitor,
            ResponseHandler, ResponseLevel,
            PersistenceScanner, AuditdMonitor,
            ContainerMonitor, TelegramBot,
            WebhookNotifier
        )
        logger.info("Detection modules loaded successfully")
    except ImportError as e:
        logger.error(f"Failed to import detection modules: {e}")
        sys.exit(1)

    # Initialize modules
    try:
        detector = Detector(config)
        resource_monitor = ResourceMonitor(config)
        network_monitor = NetworkMonitor(config)
        integrity_checker = IntegrityChecker(config)
        filesystem_monitor = FilesystemMonitor(config)
        response_handler = ResponseHandler(config)
        persistence_scanner = PersistenceScanner(config)
        auditd_monitor = AuditdMonitor(config)
        container_monitor = ContainerMonitor(config)
        telegram_bot = TelegramBot(config)
        webhook_notifier = WebhookNotifier(config)
        logger.info("All modules initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize modules: {e}", exc_info=True)
        sys.exit(1)

    # Start Telegram bot polling
    telegram_bot.start_polling()

    scan_interval = config['detection']['scan_interval_seconds']
    logger.info(f"Starting monitoring loop (scan interval: {scan_interval}s)")

    # Track last scan times for modules with different intervals
    last_persistence_scan = 0
    last_auditd_parse = 0
    last_forensics_cleanup = 0
    last_container_check = 0

    while True:
        try:
            clean_zombies()

            # PRIORITY 1: Detector - Suspicious process names/terms (HARD_KILL)
            try:
                threats = detector.scan()
                for threat in threats:
                    logger.warning(f"Threat detected: {threat.reason} - PID {threat.pid} ({threat.name})")
                    response_handler.handle_threat(
                        pid=threat.pid,
                        name=threat.name,
                        reason=threat.reason,
                        level=ResponseLevel.KILL,
                        exe_path=threat.exe,
                        extra_details={'severity': threat.severity, 'cmdline': threat.cmdline}
                    )
            except Exception as e:
                logger.error(f"Error in detector.scan(): {e}", exc_info=True)

            # PRIORITY 2: Network - Mining pool connections (HARD_KILL)
            try:
                network_threats = network_monitor.scan()
                for threat in network_threats:
                    logger.warning(f"Network threat: {threat.reason} - PID {threat.pid} ({threat.name})")
                    try:
                        import psutil
                        proc = psutil.Process(threat.pid)
                        exe_path = proc.exe()
                    except:
                        exe_path = None

                    response_handler.handle_threat(
                        pid=threat.pid,
                        name=threat.name,
                        reason=threat.reason,
                        level=ResponseLevel.KILL,
                        exe_path=exe_path,
                        extra_details={
                            'remote_ip': threat.remote_ip,
                            'remote_port': threat.remote_port
                        }
                    )
            except Exception as e:
                logger.error(f"Error in network_monitor.scan(): {e}", exc_info=True)

            # PRIORITY 3: Integrity - Binary tampering (HARD_KILL + CRITICAL ALERT)
            try:
                violations = integrity_checker.check()
                for violation in violations:
                    logger.critical(f"INTEGRITY VIOLATION: {violation.path} - Expected: {violation.expected_hash[:16]}... Got: {violation.actual_hash[:16] if violation.actual_hash != 'FILE_MISSING' else 'MISSING'}")
                    # For integrity violations, we can't kill a specific PID
                    # Just log as critical incident
                    response_handler._log_incident(response_handler.Incident(
                        timestamp=time.strftime('%Y-%m-%d %H:%M:%S'),
                        pid=0,
                        process_name='N/A',
                        threat_type='integrity_violation',
                        reason=f"Binary tampered: {violation.path}",
                        action_taken='critical_alert',
                        details={
                            'expected_hash': violation.expected_hash,
                            'actual_hash': violation.actual_hash,
                            'severity': violation.severity
                        }
                    ))

                # Rootkit detection
                rootkit_indicators = integrity_checker.check_rootkits()
                for indicator in rootkit_indicators:
                    logger.critical(f"ROOTKIT INDICATOR: {indicator.check_name} - {indicator.description}")
                    response_handler.handle_threat(
                        pid=0,
                        name=f"rootkit:{indicator.check_name}",
                        reason=indicator.description,
                        level=ResponseLevel.NOTIFY,
                        exe_path=None,
                        extra_details={
                            'check_name': indicator.check_name,
                            'severity': indicator.severity,
                            'evidence': indicator.evidence
                        }
                    )
            except Exception as e:
                logger.error(f"Error in integrity_checker.check(): {e}", exc_info=True)

            # PRIORITY 4: Filesystem - Executables in temp dirs (KILL)
            try:
                suspicious_files = filesystem_monitor.scan()
                for sus_file in suspicious_files:
                    logger.warning(f"Suspicious file: {sus_file.path} - {sus_file.reason}")
                    # Try to find which process is using this file
                    import psutil
                    file_deleted = False
                    for proc in psutil.process_iter(['pid', 'name', 'exe']):
                        try:
                            if proc.info['exe'] == sus_file.path:
                                response_handler.handle_threat(
                                    pid=proc.info['pid'],
                                    name=proc.info['name'],
                                    reason=f"Suspicious executable: {sus_file.reason}",
                                    level=ResponseLevel.KILL,
                                    exe_path=sus_file.path,
                                    extra_details={
                                        'file_age_minutes': sus_file.age_minutes,
                                        'file_size': sus_file.size_bytes
                                    }
                                )
                                file_deleted = True
                                break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue

                    # If no process found, just quarantine the file
                    if not file_deleted and os.path.exists(sus_file.path):
                        try:
                            response_handler._quarantine_file(sus_file.path)
                            logger.info(f"Quarantined orphan file: {sus_file.path}")
                        except Exception as qe:
                            logger.error(f"Failed to quarantine {sus_file.path}: {qe}")
            except Exception as e:
                logger.error(f"Error in filesystem_monitor.scan(): {e}", exc_info=True)

            # PRIORITY 5: Resources - Sustained CPU/RAM (NOTIFY or KILL)
            try:
                resource_alerts = resource_monitor.check()
                for alert in resource_alerts:
                    if alert.should_kill:
                        logger.warning(f"Resource KILL: {alert.name} (PID {alert.pid}) - {alert.duration_minutes:.1f}min sustained usage")
                        try:
                            import psutil
                            proc = psutil.Process(alert.pid)
                            exe_path = proc.exe()
                        except:
                            exe_path = None

                        response_handler.handle_threat(
                            pid=alert.pid,
                            name=alert.name,
                            reason=f"Sustained high resource usage for {alert.duration_minutes:.1f} minutes",
                            level=ResponseLevel.KILL,
                            exe_path=exe_path,
                            extra_details={
                                'cpu_percent': alert.cpu_percent,
                                'memory_percent': alert.memory_percent,
                                'duration_minutes': alert.duration_minutes
                            }
                        )
                    elif alert.should_notify:
                        logger.info(f"Resource NOTIFY: {alert.name} (PID {alert.pid}) - {alert.duration_minutes:.1f}min, kill in {alert.time_until_kill:.1f}min")
                        response_handler.handle_threat(
                            pid=alert.pid,
                            name=alert.name,
                            reason=f"High resource usage for {alert.duration_minutes:.1f} minutes",
                            level=ResponseLevel.NOTIFY,
                            exe_path=None,
                            extra_details={
                                'cpu_percent': alert.cpu_percent,
                                'memory_percent': alert.memory_percent,
                                'duration_minutes': alert.duration_minutes,
                                'time_until_kill': alert.time_until_kill
                            }
                        )
            except Exception as e:
                logger.error(f"Error in resource_monitor.check(): {e}", exc_info=True)

            # PRIORITY 6: Persistence - Malware persistence mechanisms (every 60s)
            current_time = time.time()
            persistence_interval = config.get('persistence', {}).get('scan_interval_seconds', 60)
            if persistence_scanner.enabled and (current_time - last_persistence_scan >= persistence_interval):
                try:
                    persistence_threats = persistence_scanner.scan()
                    for threat in persistence_threats:
                        logger.warning(f"Persistence mechanism detected: {threat.type.value} at {threat.path}")
                        # Send notification for high severity threats
                        if threat.severity == 'high':
                            response_handler.handle_threat(
                                pid=0,
                                name=f"persistence:{threat.type.value}",
                                reason=f"{threat.type.value} at {threat.path}: {threat.content_snippet[:100] if threat.content_snippet else 'N/A'}",
                                level=ResponseLevel.NOTIFY,
                                exe_path=None,
                                extra_details={
                                    'persistence_type': threat.type.value,
                                    'path': threat.path,
                                    'severity': threat.severity,
                                    'content_snippet': threat.content_snippet[:200] if threat.content_snippet else None
                                }
                            )
                    last_persistence_scan = current_time
                except Exception as e:
                    logger.error(f"Error in persistence_scanner.scan(): {e}", exc_info=True)

            # PRIORITY 7: Auditd - Suspicious executions in monitored paths (every 30s)
            if auditd_monitor.enabled and (current_time - last_auditd_parse >= 30):
                try:
                    events = auditd_monitor.parse_log(since_last=True)
                    suspicious = auditd_monitor.get_suspicious_events(events)
                    for event in suspicious:
                        logger.warning(f"Auditd: Suspicious exec in {event.key}: {event.exe}")
                        response_handler.handle_threat(
                            pid=event.pid,
                            name=event.exe.split('/')[-1] if event.exe else 'unknown',
                            reason=f"Execution in monitored path: {' '.join(event.cmdline) if event.cmdline else event.exe}",
                            level=ResponseLevel.KILL,
                            exe_path=event.exe,
                            extra_details={
                                'auditd_key': event.key,
                                'cmdline': event.cmdline,
                                'cwd': event.cwd,
                                'timestamp': event.timestamp
                            }
                        )
                    last_auditd_parse = current_time
                except Exception as e:
                    logger.error(f"Error in auditd_monitor.parse_log(): {e}", exc_info=True)

            # PRIORITY 8: Container resource monitoring (every 60s by default)
            container_interval = config.get('containers', {}).get('resource_monitoring', {}).get('check_interval_seconds', 60)
            if container_monitor.enabled and (current_time - last_container_check >= container_interval):
                try:
                    # Check for warnings (5+ min high CPU)
                    warnings = container_monitor.get_warnings()
                    for warn in warnings:
                        logger.warning(
                            f"Container {warn['container_name']} high CPU for {warn['duration_minutes']:.1f}min"
                        )
                        telegram_bot.send_container_warning(
                            container_name=warn['container_name'],
                            container_id=warn['container_id'],
                            cpu_percent=warn['cpu_percent'],
                            duration_minutes=warn['duration_minutes'],
                            image=warn['image'],
                            labels=warn['labels']
                        )
                        webhook_notifier.send_container_warning(
                            container_name=warn['container_name'],
                            container_id=warn['container_id'],
                            cpu_percent=warn['cpu_percent'],
                            duration_minutes=warn['duration_minutes'],
                            image=warn['image'],
                            labels=warn['labels']
                        )

                    # Check for abusive containers (15+ min high CPU)
                    abusive = container_monitor.check()
                    for abuse in abusive:
                        logger.critical(
                            f"CONTAINER CPU ABUSE: {abuse.container_name} ({abuse.container_id[:12]}) "
                            f"at {abuse.cpu_percent:.1f}% for {abuse.duration_minutes:.1f} minutes"
                        )

                        # Stop the container
                        if container_monitor.stop_container(abuse.container_id):
                            # Send notification
                            response_handler.handle_threat(
                                pid=0,
                                process_name=f"container:{abuse.container_name}",
                                threat_type="CONTAINER_CPU_ABUSE",
                                reason=f"Container {abuse.container_name} used {abuse.cpu_percent:.1f}% CPU for {abuse.duration_minutes:.1f} minutes",
                                level=ResponseLevel.NOTIFY,
                                exe_path=None,
                                extra_details={
                                    'container_id': abuse.container_id,
                                    'container_name': abuse.container_name,
                                    'image': abuse.image,
                                    'cpu_percent': abuse.cpu_percent,
                                    'duration_minutes': abuse.duration_minutes,
                                    'labels': abuse.labels
                                }
                            )
                    last_container_check = current_time
                except Exception as e:
                    logger.error(f"Container monitoring error: {e}", exc_info=True)

            # Forensics cleanup (every hour)
            if current_time - last_forensics_cleanup >= 3600:
                try:
                    deleted = response_handler.forensics.cleanup_old()
                    if deleted > 0:
                        logger.info(f"Cleaned up {deleted} old forensics files")
                    last_forensics_cleanup = current_time
                except Exception as e:
                    logger.error(f"Error in forensics cleanup: {e}", exc_info=True)

            time.sleep(scan_interval)

        except KeyboardInterrupt:
            logger.info("Guardian stopped by user")
            break
        except Exception as e:
            logger.error(f"Error in main loop: {e}", exc_info=True)
            time.sleep(scan_interval)

if __name__ == "__main__":
    main()
