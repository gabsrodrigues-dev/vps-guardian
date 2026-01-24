"""Interactive Telegram bot for VPS Guardian.

Provides remote monitoring and control via Telegram commands and inline buttons.
"""

import json
import logging
import threading
import subprocess
import os
import signal
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
from pathlib import Path
import requests
import time
import psutil


@dataclass
class TelegramAction:
    """Pending action awaiting user confirmation."""
    action_id: str
    action_type: str
    target: str
    details: Dict[str, Any]
    created_at: float
    expires_at: float


class TelegramBot:
    """Interactive Telegram bot with command support.

    Features:
    - Send alerts with inline action buttons
    - Process commands: /status, /containers, /processes, /help
    - Execute remote actions: kill containers, stop processes
    """

    def __init__(self, config: dict):
        telegram_config = config.get('response', {}).get('telegram', {})

        self.enabled = telegram_config.get('enabled', False)
        self.bot_token = telegram_config.get('bot_token')
        self.chat_id = telegram_config.get('chat_id')
        self.webhook_url = telegram_config.get('webhook_url')

        # Interactive features
        interactive_config = telegram_config.get('interactive', {})
        self.interactive_enabled = interactive_config.get('enabled', True)
        self.action_timeout_minutes = interactive_config.get('action_timeout_minutes', 30)
        self.poll_interval = interactive_config.get('poll_interval_seconds', 2)

        # Allowed users (security)
        self.allowed_user_ids = set(telegram_config.get('allowed_user_ids', []))

        self.logger = logging.getLogger('guardian.telegram')
        self.base_url = f"https://api.telegram.org/bot{self.bot_token}" if self.bot_token else None

        # Pending actions store
        self._pending_actions: Dict[str, TelegramAction] = {}
        self._last_update_id = 0

        # Command handlers
        self._commands: Dict[str, Callable] = {
            'status': self._cmd_status,
            'containers': self._cmd_containers,
            'processes': self._cmd_processes,
            'help': self._cmd_help,
            'kill': self._cmd_kill,
            'ports': self._cmd_ports,
            'connections': self._cmd_connections,
            'firewall': self._cmd_firewall,
        }

        # Polling thread
        self._polling_thread: Optional[threading.Thread] = None
        self._stop_polling = threading.Event()

    def start_polling(self):
        """Start background thread to poll for Telegram updates."""
        if not self.enabled or not self.bot_token or not self.interactive_enabled:
            return

        self._stop_polling.clear()
        self._polling_thread = threading.Thread(target=self._poll_updates, daemon=True)
        self._polling_thread.start()
        self.logger.info("Telegram bot polling started")

    def stop_polling(self):
        """Stop the polling thread."""
        self._stop_polling.set()
        if self._polling_thread:
            self._polling_thread.join(timeout=5)

    def _poll_updates(self):
        """Poll Telegram for updates (commands and button clicks)."""
        while not self._stop_polling.is_set():
            try:
                updates = self._get_updates()
                for update in updates:
                    self._process_update(update)
            except Exception as e:
                self.logger.error(f"Polling error: {e}")

            self._stop_polling.wait(self.poll_interval)

    def _get_updates(self) -> List[dict]:
        """Get pending updates from Telegram."""
        if not self.base_url:
            return []

        try:
            response = requests.get(
                f"{self.base_url}/getUpdates",
                params={'offset': self._last_update_id + 1, 'timeout': 30},
                timeout=35
            )
            data = response.json()

            if data.get('ok') and data.get('result'):
                updates = data['result']
                if updates:
                    self._last_update_id = updates[-1]['update_id']
                return updates
        except Exception as e:
            self.logger.debug(f"Get updates error: {e}")

        return []

    def _process_update(self, update: dict):
        """Process a single Telegram update."""
        # Check for callback query (button click)
        if 'callback_query' in update:
            self._handle_callback(update['callback_query'])
            return

        # Check for message (command)
        message = update.get('message', {})
        text = message.get('text', '')
        user_id = message.get('from', {}).get('id')
        chat_id = message.get('chat', {}).get('id')

        # Security check
        if self.allowed_user_ids and user_id not in self.allowed_user_ids:
            self.logger.warning(f"Unauthorized user {user_id} attempted command: {text}")
            return

        # Process commands
        if text.startswith('/'):
            self._handle_command(text, chat_id, user_id)

    def _handle_command(self, text: str, chat_id: int, user_id: int):
        """Handle a /command."""
        parts = text.split()
        command = parts[0][1:].lower()  # Remove leading /
        args = parts[1:] if len(parts) > 1 else []

        # Remove @botname suffix if present
        if '@' in command:
            command = command.split('@')[0]

        handler = self._commands.get(command)
        if handler:
            try:
                response = handler(args, user_id)
                self.send_message(response, chat_id=chat_id)
            except Exception as e:
                self.logger.error(f"Command {command} error: {e}")
                self.send_message(f"❌ Erro: {e}", chat_id=chat_id)
        else:
            self.send_message(
                f"❓ Comando desconhecido: /{command}\nUse /help para ver comandos.",
                chat_id=chat_id
            )

    def _handle_callback(self, callback: dict):
        """Handle inline button callback."""
        callback_id = callback.get('id')
        data = callback.get('data', '')
        user_id = callback.get('from', {}).get('id')
        message_id = callback.get('message', {}).get('message_id')
        chat_id = callback.get('message', {}).get('chat', {}).get('id')

        # Security check
        if self.allowed_user_ids and user_id not in self.allowed_user_ids:
            self._answer_callback(callback_id, "⛔ Não autorizado")
            return

        # Parse action
        if data.startswith('kill_container:'):
            container_id = data.split(':', 1)[1]
            success = self._execute_kill_container(container_id)
            if success:
                self._answer_callback(callback_id, "✅ Container parado!")
                self._edit_message(chat_id, message_id, "✅ Container parado com sucesso.")
            else:
                self._answer_callback(callback_id, "❌ Falha ao parar container")

        elif data.startswith('kill_process:'):
            pid = data.split(':', 1)[1]
            success = self._execute_kill_process(pid)
            if success:
                self._answer_callback(callback_id, "✅ Processo eliminado!")
                self._edit_message(chat_id, message_id, "✅ Processo eliminado com sucesso.")
            else:
                self._answer_callback(callback_id, "❌ Falha ao eliminar processo")

        elif data == 'ignore':
            self._answer_callback(callback_id, "👌 Ignorado")
            self._edit_message(chat_id, message_id, "ℹ️ Alerta ignorado pelo usuário.")

        else:
            self._answer_callback(callback_id, "❓ Ação desconhecida")

    def _answer_callback(self, callback_id: str, text: str):
        """Answer a callback query."""
        if not self.base_url:
            return
        try:
            requests.post(
                f"{self.base_url}/answerCallbackQuery",
                json={'callback_query_id': callback_id, 'text': text}
            )
        except Exception as e:
            self.logger.debug(f"Answer callback error: {e}")

    def _edit_message(self, chat_id: int, message_id: int, text: str):
        """Edit a message to update status."""
        if not self.base_url:
            return
        try:
            requests.post(
                f"{self.base_url}/editMessageText",
                json={
                    'chat_id': chat_id,
                    'message_id': message_id,
                    'text': text,
                    'parse_mode': 'HTML'
                }
            )
        except Exception as e:
            self.logger.debug(f"Edit message error: {e}")

    def _execute_kill_container(self, container_id: str) -> bool:
        """Kill a container by ID."""
        try:
            result = subprocess.run(
                ['docker', 'stop', container_id],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                self.logger.warning(f"Container {container_id} stopped via Telegram")
                return True
        except Exception as e:
            self.logger.error(f"Kill container error: {e}")
        return False

    def _execute_kill_process(self, pid: str) -> bool:
        """Kill a process by PID."""
        try:
            os.kill(int(pid), signal.SIGKILL)
            self.logger.warning(f"Process {pid} killed via Telegram")
            return True
        except Exception as e:
            self.logger.error(f"Kill process error: {e}")
        return False

    # === Command Handlers ===

    def _cmd_help(self, args: List[str], user_id: int) -> str:
        """Show available commands."""
        return """🛡️ <b>VPS Guardian - Comandos</b>

<b>📊 Monitoramento:</b>
/status - Status geral do sistema
/containers - Lista containers com CPU/RAM
/processes - Top 10 processos por CPU

<b>🌐 Rede & Segurança:</b>
/ports - Portas abertas (LISTEN)
/connections - Conexões ativas
/firewall - Regras de firewall e bloqueios

<b>⚡ Ações:</b>
/kill container &lt;id&gt; - Para um container
/kill process &lt;pid&gt; - Mata um processo

<b>Exemplos:</b>
<code>/ports</code>
<code>/firewall</code>
<code>/kill container abc123</code>
"""

    def _cmd_status(self, args: List[str], user_id: int) -> str:
        """Get system status."""
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage('/')

        # Count containers
        try:
            result = subprocess.run(
                ['docker', 'ps', '-q'],
                capture_output=True, text=True, timeout=10
            )
            container_count = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
        except:
            container_count = "?"

        uptime = datetime.now() - datetime.fromtimestamp(psutil.boot_time())
        uptime_str = f"{uptime.days}d {uptime.seconds//3600}h"

        return f"""📊 <b>Status do Sistema</b>

<b>CPU:</b> {cpu:.1f}%
<b>RAM:</b> {mem.percent:.1f}% ({mem.used // (1024**3):.1f}GB / {mem.total // (1024**3):.1f}GB)
<b>Disco:</b> {disk.percent:.1f}% ({disk.used // (1024**3):.0f}GB / {disk.total // (1024**3):.0f}GB)
<b>Uptime:</b> {uptime_str}
<b>Containers:</b> {container_count} rodando

🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""

    def _cmd_containers(self, args: List[str], user_id: int) -> str:
        """List containers with resource usage."""
        try:
            result = subprocess.run(
                ['docker', 'stats', '--no-stream', '--format',
                 '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.ID}}'],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                return "❌ Erro ao obter stats dos containers"

            lines = result.stdout.strip().split('\n')
            if not lines or not lines[0]:
                return "📦 Nenhum container rodando"

            # Sort by CPU usage (descending)
            containers = []
            for line in lines:
                parts = line.split('\t')
                if len(parts) >= 4:
                    name, cpu, mem, cid = parts[0], parts[1], parts[2], parts[3]
                    cpu_val = float(cpu.rstrip('%')) if cpu.rstrip('%') else 0
                    containers.append((name, cpu, mem, cid, cpu_val))

            containers.sort(key=lambda x: x[4], reverse=True)

            msg = "📦 <b>Containers (por CPU)</b>\n\n"
            for name, cpu, mem, cid, _ in containers[:15]:
                # Emoji based on CPU
                cpu_num = float(cpu.rstrip('%') or 0)
                if cpu_num > 100:
                    emoji = "🔴"
                elif cpu_num > 50:
                    emoji = "🟡"
                else:
                    emoji = "🟢"

                msg += f"{emoji} <b>{name[:20]}</b>\n"
                msg += f"   CPU: {cpu} | RAM: {mem}\n"
                msg += f"   ID: <code>{cid}</code>\n\n"

            return msg

        except Exception as e:
            return f"❌ Erro: {e}"

    def _cmd_processes(self, args: List[str], user_id: int) -> str:
        """List top processes by CPU."""
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'username']):
            try:
                pinfo = proc.info
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # Sort by CPU
        processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)

        msg = "⚡ <b>Top 10 Processos (CPU)</b>\n\n"
        for p in processes[:10]:
            cpu = p['cpu_percent'] or 0
            mem = p['memory_percent'] or 0

            if cpu > 80:
                emoji = "🔴"
            elif cpu > 50:
                emoji = "🟡"
            else:
                emoji = "🟢"

            msg += f"{emoji} <b>{p['name'][:20]}</b> (PID: {p['pid']})\n"
            msg += f"   CPU: {cpu:.1f}% | RAM: {mem:.1f}% | User: {p['username']}\n\n"

        return msg

    def _cmd_kill(self, args: List[str], user_id: int) -> str:
        """Kill container or process."""
        if len(args) < 2:
            return "❌ Uso: /kill container <id> ou /kill process <pid>"

        target_type = args[0].lower()
        target_id = args[1]

        if target_type == 'container':
            if self._execute_kill_container(target_id):
                return f"✅ Container {target_id} parado com sucesso"
            else:
                return f"❌ Falha ao parar container {target_id}"

        elif target_type == 'process':
            if self._execute_kill_process(target_id):
                return f"✅ Processo {target_id} eliminado com sucesso"
            else:
                return f"❌ Falha ao eliminar processo {target_id}"

        return "❌ Tipo inválido. Use: container ou process"

    def _cmd_ports(self, args: List[str], user_id: int) -> str:
        """List active listening ports."""
        connections = psutil.net_connections(kind='inet')
        listening = [c for c in connections if c.status == 'LISTEN']

        # Group by port
        ports = {}
        for conn in listening:
            port = conn.laddr.port
            if port not in ports:
                # Try to get process name
                try:
                    proc = psutil.Process(conn.pid) if conn.pid else None
                    name = proc.name() if proc else "?"
                except:
                    name = "?"
                ports[port] = {'name': name, 'pid': conn.pid, 'addr': conn.laddr.ip}

        # Sort by port number
        sorted_ports = sorted(ports.items())

        msg = "🔌 <b>Portas Ativas (LISTEN)</b>\n\n"

        for port, info in sorted_ports[:30]:  # Limit to 30
            # Highlight common dangerous ports
            if port in [22, 80, 443, 3306, 5432, 6379]:
                emoji = "🟢"  # Known services
            elif port > 10000:
                emoji = "🟡"  # High ports (potentially suspicious)
            else:
                emoji = "⚪"

            addr = info['addr'] if info['addr'] != '0.0.0.0' else '*'
            msg += f"{emoji} <b>{port}</b> ({addr})\n"
            msg += f"   Processo: {info['name']} (PID: {info['pid']})\n"

        if len(sorted_ports) > 30:
            msg += f"\n... e mais {len(sorted_ports) - 30} portas"

        msg += f"\n\n📊 Total: {len(sorted_ports)} portas abertas"
        return msg

    def _cmd_connections(self, args: List[str], user_id: int) -> str:
        """List active network connections (ESTABLISHED)."""
        connections = psutil.net_connections(kind='inet')
        established = [c for c in connections if c.status == 'ESTABLISHED']

        # Group by remote address
        remotes = {}
        for conn in established:
            if conn.raddr:
                remote = f"{conn.raddr.ip}:{conn.raddr.port}"
                if remote not in remotes:
                    try:
                        proc = psutil.Process(conn.pid) if conn.pid else None
                        name = proc.name() if proc else "?"
                    except:
                        name = "?"
                    remotes[remote] = {'name': name, 'pid': conn.pid, 'local_port': conn.laddr.port}

        msg = "🌐 <b>Conexões Ativas (ESTABLISHED)</b>\n\n"

        # Sort by process name
        sorted_conns = sorted(remotes.items(), key=lambda x: x[1]['name'])

        for remote, info in sorted_conns[:25]:
            # Check for suspicious ports
            remote_port = int(remote.split(':')[1]) if ':' in remote else 0
            if remote_port in [3333, 4444, 5555, 7777, 8888, 9999, 14433, 14444, 45700]:
                emoji = "🔴"  # Mining pool ports!
            else:
                emoji = "🔵"

            msg += f"{emoji} {remote}\n"
            msg += f"   ← {info['name']} (PID: {info['pid']})\n"

        if len(sorted_conns) > 25:
            msg += f"\n... e mais {len(sorted_conns) - 25} conexões"

        msg += f"\n\n📊 Total: {len(established)} conexões ativas"
        return msg

    def _cmd_firewall(self, args: List[str], user_id: int) -> str:
        """List firewall rules and blocks."""
        msg = "🛡️ <b>Firewall (iptables)</b>\n\n"

        # Get iptables rules
        try:
            # INPUT chain - what's blocked
            result = subprocess.run(
                ['iptables', '-L', 'INPUT', '-n', '-v', '--line-numbers'],
                capture_output=True, text=True, timeout=10
            )

            if result.returncode != 0:
                # Try with sudo hint
                return "❌ Sem permissão. Execute Guardian como root."

            lines = result.stdout.strip().split('\n')

            # Parse rules
            drop_rules = []
            accept_rules = []

            for line in lines[2:]:  # Skip headers
                if not line.strip():
                    continue
                parts = line.split()
                if len(parts) >= 4:
                    num = parts[0]
                    target = parts[2]
                    source = parts[7] if len(parts) > 7 else "any"
                    dest = parts[8] if len(parts) > 8 else "any"

                    if target == 'DROP' or target == 'REJECT':
                        drop_rules.append(f"#{num}: {source} → {dest}")
                    elif target == 'ACCEPT':
                        accept_rules.append(f"#{num}: {source} → {dest}")

            msg += "<b>🚫 Regras de BLOQUEIO:</b>\n"
            if drop_rules:
                for rule in drop_rules[:10]:
                    msg += f"  {rule}\n"
                if len(drop_rules) > 10:
                    msg += f"  ... +{len(drop_rules) - 10} regras\n"
            else:
                msg += "  (nenhuma)\n"

            msg += f"\n<b>✅ Regras de ACCEPT:</b> {len(accept_rules)}\n"

        except subprocess.TimeoutExpired:
            msg += "❌ Timeout ao consultar iptables\n"
        except FileNotFoundError:
            msg += "❌ iptables não encontrado\n"
        except Exception as e:
            msg += f"❌ Erro: {e}\n"

        # Check fail2ban status
        msg += "\n<b>🔒 Fail2ban:</b>\n"
        try:
            result = subprocess.run(
                ['fail2ban-client', 'status'],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                # Count jails and banned IPs
                jails = []
                for line in result.stdout.split('\n'):
                    if 'Jail list:' in line:
                        jails = line.split(':')[1].strip().split(', ')

                msg += f"  Jails ativos: {len(jails)}\n"

                # Get banned count from sshd jail
                if 'sshd' in jails:
                    result2 = subprocess.run(
                        ['fail2ban-client', 'status', 'sshd'],
                        capture_output=True, text=True, timeout=10
                    )
                    for line in result2.stdout.split('\n'):
                        if 'Currently banned' in line:
                            banned = line.split(':')[1].strip()
                            msg += f"  IPs banidos (sshd): {banned}\n"
            else:
                msg += "  (não instalado ou inativo)\n"
        except:
            msg += "  (não disponível)\n"

        # Guardian blocklists
        msg += "\n<b>📋 Guardian Blocklists:</b>\n"
        blocklist_dir = Path('/opt/vps-guardian/firewall/blocklists')
        if blocklist_dir.exists():
            for f in blocklist_dir.glob('*.txt'):
                try:
                    count = sum(1 for line in open(f) if line.strip() and not line.startswith('#'))
                    msg += f"  {f.name}: {count} entradas\n"
                except:
                    pass
        else:
            msg += "  (diretório não encontrado)\n"

        return msg

    # === Notification Methods ===

    def send_message(self, text: str, chat_id: int = None, reply_markup: dict = None) -> bool:
        """Send a message to Telegram."""
        target_chat = chat_id or self.chat_id

        if not self.enabled or not target_chat:
            return False

        # Try bot API first
        if self.base_url:
            try:
                payload = {
                    'chat_id': target_chat,
                    'text': text,
                    'parse_mode': 'HTML'
                }
                if reply_markup:
                    payload['reply_markup'] = json.dumps(reply_markup)

                response = requests.post(
                    f"{self.base_url}/sendMessage",
                    json=payload,
                    timeout=10
                )
                return response.status_code == 200
            except Exception as e:
                self.logger.error(f"Telegram send error: {e}")

        # Fallback to webhook
        if self.webhook_url:
            try:
                requests.post(self.webhook_url, json={'text': text}, timeout=10)
                return True
            except Exception as e:
                self.logger.error(f"Webhook send error: {e}")

        return False

    def send_container_warning(self, container_name: str, container_id: str,
                               cpu_percent: float, duration_minutes: float,
                               image: str, labels: Dict[str, str]) -> bool:
        """Send container CPU warning with action buttons."""

        # Build detailed message
        text = f"""⚠️ <b>ALERTA: Container Alto CPU</b>

<b>Container:</b> {container_name}
<b>ID:</b> <code>{container_id[:12]}</code>
<b>Imagem:</b> {image}
<b>CPU:</b> {cpu_percent:.1f}%
<b>Duração:</b> {duration_minutes:.1f} minutos

"""
        # Add relevant labels
        relevant_labels = {k: v for k, v in labels.items()
                         if any(x in k.lower() for x in ['coolify', 'traefik', 'app', 'service'])}
        if relevant_labels:
            text += "<b>Labels:</b>\n"
            for k, v in list(relevant_labels.items())[:5]:
                text += f"  • {k}: {v[:30]}\n"

        text += f"\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        # Inline keyboard with action buttons
        reply_markup = {
            'inline_keyboard': [
                [
                    {'text': '🛑 Parar Container', 'callback_data': f'kill_container:{container_id}'},
                    {'text': '👌 Ignorar', 'callback_data': 'ignore'}
                ]
            ]
        }

        return self.send_message(text, reply_markup=reply_markup)

    def send_process_warning(self, pid: int, process_name: str,
                            cpu_percent: float, reason: str,
                            details: Dict[str, Any] = None) -> bool:
        """Send process threat warning with action buttons."""

        text = f"""🚨 <b>ALERTA: Processo Suspeito</b>

<b>Processo:</b> {process_name}
<b>PID:</b> {pid}
<b>CPU:</b> {cpu_percent:.1f}%
<b>Motivo:</b> {reason}

"""
        if details:
            if details.get('exe_path'):
                text += f"<b>Executável:</b> {details['exe_path']}\n"
            if details.get('cmdline'):
                cmdline = ' '.join(details['cmdline'])[:100]
                text += f"<b>Comando:</b> <code>{cmdline}</code>\n"
            if details.get('username'):
                text += f"<b>Usuário:</b> {details['username']}\n"
            if details.get('container_info'):
                cinfo = details['container_info']
                text += f"<b>Container:</b> {cinfo.get('container_id', 'N/A')[:12]}\n"

        text += f"\n🕐 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

        reply_markup = {
            'inline_keyboard': [
                [
                    {'text': '💀 Matar Processo', 'callback_data': f'kill_process:{pid}'},
                    {'text': '👌 Ignorar', 'callback_data': 'ignore'}
                ]
            ]
        }

        return self.send_message(text, reply_markup=reply_markup)
