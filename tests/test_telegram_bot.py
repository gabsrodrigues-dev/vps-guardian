#!/usr/bin/env python3
"""
VPS Guardian - Telegram Bot Tests
Tests interactive telegram bot with command handling and callbacks.
"""

import pytest
import json
import time
from unittest.mock import Mock, patch, MagicMock, call
from guardian.modules.telegram_bot import TelegramBot, TelegramAction


class TestTelegramBotInit:
    """Test TelegramBot initialization."""

    def test_init_disabled(self, mock_config):
        """Should initialize with disabled state."""
        mock_config['response']['telegram']['enabled'] = False
        bot = TelegramBot(mock_config)

        assert bot.enabled is False
        assert bot.interactive_enabled is True  # Default
        assert bot.base_url is None

    def test_init_enabled_with_token(self, mock_config):
        """Should initialize with bot token."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'test_token_123'
        mock_config['response']['telegram']['chat_id'] = '987654321'

        bot = TelegramBot(mock_config)

        assert bot.enabled is True
        assert bot.bot_token == 'test_token_123'
        assert bot.chat_id == '987654321'
        assert bot.base_url == 'https://api.telegram.org/bottest_token_123'

    def test_init_with_interactive_config(self, mock_config):
        """Should load interactive configuration."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['interactive'] = {
            'enabled': True,
            'action_timeout_minutes': 60,
            'poll_interval_seconds': 5
        }

        bot = TelegramBot(mock_config)

        assert bot.interactive_enabled is True
        assert bot.action_timeout_minutes == 60
        assert bot.poll_interval == 5

    def test_init_with_allowed_user_ids(self, mock_config):
        """Should load allowed user IDs for security."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['allowed_user_ids'] = [123, 456, 789]

        bot = TelegramBot(mock_config)

        assert bot.allowed_user_ids == {123, 456, 789}


class TestTelegramBotSendMessage:
    """Test message sending functionality."""

    @patch('guardian.modules.telegram_bot.requests.post')
    def test_send_message_success(self, mock_post, mock_config):
        """Should send message successfully via bot API."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['chat_id'] = '12345'

        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        bot = TelegramBot(mock_config)
        result = bot.send_message('Test message')

        assert result is True
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs['json']['text'] == 'Test message'
        assert call_kwargs['json']['chat_id'] == '12345'
        assert call_kwargs['json']['parse_mode'] == 'HTML'

    @patch('guardian.modules.telegram_bot.requests.post')
    def test_send_message_with_inline_keyboard(self, mock_post, mock_config):
        """Should send message with inline buttons."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['chat_id'] = '12345'

        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        bot = TelegramBot(mock_config)
        reply_markup = {
            'inline_keyboard': [
                [{'text': 'Action', 'callback_data': 'action:123'}]
            ]
        }

        result = bot.send_message('Alert', reply_markup=reply_markup)

        assert result is True
        call_kwargs = mock_post.call_args[1]
        assert 'reply_markup' in call_kwargs['json']
        assert 'inline_keyboard' in json.loads(call_kwargs['json']['reply_markup'])

    @patch('guardian.modules.telegram_bot.requests.post')
    def test_send_message_disabled(self, mock_post, mock_config):
        """Should not send when disabled."""
        mock_config['response']['telegram']['enabled'] = False

        bot = TelegramBot(mock_config)
        result = bot.send_message('Test')

        assert result is False
        mock_post.assert_not_called()

    @patch('guardian.modules.telegram_bot.requests.post')
    def test_send_message_api_error_fallback_webhook(self, mock_post, mock_config):
        """Should fallback to webhook on API error."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['chat_id'] = '12345'
        mock_config['response']['telegram']['webhook_url'] = 'https://webhook.example.com'

        # First call (bot API) fails, second (webhook) succeeds
        mock_post.side_effect = [
            Exception('API error'),
            Mock(status_code=200)
        ]

        bot = TelegramBot(mock_config)
        result = bot.send_message('Test')

        assert result is True
        assert mock_post.call_count == 2

    @patch('guardian.modules.telegram_bot.requests.post')
    def test_send_message_custom_chat_id(self, mock_post, mock_config):
        """Should send to custom chat_id when provided."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['chat_id'] = '12345'

        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        bot = TelegramBot(mock_config)
        result = bot.send_message('Test', chat_id=99999)

        assert result is True
        call_kwargs = mock_post.call_args[1]
        assert call_kwargs['json']['chat_id'] == 99999


class TestTelegramBotPolling:
    """Test Telegram updates polling."""

    @patch('guardian.modules.telegram_bot.requests.get')
    def test_get_updates_success(self, mock_get, mock_config):
        """Should get updates from Telegram."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        mock_response = Mock()
        mock_response.json.return_value = {
            'ok': True,
            'result': [
                {'update_id': 1, 'message': {'text': '/help'}},
                {'update_id': 2, 'message': {'text': '/status'}}
            ]
        }
        mock_get.return_value = mock_response

        bot = TelegramBot(mock_config)
        updates = bot._get_updates()

        assert len(updates) == 2
        assert bot._last_update_id == 2

    @patch('guardian.modules.telegram_bot.requests.get')
    def test_get_updates_no_results(self, mock_get, mock_config):
        """Should handle empty updates."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        mock_response = Mock()
        mock_response.json.return_value = {'ok': True, 'result': []}
        mock_get.return_value = mock_response

        bot = TelegramBot(mock_config)
        updates = bot._get_updates()

        assert updates == []

    @patch('guardian.modules.telegram_bot.requests.get')
    def test_get_updates_network_error(self, mock_get, mock_config):
        """Should handle network errors gracefully."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        mock_get.side_effect = Exception('Network error')

        bot = TelegramBot(mock_config)
        updates = bot._get_updates()

        assert updates == []


class TestTelegramBotCommands:
    """Test command handlers."""

    def test_cmd_help(self, mock_config):
        """Should return help text."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        bot = TelegramBot(mock_config)
        response = bot._cmd_help([], user_id=123)

        assert 'VPS Guardian' in response
        assert '/status' in response
        assert '/containers' in response
        assert '/processes' in response
        assert '/ports' in response
        assert '/connections' in response
        assert '/firewall' in response

    @patch('guardian.modules.telegram_bot.psutil')
    @patch('guardian.modules.telegram_bot.subprocess.run')
    def test_cmd_status(self, mock_run, mock_psutil, mock_config):
        """Should return system status."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        # Mock psutil
        mock_psutil.cpu_percent.return_value = 45.5
        mock_mem = Mock()
        mock_mem.percent = 60.2
        mock_mem.used = 8 * (1024 ** 3)
        mock_mem.total = 16 * (1024 ** 3)
        mock_psutil.virtual_memory.return_value = mock_mem

        mock_disk = Mock()
        mock_disk.percent = 75.0
        mock_disk.used = 100 * (1024 ** 3)
        mock_disk.total = 200 * (1024 ** 3)
        mock_psutil.disk_usage.return_value = mock_disk

        mock_psutil.boot_time.return_value = time.time() - 86400  # 1 day ago

        # Mock docker ps
        mock_run.return_value = Mock(returncode=0, stdout='abc123\ndef456\n')

        bot = TelegramBot(mock_config)
        response = bot._cmd_status([], user_id=123)

        assert 'Status do Sistema' in response
        assert '45.5%' in response  # CPU
        assert '60.2%' in response  # RAM
        assert '75.0%' in response  # Disk
        assert '2' in response  # Container count

    @patch('guardian.modules.telegram_bot.subprocess.run')
    def test_cmd_containers(self, mock_run, mock_config):
        """Should list containers with stats."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        # Mock docker stats output
        mock_run.return_value = Mock(
            returncode=0,
            stdout='web\t150.5%\t512MiB / 2GiB\tabc123\ndb\t5.2%\t1GiB / 2GiB\tdef456\n'
        )

        bot = TelegramBot(mock_config)
        response = bot._cmd_containers([], user_id=123)

        assert 'Containers' in response
        assert 'web' in response
        assert '150.5%' in response
        assert 'abc123' in response
        assert 'db' in response

    @patch('guardian.modules.telegram_bot.subprocess.run')
    def test_cmd_containers_no_containers(self, mock_run, mock_config):
        """Should handle no running containers."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        mock_run.return_value = Mock(returncode=0, stdout='')

        bot = TelegramBot(mock_config)
        response = bot._cmd_containers([], user_id=123)

        assert 'Nenhum container' in response

    @patch('guardian.modules.telegram_bot.psutil')
    def test_cmd_processes(self, mock_psutil, mock_config):
        """Should list top processes."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        # Mock processes
        mock_proc1 = Mock()
        mock_proc1.info = {
            'pid': 1234,
            'name': 'high_cpu_process',
            'cpu_percent': 95.5,
            'memory_percent': 20.0,
            'username': 'root'
        }

        mock_proc2 = Mock()
        mock_proc2.info = {
            'pid': 5678,
            'name': 'normal_process',
            'cpu_percent': 5.2,
            'memory_percent': 10.0,
            'username': 'www-data'
        }

        mock_psutil.process_iter.return_value = [mock_proc1, mock_proc2]

        bot = TelegramBot(mock_config)
        response = bot._cmd_processes([], user_id=123)

        assert 'Top 10 Processos' in response
        assert 'high_cpu_process' in response
        assert '95.5%' in response
        assert '1234' in response

    @patch('guardian.modules.telegram_bot.subprocess.run')
    def test_cmd_kill_container_success(self, mock_run, mock_config):
        """Should kill container successfully."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        mock_run.return_value = Mock(returncode=0)

        bot = TelegramBot(mock_config)
        response = bot._cmd_kill(['container', 'abc123'], user_id=123)

        assert 'parado com sucesso' in response
        mock_run.assert_called_once_with(
            ['docker', 'stop', 'abc123'],
            capture_output=True,
            text=True,
            timeout=30
        )

    @patch('guardian.modules.telegram_bot.os.kill')
    def test_cmd_kill_process_success(self, mock_kill, mock_config):
        """Should kill process successfully."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        bot = TelegramBot(mock_config)
        response = bot._cmd_kill(['process', '1234'], user_id=123)

        assert 'eliminado com sucesso' in response

    def test_cmd_kill_invalid_usage(self, mock_config):
        """Should show usage on invalid command."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        bot = TelegramBot(mock_config)
        response = bot._cmd_kill([], user_id=123)

        assert 'Uso:' in response
        assert '/kill container' in response


class TestTelegramBotCallbacks:
    """Test callback query handling."""

    @patch('guardian.modules.telegram_bot.requests.post')
    @patch('guardian.modules.telegram_bot.subprocess.run')
    def test_handle_callback_kill_container(self, mock_run, mock_post, mock_config):
        """Should handle kill container callback."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        mock_run.return_value = Mock(returncode=0)
        mock_post.return_value = Mock(status_code=200)

        callback = {
            'id': 'callback_123',
            'data': 'kill_container:abc123',
            'from': {'id': 999},
            'message': {'message_id': 456, 'chat': {'id': 12345}}
        }

        bot = TelegramBot(mock_config)
        bot._handle_callback(callback)

        # Should call docker stop
        mock_run.assert_called()
        # Should answer callback and edit message
        assert mock_post.call_count >= 2

    @patch('guardian.modules.telegram_bot.requests.post')
    @patch('guardian.modules.telegram_bot.os.kill')
    def test_handle_callback_kill_process(self, mock_kill, mock_post, mock_config):
        """Should handle kill process callback."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        mock_post.return_value = Mock(status_code=200)

        callback = {
            'id': 'callback_123',
            'data': 'kill_process:1234',
            'from': {'id': 999},
            'message': {'message_id': 456, 'chat': {'id': 12345}}
        }

        bot = TelegramBot(mock_config)
        bot._handle_callback(callback)

        # Should answer callback
        assert mock_post.call_count >= 1

    @patch('guardian.modules.telegram_bot.requests.post')
    def test_handle_callback_ignore(self, mock_post, mock_config):
        """Should handle ignore callback."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        mock_post.return_value = Mock(status_code=200)

        callback = {
            'id': 'callback_123',
            'data': 'ignore',
            'from': {'id': 999},
            'message': {'message_id': 456, 'chat': {'id': 12345}}
        }

        bot = TelegramBot(mock_config)
        bot._handle_callback(callback)

        # Should answer and edit
        assert mock_post.call_count >= 1

    @patch('guardian.modules.telegram_bot.requests.post')
    def test_handle_callback_unauthorized_user(self, mock_post, mock_config):
        """Should reject callback from unauthorized user."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['allowed_user_ids'] = [123, 456]

        mock_post.return_value = Mock(status_code=200)

        callback = {
            'id': 'callback_123',
            'data': 'kill_container:abc',
            'from': {'id': 999},  # Not in allowed list
            'message': {'message_id': 456, 'chat': {'id': 12345}}
        }

        bot = TelegramBot(mock_config)
        bot._handle_callback(callback)

        # Should only answer with unauthorized
        call_kwargs = mock_post.call_args[1]
        assert 'callback_query_id' in call_kwargs['json']


class TestTelegramBotNotifications:
    """Test notification methods."""

    @patch('guardian.modules.telegram_bot.requests.post')
    def test_send_container_warning(self, mock_post, mock_config):
        """Should send container warning with action buttons."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['chat_id'] = '12345'

        mock_post.return_value = Mock(status_code=200)

        bot = TelegramBot(mock_config)
        result = bot.send_container_warning(
            container_name='suspicious_app',
            container_id='abc123def456',
            cpu_percent=150.5,
            duration_minutes=7.5,
            image='user/app:latest',
            labels={'coolify.project': 'test'}
        )

        assert result is True
        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs['json']

        assert 'ALERTA: Container Alto CPU' in payload['text']
        assert 'suspicious_app' in payload['text']
        assert '150.5%' in payload['text']
        assert '7.5 minutos' in payload['text']
        assert 'reply_markup' in payload

        markup = json.loads(payload['reply_markup'])
        assert 'inline_keyboard' in markup
        assert len(markup['inline_keyboard']) > 0

    @patch('guardian.modules.telegram_bot.requests.post')
    def test_send_process_warning(self, mock_post, mock_config):
        """Should send process warning with action buttons."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['chat_id'] = '12345'

        mock_post.return_value = Mock(status_code=200)

        bot = TelegramBot(mock_config)
        result = bot.send_process_warning(
            pid=1234,
            process_name='xmrig',
            cpu_percent=95.5,
            reason='Suspicious process name',
            details={
                'exe_path': '/tmp/xmrig',
                'cmdline': ['xmrig', '-o', 'pool.example.com'],
                'username': 'www-data'
            }
        )

        assert result is True
        call_kwargs = mock_post.call_args[1]
        payload = call_kwargs['json']

        assert 'ALERTA: Processo Suspeito' in payload['text']
        assert 'xmrig' in payload['text']
        assert '1234' in payload['text']
        assert '95.5%' in payload['text']
        assert 'reply_markup' in payload


class TestTelegramBotSecurity:
    """Test security features."""

    @patch('guardian.modules.telegram_bot.requests.post')
    def test_unauthorized_command_rejected(self, mock_post, mock_config):
        """Should reject commands from unauthorized users."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['allowed_user_ids'] = [123, 456]

        mock_post.return_value = Mock(status_code=200)

        message = {
            'message': {
                'text': '/kill container abc',
                'from': {'id': 999},  # Not authorized
                'chat': {'id': 12345}
            }
        }

        bot = TelegramBot(mock_config)
        bot._process_update(message)

        # Should not send any message (command ignored)
        mock_post.assert_not_called()

    @patch('guardian.modules.telegram_bot.requests.post')
    @patch('guardian.modules.telegram_bot.psutil')
    def test_authorized_command_accepted(self, mock_psutil, mock_post, mock_config):
        """Should accept commands from authorized users."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['allowed_user_ids'] = [123, 456]

        mock_post.return_value = Mock(status_code=200)
        mock_psutil.cpu_percent.return_value = 50.0
        mock_psutil.virtual_memory.return_value = Mock(percent=60, used=8*(1024**3), total=16*(1024**3))
        mock_psutil.disk_usage.return_value = Mock(percent=70, used=100*(1024**3), total=200*(1024**3))
        mock_psutil.boot_time.return_value = time.time() - 3600

        message = {
            'message': {
                'text': '/status',
                'from': {'id': 123},  # Authorized
                'chat': {'id': 12345}
            }
        }

        bot = TelegramBot(mock_config)
        bot._process_update(message)

        # Should send status message
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args[1]
        assert 'Status do Sistema' in call_kwargs['json']['text']

    def test_empty_allowed_users_accepts_all(self, mock_config):
        """Should accept all users when allowed_user_ids is empty."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['allowed_user_ids'] = []

        bot = TelegramBot(mock_config)

        # Empty set should allow all
        assert bot.allowed_user_ids == set()


class TestTelegramBotThreading:
    """Test polling thread management."""

    @patch('guardian.modules.telegram_bot.threading.Thread')
    def test_start_polling(self, mock_thread, mock_config):
        """Should start polling thread when enabled."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'
        mock_config['response']['telegram']['interactive'] = {'enabled': True}

        bot = TelegramBot(mock_config)
        bot.start_polling()

        mock_thread.assert_called_once()
        assert mock_thread.call_args[1]['daemon'] is True

    def test_start_polling_disabled(self, mock_config):
        """Should not start polling when disabled."""
        mock_config['response']['telegram']['enabled'] = False

        bot = TelegramBot(mock_config)
        bot.start_polling()

        assert bot._polling_thread is None

    def test_stop_polling(self, mock_config):
        """Should stop polling gracefully."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        bot = TelegramBot(mock_config)
        bot._polling_thread = Mock()
        bot.stop_polling()

        assert bot._stop_polling.is_set()
        bot._polling_thread.join.assert_called_once()


class TestTelegramBotSecurityCommands:
    """Test security audit commands."""

    @patch('guardian.modules.telegram_bot.psutil.net_connections')
    @patch('guardian.modules.telegram_bot.psutil.Process')
    def test_cmd_ports(self, mock_process, mock_conn, mock_config):
        """Test /ports command."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        # Mock listening connections
        mock_conn.return_value = [
            Mock(status='LISTEN', laddr=Mock(port=22, ip='0.0.0.0'), pid=1),
            Mock(status='LISTEN', laddr=Mock(port=80, ip='0.0.0.0'), pid=2),
            Mock(status='ESTABLISHED', laddr=Mock(port=12345, ip='0.0.0.0'), pid=3),
        ]
        mock_process.return_value.name.return_value = 'sshd'

        bot = TelegramBot(mock_config)
        response = bot._cmd_ports([], 123)

        assert 'Portas Ativas' in response
        assert '22' in response
        assert '80' in response
        assert '12345' not in response  # Not LISTEN

    @patch('guardian.modules.telegram_bot.psutil.net_connections')
    @patch('guardian.modules.telegram_bot.psutil.Process')
    def test_cmd_connections(self, mock_process, mock_conn, mock_config):
        """Test /connections command."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        # Mock established connections
        mock_conn.return_value = [
            Mock(
                status='ESTABLISHED',
                laddr=Mock(port=12345, ip='192.168.1.1'),
                raddr=Mock(ip='8.8.8.8', port=443),
                pid=1
            ),
        ]
        mock_process.return_value.name.return_value = 'curl'

        bot = TelegramBot(mock_config)
        response = bot._cmd_connections([], 123)

        assert 'Conexões Ativas' in response
        assert '8.8.8.8:443' in response

    @patch('guardian.modules.telegram_bot.subprocess.run')
    def test_cmd_firewall(self, mock_run, mock_config):
        """Test /firewall command."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        mock_run.return_value = Mock(
            returncode=0,
            stdout="Chain INPUT\nnum target prot opt source destination\n1 DROP all -- 1.2.3.4 0.0.0.0/0"
        )

        bot = TelegramBot(mock_config)
        response = bot._cmd_firewall([], 123)

        assert 'Firewall' in response
        assert 'BLOQUEIO' in response

    @patch('guardian.modules.telegram_bot.psutil.net_connections')
    @patch('guardian.modules.telegram_bot.psutil.Process')
    def test_cmd_connections_highlights_mining_ports(self, mock_process, mock_conn, mock_config):
        """Test that mining pool ports are highlighted."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        mock_conn.return_value = [
            Mock(
                status='ESTABLISHED',
                laddr=Mock(port=12345, ip='192.168.1.1'),
                raddr=Mock(ip='pool.mining.com', port=3333),  # Mining port!
                pid=1
            ),
        ]
        mock_process.return_value.name.return_value = 'xmrig'

        bot = TelegramBot(mock_config)
        response = bot._cmd_connections([], 123)

        assert '🔴' in response  # Red emoji for mining ports

    @patch('guardian.modules.telegram_bot.psutil.net_connections')
    def test_cmd_ports_handles_process_errors(self, mock_conn, mock_config):
        """Test /ports command handles process access errors gracefully."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        # Connection with missing/inaccessible process
        mock_conn.return_value = [
            Mock(status='LISTEN', laddr=Mock(port=22, ip='0.0.0.0'), pid=None),
        ]

        bot = TelegramBot(mock_config)
        response = bot._cmd_ports([], 123)

        assert 'Portas Ativas' in response
        assert '22' in response
        assert '?' in response  # Unknown process name

    @patch('guardian.modules.telegram_bot.subprocess.run')
    def test_cmd_firewall_no_permission(self, mock_run, mock_config):
        """Test /firewall command when not running as root."""
        mock_config['response']['telegram']['enabled'] = True
        mock_config['response']['telegram']['bot_token'] = 'token'

        mock_run.return_value = Mock(returncode=1, stdout='')

        bot = TelegramBot(mock_config)
        response = bot._cmd_firewall([], 123)

        assert 'Sem permissão' in response
