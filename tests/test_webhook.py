#!/usr/bin/env python3
"""
VPS Guardian - Webhook Notifier Tests
Tests webhook notification with HTTP POST, auth headers, retries, and payloads.
"""

import pytest
import json
from unittest.mock import Mock, patch, call
from guardian.modules.webhook import WebhookNotifier


class TestWebhookNotifierInit:
    """Test WebhookNotifier initialization."""

    def test_init_disabled(self, mock_config):
        """Should initialize with disabled state."""
        mock_config['response']['webhook']['enabled'] = False
        notifier = WebhookNotifier(mock_config)

        assert notifier.enabled is False

    def test_init_enabled_with_token(self, mock_config):
        """Should initialize with configured auth token."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'my-secret-token'

        notifier = WebhookNotifier(mock_config)

        assert notifier.enabled is True
        assert notifier.webhook_url == 'https://example.com/hook'
        assert notifier.auth_token == 'my-secret-token'
        assert notifier.timeout == 10
        assert notifier.retry_count == 2

    def test_init_auto_generates_token_when_missing(self, mock_config):
        """Should auto-generate auth token when not configured."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = None

        notifier = WebhookNotifier(mock_config)

        assert notifier.enabled is True
        assert notifier.auth_token is not None
        assert len(notifier.auth_token) == 64  # secrets.token_hex(32)

    def test_init_disables_when_no_url(self, mock_config):
        """Should disable when enabled but no URL configured."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = None

        notifier = WebhookNotifier(mock_config)

        assert notifier.enabled is False

    def test_init_custom_timeout_and_retry(self, mock_config):
        """Should load custom timeout and retry settings."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['timeout_seconds'] = 30
        mock_config['response']['webhook']['retry_count'] = 5

        notifier = WebhookNotifier(mock_config)

        assert notifier.timeout == 30
        assert notifier.retry_count == 5

    def test_init_missing_webhook_section(self):
        """Should handle missing webhook config section gracefully."""
        config = {'response': {'quarantine_dir': '/tmp', 'log_file': '/tmp/log', 'telegram': {'enabled': False}}}
        notifier = WebhookNotifier(config)

        assert notifier.enabled is False

    def test_init_hostname_set(self, mock_config):
        """Should set hostname from system."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'

        notifier = WebhookNotifier(mock_config)

        assert notifier.hostname is not None
        assert isinstance(notifier.hostname, str)


class TestWebhookNotifierPost:
    """Test HTTP POST functionality."""

    @patch('guardian.modules.webhook.requests.post')
    def test_post_success(self, mock_post, mock_config):
        """Should send POST request successfully."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        notifier = WebhookNotifier(mock_config)
        result = notifier._post({"event": "test"})

        assert result is True
        mock_post.assert_called_once()

        call_kwargs = mock_post.call_args
        assert call_kwargs[1]['json'] == {"event": "test"}
        assert call_kwargs[1]['headers']['Authorization'] == 'Bearer test-token'
        assert call_kwargs[1]['headers']['Content-Type'] == 'application/json'
        assert call_kwargs[1]['headers']['User-Agent'] == 'VPS-Guardian/1.1.0'
        assert call_kwargs[1]['timeout'] == 10

    @patch('guardian.modules.webhook.requests.post')
    def test_post_disabled(self, mock_post, mock_config):
        """Should not send when disabled."""
        mock_config['response']['webhook']['enabled'] = False

        notifier = WebhookNotifier(mock_config)
        result = notifier._post({"event": "test"})

        assert result is False
        mock_post.assert_not_called()

    @patch('guardian.modules.webhook.requests.post')
    def test_post_retries_on_server_error(self, mock_post, mock_config):
        """Should retry on HTTP 5xx errors."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'
        mock_config['response']['webhook']['retry_count'] = 3

        mock_response_500 = Mock(status_code=500)
        mock_response_200 = Mock(status_code=200)
        mock_post.side_effect = [mock_response_500, mock_response_200]

        notifier = WebhookNotifier(mock_config)
        result = notifier._post({"event": "test"})

        assert result is True
        assert mock_post.call_count == 2

    @patch('guardian.modules.webhook.requests.post')
    def test_post_fails_after_all_retries(self, mock_post, mock_config):
        """Should return False after exhausting retries."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'
        mock_config['response']['webhook']['retry_count'] = 2

        mock_response = Mock(status_code=500)
        mock_post.return_value = mock_response

        notifier = WebhookNotifier(mock_config)
        result = notifier._post({"event": "test"})

        assert result is False
        assert mock_post.call_count == 2

    @patch('guardian.modules.webhook.requests.post')
    def test_post_handles_timeout(self, mock_post, mock_config):
        """Should handle request timeouts with retry."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'
        mock_config['response']['webhook']['retry_count'] = 2

        import requests as req
        mock_post.side_effect = [
            req.exceptions.Timeout("timeout"),
            Mock(status_code=200)
        ]

        notifier = WebhookNotifier(mock_config)
        result = notifier._post({"event": "test"})

        assert result is True
        assert mock_post.call_count == 2

    @patch('guardian.modules.webhook.requests.post')
    def test_post_handles_connection_error(self, mock_post, mock_config):
        """Should handle connection errors with retry."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'
        mock_config['response']['webhook']['retry_count'] = 2

        import requests as req
        mock_post.side_effect = req.exceptions.ConnectionError("refused")

        notifier = WebhookNotifier(mock_config)
        result = notifier._post({"event": "test"})

        assert result is False
        assert mock_post.call_count == 2

    @patch('guardian.modules.webhook.requests.post')
    def test_post_handles_unexpected_exception(self, mock_post, mock_config):
        """Should handle unexpected exceptions without retry."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_post.side_effect = RuntimeError("unexpected")

        notifier = WebhookNotifier(mock_config)
        result = notifier._post({"event": "test"})

        assert result is False
        assert mock_post.call_count == 1

    @patch('guardian.modules.webhook.requests.post')
    def test_post_accepts_2xx_status_codes(self, mock_post, mock_config):
        """Should accept any 2xx status code as success."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        for status in [200, 201, 202, 204]:
            mock_post.return_value = Mock(status_code=status)
            notifier = WebhookNotifier(mock_config)
            assert notifier._post({"event": "test"}) is True


class TestWebhookNotifierSendIncident:
    """Test incident notification sending."""

    @patch('guardian.modules.webhook.requests.post')
    def test_send_incident_kill(self, mock_post, mock_config):
        """Should send kill incident with critical severity."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_post.return_value = Mock(status_code=200)

        notifier = WebhookNotifier(mock_config)
        result = notifier.send_incident(
            pid=1234,
            name='xmrig',
            reason='Suspicious process: mining detected',
            is_kill=True,
            details={'cpu_percent': 95.5, 'memory_percent': 12.3},
            forensics_path='/var/lib/guardian/forensics/evidence_001'
        )

        assert result is True
        payload = mock_post.call_args[1]['json']
        assert payload['event'] == 'threat_detected'
        assert payload['severity'] == 'critical'
        assert payload['process']['pid'] == 1234
        assert payload['process']['name'] == 'xmrig'
        assert payload['reason'] == 'Suspicious process: mining detected'
        assert payload['action_taken'] == 'killed'
        assert payload['details']['cpu_percent'] == 95.5
        assert payload['forensics_path'] == '/var/lib/guardian/forensics/evidence_001'

    @patch('guardian.modules.webhook.requests.post')
    def test_send_incident_notify(self, mock_post, mock_config):
        """Should send notify incident with warning severity."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_post.return_value = Mock(status_code=200)

        notifier = WebhookNotifier(mock_config)
        result = notifier.send_incident(
            pid=5678,
            name='suspicious_app',
            reason='High CPU for 12 minutes',
            is_kill=False,
            details={'cpu_percent': 80.0, 'duration_minutes': 12.5}
        )

        assert result is True
        payload = mock_post.call_args[1]['json']
        assert payload['severity'] == 'warning'
        assert payload['action_taken'] == 'monitoring'
        assert payload['forensics_path'] is None

    @patch('guardian.modules.webhook.requests.post')
    def test_send_incident_with_forensics_summary(self, mock_post, mock_config):
        """Should include forensics summary in details."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_post.return_value = Mock(status_code=200)

        notifier = WebhookNotifier(mock_config)
        result = notifier.send_incident(
            pid=1234,
            name='malware',
            reason='Detected malware',
            is_kill=True,
            details={'cpu_percent': 99.0},
            forensics_summary='Cmdline: ./malware -c config.json'
        )

        assert result is True
        payload = mock_post.call_args[1]['json']
        assert payload['details']['forensics_summary'] == 'Cmdline: ./malware -c config.json'

    @patch('guardian.modules.webhook.requests.post')
    def test_send_incident_disabled(self, mock_post, mock_config):
        """Should not send when disabled."""
        mock_config['response']['webhook']['enabled'] = False

        notifier = WebhookNotifier(mock_config)
        result = notifier.send_incident(
            pid=1234, name='test', reason='test', is_kill=False
        )

        assert result is False
        mock_post.assert_not_called()


class TestWebhookNotifierSendContainerWarning:
    """Test container warning sending."""

    @patch('guardian.modules.webhook.requests.post')
    def test_send_container_warning(self, mock_post, mock_config):
        """Should send container warning with full details."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_post.return_value = Mock(status_code=200)

        notifier = WebhookNotifier(mock_config)
        result = notifier.send_container_warning(
            container_name='suspicious_app',
            container_id='abc123def456',
            cpu_percent=150.5,
            duration_minutes=7.5,
            image='user/app:latest',
            labels={'coolify.project': 'test'}
        )

        assert result is True
        payload = mock_post.call_args[1]['json']
        assert payload['event'] == 'container_warning'
        assert payload['severity'] == 'warning'
        assert payload['process']['name'] == 'container:suspicious_app'
        assert payload['details']['container_id'] == 'abc123def456'
        assert payload['details']['cpu_percent'] == 150.5
        assert payload['details']['duration_minutes'] == 7.5
        assert payload['details']['image'] == 'user/app:latest'
        assert payload['details']['labels'] == {'coolify.project': 'test'}
        assert '150.5%' in payload['reason']
        assert '7.5 min' in payload['reason']

    @patch('guardian.modules.webhook.requests.post')
    def test_send_container_warning_disabled(self, mock_post, mock_config):
        """Should not send when disabled."""
        mock_config['response']['webhook']['enabled'] = False

        notifier = WebhookNotifier(mock_config)
        result = notifier.send_container_warning(
            container_name='app', container_id='abc',
            cpu_percent=100.0, duration_minutes=5.0,
            image='img:latest', labels={}
        )

        assert result is False
        mock_post.assert_not_called()


class TestWebhookNotifierSendProcessWarning:
    """Test process warning sending."""

    @patch('guardian.modules.webhook.requests.post')
    def test_send_process_warning(self, mock_post, mock_config):
        """Should send process warning with details."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_post.return_value = Mock(status_code=200)

        notifier = WebhookNotifier(mock_config)
        result = notifier.send_process_warning(
            pid=1234,
            process_name='xmrig',
            cpu_percent=95.5,
            reason='Suspicious process name',
            details={'exe_path': '/tmp/xmrig', 'username': 'www-data'}
        )

        assert result is True
        payload = mock_post.call_args[1]['json']
        assert payload['event'] == 'process_warning'
        assert payload['severity'] == 'critical'
        assert payload['process']['pid'] == 1234
        assert payload['process']['name'] == 'xmrig'
        assert payload['details']['cpu_percent'] == 95.5
        assert payload['details']['exe_path'] == '/tmp/xmrig'
        assert payload['details']['username'] == 'www-data'

    @patch('guardian.modules.webhook.requests.post')
    def test_send_process_warning_no_extra_details(self, mock_post, mock_config):
        """Should handle process warning without extra details."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_post.return_value = Mock(status_code=200)

        notifier = WebhookNotifier(mock_config)
        result = notifier.send_process_warning(
            pid=5678,
            process_name='unknown_proc',
            cpu_percent=80.0,
            reason='High CPU usage'
        )

        assert result is True
        payload = mock_post.call_args[1]['json']
        assert payload['details']['cpu_percent'] == 80.0


class TestWebhookNotifierSendTest:
    """Test connectivity test sending."""

    @patch('guardian.modules.webhook.requests.post')
    def test_send_test_success(self, mock_post, mock_config):
        """Should send test notification successfully."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_post.return_value = Mock(status_code=200)

        notifier = WebhookNotifier(mock_config)
        result = notifier.send_test()

        assert result is True
        payload = mock_post.call_args[1]['json']
        assert payload['event'] == 'test'
        assert payload['severity'] == 'info'
        assert payload['action_taken'] == 'none'

    @patch('guardian.modules.webhook.requests.post')
    def test_send_test_failure(self, mock_post, mock_config):
        """Should return False on test failure."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'
        mock_config['response']['webhook']['retry_count'] = 1

        mock_post.return_value = Mock(status_code=500)

        notifier = WebhookNotifier(mock_config)
        result = notifier.send_test()

        assert result is False


class TestWebhookNotifierIntegrationInfo:
    """Test integration info method."""

    def test_get_integration_info(self, mock_config):
        """Should return complete integration info."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'my-token-123'

        notifier = WebhookNotifier(mock_config)
        info = notifier.get_integration_info()

        assert info['webhook_url'] == 'https://example.com/hook'
        assert info['method'] == 'POST'
        assert info['content_type'] == 'application/json'
        assert info['authorization_header'] == 'Bearer my-token-123'
        assert info['authorization_token'] == 'my-token-123'
        assert 'body_schema' in info
        assert 'example_body' in info
        assert info['example_body']['event'] == 'threat_detected'
        assert info['example_body']['severity'] == 'critical'

    def test_get_integration_info_has_all_event_types_in_schema(self, mock_config):
        """Should document all event types in schema."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'token'

        notifier = WebhookNotifier(mock_config)
        info = notifier.get_integration_info()
        schema_event = info['body_schema']['event']

        assert 'threat_detected' in schema_event
        assert 'container_warning' in schema_event
        assert 'process_warning' in schema_event
        assert 'test' in schema_event


class TestWebhookNotifierPayloadStructure:
    """Test payload structure and content."""

    @patch('guardian.modules.webhook.requests.post')
    def test_payload_has_all_required_fields(self, mock_post, mock_config):
        """Should include all required fields in payload."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_post.return_value = Mock(status_code=200)

        notifier = WebhookNotifier(mock_config)
        notifier.send_incident(
            pid=1, name='test', reason='test', is_kill=False
        )

        payload = mock_post.call_args[1]['json']
        required_fields = ['event', 'timestamp', 'hostname', 'severity',
                          'process', 'reason', 'action_taken', 'details',
                          'forensics_path']

        for field in required_fields:
            assert field in payload, f"Missing field: {field}"

        assert 'pid' in payload['process']
        assert 'name' in payload['process']

    @patch('guardian.modules.webhook.requests.post')
    def test_payload_timestamp_is_iso_format(self, mock_post, mock_config):
        """Should use ISO 8601 timestamp format."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_post.return_value = Mock(status_code=200)

        notifier = WebhookNotifier(mock_config)
        notifier.send_test()

        payload = mock_post.call_args[1]['json']
        from datetime import datetime
        datetime.fromisoformat(payload['timestamp'])

    @patch('guardian.modules.webhook.requests.post')
    def test_payload_hostname_matches_system(self, mock_post, mock_config):
        """Should include system hostname."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_post.return_value = Mock(status_code=200)

        import socket
        expected_hostname = socket.gethostname()

        notifier = WebhookNotifier(mock_config)
        notifier.send_test()

        payload = mock_post.call_args[1]['json']
        assert payload['hostname'] == expected_hostname

    @patch('guardian.modules.webhook.requests.post')
    def test_payload_details_not_mutated(self, mock_post, mock_config):
        """Should not mutate the original details dict."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'test-token'

        mock_post.return_value = Mock(status_code=200)

        notifier = WebhookNotifier(mock_config)
        original_details = {'cpu_percent': 50.0}
        notifier.send_incident(
            pid=1, name='test', reason='test', is_kill=True,
            details=original_details, forensics_summary='summary'
        )

        assert 'forensics_summary' not in original_details


class TestWebhookNotifierAuthHeaders:
    """Test Authorization header behavior."""

    @patch('guardian.modules.webhook.requests.post')
    def test_bearer_token_in_header(self, mock_post, mock_config):
        """Should send Bearer token in Authorization header."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = 'secret-token-xyz'

        mock_post.return_value = Mock(status_code=200)

        notifier = WebhookNotifier(mock_config)
        notifier.send_test()

        headers = mock_post.call_args[1]['headers']
        assert headers['Authorization'] == 'Bearer secret-token-xyz'

    @patch('guardian.modules.webhook.requests.post')
    def test_auto_generated_token_in_header(self, mock_post, mock_config):
        """Should use auto-generated token in Authorization header."""
        mock_config['response']['webhook']['enabled'] = True
        mock_config['response']['webhook']['url'] = 'https://example.com/hook'
        mock_config['response']['webhook']['auth_token'] = None

        mock_post.return_value = Mock(status_code=200)

        notifier = WebhookNotifier(mock_config)
        notifier.send_test()

        headers = mock_post.call_args[1]['headers']
        assert headers['Authorization'].startswith('Bearer ')
        token = headers['Authorization'].replace('Bearer ', '')
        assert len(token) == 64
