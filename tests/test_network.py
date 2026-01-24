#!/usr/bin/env python3
"""
VPS Guardian - Network Monitor Tests
Tests network connection detection with mocks.
"""

import pytest
import psutil
from unittest.mock import Mock, patch, MagicMock
from collections import namedtuple
from guardian.modules.network import NetworkMonitor, NetworkThreat


# Mock network connection structure
MockConnection = namedtuple('Connection', ['pid', 'status', 'laddr', 'raddr'])
MockAddr = namedtuple('Addr', ['ip', 'port'])


class TestNetworkMonitor:
    """Test suite for the NetworkMonitor module."""

    @pytest.fixture
    def network_config(self, tmp_path):
        """Network-specific configuration with temp files."""
        mining_pools = tmp_path / 'mining-pools.txt'
        mining_pools.write_text('pool.minexmr.com\nxmr.pool.minergate.com\n')

        tor_nodes = tmp_path / 'tor-nodes.txt'
        tor_nodes.write_text('185.220.101.1\n104.244.76.13\n')

        return {
            'network': {
                'mining_pools_list': str(mining_pools),
                'tor_nodes_list': str(tor_nodes),
                'suspicious_ports': [3333, 4444, 5555, 14444]
            }
        }

    def test_detect_mining_port_connection(self, network_config):
        """Should detect connection to known mining port (3333)."""
        monitor = NetworkMonitor(network_config)

        with patch('psutil.net_connections') as mock_net_conn:
            with patch('psutil.Process') as mock_proc_class:
                mock_proc = Mock()
                mock_proc.name.return_value = 'xmrig'
                mock_proc_class.return_value = mock_proc

                mock_net_conn.return_value = [
                    MockConnection(
                        pid=1234,
                        status='ESTABLISHED',
                        laddr=MockAddr('192.168.1.100', 50000),
                        raddr=MockAddr('45.76.230.12', 3333)  # Mining port
                    )
                ]

                threats = monitor.scan()

                assert len(threats) == 1
                assert threats[0].pid == 1234
                assert threats[0].remote_port == 3333
                assert 'mining port' in threats[0].reason.lower()

    def test_detect_tor_node_connection(self, network_config):
        """Should detect connection to TOR exit node IP."""
        monitor = NetworkMonitor(network_config)

        with patch('psutil.net_connections') as mock_net_conn:
            with patch('psutil.Process') as mock_proc_class:
                mock_proc = Mock()
                mock_proc.name.return_value = 'suspicious_app'
                mock_proc_class.return_value = mock_proc

                mock_net_conn.return_value = [
                    MockConnection(
                        pid=5678,
                        status='ESTABLISHED',
                        laddr=MockAddr('192.168.1.100', 50001),
                        raddr=MockAddr('185.220.101.1', 9001)  # TOR exit node
                    )
                ]

                threats = monitor.scan()

                assert len(threats) == 1
                assert threats[0].remote_ip == '185.220.101.1'
                assert 'tor' in threats[0].reason.lower()

    def test_not_detect_normal_connection(self, network_config):
        """Should NOT detect normal HTTPS connection."""
        monitor = NetworkMonitor(network_config)

        with patch('psutil.net_connections') as mock_net_conn:
            with patch('psutil.Process') as mock_proc_class:
                mock_proc = Mock()
                mock_proc.name.return_value = 'firefox'
                mock_proc_class.return_value = mock_proc

                mock_net_conn.return_value = [
                    MockConnection(
                        pid=9999,
                        status='ESTABLISHED',
                        laddr=MockAddr('192.168.1.100', 50002),
                        raddr=MockAddr('142.250.185.46', 443)  # Google HTTPS
                    )
                ]

                threats = monitor.scan()

                assert len(threats) == 0

    def test_skip_non_established_connections(self, network_config):
        """Should skip connections that are not ESTABLISHED."""
        monitor = NetworkMonitor(network_config)

        with patch('psutil.net_connections') as mock_net_conn:
            mock_net_conn.return_value = [
                MockConnection(
                    pid=1111,
                    status='LISTEN',  # Not established
                    laddr=MockAddr('0.0.0.0', 80),
                    raddr=None
                ),
                MockConnection(
                    pid=2222,
                    status='TIME_WAIT',
                    laddr=MockAddr('192.168.1.100', 50003),
                    raddr=MockAddr('1.2.3.4', 3333)
                )
            ]

            threats = monitor.scan()

            assert len(threats) == 0

    def test_skip_self_connections(self, network_config):
        """Should skip connections from Guardian's own PID."""
        monitor = NetworkMonitor(network_config)

        with patch('os.getpid', return_value=7777):
            with patch('psutil.net_connections') as mock_net_conn:
                mock_net_conn.return_value = [
                    MockConnection(
                        pid=7777,  # Guardian's own PID
                        status='ESTABLISHED',
                        laddr=MockAddr('192.168.1.100', 50004),
                        raddr=MockAddr('1.2.3.4', 3333)
                    )
                ]

                threats = monitor.scan()

                assert len(threats) == 0

    @patch('socket.gethostbyaddr')
    def test_detect_mining_pool_domain(self, mock_gethostbyaddr, network_config):
        """Should detect connection to mining pool domain via reverse DNS."""
        monitor = NetworkMonitor(network_config)

        # Mock reverse DNS to return mining pool domain
        mock_gethostbyaddr.return_value = ('pool.minexmr.com', [], ['1.2.3.4'])

        with patch('psutil.net_connections') as mock_net_conn:
            with patch('psutil.Process') as mock_proc_class:
                mock_proc = Mock()
                mock_proc.name.return_value = 'miner'
                mock_proc_class.return_value = mock_proc

                mock_net_conn.return_value = [
                    MockConnection(
                        pid=3333,
                        status='ESTABLISHED',
                        laddr=MockAddr('192.168.1.100', 50005),
                        raddr=MockAddr('1.2.3.4', 8080)
                    )
                ]

                threats = monitor.scan()

                assert len(threats) == 1
                assert 'blocked domain' in threats[0].reason.lower()

    def test_handle_process_access_denied(self, network_config):
        """Should handle access denied when getting process info."""
        monitor = NetworkMonitor(network_config)

        with patch('psutil.net_connections') as mock_net_conn:
            with patch('psutil.Process') as mock_proc_class:
                mock_proc_class.side_effect = psutil.AccessDenied()

                mock_net_conn.return_value = [
                    MockConnection(
                        pid=4444,
                        status='ESTABLISHED',
                        laddr=MockAddr('192.168.1.100', 50006),
                        raddr=MockAddr('1.2.3.4', 3333)
                    )
                ]

                threats = monitor.scan()

                # Should still detect the threat even without process name
                assert len(threats) == 1

    def test_reload_blocklists(self, network_config, tmp_path):
        """Should reload blocklists from disk."""
        monitor = NetworkMonitor(network_config)

        initial_pools = len(monitor.blocked_domains)

        # Add more pools to the file
        mining_pools_file = tmp_path / 'mining-pools.txt'
        with open(mining_pools_file, 'a') as f:
            f.write('new.mining.pool.com\n')

        monitor.reload_blocklists()

        assert len(monitor.blocked_domains) > initial_pools
        assert 'new.mining.pool.com' in monitor.blocked_domains

    def test_skip_connections_without_remote_addr(self, network_config):
        """Should skip connections without remote address."""
        monitor = NetworkMonitor(network_config)

        with patch('psutil.net_connections') as mock_net_conn:
            mock_net_conn.return_value = [
                MockConnection(
                    pid=5555,
                    status='ESTABLISHED',
                    laddr=MockAddr('192.168.1.100', 50007),
                    raddr=None  # No remote address
                )
            ]

            threats = monitor.scan()

            assert len(threats) == 0

    def test_multiple_threats_in_single_scan(self, network_config):
        """Should detect multiple threats in a single scan."""
        monitor = NetworkMonitor(network_config)

        with patch('psutil.net_connections') as mock_net_conn:
            with patch('psutil.Process') as mock_proc_class:
                mock_proc = Mock()
                mock_proc.name.return_value = 'miner'
                mock_proc_class.return_value = mock_proc

                mock_net_conn.return_value = [
                    MockConnection(
                        pid=1111,
                        status='ESTABLISHED',
                        laddr=MockAddr('192.168.1.100', 50008),
                        raddr=MockAddr('1.2.3.4', 3333)  # Mining port
                    ),
                    MockConnection(
                        pid=2222,
                        status='ESTABLISHED',
                        laddr=MockAddr('192.168.1.100', 50009),
                        raddr=MockAddr('185.220.101.1', 9001)  # TOR node
                    )
                ]

                threats = monitor.scan()

                assert len(threats) == 2
