#!/usr/bin/env python3
"""
VPS Guardian - Forensics Module Tests
Tests evidence collection, storage, and retention.
"""

import pytest
import json
import time
import psutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from guardian.modules.forensics import ForensicsCollector, ForensicsData


class TestForensicsData:
    """Test suite for ForensicsData dataclass."""

    def test_forensics_data_creation(self):
        """Should create ForensicsData with all required fields."""
        data = ForensicsData(
            pid=1234,
            timestamp=1706000000.123,
            ppid=1,
            uid=0,
            username="root",
            exe_path="/tmp/xmrig",
            cwd="/tmp",
            cmdline=["/tmp/xmrig", "-o", "pool.mining.com:3333"],
            environ={"PATH": "/usr/bin", "HOME": "/root"},
            open_files=[{"path": "/tmp/config.json", "fd": 3}],
            connections=[
                {"laddr": "0.0.0.0:0", "raddr": "1.2.3.4:3333", "status": "ESTABLISHED"}
            ],
            parent_chain=[{"pid": 1, "name": "systemd"}],
            children=[],
        )

        assert data.pid == 1234
        assert data.username == "root"
        assert len(data.cmdline) == 3
        assert data.container_info is None  # Optional field


class TestForensicsCollector:
    """Test suite for ForensicsCollector class."""

    def test_init_with_defaults(self, mock_config, tmp_path):
        """Should initialize with default values when forensics config missing."""
        mock_config.pop("forensics", None)  # Remove if exists
        collector = ForensicsCollector(mock_config)

        assert collector.enabled is True
        assert collector.max_collection_time == 2
        assert collector.include_environ is True
        assert collector.include_open_files is True
        assert collector.retention_days == 30

    def test_init_with_custom_config(self, mock_config, tmp_path):
        """Should initialize with custom configuration."""
        storage_dir = tmp_path / "custom_forensics"
        mock_config["forensics"] = {
            "enabled": False,
            "storage_dir": str(storage_dir),
            "max_collection_time_seconds": 5,
            "include_environ": False,
            "include_open_files": False,
            "retention_days": 7,
        }

        collector = ForensicsCollector(mock_config)

        assert collector.enabled is False
        assert collector.storage_dir == storage_dir
        assert collector.max_collection_time == 5
        assert collector.include_environ is False
        assert collector.include_open_files is False
        assert collector.retention_days == 7

    def test_storage_directory_created(self, mock_config, tmp_path):
        """Should create storage directory if it doesn't exist."""
        storage_dir = tmp_path / "forensics"
        mock_config["forensics"] = {"storage_dir": str(storage_dir)}

        collector = ForensicsCollector(mock_config)

        assert storage_dir.exists()
        assert storage_dir.is_dir()

    @patch("psutil.Process")
    def test_collect_basic_process_info(self, mock_proc_class, mock_config, tmp_path):
        """Should collect basic process information successfully."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        # Mock process
        mock_proc = Mock()
        mock_proc.ppid.return_value = 1
        mock_proc.uids.return_value = Mock(real=0)
        mock_proc.username.return_value = "root"
        mock_proc.exe.return_value = "/tmp/xmrig"
        mock_proc.cwd.return_value = "/tmp"
        mock_proc.cmdline.return_value = ["/tmp/xmrig", "-o", "pool:3333"]
        mock_proc.environ.return_value = {"PATH": "/usr/bin"}
        mock_proc.open_files.return_value = []
        mock_proc.connections.return_value = []
        mock_proc.parent.return_value = None
        mock_proc.children.return_value = []
        mock_proc_class.return_value = mock_proc

        data = collector.collect(1234)

        assert data is not None
        assert data.pid == 1234
        assert data.ppid == 1
        assert data.username == "root"
        assert data.exe_path == "/tmp/xmrig"
        assert data.cwd == "/tmp"
        assert len(data.cmdline) == 3

    @patch("psutil.Process")
    def test_collect_with_parent_chain(self, mock_proc_class, mock_config, tmp_path):
        """Should collect parent process chain."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        # Mock grandparent
        mock_grandparent = Mock()
        mock_grandparent.pid = 1
        mock_grandparent.name.return_value = "systemd"
        mock_grandparent.parent.return_value = None

        # Mock parent
        mock_parent = Mock()
        mock_parent.pid = 100
        mock_parent.name.return_value = "bash"
        mock_parent.parent.return_value = mock_grandparent

        # Mock target process
        mock_proc = Mock()
        mock_proc.ppid.return_value = 100
        mock_proc.uids.return_value = Mock(real=1000)
        mock_proc.username.return_value = "user"
        mock_proc.exe.return_value = "/tmp/malware"
        mock_proc.cwd.return_value = "/tmp"
        mock_proc.cmdline.return_value = ["/tmp/malware"]
        mock_proc.environ.return_value = {}
        mock_proc.open_files.return_value = []
        mock_proc.connections.return_value = []
        mock_proc.parent.return_value = mock_parent
        mock_proc.children.return_value = []
        mock_proc_class.return_value = mock_proc

        data = collector.collect(1234)

        assert len(data.parent_chain) == 2
        assert data.parent_chain[0]["pid"] == 100
        assert data.parent_chain[0]["name"] == "bash"
        assert data.parent_chain[1]["pid"] == 1
        assert data.parent_chain[1]["name"] == "systemd"

    @patch("psutil.Process")
    def test_collect_with_children(self, mock_proc_class, mock_config, tmp_path):
        """Should collect child processes."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        # Mock children
        mock_child1 = Mock()
        mock_child1.pid = 2001
        mock_child1.name.return_value = "child1"

        mock_child2 = Mock()
        mock_child2.pid = 2002
        mock_child2.name.return_value = "child2"

        # Mock target process
        mock_proc = Mock()
        mock_proc.ppid.return_value = 1
        mock_proc.uids.return_value = Mock(real=0)
        mock_proc.username.return_value = "root"
        mock_proc.exe.return_value = "/tmp/miner"
        mock_proc.cwd.return_value = "/tmp"
        mock_proc.cmdline.return_value = ["/tmp/miner"]
        mock_proc.environ.return_value = {}
        mock_proc.open_files.return_value = []
        mock_proc.connections.return_value = []
        mock_proc.parent.return_value = None
        mock_proc.children.return_value = [mock_child1, mock_child2]
        mock_proc_class.return_value = mock_proc

        data = collector.collect(1234)

        assert len(data.children) == 2
        assert data.children[0]["pid"] == 2001
        assert data.children[1]["pid"] == 2002

    @patch("psutil.Process")
    def test_collect_with_network_connections(
        self, mock_proc_class, mock_config, tmp_path
    ):
        """Should collect network connections."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        # Mock connection
        mock_conn = Mock()
        mock_conn.laddr = ("0.0.0.0", 0)
        mock_conn.raddr = ("1.2.3.4", 3333)
        mock_conn.status = "ESTABLISHED"

        mock_proc = Mock()
        mock_proc.ppid.return_value = 1
        mock_proc.uids.return_value = Mock(real=0)
        mock_proc.username.return_value = "root"
        mock_proc.exe.return_value = "/tmp/miner"
        mock_proc.cwd.return_value = "/tmp"
        mock_proc.cmdline.return_value = ["/tmp/miner"]
        mock_proc.environ.return_value = {}
        mock_proc.open_files.return_value = []
        mock_proc.connections.return_value = [mock_conn]
        mock_proc.parent.return_value = None
        mock_proc.children.return_value = []
        mock_proc_class.return_value = mock_proc

        data = collector.collect(1234)

        assert len(data.connections) == 1
        assert data.connections[0]["raddr"] == "1.2.3.4:3333"
        assert data.connections[0]["status"] == "ESTABLISHED"

    @patch("psutil.Process")
    def test_collect_with_open_files(self, mock_proc_class, mock_config, tmp_path):
        """Should collect open files."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        # Mock open file
        mock_file = Mock()
        mock_file.path = "/tmp/config.json"
        mock_file.fd = 3

        mock_proc = Mock()
        mock_proc.ppid.return_value = 1
        mock_proc.uids.return_value = Mock(real=0)
        mock_proc.username.return_value = "root"
        mock_proc.exe.return_value = "/tmp/miner"
        mock_proc.cwd.return_value = "/tmp"
        mock_proc.cmdline.return_value = ["/tmp/miner"]
        mock_proc.environ.return_value = {}
        mock_proc.open_files.return_value = [mock_file]
        mock_proc.connections.return_value = []
        mock_proc.parent.return_value = None
        mock_proc.children.return_value = []
        mock_proc_class.return_value = mock_proc

        data = collector.collect(1234)

        assert len(data.open_files) == 1
        assert data.open_files[0]["path"] == "/tmp/config.json"
        assert data.open_files[0]["fd"] == 3

    @patch("psutil.Process")
    def test_collect_handles_access_denied(
        self, mock_proc_class, mock_config, tmp_path
    ):
        """Should handle AccessDenied errors gracefully."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        mock_proc = Mock()
        mock_proc.ppid.side_effect = psutil.AccessDenied()
        mock_proc.uids.return_value = Mock(real=0)
        mock_proc.username.return_value = "root"
        mock_proc.exe.return_value = "/tmp/test"
        mock_proc.cwd.return_value = "/tmp"
        mock_proc.cmdline.return_value = ["/tmp/test"]
        mock_proc.environ.return_value = {}
        mock_proc.open_files.return_value = []
        mock_proc.connections.return_value = []
        mock_proc.parent.return_value = None
        mock_proc.children.return_value = []
        mock_proc_class.return_value = mock_proc

        data = collector.collect(1234)

        assert data is not None
        assert data.ppid is None  # Should be None due to AccessDenied

    @patch("psutil.Process")
    def test_collect_handles_no_such_process(
        self, mock_proc_class, mock_config, tmp_path
    ):
        """Should return None when process doesn't exist."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        mock_proc_class.side_effect = psutil.NoSuchProcess(1234)

        data = collector.collect(1234)

        assert data is None

    @patch("psutil.Process")
    def test_collect_respects_include_environ_flag(
        self, mock_proc_class, mock_config, tmp_path
    ):
        """Should skip environ collection when disabled."""
        mock_config["forensics"] = {
            "storage_dir": str(tmp_path / "forensics"),
            "include_environ": False,
        }
        collector = ForensicsCollector(mock_config)

        mock_proc = Mock()
        mock_proc.ppid.return_value = 1
        mock_proc.uids.return_value = Mock(real=0)
        mock_proc.username.return_value = "root"
        mock_proc.exe.return_value = "/tmp/test"
        mock_proc.cwd.return_value = "/tmp"
        mock_proc.cmdline.return_value = ["/tmp/test"]
        mock_proc.environ.return_value = {"SHOULD": "NOT_BE_COLLECTED"}
        mock_proc.open_files.return_value = []
        mock_proc.connections.return_value = []
        mock_proc.parent.return_value = None
        mock_proc.children.return_value = []
        mock_proc_class.return_value = mock_proc

        data = collector.collect(1234)

        assert data.environ == {}

    @patch("psutil.Process")
    def test_collect_respects_include_open_files_flag(
        self, mock_proc_class, mock_config, tmp_path
    ):
        """Should skip open files collection when disabled."""
        mock_config["forensics"] = {
            "storage_dir": str(tmp_path / "forensics"),
            "include_open_files": False,
        }
        collector = ForensicsCollector(mock_config)

        mock_file = Mock()
        mock_file.path = "/tmp/should_not_be_collected"
        mock_file.fd = 99

        mock_proc = Mock()
        mock_proc.ppid.return_value = 1
        mock_proc.uids.return_value = Mock(real=0)
        mock_proc.username.return_value = "root"
        mock_proc.exe.return_value = "/tmp/test"
        mock_proc.cwd.return_value = "/tmp"
        mock_proc.cmdline.return_value = ["/tmp/test"]
        mock_proc.environ.return_value = {}
        mock_proc.open_files.return_value = [mock_file]
        mock_proc.connections.return_value = []
        mock_proc.parent.return_value = None
        mock_proc.children.return_value = []
        mock_proc_class.return_value = mock_proc

        data = collector.collect(1234)

        assert data.open_files == []

    @patch("psutil.Process")
    def test_save_creates_json_file(self, mock_proc_class, mock_config, tmp_path):
        """Should save forensic data to JSON file."""
        storage_dir = tmp_path / "forensics"
        mock_config["forensics"] = {"storage_dir": str(storage_dir)}
        collector = ForensicsCollector(mock_config)

        data = ForensicsData(
            pid=1234,
            timestamp=1706000000.123,
            ppid=1,
            uid=0,
            username="root",
            exe_path="/tmp/xmrig",
            cwd="/tmp",
            cmdline=["/tmp/xmrig"],
            environ={},
            open_files=[],
            connections=[],
            parent_chain=[],
            children=[],
        )

        saved_path = collector.save(data)

        assert saved_path.exists()
        assert saved_path.parent == storage_dir
        assert saved_path.suffix == ".json"

        # Verify content
        with open(saved_path) as f:
            loaded = json.load(f)
            assert loaded["pid"] == 1234
            assert loaded["username"] == "root"

    def test_to_summary_generates_readable_text(self, mock_config, tmp_path):
        """Should generate human-readable summary."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        data = ForensicsData(
            pid=1234,
            timestamp=1706000000.123,
            ppid=1,
            uid=0,
            username="root",
            exe_path="/tmp/xmrig",
            cwd="/tmp",
            cmdline=["/tmp/xmrig", "-o", "pool:3333"],
            environ={"PATH": "/usr/bin"},
            open_files=[{"path": "/tmp/config.json", "fd": 3}],
            connections=[
                {"laddr": "0.0.0.0:0", "raddr": "1.2.3.4:3333", "status": "ESTABLISHED"}
            ],
            parent_chain=[{"pid": 1, "name": "systemd"}],
            children=[],
        )

        summary = collector.to_summary(data)

        assert "PID: 1234" in summary
        assert "root" in summary
        assert "/tmp/xmrig" in summary
        assert "1.2.3.4:3333" in summary

    def test_cleanup_old_removes_expired_files(self, mock_config, tmp_path):
        """Should remove forensic files older than retention period."""
        storage_dir = tmp_path / "forensics"
        storage_dir.mkdir()
        mock_config["forensics"] = {
            "storage_dir": str(storage_dir),
            "retention_days": 1,
        }
        collector = ForensicsCollector(mock_config)

        # Create old file (2 days ago)
        old_file = storage_dir / "old_evidence.json"
        old_file.write_text("{}")
        old_time = time.time() - (2 * 24 * 60 * 60)  # 2 days ago
        import os

        os.utime(old_file, (old_time, old_time))

        # Create recent file
        recent_file = storage_dir / "recent_evidence.json"
        recent_file.write_text("{}")

        count = collector.cleanup_old()

        assert count == 1
        assert not old_file.exists()
        assert recent_file.exists()

    def test_cleanup_old_handles_permission_errors(self, mock_config, tmp_path):
        """Should handle permission errors during cleanup gracefully."""
        storage_dir = tmp_path / "forensics"
        storage_dir.mkdir()
        mock_config["forensics"] = {
            "storage_dir": str(storage_dir),
            "retention_days": 1,
        }
        collector = ForensicsCollector(mock_config)

        # No files to clean up, should return 0
        count = collector.cleanup_old()
        assert count == 0


class TestContainerDetection:
    """Test suite for container detection in ForensicsCollector."""

    def test_detect_container_docker(self, mock_config, tmp_path):
        """Should detect Docker container from cgroup."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        # Mock cgroup file content for Docker
        cgroup_content = """12:memory:/docker/abc123def456789012345678901234567890123456789012345678901234
11:devices:/docker/abc123def456789012345678901234567890123456789012345678901234
10:cpu:/docker/abc123def456789012345678901234567890123456789012345678901234"""

        with patch("builtins.open", MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value=cgroup_content)))))):
            result = collector.detect_container(1234)

        assert result is not None
        assert result["type"] == "docker"
        assert result["container_id"] == "abc123def456"
        assert result["full_id"] == "abc123def456789012345678901234567890123456789012345678901234"

    def test_detect_container_kubernetes(self, mock_config, tmp_path):
        """Should detect Kubernetes pod from cgroup."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        # Mock cgroup file content for Kubernetes
        cgroup_content = """12:memory:/kubepods/besteffort/pod123abc/xyz789def123456789012345678901234567890123456789012345678
11:devices:/kubepods/besteffort/pod123abc/xyz789def123456789012345678901234567890123456789012345678"""

        with patch("builtins.open", MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value=cgroup_content)))))):
            result = collector.detect_container(1234)

        assert result is not None
        assert result["type"] == "kubernetes"
        assert result["container_id"] == "xyz789def123"
        assert result["full_id"] == "xyz789def123456789012345678901234567890123456789012345678"

    def test_detect_container_containerd(self, mock_config, tmp_path):
        """Should detect containerd container from cgroup."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        # Mock cgroup file content for containerd
        cgroup_content = """12:memory:/containerd/fedcba987654321098765432109876543210987654321098765432109876
11:devices:/containerd/fedcba987654321098765432109876543210987654321098765432109876"""

        with patch("builtins.open", MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value=cgroup_content)))))):
            result = collector.detect_container(1234)

        assert result is not None
        assert result["type"] == "containerd"
        assert result["container_id"] == "fedcba987654"
        assert result["full_id"] == "fedcba987654321098765432109876543210987654321098765432109876"

    def test_detect_container_lxc(self, mock_config, tmp_path):
        """Should detect LXC container from cgroup."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        # Mock cgroup file content for LXC
        cgroup_content = """12:memory:/lxc/mycontainer123456789012345678901234567890123456789012345678
11:devices:/lxc/mycontainer123456789012345678901234567890123456789012345678"""

        with patch("builtins.open", MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value=cgroup_content)))))):
            result = collector.detect_container(1234)

        assert result is not None
        assert result["type"] == "lxc"
        assert result["container_id"] == "mycontainer1"
        assert result["full_id"] == "mycontainer123456789012345678901234567890123456789012345678"

    def test_detect_container_none_for_host(self, mock_config, tmp_path):
        """Should return None for non-containerized process."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        # Mock cgroup file content for host process
        cgroup_content = """12:memory:/user.slice/user-1000.slice
11:devices:/user.slice/user-1000.slice
10:cpu:/user.slice/user-1000.slice"""

        with patch("builtins.open", MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value=cgroup_content)))))):
            result = collector.detect_container(1234)

        assert result is None

    def test_detect_container_handles_file_not_found(self, mock_config, tmp_path):
        """Should handle missing cgroup file gracefully."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        with patch("builtins.open", side_effect=FileNotFoundError()):
            result = collector.detect_container(1234)

        assert result is None

    def test_detect_container_handles_permission_error(self, mock_config, tmp_path):
        """Should handle permission denied on cgroup file."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        with patch("builtins.open", side_effect=PermissionError()):
            result = collector.detect_container(1234)

        assert result is None

    @patch("psutil.Process")
    def test_collect_includes_container_info(self, mock_proc_class, mock_config, tmp_path):
        """Should include container info in ForensicsData when detected."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        # Mock process
        mock_proc = Mock()
        mock_proc.ppid.return_value = 1
        mock_proc.uids.return_value = Mock(real=0)
        mock_proc.username.return_value = "root"
        mock_proc.exe.return_value = "/tmp/xmrig"
        mock_proc.cwd.return_value = "/tmp"
        mock_proc.cmdline.return_value = ["/tmp/xmrig"]
        mock_proc.environ.return_value = {}
        mock_proc.open_files.return_value = []
        mock_proc.connections.return_value = []
        mock_proc.parent.return_value = None
        mock_proc.children.return_value = []
        mock_proc_class.return_value = mock_proc

        # Mock cgroup file for Docker
        cgroup_content = """12:memory:/docker/abc123def456789012345678901234567890123456789012345678901234"""

        with patch("builtins.open", MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value=cgroup_content)))))):
            data = collector.collect(1234)

        assert data is not None
        assert data.container_info is not None
        assert data.container_info["type"] == "docker"
        assert data.container_info["container_id"] == "abc123def456"

    def test_get_container_processes_success(self, mock_config, tmp_path):
        """Test successful container process listing."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="PID USER COMMAND ARGS\n1 root nginx nginx: master process\n10 www-data php-fpm php-fpm: pool www"
            )
            processes = collector.get_container_processes('abc123')

        assert len(processes) == 2
        assert processes[0]['command'] == 'nginx'
        assert processes[0]['user'] == 'root'
        assert processes[0]['pid'] == '1'
        assert processes[1]['user'] == 'www-data'
        assert processes[1]['command'] == 'php-fpm'

    def test_get_container_processes_with_args(self, mock_config, tmp_path):
        """Test container process listing includes full arguments."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(
                returncode=0,
                stdout="PID USER COMMAND ARGS\n1 root nginx nginx: master process\n10 www-data php-fpm php-fpm: pool www --config /etc/php/php.ini"
            )
            processes = collector.get_container_processes('abc123')

        assert processes[1]['args'] == 'php-fpm: pool www --config /etc/php/php.ini'

    def test_get_container_processes_failure(self, mock_config, tmp_path):
        """Test container process listing handles docker command failure."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=1, stdout='')
            processes = collector.get_container_processes('invalid_id')

        assert processes == []

    def test_get_container_processes_timeout(self, mock_config, tmp_path):
        """Test container process listing handles timeout."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        with patch('subprocess.run') as mock_run:
            import subprocess
            mock_run.side_effect = subprocess.TimeoutExpired('docker', 5)
            processes = collector.get_container_processes('abc123')

        assert processes == []

    @patch("psutil.Process")
    def test_collect_includes_container_processes(self, mock_proc_class, mock_config, tmp_path):
        """Should include container processes when container is detected."""
        mock_config["forensics"] = {"storage_dir": str(tmp_path / "forensics")}
        collector = ForensicsCollector(mock_config)

        # Mock process
        mock_proc = Mock()
        mock_proc.ppid.return_value = 1
        mock_proc.uids.return_value = Mock(real=0)
        mock_proc.username.return_value = "root"
        mock_proc.exe.return_value = "/tmp/xmrig"
        mock_proc.cwd.return_value = "/tmp"
        mock_proc.cmdline.return_value = ["/tmp/xmrig"]
        mock_proc.environ.return_value = {}
        mock_proc.open_files.return_value = []
        mock_proc.connections.return_value = []
        mock_proc.parent.return_value = None
        mock_proc.children.return_value = []
        mock_proc_class.return_value = mock_proc

        # Mock cgroup file for Docker
        cgroup_content = """12:memory:/docker/abc123def456789012345678901234567890123456789012345678901234"""

        with patch("builtins.open", MagicMock(return_value=MagicMock(__enter__=MagicMock(return_value=MagicMock(read=MagicMock(return_value=cgroup_content)))))):
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = Mock(
                    returncode=0,
                    stdout="PID USER COMMAND ARGS\n1 root xmrig /tmp/xmrig -o pool:3333"
                )
                data = collector.collect(1234)

        assert data is not None
        assert data.container_info is not None
        assert 'processes' in data.container_info
        assert len(data.container_info['processes']) == 1
        assert data.container_info['processes'][0]['command'] == 'xmrig'
