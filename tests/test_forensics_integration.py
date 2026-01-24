#!/usr/bin/env python3
"""
VPS Guardian - Forensics Integration Tests
Tests forensics module integration with the broader system.
"""

import os
import json
import pytest
from pathlib import Path
from guardian.modules.forensics import ForensicsCollector, ForensicsData


class TestForensicsIntegration:
    """Integration tests for forensics module."""

    def test_collect_save_and_summarize_workflow(self, mock_config, tmp_path):
        """Should collect, save, and summarize forensic data for current process."""
        storage_dir = tmp_path / "forensics"
        mock_config["forensics"] = {"storage_dir": str(storage_dir)}

        collector = ForensicsCollector(mock_config)

        # Collect forensics from the current Python process
        current_pid = os.getpid()
        data = collector.collect(current_pid)

        # Verify data was collected
        assert data is not None
        assert data.pid == current_pid
        assert data.username is not None
        assert data.exe_path is not None
        assert (
            "python" in data.exe_path.lower() or "pytest" in str(data.cmdline).lower()
        )

        # Save forensic data
        saved_path = collector.save(data)

        # Verify file was created
        assert saved_path.exists()
        assert saved_path.suffix == ".json"

        # Verify file content is valid JSON
        with open(saved_path) as f:
            loaded = json.load(f)
            assert loaded["pid"] == current_pid
            assert loaded["username"] == data.username

        # Generate summary
        summary = collector.to_summary(data)

        # Verify summary contains key information
        assert f"PID: {current_pid}" in summary
        assert data.username in summary
        assert "FORENSIC EVIDENCE" in summary

    def test_import_from_guardian_modules(self):
        """Should be importable from guardian.modules namespace."""
        from guardian.modules import ForensicsCollector, ForensicsData

        # Verify classes are available
        assert ForensicsCollector is not None
        assert ForensicsData is not None

    def test_cleanup_integration(self, mock_config, tmp_path):
        """Should cleanup old evidence files while preserving recent ones."""
        import time

        storage_dir = tmp_path / "forensics"
        storage_dir.mkdir()
        mock_config["forensics"] = {
            "storage_dir": str(storage_dir),
            "retention_days": 1,
        }

        collector = ForensicsCollector(mock_config)

        # Create old file
        old_file = storage_dir / "1000000000_1234.json"
        old_file.write_text('{"pid": 1234}')
        old_time = time.time() - (2 * 24 * 60 * 60)  # 2 days ago
        os.utime(old_file, (old_time, old_time))

        # Create recent file
        recent_file = storage_dir / "2000000000_5678.json"
        recent_file.write_text('{"pid": 5678}')

        # Run cleanup
        deleted_count = collector.cleanup_old()

        # Verify cleanup worked
        assert deleted_count == 1
        assert not old_file.exists()
        assert recent_file.exists()

    def test_disabled_collector(self, mock_config, tmp_path):
        """Should respect enabled flag in configuration."""
        mock_config["forensics"] = {
            "enabled": False,
            "storage_dir": str(tmp_path / "forensics"),
        }

        collector = ForensicsCollector(mock_config)

        # Verify collector respects disabled state
        assert collector.enabled is False

        # Collector can still be used for manual collection if needed
        current_pid = os.getpid()
        data = collector.collect(current_pid)
        assert data is not None  # Collection still works, just not automatic
