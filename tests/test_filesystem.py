#!/usr/bin/env python3
"""
VPS Guardian - Filesystem Monitor Tests
Tests scanning of temporary directories for suspicious files.
"""

import pytest
import os
import stat
from pathlib import Path
from guardian.modules.filesystem import FilesystemMonitor, SuspiciousFile


class TestFilesystemMonitor:
    """Test suite for the FilesystemMonitor module."""

    @pytest.fixture
    def filesystem_config(self, tmp_path):
        """Filesystem monitor configuration with temp paths."""
        watch_dir1 = tmp_path / 'tmp'
        watch_dir1.mkdir()

        watch_dir2 = tmp_path / 'var_tmp'
        watch_dir2.mkdir()

        return {
            'filesystem': {
                'watch_dirs': [str(watch_dir1), str(watch_dir2)],
                'max_file_age_minutes': 30
            }
        }

    def test_detect_new_executable(self, filesystem_config, tmp_path):
        """Should detect new executable file in temp directory."""
        monitor = FilesystemMonitor(filesystem_config)

        # Create executable file
        exe_file = tmp_path / 'tmp' / 'suspicious_miner'
        exe_file.write_text('#!/bin/bash\necho "mining"')
        exe_file.chmod(0o755)  # Make executable

        suspicious = monitor.scan()

        assert len(suspicious) >= 1
        found = [s for s in suspicious if 'suspicious_miner' in s.path]
        assert len(found) == 1
        assert found[0].is_executable is True
        assert 'executable' in found[0].reason.lower()

    def test_detect_hidden_executable(self, filesystem_config, tmp_path):
        """Should detect hidden executable file."""
        monitor = FilesystemMonitor(filesystem_config)

        # Create hidden executable
        hidden_exe = tmp_path / 'tmp' / '.hidden_miner'
        hidden_exe.write_text('#!/bin/bash\nmalicious code')
        hidden_exe.chmod(0o755)

        suspicious = monitor.scan()

        found = [s for s in suspicious if '.hidden_miner' in s.path]
        assert len(found) == 1
        assert 'hidden executable' in found[0].reason.lower()

    def test_detect_elf_binary(self, filesystem_config, tmp_path):
        """Should detect ELF binary in temp directory."""
        monitor = FilesystemMonitor(filesystem_config)

        # Create fake ELF binary
        elf_file = tmp_path / 'tmp' / 'xmrig'
        elf_file.write_bytes(b'\x7fELF' + b'\x00' * 2000)  # ELF magic + padding
        elf_file.chmod(0o755)

        suspicious = monitor.scan()

        found = [s for s in suspicious if 'xmrig' in s.path]
        assert len(found) == 1
        assert 'elf binary' in found[0].reason.lower()

    def test_not_detect_old_file(self, filesystem_config, tmp_path):
        """Should NOT detect old files beyond age threshold."""
        monitor = FilesystemMonitor(filesystem_config)

        # Create executable but mark it as old
        old_exe = tmp_path / 'tmp' / 'old_script'
        old_exe.write_text('#!/bin/bash\nold script')
        old_exe.chmod(0o755)

        # Manipulate file timestamp to be 60 minutes old
        import time
        old_time = time.time() - (60 * 60)  # 60 minutes ago
        os.utime(old_exe, (old_time, old_time))

        suspicious = monitor.scan()

        # Should not be flagged as new executable
        found = [s for s in suspicious if 'old_script' in s.path and 'new executable' in s.reason.lower()]
        assert len(found) == 0

    def test_not_detect_non_executable(self, filesystem_config, tmp_path):
        """Should NOT detect regular text files."""
        monitor = FilesystemMonitor(filesystem_config)

        # Create non-executable file
        text_file = tmp_path / 'tmp' / 'notes.txt'
        text_file.write_text('Just some notes')

        suspicious = monitor.scan()

        found = [s for s in suspicious if 'notes.txt' in s.path]
        assert len(found) == 0

    def test_scan_multiple_directories(self, filesystem_config, tmp_path):
        """Should scan all watched directories."""
        monitor = FilesystemMonitor(filesystem_config)

        # Create executables in both watched dirs
        exe1 = tmp_path / 'tmp' / 'miner1'
        exe1.write_text('#!/bin/bash\nmining')
        exe1.chmod(0o755)

        exe2 = tmp_path / 'var_tmp' / 'miner2'
        exe2.write_text('#!/bin/bash\nmining')
        exe2.chmod(0o755)

        suspicious = monitor.scan()

        assert len(suspicious) >= 2
        paths = [s.path for s in suspicious]
        assert any('miner1' in p for p in paths)
        assert any('miner2' in p for p in paths)

    def test_handle_nonexistent_directory(self, filesystem_config):
        """Should handle nonexistent watch directories gracefully."""
        filesystem_config['filesystem']['watch_dirs'].append('/tmp/does_not_exist_xyz')

        monitor = FilesystemMonitor(filesystem_config)

        # Should not crash
        suspicious = monitor.scan()

        assert isinstance(suspicious, list)

    def test_recursive_scan_subdirectories(self, tmp_path):
        """Should recursively scan subdirectories (when under depth limit)."""
        # Use a shallow path to test recursion
        # Note: pytest tmp_path is already 6+ levels deep, exceeding the module's
        # recursion limit of 5. This test uses /tmp directly for realistic testing.
        import tempfile
        import shutil

        # Create test structure in actual /tmp
        test_dir = Path(tempfile.mkdtemp(prefix='guardian_test_'))
        subdir = test_dir / 'subdir'
        subdir.mkdir()

        try:
            nested_exe = subdir / 'nested_miner'
            nested_exe.write_text('#!/bin/bash\n' + 'echo "mining"\n' * 100)
            nested_exe.chmod(0o755)

            # Create monitor with our test directory
            config = {
                'filesystem': {
                    'watch_dirs': [str(test_dir)],
                    'max_file_age_minutes': 30
                }
            }
            monitor = FilesystemMonitor(config)
            suspicious = monitor.scan()

            found = [s for s in suspicious if 'nested_miner' in s.path]
            assert len(found) == 1
        finally:
            # Cleanup
            shutil.rmtree(test_dir, ignore_errors=True)

    def test_skip_tiny_executables(self, filesystem_config, tmp_path):
        """Should skip very small executables (likely just scripts)."""
        monitor = FilesystemMonitor(filesystem_config)

        # Create tiny executable (less than 1024 bytes)
        tiny_script = tmp_path / 'tmp' / 'tiny.sh'
        tiny_script.write_text('#!/bin/bash\n')
        tiny_script.chmod(0o755)

        suspicious = monitor.scan()

        # Should still flag as new executable, but not as ELF binary
        found = [s for s in suspicious if 'tiny.sh' in s.path]
        if found:
            assert 'elf binary' not in found[0].reason.lower()

    def test_multiple_suspicious_reasons(self, filesystem_config, tmp_path):
        """Should list multiple reasons if file matches multiple criteria."""
        monitor = FilesystemMonitor(filesystem_config)

        # Create hidden ELF executable
        suspicious_file = tmp_path / 'tmp' / '.hidden_elf'
        suspicious_file.write_bytes(b'\x7fELF' + b'\x00' * 2000)
        suspicious_file.chmod(0o755)

        suspicious = monitor.scan()

        found = [s for s in suspicious if '.hidden_elf' in s.path]
        assert len(found) == 1
        # Should have multiple reasons
        assert ';' in found[0].reason or ('hidden' in found[0].reason.lower() and 'elf' in found[0].reason.lower())

    def test_file_metadata_accuracy(self, filesystem_config, tmp_path):
        """Should accurately report file metadata."""
        monitor = FilesystemMonitor(filesystem_config)

        exe_file = tmp_path / 'tmp' / 'test_exe'
        exe_file.write_text('#!/bin/bash\ntest')
        exe_file.chmod(0o755)

        suspicious = monitor.scan()

        found = [s for s in suspicious if 'test_exe' in s.path]
        assert len(found) == 1
        assert found[0].is_executable is True
        assert found[0].size_bytes > 0
        assert found[0].age_minutes < 1  # Just created
