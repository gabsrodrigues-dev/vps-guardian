# VPS Guardian - Makefile
# Commands for installation, validation, and management

.PHONY: help install validate status logs test-detection uninstall lint test test-cov test-verbose config

# Default target
help:
	@echo "VPS Guardian - Available Commands"
	@echo "=================================="
	@echo ""
	@echo "  make install        - Run full installation (requires sudo)"
	@echo "  make config         - Create config.yaml from example"
	@echo "  make validate       - Validate installation (passive checks only)"
	@echo "  make status         - Show Guardian service status"
	@echo "  make logs           - Tail Guardian logs in real-time"
	@echo "  make uninstall      - Remove VPS Guardian completely"
	@echo "  make lint           - Check Python code syntax"
	@echo ""
	@echo "Configuration with Telegram:"
	@echo "  make config TELEGRAM_TOKEN=<token> TELEGRAM_CHAT_ID=<chat_id>"
	@echo ""
	@echo "Testing (LOCAL development only):"
	@echo "  make test           - Run unit tests"
	@echo "  make test-cov       - Run tests with coverage report"
	@echo "  make test-detection - Creates fake miner (DO NOT USE IN PRODUCTION)"
	@echo ""

# Install VPS Guardian
install:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: Run with sudo: sudo make install"; \
		exit 1; \
	fi
	@./setup.sh

# Create config.yaml from example
# Usage: make config
# Usage: make config TELEGRAM_TOKEN=<token> TELEGRAM_CHAT_ID=<chat_id>
config:
	@echo "============================================"
	@echo "VPS Guardian - Configuration Setup"
	@echo "============================================"
	@if [ ! -f "config.yaml.example" ]; then \
		echo "❌ config.yaml.example not found!"; \
		exit 1; \
	fi
	@cp config.yaml.example guardian/config.yaml
	@echo "✅ Created guardian/config.yaml from example"
	@if [ -n "$(TELEGRAM_TOKEN)" ] && [ -n "$(TELEGRAM_CHAT_ID)" ]; then \
		sed -i 's|enabled: false|enabled: true|' guardian/config.yaml; \
		sed -i 's|<SEU_TOKEN>|$(TELEGRAM_TOKEN)|' guardian/config.yaml; \
		sed -i 's|<SEU_CHAT_ID>|$(TELEGRAM_CHAT_ID)|' guardian/config.yaml; \
		echo "✅ Telegram configured:"; \
		echo "   Token: $(TELEGRAM_TOKEN)"; \
		echo "   Chat ID: $(TELEGRAM_CHAT_ID)"; \
	else \
		echo "ℹ️  Telegram not configured (optional)"; \
		echo "   To enable: make config TELEGRAM_TOKEN=xxx TELEGRAM_CHAT_ID=yyy"; \
	fi
	@echo ""
	@echo "Config file: guardian/config.yaml"
	@echo "Edit manually if needed, then run: sudo make install"

# Validate installation
validate:
	@echo "============================================"
	@echo "VPS Guardian - Installation Validation"
	@echo "============================================"
	@echo ""
	@ERRORS=0; \
	\
	echo "[1/10] Checking Guardian service..."; \
	if systemctl is-active --quiet guardian 2>/dev/null; then \
		echo "  ✅ Guardian service is running"; \
	else \
		echo "  ❌ Guardian service is NOT running"; \
		ERRORS=$$((ERRORS+1)); \
	fi; \
	\
	echo "[2/10] Checking installation directory..."; \
	if [ -d "/opt/vps-guardian" ]; then \
		echo "  ✅ /opt/vps-guardian exists"; \
	else \
		echo "  ❌ /opt/vps-guardian NOT found"; \
		ERRORS=$$((ERRORS+1)); \
	fi; \
	\
	echo "[3/10] Checking config.yaml..."; \
	if [ -f "/opt/vps-guardian/guardian/config.yaml" ]; then \
		echo "  ✅ config.yaml exists"; \
	else \
		echo "  ❌ config.yaml NOT found"; \
		ERRORS=$$((ERRORS+1)); \
	fi; \
	\
	echo "[4/10] Checking integrity database..."; \
	if [ -f "/var/lib/guardian/hashes.json" ]; then \
		echo "  ✅ Integrity hashes initialized"; \
	else \
		echo "  ⚠️  Integrity hashes not found (will be created on first run)"; \
	fi; \
	\
	echo "[5/10] Checking quarantine directory..."; \
	if [ -d "/var/quarantine" ]; then \
		echo "  ✅ /var/quarantine exists"; \
	else \
		echo "  ❌ /var/quarantine NOT found"; \
		ERRORS=$$((ERRORS+1)); \
	fi; \
	\
	echo "[6/10] Checking Fail2ban..."; \
	if systemctl is-active --quiet fail2ban 2>/dev/null; then \
		echo "  ✅ Fail2ban is running"; \
	else \
		echo "  ⚠️  Fail2ban is not running"; \
	fi; \
	\
	echo "[7/10] Checking SSH hardening..."; \
	if [ -f "/etc/ssh/sshd_config.d/90-guardian.conf" ]; then \
		echo "  ✅ SSH hardening config installed"; \
	else \
		echo "  ⚠️  SSH hardening config not found"; \
	fi; \
	\
	echo "[8/10] Checking firewall blocklists..."; \
	if [ -f "/opt/vps-guardian/firewall/blocklists/mining-pools.txt" ]; then \
		POOLS=$$(wc -l < /opt/vps-guardian/firewall/blocklists/mining-pools.txt); \
		echo "  ✅ Mining pools blocklist: $$POOLS entries"; \
	else \
		echo "  ❌ Mining pools blocklist NOT found"; \
		ERRORS=$$((ERRORS+1)); \
	fi; \
	\
	echo "[9/10] Checking ipset rules..."; \
	if command -v ipset >/dev/null 2>&1 && ipset list guardian_tor_nodes >/dev/null 2>&1; then \
		TOR=$$(ipset list guardian_tor_nodes 2>/dev/null | grep -c "^[0-9]" || echo 0); \
		echo "  ✅ TOR exit nodes blocked: $$TOR IPs"; \
	else \
		echo "  ⚠️  ipset not configured (run firewall/rules.sh)"; \
	fi; \
	\
	echo "[10/10] Checking cron jobs..."; \
	if crontab -l 2>/dev/null | grep -q "update-blocklist.sh"; then \
		echo "  ✅ Daily blocklist update scheduled"; \
	else \
		echo "  ⚠️  Blocklist cron not found"; \
	fi; \
	\
	echo ""; \
	echo "============================================"; \
	if [ $$ERRORS -eq 0 ]; then \
		echo "✅ All critical checks passed!"; \
		echo "============================================"; \
		exit 0; \
	else \
		echo "❌ $$ERRORS critical error(s) found"; \
		echo "============================================"; \
		exit 1; \
	fi

# Show service status
status:
	@echo "=== Guardian Service ==="
	@systemctl status guardian --no-pager -l 2>/dev/null || echo "Service not installed"
	@echo ""
	@echo "=== Resource Usage ==="
	@ps aux | grep -E "[g]uardian.py" | awk '{print "CPU: "$$3"% | RAM: "$$4"% | PID: "$$2}' || echo "Not running"
	@echo ""
	@echo "=== Recent Activity ==="
	@journalctl -u guardian --no-pager -n 10 2>/dev/null || echo "No logs available"

# Tail logs
logs:
	@journalctl -fu guardian

# Test detection (creates a fake miner process)
# WARNING: This is for LOCAL TESTING ONLY - do NOT run on production VPS
# as creating suspicious processes may trigger abuse detection by your provider
test-detection:
	@echo "============================================" && \
	echo "⚠️  WARNING: LOCAL TESTING ONLY" && \
	echo "============================================" && \
	echo "This creates a fake miner process to test Guardian." && \
	echo "Do NOT run this on production VPS - it may trigger" && \
	echo "abuse detection by your hosting provider." && \
	echo "" && \
	read -p "Continue? (y/N) " confirm && \
	if [ "$$confirm" != "y" ] && [ "$$confirm" != "Y" ]; then \
		echo "Aborted."; \
		exit 0; \
	fi && \
	echo "" && \
	echo "Creating fake miner process for 15 seconds..." && \
	bash -c 'exec -a "xmrig-test-fake" sleep 15' & \
	PID=$$!; \
	echo "Fake miner PID: $$PID"; \
	echo "Watching for Guardian response..."; \
	sleep 12; \
	if kill -0 $$PID 2>/dev/null; then \
		echo "❌ Process still alive - Guardian may not be detecting"; \
		kill $$PID 2>/dev/null; \
	else \
		echo "✅ Process was killed by Guardian!"; \
		echo "Check logs: journalctl -u guardian -n 20"; \
	fi

# Uninstall
uninstall:
	@if [ "$$(id -u)" != "0" ]; then \
		echo "Error: Run with sudo: sudo make uninstall"; \
		exit 1; \
	fi
	@./uninstall.sh

# Lint Python code
lint:
	@echo "Checking Python syntax..."
	@python3 -m py_compile guardian/guardian.py && echo "✅ guardian.py OK"
	@python3 -m py_compile guardian/modules/detector.py && echo "✅ detector.py OK"
	@python3 -m py_compile guardian/modules/resources.py && echo "✅ resources.py OK"
	@python3 -m py_compile guardian/modules/network.py && echo "✅ network.py OK"
	@python3 -m py_compile guardian/modules/integrity.py && echo "✅ integrity.py OK"
	@python3 -m py_compile guardian/modules/filesystem.py && echo "✅ filesystem.py OK"
	@python3 -m py_compile guardian/modules/response.py && echo "✅ response.py OK"
	@echo "All Python files passed syntax check!"

# Run unit tests
test:
	@echo "Running VPS Guardian test suite..."
	@python3 -m pytest tests/ -v --tb=short

# Run tests with coverage report
test-cov:
	@echo "Running tests with coverage analysis..."
	@python3 -m pytest tests/ --cov=guardian --cov-report=term-missing --cov-report=html
	@echo ""
	@echo "HTML coverage report generated: htmlcov/index.html"

# Run tests with verbose output
test-verbose:
	@echo "Running tests with verbose output..."
	@python3 -m pytest tests/ -vv --tb=long
