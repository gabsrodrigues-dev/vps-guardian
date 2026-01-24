# VPS Guardian - Security Lessons Learned

## Incident: Heimdall Container Compromise

### What Happened
- Attacker exploited application vulnerability in Heimdall container
- Miner executed INSIDE the container (not new container created)
- Container had network access and CPU resources

### Attack Vector
Application-level vulnerability → Remote Code Execution → Cryptominer deployment

### Why Previous Detection Failed
1. Guardian wasn't monitoring processes INSIDE containers
2. No baseline of expected container processes
3. Container resource usage not tracked separately

---

## Implemented Mitigations (Current PR)

### 1. Forensics Module
- Captures full evidence before killing processes
- Includes container detection (Docker, K8s, containerd)
- Stores PPID chain to trace attack origin

### 2. Container Awareness
- Detects if suspicious process runs in container
- Can stop/kill compromised containers
- Logs container ID for investigation

### 3. Persistence Detection
- Scans for crontabs, systemd services, SSH keys
- Detects how attackers maintain access

### 4. Rootkit Detection
- LD_PRELOAD hijacking
- Hidden processes
- Suspicious kernel modules

### 5. Container Process Monitoring
- Captures list of processes running inside containers
- Stored in forensics data for baseline comparison
- Helps identify malicious processes in containers

---

## Recommended Additional Mitigations

### Phase 6: Container Process Baseline (Future)

**Problem**: We detect miners, but attackers could use renamed binaries.

**Solution**: Maintain expected process list per container image.

```yaml
containers:
  baselines:
    heimdall:
      expected_processes:
        - php-fpm
        - nginx
        - supervisord
      alert_on_unknown: true
```

### Phase 7: Docker Events Integration (Future)

**Problem**: Attackers can exec into containers.

**Solution**: Monitor Docker events API for suspicious exec commands.

```python
# docker events --filter event=exec_start
# Alert on: exec into container by non-admin user
```

### Phase 8: Container Resource Limits Enforcement (Future)

**Problem**: Miners use all available CPU.

**Solution**: Enforce and monitor container resource limits.

```yaml
containers:
  resource_monitoring:
    enabled: true
    alert_on_no_limits: true  # Alert if container has no CPU limits
    cpu_threshold_percent: 80
```

### Phase 9: Network Egress Monitoring (Future)

**Problem**: Miners connect to mining pools.

**Solution**: Per-container network monitoring.

```yaml
containers:
  network_monitoring:
    enabled: true
    allowed_egress:
      heimdall:
        - "*.schubert.com.br"
        - "github.com"
    block_unknown: false  # true = strict mode
```

---

## Immediate Actions for Heimdall

1. **Patch the vulnerability** in Heimdall application
2. **Add to Guardian whitelist** (known container ID) after patching
3. **Set CPU limits** on container: `--cpus=2`
4. **Review Traefik rules** for unnecessary exposure
5. **Enable Guardian container monitoring**:
   ```yaml
   containers:
     enabled: true
     on_threat: stop  # Stop compromised containers
   ```

---

## Configuration Checklist

```yaml
# /opt/vps-guardian/guardian/config.yaml

# Enable all new protections
forensics:
  enabled: true

persistence:
  enabled: true

integrity:
  rootkit_detection:
    enabled: true

containers:
  enabled: true
  on_threat: stop
  whitelist: []  # Add known-good container IDs after patching

auditd:
  enabled: true  # Catch short-lived processes
```

---

## Monitoring Commands

```bash
# View forensics evidence
ls -la /var/lib/guardian/forensics/

# Check for persistence mechanisms
grep -r "wget\|curl" /etc/cron* /var/spool/cron/

# Monitor container processes
docker top <container_id>

# View Guardian alerts
tail -f /var/log/guardian.log | grep -E "(KILL|THREAT|ROOTKIT)"

# Check auditd for /tmp executions
ausearch -k guardian_tmp -ts recent
```

---

## Post-Incident Analysis Workflow

When Guardian detects a threat in a container:

1. **Review Forensics**:
   ```bash
   cat /var/lib/guardian/forensics/<timestamp>_<pid>.json
   ```
   Look for:
   - Container ID and type
   - List of processes running in container
   - Network connections to mining pools
   - Parent process chain

2. **Identify Attack Origin**:
   - Check parent chain to see if it started from web server (PHP, nginx)
   - Review container logs: `docker logs <container_id>`
   - Check application logs for RCE indicators

3. **Containment**:
   - Guardian will stop/kill the container (if configured)
   - Remove container: `docker rm -f <container_id>`
   - Block attacker IP at firewall level

4. **Remediation**:
   - Update application to patched version
   - Rebuild container with latest security updates
   - Set resource limits: `--cpus=2 --memory=512m`

5. **Prevention**:
   - Add container baseline to Guardian config
   - Enable stricter security policies
   - Review and minimize container privileges
