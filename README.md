# VPS Guardian

**Read this in other languages: [English](#english) | [Português](#português)**

---

# English

**Anti-Cryptojacking Protection System for Linux VPS**

Protect your VPS against cryptocurrency miners, rootkits, and intrusions. Clone, run one command, and your VPS is protected.

## The Problem

Linux VPS are frequent targets of cryptojacking attacks:
- Attackers exploit SSH with weak passwords
- Malware like **perfctl** uses rootkits to hide
- Miners consume 100% CPU, causing abuse-related suspensions
- Communication via TOR makes detection difficult

## The Solution

VPS Guardian implements **defense in depth** with 4 layers:

```
┌─────────────────────────────────────────────────────────────┐
│                    LAYER 1: PREVENTION                      │
│  SSH key-only │ Fail2ban │ /tmp noexec │ Firewall blocklist │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    LAYER 2: DETECTION                       │
│  Suspicious terms │ High CPU/RAM │ Pool connections │ Hash  │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    LAYER 3: RESPONSE                        │
│     Kill process │ Quarantine binary │ Log │ Telegram       │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    LAYER 4: AUDIT                           │
│         chkrootkit │ rkhunter │ Weekly verification         │
└─────────────────────────────────────────────────────────────┘
```

## Quick Installation

```bash
# Clone the repository
git clone https://github.com/rfschubert/vps-guardian.git
cd vps-guardian

# Install
sudo make install

# Validate the installation
make validate

# Monitor in real-time
make logs
```

**Done!** Your VPS is now protected.

## Available Commands

```bash
make help           # List all commands
sudo make install   # Install VPS Guardian
make validate       # Validate installation is correct (10 checks)
make status         # Show Guardian service status
make logs           # Display logs in real-time
make test-detection # Test detection (creates fake process)
make test           # Run test suite (67 tests)
sudo make uninstall # Remove completely
```

## What Gets Installed

| Component | Description |
|-----------|-------------|
| **Guardian Service** | Python daemon that monitors processes 24/7 |
| **SSH Hardening** | Disables password login, limits attempts |
| **Fail2ban** | Blocks IPs after 3 failed attempts |
| **Firewall Rules** | Blocks mining ports and TOR exit nodes |
| **Integrity Checker** | Detects modified binaries (rootkits) |
| **Blocklists** | Daily updates of mining pool IPs |

## How It Works

### Miner Detection

1. **By Name**: Detects processes with terms like `xmrig`, `monero`, `miner`
2. **By Behavior**: Processes using >75% CPU for more than 10 minutes
3. **By Network**: Connections to known mining pools
4. **By Location**: Executables in `/tmp`, `/dev/shm`

### Automatic Response

| Situation | Action |
|-----------|--------|
| Suspicious term detected | Immediate kill |
| Connection to mining pool | Immediate kill |
| CPU >75% for 10 minutes | Telegram notification |
| CPU >75% for 20 minutes | Automatic kill |
| Modified system binary | Critical alert |

## Configuration

Edit `/opt/vps-guardian/guardian/config.yaml`:

```yaml
# Resource thresholds
resources:
  cpu_threshold_percent: 75
  memory_threshold_percent: 75
  notify_after_minutes: 10    # Notify
  kill_after_minutes: 20      # Kill

# Telegram notifications (optional)
response:
  telegram:
    enabled: true
    webhook_url: "https://api.telegram.org/bot<TOKEN>/sendMessage"
    chat_id: "123456789"

# Ignored processes (whitelist)
resources:
  whitelist:
    - dockerd
    - containerd
    - systemd
    - sshd
    - guardian.py
```

### Configure Telegram

1. Create a bot with [@BotFather](https://t.me/botfather)
2. Get the bot token
3. Find your chat_id with [@userinfobot](https://t.me/userinfobot)
4. Update `config.yaml`

## Useful Commands

```bash
# Service status
systemctl status guardian

# Real-time logs
journalctl -fu guardian

# Stop temporarily
systemctl stop guardian

# Restart after config change
systemctl restart guardian

# Check firewall rules
/opt/vps-guardian/firewall/rules.sh status

# Run manual audit
sudo /opt/vps-guardian/audit/audit.sh

# Update blocklists manually
sudo /opt/vps-guardian/firewall/blocklists/update-blocklist.sh
```

## Logs and Monitoring

| Log | Location |
|-----|----------|
| Guardian Service | `journalctl -u guardian` |
| Incidents (JSON) | `/var/log/guardian.log` |
| Blocklist updates | `/var/log/guardian-blocklist.log` |
| Audits | `/var/log/guardian-audit-*.log` |
| Quarantined files | `/var/quarantine/` |

## Uninstallation

```bash
sudo /opt/vps-guardian/uninstall.sh
```

## Requirements

- **OS**: Ubuntu 20.04+, Debian 10+, RHEL 8+, CentOS 8+
- **Python**: 3.8+
- **Privileges**: Root (required for process killing and firewall)
- **Dependencies**: Automatically installed by setup.sh

## FAQ

### My legitimate process was killed!

Add it to the whitelist in `config.yaml`:

```yaml
resources:
  whitelist:
    - my-process
```

### How do I test if it's working?

```bash
# Simulate a suspicious process (create test script)
cat > /tmp/test_miner.sh << 'EOF'
#!/bin/bash
# Rename process to suspicious term
exec -a xmrig sleep 300
EOF
chmod +x /tmp/test_miner.sh
/tmp/test_miner.sh &

# Check logs to confirm detection
journalctl -fu guardian
```

### SSH stopped working!

The setup.sh disables password login. Make sure you have SSH keys configured:

```bash
# On your local computer
ssh-copy-id user@your-vps
```

### Can I use it with Docker?

Yes, but Guardian must run on the host, not inside containers. It monitors all system processes.

## Contributing

1. Fork the repository
2. Create your branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [CoinBlockerLists](https://zerodot1.gitlab.io/CoinBlockerLists/) - Mining pool blocklist
- [TorProject](https://check.torproject.org/exit-addresses) - Exit node list
- [psutil](https://github.com/giampaolo/psutil) - Process monitoring

---

**Developed to protect VPS from cryptojacking attacks.**

---

# Português

**Sistema de Proteção Anti-Cryptojacking para VPS Linux**

Proteja sua VPS contra mineradores de criptomoedas, rootkits e invasões. Clone, execute um comando e sua VPS está protegida.

## O Problema

VPS Linux são alvos frequentes de ataques de cryptojacking:
- Invasores exploram SSH com senhas fracas
- Malware como **perfctl** usa rootkits para se esconder
- Mineradores consomem 100% da CPU, causando bloqueio por abuso
- Comunicação via TOR dificulta detecção

## A Solução

VPS Guardian implementa **defesa em profundidade** com 4 camadas:

```
┌─────────────────────────────────────────────────────────────┐
│                    CAMADA 1: PREVENÇÃO                      │
│  SSH key-only │ Fail2ban │ /tmp noexec │ Firewall blocklist │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    CAMADA 2: DETECÇÃO                       │
│  Termos suspeitos │ CPU/RAM alto │ Conexões p/ pools │ Hash │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    CAMADA 3: RESPOSTA                       │
│     Kill processo │ Quarentena binário │ Log │ Telegram     │
└─────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    CAMADA 4: AUDITORIA                      │
│         chkrootkit │ rkhunter │ Verificação semanal         │
└─────────────────────────────────────────────────────────────┘
```

## Instalação Rápida

```bash
# Clone o repositório
git clone https://github.com/rfschubert/vps-guardian.git
cd vps-guardian

# Instale
sudo make install

# Valide a instalação
make validate

# Monitore em tempo real
make logs
```

**Pronto!** Sua VPS está protegida.

## Comandos Disponíveis

```bash
make help           # Lista todos os comandos
sudo make install   # Instala o VPS Guardian
make validate       # Valida se instalação está correta (10 checks)
make status         # Mostra status do serviço Guardian
make logs           # Exibe logs em tempo real
make test-detection # Testa detecção (cria processo fake)
make test           # Roda suite de testes (67 testes)
sudo make uninstall # Remove completamente
```

## O Que é Instalado

| Componente | Descrição |
|------------|-----------|
| **Guardian Service** | Daemon Python que monitora processos 24/7 |
| **SSH Hardening** | Desabilita login por senha, limita tentativas |
| **Fail2ban** | Bloqueia IPs após 3 tentativas falhas |
| **Firewall Rules** | Bloqueia portas de mining e TOR exit nodes |
| **Integrity Checker** | Detecta binários alterados (rootkits) |
| **Blocklists** | Atualização diária de IPs de mining pools |

## Como Funciona

### Detecção de Mineradores

1. **Por Nome**: Detecta processos com termos como `xmrig`, `monero`, `miner`
2. **Por Comportamento**: Processos usando >75% CPU por mais de 10 minutos
3. **Por Rede**: Conexões para mining pools conhecidos
4. **Por Localização**: Executáveis em `/tmp`, `/dev/shm`

### Resposta Automática

| Situação | Ação |
|----------|------|
| Termo suspeito detectado | Kill imediato |
| Conexão para mining pool | Kill imediato |
| CPU >75% por 10 minutos | Notificação Telegram |
| CPU >75% por 20 minutos | Kill automático |
| Binário do sistema alterado | Alerta crítico |

## Configuração

Edite `/opt/vps-guardian/guardian/config.yaml`:

```yaml
# Thresholds de recursos
resources:
  cpu_threshold_percent: 75
  memory_threshold_percent: 75
  notify_after_minutes: 10    # Notificar
  kill_after_minutes: 20      # Matar

# Notificações Telegram (opcional)
response:
  telegram:
    enabled: true
    webhook_url: "https://api.telegram.org/bot<TOKEN>/sendMessage"
    chat_id: "123456789"

# Processos ignorados (whitelist)
resources:
  whitelist:
    - dockerd
    - containerd
    - systemd
    - sshd
    - guardian.py
```

### Configurar Telegram

1. Crie um bot com [@BotFather](https://t.me/botfather)
2. Obtenha o token do bot
3. Descubra seu chat_id com [@userinfobot](https://t.me/userinfobot)
4. Atualize o `config.yaml`

## Comandos Úteis

```bash
# Status do serviço
systemctl status guardian

# Logs em tempo real
journalctl -fu guardian

# Parar temporariamente
systemctl stop guardian

# Reiniciar após mudança de config
systemctl restart guardian

# Verificar regras de firewall
/opt/vps-guardian/firewall/rules.sh status

# Executar auditoria manual
sudo /opt/vps-guardian/audit/audit.sh

# Atualizar blocklists manualmente
sudo /opt/vps-guardian/firewall/blocklists/update-blocklist.sh
```

## Logs e Monitoramento

| Log | Localização |
|-----|-------------|
| Serviço Guardian | `journalctl -u guardian` |
| Incidentes (JSON) | `/var/log/guardian.log` |
| Atualizações blocklist | `/var/log/guardian-blocklist.log` |
| Auditorias | `/var/log/guardian-audit-*.log` |
| Arquivos em quarentena | `/var/quarantine/` |

## Desinstalação

```bash
sudo /opt/vps-guardian/uninstall.sh
```

## Requisitos

- **OS**: Ubuntu 20.04+, Debian 10+, RHEL 8+, CentOS 8+
- **Python**: 3.8+
- **Privilégios**: Root (necessário para kill de processos e firewall)
- **Dependências**: Instaladas automaticamente pelo setup.sh

## FAQ

### Meu processo legítimo foi morto!

Adicione-o à whitelist em `config.yaml`:

```yaml
resources:
  whitelist:
    - meu-processo
```

### Como testar se está funcionando?

```bash
# Simule um processo suspeito (criar script de teste)
cat > /tmp/test_miner.sh << 'EOF'
#!/bin/bash
# Renomear processo para termo suspeito
exec -a xmrig sleep 300
EOF
chmod +x /tmp/test_miner.sh
/tmp/test_miner.sh &

# Verificar logs para confirmar detecção
journalctl -fu guardian
```

### O SSH parou de funcionar!

O setup.sh desabilita login por senha. Certifique-se de ter SSH keys configuradas:

```bash
# No seu computador local
ssh-copy-id usuario@sua-vps
```

### Posso usar em Docker?

Sim, mas o Guardian deve rodar no host, não dentro de containers. Ele monitora todos os processos do sistema.

## Contribuindo

1. Fork o repositório
2. Crie sua branch (`git checkout -b feature/minha-feature`)
3. Commit suas mudanças (`git commit -m 'Add minha feature'`)
4. Push para a branch (`git push origin feature/minha-feature`)
5. Abra um Pull Request

## Licença

MIT License - veja [LICENSE](LICENSE) para detalhes.

## Agradecimentos

- [CoinBlockerLists](https://zerodot1.gitlab.io/CoinBlockerLists/) - Blocklist de mining pools
- [TorProject](https://check.torproject.org/exit-addresses) - Lista de exit nodes
- [psutil](https://github.com/giampaolo/psutil) - Monitoramento de processos

---

**Desenvolvido para proteger VPS de ataques de cryptojacking.**
