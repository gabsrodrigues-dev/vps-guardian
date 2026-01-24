# VPS Guardian

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
