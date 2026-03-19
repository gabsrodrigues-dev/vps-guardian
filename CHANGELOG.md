# Changelog

Todas as mudanças notáveis do projeto serão documentadas aqui.

O formato segue [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/).

## [1.1.0] - 2026-03-19

### Adicionado
- **Webhook Notifications**
  - Notificações via HTTP POST para qualquer endpoint externo
  - Header `Authorization: Bearer <token>` configurável
  - Auto-geração de token seguro quando não configurado
  - Retry automático com contagem configurável
  - Compatível com Slack, Discord, SIEM, dashboards customizados
  - Eventos: `threat_detected`, `container_warning`, `process_warning`, `test`
  - Método `send_test()` para verificar conectividade
  - Método `get_integration_info()` com schema do body e instruções
  - Integração com ResponseHandler (notifica junto com Telegram)
  - Integração com guardian.py para alertas de container
  - Suite completa de testes (`test_webhook.py`)

## [1.0.0] - 2026-01-24

### Adicionado
- **Camada de Prevenção**
  - Hardening SSH (key-only, MaxAuthTries=3)
  - Fail2ban com jail customizado
  - Mount /tmp e /dev/shm com noexec
  - Firewall com blocklist de mining pools
  - Bloqueio de TOR exit nodes

- **Camada de Detecção**
  - Detector de processos por termos suspeitos
  - Monitor de recursos com lógica temporal (10min notify, 20min kill)
  - Monitor de conexões de rede para mining pools
  - Verificador de integridade de binários (anti-rootkit)
  - Monitor de filesystem (/tmp, /dev/shm)

- **Camada de Resposta**
  - Kill automático de processos maliciosos
  - Quarentena de binários suspeitos
  - Notificações via Telegram
  - Logs estruturados em JSON

- **Camada de Auditoria**
  - Integração com chkrootkit
  - Integração com rkhunter
  - Verificação semanal automatizada

- **Infraestrutura**
  - Instalador idempotente (setup.sh)
  - Desinstalador completo (uninstall.sh)
  - Atualização automática de blocklists (cron diário)
  - Serviço systemd com resource limits

### Origem
- Evoluído a partir de `sg.py` (script simples de kill por nome)
- Arquitetura modular seguindo SOLID
- Configuração centralizada em YAML

### Segurança
- Proteção contra malware perfctl e similares
- Detecção de rootkits por hash de binários
- Prevenção de execução em /tmp (noexec mount)
- Bloqueio de comunicação TOR

---

## [0.1.0] - Versão Original (sg.py)

### Funcionalidades
- Kill de processos por nome (xmrig, monero, miner, etc.)
- Limpeza de processos zumbi
- Loop de verificação a cada 5 segundos

### Limitações (resolvidas na v1.0)
- Detecção apenas por nome (fácil de evadir)
- Sem monitoramento de rede
- Sem verificação de integridade
- Sem prevenção (apenas reativo)
- Sem notificações
