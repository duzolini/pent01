# Assessment Orchestrator

Um orquestrador de **assessment autorizado**: você declara um escopo, confirma que
tem permissão por escrito, e ele roda ferramentas open-source consagradas de recon
e scanning em pipeline, agregando tudo em um relatório. CLI + dashboard web.

> ⚠️ **Uso autorizado apenas.** Esta ferramenta foi feita para pentests contratados,
> programas de bug bounty, e sua própria infraestrutura. Rodar scanners contra alvos
> sem autorização é ilegal (no Brasil, Lei 12.737/2012 e Marco Civil) e pode derrubar
> o serviço do alvo. Cada scan registra quem autorizou o teste. **Não aponte para
> sistemas que você não tem permissão para testar.**

## Como a autorização é garantida

Nada neste projeto toca um alvo que não esteja explicitamente no escopo:

1. Todo alvo passa por uma **allow-list** (`domains`, `hosts`, `cidrs`) com exclusões
   que vencem sobre tudo. Checado em `scope.py` — o único ponto de passagem.
2. Nenhum scan roda enquanto o escopo não estiver marcado `authorized: true`
   (`require_authorized()`). CLI e dashboard passam pelo mesmo gate.
3. A proveniência da autorização (cliente, quem autorizou, referência de contrato)
   é gravada no resultado de cada scan, para trilha de auditoria.
4. Por padrão é **não-destrutivo**: sem brute-force, fuzzing ou DoS. Templates
   intrusivos do nuclei só rodam se o escopo marcar `intrusive: true`.

## Pipeline

| Estágio | Ferramentas | O que faz |
|---------|-------------|-----------|
| recon   | `subfinder`, `dnsx`, `httpx` | subdomínios, resolução, URLs vivas |
| ports   | `naabu`, `nmap`             | portas/serviços abertos |
| web     | `nuclei`, `nikto`, + checks nativos | vulns, headers de segurança, TLS |

Cada ferramenta é **detectada em runtime**: se o binário não estiver no PATH, o
estágio é marcado `skipped` em vez de quebrar o scan. Os checks de **security
headers** e **TLS** são em Python puro e funcionam sem nenhuma instalação.

## Instalação

```bash
pip install -r requirements.txt
```

Ferramentas externas (opcionais, mas recomendadas) — instale na sua máquina de
pentest. Projeto ProjectDiscovery:

```bash
# via go install, ou binários em github.com/projectdiscovery
subfinder dnsx httpx naabu nuclei
# e, dos repositórios do sistema:
nmap nikto
```

## Uso — CLI

```bash
# 1. gerar um escopo de exemplo e editar
python -m orchestrator init-scope scopes/cliente.yaml

# 2. testar se alvos caem no escopo
python -m orchestrator check-scope scopes/cliente.yaml app.cliente.com evil.com

# 3. rodar (só funciona com authorized: true no YAML)
python -m orchestrator scan scopes/cliente.yaml --report relatorio.html

# 4. listar scans e re-gerar relatórios
python -m orchestrator list
python -m orchestrator report <SCAN_ID> --format html -o relatorio.html
```

## Uso — dashboard web

```bash
python -m orchestrator serve           # http://127.0.0.1:8000
```

Escolha um escopo autorizado, marque a confirmação de autorização, e dispare.
A página do scan atualiza sozinha enquanto roda e linka o relatório HTML/Markdown.
O servidor sobe em `localhost` de propósito — é um console de operador, não um
serviço público.

## Formato do escopo

```yaml
name: engajamento-cliente
authorized: false            # o gate — só true com permissão por escrito
client: "Cliente X"
authorized_by: "Fulano (CISO)"
authorization_ref: "Contrato SOW-2026-014"
expires: "2026-12-31"
domains: [cliente.com]       # apex — subdomínios incluídos
hosts: []                    # FQDNs/IPs individuais
cidrs: []                    # ex. 203.0.113.0/24
exclude: []                  # vence sobre tudo
rate_limit: 50               # req/s repassado às ferramentas
max_concurrency: 10
intrusive: false             # true habilita templates fuzz/brute/dos do nuclei
```

## Testes

```bash
python tests/test_smoke.py       # sem rede; valida gate, escopo, serialização, relatório
```

## Estrutura

```
orchestrator/
  scope.py      # allow-list + gate de autorização (ponto de passagem único)
  models.py     # Asset, Finding, ScanResult
  tools.py      # wrappers de ferramentas + checks nativos (headers, TLS)
  runner.py     # pipeline em estágios
  report.py     # relatório HTML / Markdown
  store.py      # persistência (JSON em data/scans/)
  cli.py        # entry point de linha de comando
  web/          # dashboard Flask
```

## Licença e responsabilidade

Use apenas dentro da lei e do seu escopo autorizado. Os autores não se
responsabilizam por uso indevido.
