# Scanner de Portas

Scanner de portas TCP escrito em Python, para fins educacionais e de estudo em cibersegurança.

Três versões disponíveis:
- **`scanner.py`** — versão simples, sequencial, ideal para entender a lógica básica
- **`scanner_avancado.py`** — versão via terminal com multithreading, banner grabbing e exportação JSON
- **`scanner_gui.py`** — versão com interface gráfica (Tkinter)

## O que faz

O script tenta se conectar em um intervalo de portas de um host e informa quais estão abertas, junto com o nome do serviço comum associado a cada uma.

## Tecnologias

- Python 3
- `socket` — comunicação de rede
- `concurrent.futures.ThreadPoolExecutor` — paralelismo
- `tkinter` — interface gráfica
- `argparse` — interface de linha de comando (versões via terminal)
- `json` — exportação de resultados

## Como usar

### Versão simples (terminal)

\`\`\`bash
python3 scanner.py <host> -p <inicio>-<fim> -t <timeout>
\`\`\`

### Versão avançada (terminal)

\`\`\`bash
python3 scanner_avancado.py <host> -p <inicio>-<fim> -t <timeout> -w <threads> -b -o resultado.json
\`\`\`

### Versão com interface gráfica

\`\`\`bash
python3 scanner_gui.py
\`\`\`

Uma janela será aberta onde você pode:
1. Digitar o host, intervalo de portas e timeout
2. Clicar em "Escanear"
3. Ver as portas abertas aparecendo em tempo real na tabela
4. Exportar o resultado para JSON com um clique

**Requisito:** o Tkinter precisa estar instalado. No Linux (Debian/Ubuntu), instale com:

\`\`\`bash
sudo apt-get install python3-tk
\`\`\`

## Parâmetros (versão avançada via terminal)

| Parâmetro | Descrição | Padrão |
|---|---|---|
| `host` | IP ou hostname alvo | obrigatório |
| `-p`, `--ports` | Intervalo de portas (formato `inicio-fim`) | `1-1024` |
| `-t`, `--timeout` | Timeout por porta em segundos | `1.0` |
| `-w`, `--workers` | Número máximo de threads simultâneas | `100` |
| `-b`, `--banner` | Ativa captura de banner dos serviços | desativado |
| `-o`, `--output` | Caminho do arquivo JSON de saída | nenhum |

## Aviso importante

Este projeto tem finalidade **educacional**. Utilize o scanner apenas em:
- Hosts de sua propriedade
- Ambientes de laboratório (ex: máquinas virtuais próprias)
- Sistemas com autorização explícita para teste

Escanear portas de terceiros sem autorização pode violar leis de crimes cibernéticos.

## Possíveis melhorias futuras

- Suporte a escaneamento UDP
- Detecção de sistema operacional (fingerprinting)
- Histórico de escaneamentos anteriores na interface gráfica
