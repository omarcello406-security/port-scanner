#!/usr/bin/env python3
"""
Scanner de Portas Avançado
Verifica portas TCP abertas em um host, com suporte a:
- Escaneamento multithread (mais rápido)
- Banner grabbing (identifica o serviço rodando)
- Exportação de resultados em JSON

Uso educacional — utilize apenas em sistemas que você possui
ou tem autorização explícita para testar.
"""

import socket
import sys
import json
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

print_lock = Lock()


def grab_banner(sock):
    """Tenta capturar o banner de resposta do serviço."""
    try:
        sock.settimeout(0.8)
        banner = sock.recv(1024).decode(errors="ignore").strip()
        return banner if banner else None
    except socket.error:
        return None


def scan_port(host, port, timeout=1, do_banner=False):
    """Tenta conectar em uma porta. Retorna dict com o resultado ou None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result != 0:
            return None

        service = get_service_name(port)
        banner = grab_banner(sock) if do_banner else None

        return {
            "port": port,
            "service": service,
            "banner": banner
        }
    except socket.error:
        return None
    finally:
        sock.close()


def get_service_name(port):
    """Tenta identificar o serviço comum associado à porta."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "desconhecido"


def scan_range(host, start_port, end_port, timeout=1, max_workers=100, do_banner=False):
    """Escaneia um intervalo de portas em paralelo usando threads."""
    print(f"\nEscaneando host: {host}")
    print(f"Intervalo de portas: {start_port}-{end_port}")
    print(f"Threads: {max_workers}")
    print(f"Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    print("-" * 60)

    open_ports = []
    ports = range(start_port, end_port + 1)

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(scan_port, host, port, timeout, do_banner): port
                for port in ports
            }

            for future in as_completed(futures):
                result = future.result()
                if result:
                    with print_lock:
                        banner_info = f" | {result['banner']}" if result["banner"] else ""
                        print(f"[ABERTA]  Porta {result['port']:5d}  ({result['service']}){banner_info}")
                    open_ports.append(result)
    except KeyboardInterrupt:
        print("\nEscaneamento interrompido pelo usuário.")
        sys.exit(1)

    open_ports.sort(key=lambda x: x["port"])

    print("-" * 60)
    print(f"\nFim: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total de portas abertas encontradas: {len(open_ports)}")

    return open_ports


def export_json(host, open_ports, filename):
    """Exporta os resultados do escaneamento para um arquivo JSON."""
    data = {
        "host": host,
        "scan_date": datetime.now().isoformat(),
        "open_ports_count": len(open_ports),
        "open_ports": open_ports
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Resultados exportados para: {filename}")


def resolve_host(host):
    """Resolve um hostname para IP, se necessário."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Erro: não foi possível resolver o host '{host}'")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Scanner de portas TCP avançado para fins educacionais."
    )
    parser.add_argument("host", help="IP ou hostname alvo")
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help="Intervalo de portas no formato inicio-fim (padrão: 1-1024)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=float,
        default=1.0,
        help="Timeout em segundos por porta (padrão: 1.0)"
    )
    parser.add_argument(
        "-w", "--workers",
        type=int,
        default=100,
        help="Número máximo de threads simultâneas (padrão: 100)"
    )
    parser.add_argument(
        "-b", "--banner",
        action="store_true",
        help="Ativa a captura de banner dos serviços encontrados"
    )
    parser.add_argument(
        "-o", "--output",
        help="Caminho do arquivo JSON de saída (opcional)"
    )

    args = parser.parse_args()

    try:
        start_port, end_port = map(int, args.ports.split("-"))
    except ValueError:
        print("Erro: formato de portas inválido. Use, por exemplo: -p 1-1024")
        sys.exit(1)

    ip = resolve_host(args.host)
    open_ports = scan_range(
        ip, start_port, end_port,
        timeout=args.timeout,
        max_workers=args.workers,
        do_banner=args.banner
    )

    if args.output:
        export_json(ip, open_ports, args.output)


if __name__ == "__main__":
    main()
