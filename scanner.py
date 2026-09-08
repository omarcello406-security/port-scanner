#!/usr/bin/env python3
"""
Scanner de Portas Simples
Verifica quais portas TCP estão abertas em um host.

Uso educacional — utilize apenas em sistemas que você possui
ou tem autorização explícita para testar.
"""

import socket
import sys
import argparse
from datetime import datetime


def scan_port(host, port, timeout=1):
    """Tenta conectar em uma porta e retorna True se estiver aberta."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        return result == 0
    except socket.error:
        return False
    finally:
        sock.close()


def get_service_name(port):
    """Tenta identificar o serviço comum associado à porta."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "desconhecido"


def scan_range(host, start_port, end_port, timeout=1):
    """Escaneia um intervalo de portas e exibe o progresso."""
    print(f"\nEscaneando host: {host}")
    print(f"Intervalo de portas: {start_port}-{end_port}")
    print(f"Início: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    print("-" * 50)

    open_ports = []

    try:
        for port in range(start_port, end_port + 1):
            if scan_port(host, port, timeout):
                service = get_service_name(port)
                print(f"[ABERTA]  Porta {port:5d}  ({service})")
                open_ports.append(port)
    except KeyboardInterrupt:
        print("\nEscaneamento interrompido pelo usuário.")
        sys.exit(1)

    print("-" * 50)
    print(f"\nFim: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Total de portas abertas encontradas: {len(open_ports)}")

    return open_ports


def resolve_host(host):
    """Resolve um hostname para IP, se necessário."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Erro: não foi possível resolver o host '{host}'")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Scanner de portas TCP simples para fins educacionais."
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

    args = parser.parse_args()

    try:
        start_port, end_port = map(int, args.ports.split("-"))
    except ValueError:
        print("Erro: formato de portas inválido. Use, por exemplo: -p 1-1024")
        sys.exit(1)

    ip = resolve_host(args.host)
    scan_range(ip, start_port, end_port, args.timeout)


if __name__ == "__main__":
    main()
