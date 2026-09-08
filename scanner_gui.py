#!/usr/bin/env python3
"""
Scanner de Portas com Interface Gráfica
Interface Tkinter para o scanner de portas TCP.

Uso educacional — utilize apenas em sistemas que você possui
ou tem autorização explícita para testar.
"""

import socket
import json
import threading
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_service_name(port):
    """Tenta identificar o serviço comum associado à porta."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "desconhecido"


def scan_port(host, port, timeout=1):
    """Tenta conectar em uma porta. Retorna dict com o resultado ou None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        if result != 0:
            return None
        return {"port": port, "service": get_service_name(port)}
    except socket.error:
        return None
    finally:
        sock.close()


class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner de Portas")
        self.root.geometry("560x520")
        self.root.resizable(False, False)

        self.result_queue = queue.Queue()
        self.open_ports = []
        self.scanning = False

        self._build_ui()
        self._poll_queue()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}

        frame_top = ttk.Frame(self.root)
        frame_top.pack(fill="x", **pad)

        ttk.Label(frame_top, text="Host:").grid(row=0, column=0, sticky="w")
        self.host_entry = ttk.Entry(frame_top, width=25)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.grid(row=0, column=1, padx=5)

        ttk.Label(frame_top, text="Porta inicial:").grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.start_port_entry = ttk.Entry(frame_top, width=10)
        self.start_port_entry.insert(0, "1")
        self.start_port_entry.grid(row=1, column=1, sticky="w", padx=5, pady=(6, 0))

        ttk.Label(frame_top, text="Porta final:").grid(row=2, column=0, sticky="w")
        self.end_port_entry = ttk.Entry(frame_top, width=10)
        self.end_port_entry.insert(0, "1024")
        self.end_port_entry.grid(row=2, column=1, sticky="w", padx=5)

        ttk.Label(frame_top, text="Timeout (s):").grid(row=3, column=0, sticky="w")
        self.timeout_entry = ttk.Entry(frame_top, width=10)
        self.timeout_entry.insert(0, "0.5")
        self.timeout_entry.grid(row=3, column=1, sticky="w", padx=5)

        frame_buttons = ttk.Frame(self.root)
        frame_buttons.pack(fill="x", **pad)

        self.scan_button = ttk.Button(frame_buttons, text="Escanear", command=self.start_scan)
        self.scan_button.pack(side="left", padx=5)

        self.export_button = ttk.Button(
            frame_buttons, text="Exportar JSON", command=self.export_json, state="disabled"
        )
        self.export_button.pack(side="left", padx=5)

        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0, 6))

        self.status_label = ttk.Label(self.root, text="Pronto.")
        self.status_label.pack(anchor="w", padx=10)

        columns = ("porta", "servico")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=15)
        self.tree.heading("porta", text="Porta")
        self.tree.heading("servico", text="Serviço")
        self.tree.column("porta", width=100, anchor="center")
        self.tree.column("servico", width=400)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

    def start_scan(self):
        if self.scanning:
            return

        host = self.host_entry.get().strip()
        try:
            start_port = int(self.start_port_entry.get())
            end_port = int(self.end_port_entry.get())
            timeout = float(self.timeout_entry.get())
        except ValueError:
            messagebox.showerror("Erro", "Verifique os valores de porta e timeout.")
            return

        if not host:
            messagebox.showerror("Erro", "Informe um host.")
            return

        try:
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            messagebox.showerror("Erro", f"Não foi possível resolver o host '{host}'.")
            return

        self.tree.delete(*self.tree.get_children())
        self.open_ports = []
        self.export_button.config(state="disabled")
        self.scanning = True
        self.scan_button.config(state="disabled", text="Escaneando...")

        total_ports = end_port - start_port + 1
        self.progress.config(maximum=total_ports, value=0)
        self.status_label.config(text=f"Escaneando {ip} ({total_ports} portas)...")

        thread = threading.Thread(
            target=self._run_scan, args=(ip, start_port, end_port, timeout), daemon=True
        )
        thread.start()

    def _run_scan(self, ip, start_port, end_port, timeout):
        scanned = 0
        with ThreadPoolExecutor(max_workers=150) as executor:
            futures = {
                executor.submit(scan_port, ip, port, timeout): port
                for port in range(start_port, end_port + 1)
            }
            for future in as_completed(futures):
                scanned += 1
                result = future.result()
                self.result_queue.put(("progress", scanned))
                if result:
                    self.result_queue.put(("open_port", result))

        self.result_queue.put(("done", ip))

    def _poll_queue(self):
        try:
            while True:
                kind, data = self.result_queue.get_nowait()
                if kind == "progress":
                    self.progress.config(value=data)
                elif kind == "open_port":
                    self.open_ports.append(data)
                    self.tree.insert("", "end", values=(data["port"], data["service"]))
                elif kind == "done":
                    self.scanning = False
                    self.scan_button.config(state="normal", text="Escanear")
                    self.status_label.config(
                        text=f"Concluído. {len(self.open_ports)} porta(s) aberta(s) em {data}."
                    )
                    if self.open_ports:
                        self.export_button.config(state="normal")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def export_json(self):
        if not self.open_ports:
            return
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile="resultado_scan.json"
        )
        if not filename:
            return

        data = {
            "host": self.host_entry.get().strip(),
            "scan_date": datetime.now().isoformat(),
            "open_ports_count": len(self.open_ports),
            "open_ports": self.open_ports
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        messagebox.showinfo("Exportado", f"Resultados salvos em:\n{filename}")


def main():
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
