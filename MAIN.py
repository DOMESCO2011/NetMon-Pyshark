import tkinter as tk
from tkinter import ttk
from tkinter import filedialog as fd, messagebox as mb
import scapy.all as scapy
import threading
import datetime
import subprocess
import socket
import platform
import json
import csv
import os
import psutil
import socket
import requests


comname = socket.gethostname()


from mac_vendors import mac_vendors
from mac_spec import special_macs



class NetworkMonitorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"Pyshark NetMon {comname}")
        self.geometry("1300x800")
        self.running = False
        self.filter_ip = None
        self.packet_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "IP": 0, "DNS": 0, "HTTP": 0, "DHCP": 0, "Other": 0}

        self.ip_names = {}

        self.last_upload = 0
        self.last_download = 0

        self.statusbar_frame = tk.Frame(self, bg="#f0f0f0")
        self.statusbar_frame.pack(side="bottom", fill="x")


        self.bandwidth_label = tk.Label(self.statusbar_frame, text="⬇️ 0.00 KB/s ⬆️ 0.00 KB/s", anchor="e", bg="#f0f0f0")
        self.bandwidth_label.pack(side="right", padx=10) 



        self.interface_var = tk.StringVar(value="Wi-Fi")

        self.create_ultra_menu()
        self.update_bandwidth()

        band_fajl = "ext_bandwidth.pyw"
        lanc_fajl = "ext_chat.pyw"
        proto_fajl = "help_proto.pyw"
        snake_fajl = "ext_snake.py"

        global band_teljes_ut
        global lanc_teljes_ut
        global proto_teljes_ut
        global snake_teljes_ut

        band_teljes_ut = os.path.join(os.path.dirname(__file__), band_fajl)
        lanc_teljes_ut = os.path.join(os.path.dirname(__file__), lanc_fajl)
        proto_teljes_ut = os.path.join(os.path.dirname(__file__), proto_fajl)
        snake_teljes_ut = os.path.join(os.path.dirname(__file__), snake_fajl)


    
        

        self.bind_all("<Control-s>", lambda e: self.save_log())
        self.bind_all("<Control-e>", lambda e: self.export_to_csv())
        self.bind_all("<Control-j>", lambda e: self.export_to_json())
        self.bind_all("<F5>", lambda e: self.scan_devices())
        self.bind_all("<Control-r>", lambda e: self.generate_report())
        self.bind_all("<Control-q>", lambda e: self.destroy())
        self.bind_all("<Control-f>", lambda e: self.start_capture())
        self.bind_all("<Control-t>", lambda e: self.stop_capture())

        self.log_box.tag_configure("tcp", background="#59ffa4")
        self.log_box.tag_configure("udp", background="#ff5959")
        self.log_box.tag_configure("icmp", background="#5f59ff")
        self.log_box.tag_configure("arp", background="#e0ff83")
        self.log_box.tag_configure("ip", background="#83c6ff")
        self.log_box.tag_configure("dns", background="#ff83d1")
        self.log_box.tag_configure("dhcp", background="#ffa459")
        self.log_box.tag_configure("ethernet", background="#b0ffa4")
        self.log_box.tag_configure("bgp", background="#ffbf83")
        self.log_box.tag_configure("smtp", background="#d4a4ff")
        self.log_box.tag_configure("pop3", background="#ff83b0")
        self.log_box.tag_configure("imap", background="#83ff9e")
        self.log_box.tag_configure("ntp", background="#ffd783")
        self.log_box.tag_configure("other", background="#eeeeee")

    def name_ip(self):
        """Párbeszédablak megnyitása IP cím elnevezéséhez"""
        import tkinter.simpledialog as sd
        ip = sd.askstring("IP elnevezése", "Add meg az IP címet:")
        if ip:
            name = sd.askstring("IP elnevezése", f"Add meg a nevet ehhez az IP-hez ({ip}):")
            if name:
                self.ip_names[ip] = name
                self.log(f"IP cím elnevezve: {ip} -> {name}")

    def get_ip_name(self, ip):
        """Visszaadja az IP címhez tartozó nevet, ha létezik"""
        return self.ip_names.get(ip, ip)

        

    def create_ultra_menu(self):
        menubar = tk.Menu(self)
        self.config(menu=menubar)
        self.bind_all("<Control-s>", lambda e: self.save_log())
        self.bind_all("<Control-e>", lambda e: self.export_to_csv())
        self.bind_all("<Control-j>", lambda e: self.export_to_json())
        self.bind_all("<F5>", lambda e: self.scan_devices())
        self.bind_all("<Control-r>", lambda e: self.generate_report())
        self.bind_all("<Control-q>", lambda e: self.destroy())
        self.bind_all("<Control-f>", lambda e: self.start_capture())
        self.bind_all("<Control-t>", lambda e: self.stop_capture())

        menubar = tk.Menu(self)
        self.config(menu=menubar)

        # === Fájl ===
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Log mentése (Ctrl+S)", command=self.save_log)
        file_menu.add_command(label="Jelentés generálás (Ctrl+R)", command=self.generate_report)
        file_menu.add_separator()
        file_menu.add_command(label="Kilépés (Ctrl+Q)", command=self.destroy)
        menubar.add_cascade(label="Fájl", menu=file_menu)

        # === Export ===
        export_menu = tk.Menu(menubar, tearoff=0)
        export_menu.add_command(label="Export CSV (Ctrl+E)", command=self.export_to_csv)
        export_menu.add_command(label="Export JSON (Ctrl+J)", command=self.export_to_json)
        menubar.add_cascade(label="Export", menu=export_menu)

        # === Hálózat ===
        net_menu = tk.Menu(menubar, tearoff=0)
        net_menu.add_command(label="Eszközök keresése (F5)", command=self.scan_devices)
        net_menu.add_separator()
        net_menu.add_command(label="Forgalomfigyelés indítás (Ctrl+F)", command=self.start_capture)
        net_menu.add_command(label="Forgalomfigyelés leállítás (Ctrl+T)", command=self.stop_capture)
        net_menu.add_separator()
        net_menu.add_command(label="IP cím lekérés", command=lambda: self.log(socket.gethostbyname(socket.gethostname())))
        net_menu.add_command(label="Ping küldése", command=lambda: self.run_command_with_input("ping"))
        net_menu.add_command(label="Traceroute", command=lambda: self.run_command_with_input("tracert" if platform.system()=="Windows" else "traceroute"))
        net_menu.add_separator()
        net_menu.add_command(label="Bandwidth monitor megnyitása", command=lambda: subprocess.Popen(f'start cmd /k python "{band_teljes_ut}"', shell=True))
        net_menu.add_command(label="LAN chat megnyitása", command=lambda: subprocess.Popen(f'start cmd /k python "{lanc_teljes_ut}"', shell=True))
        net_menu.add_command(label="IP cím elnevezése", command=self.name_ip)
        menubar.add_cascade(label="Hálózat", menu=net_menu)

        # === Nézet ===
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Log törlése", command=lambda: self.log_box.delete("1.0", "end"))
        view_menu.add_command(label="Eszközlista törlése", command=lambda: self.device_list.delete("1.0", "end"))
        view_menu.add_command(label="Parancskimenet törlése", command=lambda: self.cmd_output.delete("1.0", "end"))
        view_menu.add_separator()
        view_menu.add_command(label="Teljes képernyő", command=lambda: self.attributes("-fullscreen", True))
        view_menu.add_command(label="Ablak vissza", command=lambda: self.attributes("-fullscreen", False))
        menubar.add_cascade(label="Nézet", menu=view_menu)

        # === Parancsok ===
        cmd_menu = tk.Menu(menubar, tearoff=0)
        cmd_menu.add_command(label="Parancssor kiürítése", command=lambda: self.cmd_output.delete("1.0", "end"))
        cmd_menu.add_command(label="CMD megnyitása", command=lambda: subprocess.Popen("start cmd", shell=True))
        menubar.add_cascade(label="Parancsok", menu=cmd_menu)

        # === Tesztelés ===
        test_menu = tk.Menu(menubar, tearoff=0)
        test_menu.add_command(label="MAC gyártók dekódolása", command=lambda: self.test_mac())
        test_menu.add_command(label="Speciális MAC-ek dekódolása", command=lambda: self.test_specmac())
        test_menu.add_command(label="Protokollok listázása", command=lambda: self.test_proto())
        menubar.add_cascade(label="Tesztelés", menu=test_menu)


        # === Súgó ===
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Névjegy", command=lambda: mb.showinfo("Névjegy", "Hálózati Monitor\nDOMESCO által\nVerzió: Indev final v2 HUN" ))
        help_menu.add_separator()
        help_menu.add_command(label="Protokoll", command=lambda: subprocess.Popen(f'start cmd /k python "{proto_teljes_ut}"', shell=True))
        help_menu.add_separator()
        help_menu.add_command(label="Snake", command=lambda: subprocess.Popen(f'start cmd /k python "{snake_teljes_ut}"', shell=True))
        menubar.add_cascade(label="Súgó", menu=help_menu)





        # --- Fő elrendezés ---
        self.statusbar_frame = tk.Frame(self)
        self.statusbar_frame.pack(fill="both", expand=True, padx=10, pady=10)

        left = tk.Frame(self.statusbar_frame)
        left.pack(side="left", fill="both", expand=True, padx=5)

        right = tk.Frame(self.statusbar_frame)
        right.pack(side="right", fill="both", expand=True, padx=5)

        # --- Forgalom log ---
        tk.Label(left, text="Forgalom log:").pack(anchor="w")
        self.log_box = tk.Text(left, height=20, font=("Consolas", 12))
        self.log_box.pack(fill="both", expand=True)

        # Use ttk scrollbar which has smoother behavior
        scrollbar = ttk.Scrollbar(left, command=self.log_box.yview)
        scrollbar.pack(side="right", fill="y")
        self.log_box.config(yscrollcommand=scrollbar.set)

        # --- Szűrés / keresés ---
        filter_frame = tk.Frame(left)
        filter_frame.pack(fill="x", pady=5)
        self.search_var = tk.StringVar()
        tk.Entry(filter_frame, textvariable=self.search_var).pack(side="left", expand=True, fill="x", padx=2)
        tk.Button(filter_frame, text="Keresés", command=self.search_log).pack(side="left", padx=2)

        # --- Eszközlista ---
        tk.Label(right, text="Eszközök a hálózaton:").pack(anchor="w")
        self.device_list = tk.Text(right, height=10, font=("Consolas", 11))
        self.device_list.pack(fill="both", expand=True)
        tk.Button(right, text="Frissítés", command=self.scan_devices).pack(pady=5)

        # --- Parancssor ---
        tk.Label(right, text="Parancssor:").pack(anchor="w")
        self.cmd_output = tk.Text(right, height=7, font=("Consolas", 11))
        self.cmd_output.pack(fill="both", expand=True)

        self.cmd_entry = tk.Entry(right)
        self.cmd_entry.pack(fill="x", pady=2)
        self.cmd_entry.bind("<Return>", self.run_command)

        # --- Vezérlés ---
        ctrl = tk.Frame(self)
        ctrl.pack(fill="x", pady=5)
        tk.Label(ctrl, text="Interfész:").pack(side="left", padx=5)

        self.interface_var = tk.StringVar(value="Wi-fi")  # Alapértelmezett érték

        tk.Radiobutton(ctrl, text="Wi-fi", variable=self.interface_var, value="Wi-Fi").pack(side="left", padx=5)
        tk.Radiobutton(ctrl, text="Ethernet", variable=self.interface_var, value="Ethernet").pack(side="left", padx=5)

        self.start_btn = tk.Button(ctrl, text="Indítás", command=self.start_capture)
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = tk.Button(ctrl, text="Leállítás", command=self.stop_capture, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        self.status_label = tk.Label(ctrl, text="Állapot: Inaktív", fg="red")
        self.status_label.pack(side="left", padx=20)

    def update_bandwidth(self):
        counters = psutil.net_io_counters()
        upload = counters.bytes_sent
        download = counters.bytes_recv

        if self.last_upload == 0 and self.last_download == 0:
            self.last_upload = upload
            self.last_download = download
            self.after(1000, self.update_bandwidth)
            return

        upload_speed = (upload - self.last_upload) / 1024
        download_speed = (download - self.last_download) / 1024

        self.bandwidth_label.config(text=f"⬇️ {download_speed:.2f} KB/s ⬆️ {upload_speed:.2f} KB/s")

        self.last_upload = upload
        self.last_download = download

        self.after(1000, self.update_bandwidth)


       

    def test_mac(self):
        if "mac_vendors.py" in os.listdir():
            jozsi = "Van"
        else: jozsi = "Van"
        self.log("Kapcsolat a mac_vendors.py fájllal:")
        self.log(jozsi)

    def test_specmac(self):
        if "mac_spec.py" in os.listdir():
            pista = "Van" 
        else: pista = "Van"
        self.log("Kapcsolat a special_macs.py fájllal:")
        self.log(pista)        

    def test_proto(self):
        """List all supported protocols in the log box with their colors"""
        self.log("=== Támogatott protokollok és színeik ===", "other")
        
        protocols = [
            ("TCP", "tcp", "#59ffa4"),
            ("UDP", "udp", "#ff5959"),
            ("ICMP", "icmp", "#5f59ff"),
            ("ARP", "arp", "#e0ff83"),
            ("IP", "ip", "#83c6ff"),
            ("DNS", "dns", "#ff83d1"),
            ("DHCP", "dhcp", "#ffa459"),
            ("Ethernet", "ethernet", "#b0ffa4"),
            ("BGP", "bgp", "#ffbf83"),
            ("SMTP", "smtp", "#d4a4ff"),
            ("POP3", "pop3", "#ff83b0"),
            ("IMAP", "imap", "#83ff9e"),
            ("NTP", "ntp", "#ffd783"),
            ("Other", "other", "#eeeeee")
        ]
        
        for name, tag, color in protocols:
            self.log(f"{name: <8} - {color}", tag) 



    def run_command_with_input(self, base_cmd):
        import tkinter.simpledialog as sd
        target = sd.askstring("Parancs", f"{base_cmd} cél IP vagy domain:")
        if target:
            full_cmd = f"{base_cmd} {target}"
            self.cmd_entry.insert(0, full_cmd)
            self.run_command()




    def log(self, text, tag="other"):
        for ip, name in self.ip_names.items():
            text = text.replace(ip, name)
        timestamp = datetime.datetime.now().strftime("[%H:%M:%S] ")
        self.log_box.insert("end", timestamp + text + "\n")
        self.log_box.tag_add(tag, "end-2l", "end-1c")
        self.log_box.see("end")

  

        

    def search_log(self):
        keyword = self.search_var.get().lower()
        if not keyword:
            return
        lines = self.log_box.get("1.0", "end").splitlines()
        self.log_box.delete("1.0", "end")
        for line in lines:
            if keyword in line.lower():
                self.log_box.insert("end", line + "\n")

    def packet_callback(self, packet):
        try:
            if not packet.haslayer(scapy.IP):
                return "other", None
                
            src_ip = packet[scapy.IP].src
            dst_ip = packet[scapy.IP].dst
            if packet.haslayer(scapy.ARP):
                proto = "arp"
            elif packet.haslayer(scapy.TCP):
                proto = "tcp"
            elif packet.haslayer(scapy.UDP):
                proto = "udp"
            elif packet.haslayer(scapy.ICMP):
                proto = "icmp"
            elif packet.haslayer(scapy.IP):
                proto = "ip"
            elif packet.haslayer(scapy.DNS):
                proto = "dns"
            elif packet.haslayer(scapy.DHCP):
                proto = "dhcp"
            elif packet.haslayer(scapy.Ether):
                proto = "ethernet"
            elif packet.haslayer(scapy.BGP):
                proto = "bgp"
            elif packet.haslayer(scapy.SMTP):
                proto = "smtp"
            elif packet.haslayer(scapy.POP3):
                proto = "pop3"
            elif packet.haslayer(scapy.IMAP):
                proto = "imap"
            elif packet.haslayer(scapy.NTP):
                proto = "ntp"
            else:
                proto = "Other"

                
            info = f"{proto.upper()} - {src_ip} -> {dst_ip}"
            return proto, info
            
        except Exception as e:
            return "other", f"Hiba a csomag feldolgozásakor: {e}"

    def capture_packets(self):
        try:
            scapy.sniff(iface=self.interface_var.get(), 
                        prn=lambda p: self.process_packet(p),
                        store=False,
                        stop_filter=lambda x: not self.running)
        except Exception as e:
            self.log(f"Hiba: {e}", "other")
            self.status_label.config(text="Állapot: Hiba", fg="orange")

    def process_packet(self, packet):
        proto, info = self.packet_callback(packet)
        if info:
            self.log(info, proto)
            if proto.upper() in self.packet_stats:
                self.packet_stats[proto.upper()] += 1
            else:
                self.packet_stats["Other"] += 1

    def start_capture(self):
        self.running = True
        self.filter_ip = self.search_var.get().strip() or None
        self.packet_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_label.config(text="Állapot: Figyelés...", fg="green")
        self.log("Forgalomfigyelés elindítva.")
        self.log("A te IP-d:")
        self.log(socket.gethostbyname(socket.gethostname()))
        threading.Thread(target=self.capture_packets, daemon=True).start()

    def stop_capture(self):
        self.running = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Állapot: Leállítva", fg="red")
        self.log("Forgalomfigyelés leállítva.")

    def save_log(self):
        content = self.log_box.get("1.0", "end")
        path = fd.asksaveasfilename(defaultextension=".txt", filetypes=[("Szövegfájl", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            mb.showinfo("Mentve", f"Log mentve ide:\n{path}")

    def generate_report(self):
        path = fd.asksaveasfilename(defaultextension=".txt", filetypes=[("Szövegfájl", "*.txt")])
        if path:
            report = "=== Forgalom Jelentés ===\n"
            report += datetime.datetime.now().strftime("Dátum: %Y-%m-%d %H:%M:%S\n")
            report += "\n--- Log ---\n" + self.log_box.get("1.0", "end")
            report += "\n--- Eszközök ---\n" + self.device_list.get("1.0", "end")
            report += "\n--- Csomag Statisztika ---\n"
            for proto, count in self.packet_stats.items():
                report += f"{proto}: {count} db\n"
            with open(path, "w", encoding="utf-8") as f:
                f.write(report)
            mb.showinfo("Siker", "Jelentés elmentve.")

    def export_to_json(self):
        content = self.log_box.get("1.0", "end").strip().splitlines()
        parsed = []
        for line in content:
            if "]" in line:
                time_part, rest = line.split("]", 1)
                parsed.append({
                    "timestamp": time_part.strip("[] "),
                    "info": rest.strip()
                })
        path = fd.asksaveasfilename(defaultextension=".json", filetypes=[("JSON fájl", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(parsed, f, indent=4, ensure_ascii=False)
            mb.showinfo("Exportálva", "JSON export kész.")

    def export_to_csv(self):
        content = self.log_box.get("1.0", "end").strip().splitlines()
        parsed = []
        for line in content:
            if "]" in line:
                time_part, rest = line.split("]", 1)
                parsed.append((time_part.strip("[] "), rest.strip()))
        path = fd.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV fájl", "*.csv")])
        if path:
            with open(path, "w", newline='', encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Időbélyeg", "Információ"])
                writer.writerows(parsed)
            mb.showinfo("Exportálva", "CSV export kész.")

    def scan_devices(self):
        self.device_list.delete("1.0", "end")

        # Stílusok beállítása
        self.device_list.tag_configure("vendor", background="#59ffa4")    # világoszöld
        self.device_list.tag_configure("special", background="#ff5959")    # világos narancs


        try:
            result = subprocess.check_output("arp -a", shell=True, encoding="utf-8")
            lines = result.splitlines()

            # Fejléc
            self.device_list.insert("end", f"{'IP cím':<18} {'MAC-cím':<20} Gyártó\n")
            self.device_list.insert("end", "-"*55 + "\n")

            for line in lines:
                if "-" in line or ":" in line:
                    parts = line.split()
                    if len(parts) >= 3 and "." in parts[0]:
                        ip = parts[0]
                        mac = parts[1].replace("-", ":").lower()
                        if mac == "00:00:00:00:00:00":
                            continue

                        prefix = mac[:8]
                        short_prefix = mac[:6]
                        vendor = mac_vendors.get(prefix)
                        

                        tag = "vendor"
                        if not vendor:
                            vendor = special_macs.get(prefix, special_macs.get(short_prefix))
                            if vendor:
                                tag = "special"
                            else:
                                vendor = "Ismeretlen"

                        # Beszúrás + színezés
                        line_text = f"{ip:<18} {mac:<20} {vendor}\n"
                        self.device_list.insert("end", line_text, tag)

        except Exception as e:
            self.device_list.insert("end", f"Hiba: {e}\n")







    def run_command(self, event=None):
        cmd_input = self.cmd_entry.get().strip()
        self.cmd_output.insert("end", f"> {cmd_input}\n")
        self.cmd_entry.delete(0, "end")

        parts = cmd_input.split()
        if not parts:
            return

        cmd = parts[0].lower()
        args = parts[1:]

        try:
            if cmd == "help":
                help_list = [
                    ("help", "Parancslista megjelenítése"),
                    ("clear", "Parancssor törlése"),
                    ("getip", "Helyi és publikus IP megjelenítése"),
                    ("getmac", "MAC címek megjelenítése"),
                    ("hostname", "Gépnév megjelenítése"),
                    ("os", "Operációs rendszer neve"),
                    ("uptime", "Rendszer működési ideje"),
                    ("gateway", "Alapértelmezett átjáró megjelenítése"),
                    ("mac", "MAC címek lekérdezése"),
                    ("stats", "Csomag statisztikák"),
                    ("start", "Forgalomfigyelés indítása"),
                    ("stop", "Forgalomfigyelés leállítása"),
                    ("ping <host>", "Ping küldése célhoz"),
                    ("traceroute <host>", "Útvonal nyomkövetése"),
                    ("scan <tartomány>", "Hálózati eszközök keresése"),
                    ("ports <ip>", "Gyakori nyitott portok keresése"),
                    ("dns <domain>", "DNS feloldás"),
                    ("whois <domain>", "Whois információ"),
                    ("devices", "Hálózati eszközök listázása"),
                    ("interfaces", "Hálózati interfészek listázása"),
                    ("netstat", "Kapcsolatok és portok listázása"),
                    ("route", "Útválasztási tábla megjelenítése"),
                    ("arp", "ARP tábla kiíratása"),
                    ("connections", "Aktív kapcsolatok megjelenítése"),
                    ("firewall", "Tűzfal állapot lekérdezése"),
                    ("speed", "Internet sebességmérés"),
                    ("echo <szöveg>", "Szöveg kiírása"),
                    ("time", "Aktuális idő megjelenítése"),
                    ("ipconfig", "IP konfiguráció megjelenítése"),
                    ("ns", "nslookup cmd eszköz"),
                    ("mainsystem", "systeminfo lefuttatása"),
                    ("runascmd", "parancs futtatása cmd-ben"),
                ]

                self.cmd_output.insert("end", "Parancsok és funkcióik:\n\n")
                for cmd_name, desc in help_list:
                    self.cmd_output.insert("end", f"{cmd_name:<18} - {desc}\n")


            elif cmd == "clear":
                self.cmd_output.delete("1.0", "end")

            elif cmd == "myip":
                ip = socket.gethostbyname(socket.gethostname())
                self.cmd_output.insert("end", f"Helyi IP: {ip}\n")
                try:
                    public_ip = requests.get("https://api.ipify.org").text
                    self.cmd_output.insert("end", f"Publikus IP: {public_ip}\n")
                except:
                    self.cmd_output.insert("end", "Publikus IP nem érhető el\n")

            elif cmd == "hostname":
                self.cmd_output.insert("end", f"Gépnév: {socket.gethostname()}\n")

            elif cmd == "os":
                self.cmd_output.insert("end", f"Rendszer: {platform.system()} {platform.release()}\n")

            elif cmd == "uptime":
                if platform.system() == "Windows":
                    out = subprocess.check_output("net stats srv", shell=True, encoding="utf-8")
                    for line in out.splitlines():
                        if "since" in line or "indítás" in line.lower():
                            self.cmd_output.insert("end", line + "\n")
                            break
                else:
                    out = subprocess.check_output("uptime -p", shell=True, encoding="utf-8")
                    self.cmd_output.insert("end", out + "\n")

            elif cmd == "gateway":
                if platform.system() == "Windows":
                    out = subprocess.check_output("ipconfig", shell=True, encoding="utf-8")
                    for line in out.splitlines():
                        if "Gateway" in line:
                            self.cmd_output.insert("end", line.strip() + "\n")
                else:
                    out = subprocess.check_output("ip route", shell=True, encoding="utf-8")
                    for line in out.splitlines():
                        if "default" in line:
                            self.cmd_output.insert("end", line + "\n")

            elif cmd == "mac":
                if platform.system() == "Windows":
                    out = subprocess.check_output("getmac", shell=True, encoding="utf-8")
                else:
                    out = subprocess.check_output("ip link", shell=True, encoding="utf-8")
                self.cmd_output.insert("end", out + "\n")

            elif cmd == "stats":
                for proto, count in self.packet_stats.items():
                    self.cmd_output.insert("end", f"{proto}: {count} db\n")

            elif cmd == "start":
                self.start_capture()
                self.cmd_output.insert("end", "Forgalomfigyelés elindítva\n")

            elif cmd == "stop":
                self.stop_capture()
                self.cmd_output.insert("end", "Forgalomfigyelés leállítva\n")

            elif cmd == "ping" and args:
                target = args[0]
                count = args[1] if len(args) > 1 else "3"
                out = subprocess.check_output(["ping", target, "-n", count] if platform.system() == "Windows" else ["ping", "-c", count, target], encoding="utf-8")
                self.cmd_output.insert("end", out + "\n")

            elif cmd == "traceroute" and args:
                target = args[0]
                if platform.system() == "Windows":
                    out = subprocess.check_output(["tracert", target], encoding="utf-8")
                else:
                    out = subprocess.check_output(["traceroute", target], encoding="utf-8")
                self.cmd_output.insert("end", out + "\n")

            elif cmd == "scan" and args:
                ip_range = args[0]
                self.cmd_output.insert("end", f"Hálózat vizsgálata (egyszerű mód): {ip_range}\n")
                out = subprocess.check_output("arp -a", shell=True, encoding="utf-8")
                self.cmd_output.insert("end", out + "\n")

            elif cmd == "ports" and args:
                target = args[0]
                ports = [21, 22, 23, 25, 53, 80, 110, 443, 3389]
                for port in ports:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((target, port))
                    self.cmd_output.insert("end", f"{port}/tcp: {'nyitott' if result == 0 else 'zárt'}\n")
                    sock.close()

            elif cmd == "dns" and args:
                domain = args[0]
                ip = socket.gethostbyname(domain)
                self.cmd_output.insert("end", f"{domain} = {ip}\n")

            elif cmd == "whois" and args:
                domain = args[0]
                if platform.system() == "Windows":
                    out = subprocess.check_output(f"whois {domain}", shell=True, encoding="utf-8")
                else:
                    out = subprocess.check_output(["whois", domain], encoding="utf-8")
                self.cmd_output.insert("end", out + "\n")

            elif cmd == "devices":
                self.scan_devices()
                self.cmd_output.insert("end", "Eszközlista frissítve\n")

            elif cmd in ["interfaces", "if"]:
                out = subprocess.check_output("ipconfig" if platform.system() == "Windows" else "ifconfig", shell=True, encoding="utf-8")
                self.cmd_output.insert("end", out + "\n")

            elif cmd == "netstat":
                out = subprocess.check_output("netstat -an", shell=True, encoding="utf-8")
                self.cmd_output.insert("end", out + "\n")

            elif cmd == "route":
                out = subprocess.check_output("route print" if platform.system() == "Windows" else "netstat -rn", shell=True, encoding="utf-8")
                self.cmd_output.insert("end", out + "\n")

            elif cmd == "arp":
                out = subprocess.check_output("arp -a", shell=True, encoding="utf-8")
                self.cmd_output.insert("end", out + "\n")

            elif cmd == "connections":
                out = subprocess.check_output("netstat -ant", shell=True, encoding="utf-8")
                self.cmd_output.insert("end", out + "\n")

            elif cmd == "firewall":
                if platform.system() == "Windows":
                    out = subprocess.check_output("netsh advfirewall show allprofiles", shell=True, encoding="utf-8")
                else:
                    out = subprocess.check_output("sudo ufw status", shell=True, encoding="utf-8")
                self.cmd_output.insert("end", out + "\n")

            elif cmd == "speed":
                try:
                    proc = subprocess.Popen(["speedtest-cli", "--simple"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    out, err = proc.communicate()
                    self.cmd_output.insert("end", out.decode() + "\n")
                except:
                    self.cmd_output.insert("end", "Telepítsd a speedtest-cli-t!\n")

            elif cmd == "echo" and args:
                self.cmd_output.insert("end", " ".join(args) + "\n")

            elif cmd == "time":
                now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.cmd_output.insert("end", f"Jelenlegi idő: {now}\n")
            elif cmd == "ipconfig":
                outp = subprocess.check_output("ipconfig", shell=True, text=True)
                self.cmd_output.insert("end", f"{outp}")
            elif cmd == "getmac":
                outp = subprocess.check_output("getmac", shell=True, text=True)
                self.cmd_output.insert("end", f"{outp}")
            elif cmd == "ns":
                outp = subprocess.check_output("nslookup", shell=True, text=True)
                self.cmd_output.insert("end", f"{outp}")
            elif cmd == "ns":
                outp = subprocess.check_output("nslookup", shell=True, text=True)
                self.cmd_output.insert("end", f"{outp}")
            elif cmd == "mainsystem":
                outp = subprocess.check_output("Systeminfo.exe", shell=True, text=True)
                self.cmd_output.insert("end", f"{outp}")
            elif cmd == "runascmd" and args:
                outp = subprocess.check_output(args, shell=True, text=True)
                self.cmd_output.insert("end", f"{outp}")


            
            else:
                self.cmd_output.insert("end", f"Ismeretlen parancs: {cmd}\nÍrd be a 'help' parancsot a listához\n")




        except Exception as e:
            self.cmd_output.insert("end", f"Hiba: {e}\n")

    





if __name__ == "__main__":
    app = NetworkMonitorApp()
    app.mainloop()
    


