import tkinter as tk
from tkinter import ttk

protokollok = {
    "ARP": "ARP\nHálózati réteg\nAz ARP protokoll célja az IP címek és MAC címek közötti leképezés.",
    "IP": "IP\nHálózati réteg\nAz alapvető hálózati réteget biztosítja a csomagok számára az interneten.",
    "TCP": "TCP\nSzállítási réteg\nAz adatkapcsolati réteget biztosítja, amely megbízható adatátvitelt garantál.",
    "UDP": "UDP\nSzállítási réteg\nAz UDP egy egyszerűbb, nem megbízható adatátviteli protokoll.",
    "ICMP": "ICMP\nHálózati réteg\nA hibajelzéseket és diagnosztikai információkat biztosító protokoll (pl. ping).",
    "DNS": "DNS\nAlkalmazási réteg\nA domain nevek és IP címek közötti leképezést végzi.",
    "HTTP": "HTTP\nAlkalmazási réteg\nA weboldalak kérését és válaszait biztosító protokoll.",
    "DHCP": "DHCP\nAlkalmazási réteg\nDinamikusan hozzárendeli a hálózati eszközök IP címeit.",
    "Ethernet": "Ethernet\nAdatkapcsolati réteg\nAz adatlink réteghez tartozó protokoll, amely az Ethernet hálózatokat biztosítja.",
    "BGP": "BGP\nHálózati réteg\nA routolási információkat cserélő protokoll az internetről.",
    "SMTP": "SMTP\nAlkalmazási réteg\nE-mailek küldésére használt protokoll.",
    "POP3": "POP3\nAlkalmazási réteg\nE-mailek letöltésére szolgáló protokoll.",
    "IMAP": "IMAP\nAlkalmazási réteg\nE-mailek letöltésére és kezelésére használt protokoll.",
    "NTP": "NTP\nAlkalmazási réteg\nAz idő szinkronizálásához használt protokoll."
}


def show_protocol(event):
    selected = listbox.get(listbox.curselection())
    text.delete(1.0, tk.END)
    text.insert(tk.END, protokollok[selected])

root = tk.Tk()
root.title("Protokoll súgó")
root.geometry("500x400")

frame = tk.Frame(root)
frame.pack(fill=tk.BOTH, expand=True)

listbox = tk.Listbox(frame, font=("Arial", 12), bg="#f0f0f0")
listbox.pack(side=tk.LEFT, fill=tk.Y)

for protocol in protokollok:
    listbox.insert(tk.END, protocol)

text = tk.Text(frame, wrap=tk.WORD, font=("Arial", 12), bg="#ffffff", padx=10, pady=10)
text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

listbox.bind("<Double-1>", show_protocol)

root.mainloop()
