import tkinter as tk
import psutil

# Konstansok
REFRESH_DELAY = 1000  # frissítési idő ms

# Állapotváltozók
last_upload = 0
last_download = 0

# Alkalmazás ablak létrehozása
window = tk.Tk()
window.title("Network Bandwidth Monitor")
window.geometry("400x300")
window.resizable(False, False)
window.configure(bg="#f0f2f5")  # világos háttér

# Alapértelmezett betűtípus
font_title = ("Segoe UI", 16, "bold")
font_label = ("Segoe UI", 11)
font_data = ("Segoe UI", 11, "bold")

# Fejléc
header = tk.Label(window, text="📡 Network Bandwidth Monitor", font=font_title, bg="#f0f2f5", fg="#333")
header.pack(pady=(10, 5))

# Tartalomkeret
main_frame = tk.Frame(window, bg="#ffffff", bd=1, relief="groove")
main_frame.pack(padx=20, pady=10, fill="both", expand=True)

# Sorok a fő adatoknak
label_total_upload = tk.Label(main_frame, text="📤 Total Upload:", font=font_label, bg="#ffffff", anchor="w")
value_total_upload = tk.Label(main_frame, text="0.00 GB", font=font_data, bg="#ffffff", anchor="e")

label_total_download = tk.Label(main_frame, text="📥 Total Download:", font=font_label, bg="#ffffff", anchor="w")
value_total_download = tk.Label(main_frame, text="0.00 GB", font=font_data, bg="#ffffff", anchor="e")

label_total_usage = tk.Label(main_frame, text="🔄 Total Usage:", font=font_label, bg="#ffffff", anchor="w")
value_total_usage = tk.Label(main_frame, text="0.00 GB", font=font_data, bg="#ffffff", anchor="e")

label_upload_speed = tk.Label(main_frame, text="⬆️ Upload Speed:", font=font_label, bg="#ffffff", anchor="w")
value_upload_speed = tk.Label(main_frame, text="0.00 KB/s", font=font_data, bg="#ffffff", anchor="e")

label_download_speed = tk.Label(main_frame, text="⬇️ Download Speed:", font=font_label, bg="#ffffff", anchor="w")
value_download_speed = tk.Label(main_frame, text="0.00 KB/s", font=font_data, bg="#ffffff", anchor="e")

# Rácsba rendezés
rows = [
    (label_total_upload, value_total_upload),
    (label_total_download, value_total_download),
    (label_total_usage, value_total_usage),
    (label_upload_speed, value_upload_speed),
    (label_download_speed, value_download_speed),
]

for i, (label, value) in enumerate(rows):
    label.grid(row=i, column=0, sticky="w", padx=10, pady=3)
    value.grid(row=i, column=1, sticky="e", padx=10, pady=3)

# Alsó sáv
footer = tk.Label(window, text="~ WaterrMalann and Domesco~", font=("Segoe UI", 9, "italic"), bg="#f0f2f5", fg="#555")
footer.pack(pady=(5, 10))

# Adatok frissítése
def update():
    global last_upload, last_download

    counters = psutil.net_io_counters()
    upload = counters.bytes_sent
    download = counters.bytes_recv

    # Első hívásnál csak tárol
    if last_upload == 0 and last_download == 0:
        last_upload = upload
        last_download = download
        window.after(REFRESH_DELAY, update)
        return

    upload_speed = (upload - last_upload) / 1024  # KB/s
    download_speed = (download - last_download) / 1024  # KB/s

    total_upload = upload / (1024 ** 3)  # GB
    total_download = download / (1024 ** 3)  # GB
    total_usage = total_upload + total_download

    # Frissítés
    value_total_upload.config(text=f"{total_upload:.2f} GB")
    value_total_download.config(text=f"{total_download:.2f} GB")
    value_total_usage.config(text=f"{total_usage:.2f} GB")
    value_upload_speed.config(text=f"{upload_speed:.2f} KB/s")
    value_download_speed.config(text=f"{download_speed:.2f} KB/s")

    last_upload = upload
    last_download = download

    window.after(REFRESH_DELAY, update)

# Indítás
update()
window.mainloop()
