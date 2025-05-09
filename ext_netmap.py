import tkinter as tk
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class NetworkMapApp(tk.Toplevel):
    def __init__(self, master=None, devices=None):
        super().__init__(master)
        self.title("Hálózati Térkép")
        self.geometry("900x700")
        self.devices = devices or []
        self.create_network_map()

    def create_network_map(self):
        # Hálózat grafikon létrehozása
        graph = nx.Graph()

        # Helyi gép hozzáadása
        hostname = "Local Device"
        graph.add_node(hostname, color='green', size=300)

        # Eszközök hozzáadása a grafikonhoz
        for device in self.devices:
            ip, mac, vendor = device
            graph.add_node(ip, color='lightblue', size=200)
            graph.add_edge(hostname, ip)

        # Hálózat vizualizáció beállítása
        pos = nx.spring_layout(graph)
        colors = [graph.nodes[node].get('color', 'lightblue') for node in graph.nodes]
        sizes = [graph.nodes[node].get('size', 200) for node in graph.nodes]
        labels = {node: node for node in graph.nodes}

        fig, ax = plt.subplots(figsize=(10, 8))
        nx.draw(graph, pos, node_color=colors, node_size=sizes, labels=labels, ax=ax, with_labels=True, font_size=8, font_weight="bold", edge_color="#cccccc", linewidths=1, alpha=0.9)

        # Grafikon megjelenítése a Tkinter ablakban
        canvas = FigureCanvasTkAgg(fig, self)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        canvas.draw()


def open_network_map(devices):
    app = NetworkMapApp(devices=devices)
    app.mainloop()
