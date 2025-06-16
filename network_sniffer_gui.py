import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import sniff, IP
import threading
import csv
from datetime import datetime
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🌐 PacketPeekX - Network Sniffer")
        self.root.configure(bg="#1e1e2f")
        self.running = False
        self.packet_data = []

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#282c34", foreground="white", fieldbackground="#282c34", rowheight=25)
        style.configure("Treeview.Heading", background="#61afef", foreground="black")
        style.map("Treeview", background=[("selected", "#98c379")])

        # Buttons
        button_frame = tk.Frame(root, bg="#1e1e2f")
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="▶ Start", command=self.start_sniffing, bg="#61afef", fg="black", width=12).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="⏹ Stop", command=self.stop_sniffing, bg="#e06c75", fg="white", width=12).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="💾 Export to CSV", command=self.export_to_csv, bg="#98c379", fg="black", width=14).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="🧹 Clear", command=self.clear_data, bg="#d19a66", fg="black", width=10).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="❓ About", command=self.show_about, bg="#c678dd", fg="white", width=10).pack(side=tk.LEFT, padx=5)

        # Treeview
        columns = ("Time", "Source", "Destination", "Protocol", "Payload")
        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=15)
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=130)
        self.tree.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Protocol Chart
        self.protocol_count = defaultdict(int)
        self.fig, self.ax = plt.subplots(figsize=(4, 2))
        self.chart_canvas = FigureCanvasTkAgg(self.fig, master=root)
        self.chart_canvas.get_tk_widget().pack(pady=5)
        self.update_chart()

    def update_chart(self):
        self.ax.clear()
        protocols = list(self.protocol_count.keys())
        counts = list(self.protocol_count.values())
        self.ax.bar(protocols, counts, color="#61afef")
        self.ax.set_title("Live Protocol Usage", color="white")
        self.ax.tick_params(axis='x', colors='white')
        self.ax.tick_params(axis='y', colors='white')
        self.fig.patch.set_facecolor('#1e1e2f')
        self.ax.set_facecolor('#1e1e2f')
        self.chart_canvas.draw()
        self.root.after(3000, self.update_chart)

    def start_sniffing(self):
        self.running = True
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.running = False

    def sniff_packets(self):
        sniff(prn=self.process_packet, store=False)

    def process_packet(self, packet):
        if not self.running:
            return
        if IP in packet:
            time = datetime.now().strftime("%H:%M:%S")
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto
            proto_name = {6: "TCP", 17: "UDP"}.get(proto, str(proto))
            payload = str(bytes(packet[IP].payload))[:40]

            self.tree.insert("", "end", values=(time, src, dst, proto_name, payload))
            self.packet_data.append((time, src, dst, proto_name, payload))
            self.protocol_count[proto_name] += 1

    def export_to_csv(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".csv")
        if file_path:
            with open(file_path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Time", "Source", "Destination", "Protocol", "Payload"])
                for row in self.tree.get_children():
                    writer.writerow(self.tree.item(row)["values"])
            messagebox.showinfo("Export", "Data exported successfully!")

    def clear_data(self):
        if messagebox.askyesno("Clear", "Are you sure you want to clear all data?"):
            for row in self.tree.get_children():
                self.tree.delete(row)
            self.packet_data.clear()
            self.protocol_count.clear()

    def show_about(self):
        messagebox.showinfo("About", "NetSniffX v2.0\nEnhanced Network Sniffer with Live Charts!")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()

