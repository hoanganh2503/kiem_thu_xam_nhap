import time 
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP
from scapy.layers.l2 import Ether
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import psutil
from scapy.all import ARP, TCP, UDP, ICMP, ICMPv6ND_NS, DNS, Raw
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.utils import hexdump

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bắt gói tin ")
        self.root.geometry("1200x700")
        self.root.configure(bg="#282C34")
        
        self.style = ttk.Style()
        self.style.configure("TButton", font=("Segoe UI", 10), padding=5, background="#61afef", foreground="red")
        
        control_frame = tk.Frame(root, bg="#282C34")
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        self.interface_var = tk.StringVar()
        self.interface_menu = ttk.Combobox(control_frame, textvariable=self.interface_var,
                                           values=self.get_network_interfaces(), state="readonly", width=20)
        self.interface_menu.pack(side=tk.LEFT, padx=5)
        
        self.start_button = ttk.Button(control_frame, text="Start", command=self.start_sniffing)
        self.start_button.pack(side=tk.LEFT, padx=5)
        self.stop_button = ttk.Button(control_frame, text="Stop", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        self.save_button = ttk.Button(control_frame, text="Save PCAP", command=self.save_pcap)
        self.save_button.pack(side=tk.LEFT, padx=5)
        self.load_button = ttk.Button(control_frame, text="Load PCAP", command=self.load_pcap)
        self.load_button.pack(side=tk.LEFT, padx=5)
        self.reset_button = ttk.Button(control_frame, text="Reset", command=self.reset_sniffing)
        self.reset_button.pack(side=tk.LEFT, padx=5)
        
        self.stats_button = ttk.Button(control_frame, text="Thống kê điểm đến", command=self.show_destination_stats)
        self.stats_button.pack(side=tk.LEFT, padx=10)

        self.source_stats_button = ttk.Button(control_frame, text="Thống kê nguồn", command=self.show_source_stats)
        self.source_stats_button.pack(side=tk.LEFT, padx=10)
        
        # Nút thống kê giao thức
        self.protocol_stats_button = ttk.Button(control_frame, text="Thống kê giao thức", command=self.show_protocol_stats)
        self.protocol_stats_button.pack(side=tk.LEFT, padx=10)

        # Nút thống kê kích thước gói tin
        self.packet_size_button = ttk.Button(control_frame, text="Thống kê kích thước gói tin", command=self.show_packet_size_stats)
        self.packet_size_button.pack(side=tk.LEFT, padx=10)
        
        # Nút thống kê lưu lượng theo giờ
        self.traffic_button = ttk.Button(control_frame, text="Thống kê lưu lượng theo giờ", command=self.show_hourly_traffic_stats)
        self.traffic_button.pack(side=tk.LEFT, padx=10)
        # Tạo PanedWindow để chia layout theo chiều dọc (có thể kéo lên/xuống)
        self.paned_window = tk.PanedWindow(root, orient=tk.VERTICAL, bg="#282C34")
        self.paned_window.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Frame chứa danh sách gói tin (Treeview)
        frame_tree = tk.Frame(self.paned_window, bg="#282C34")
        self.tree = ttk.Treeview(frame_tree, columns=("Time", "Source", "Destination", "Protocol"), show="headings", height=10)

        # Định nghĩa các cột
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")

        # Thêm thanh cuộn dọc cho Treeview
        scroll_tree_y = ttk.Scrollbar(frame_tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_tree_y.set)

        # Hiển thị thanh cuộn dọc
        scroll_tree_y.pack(side=tk.RIGHT, fill=tk.Y)

        # Hiển thị bảng gói tin
        self.tree.pack(fill=tk.BOTH, expand=True)
        frame_tree.pack(fill=tk.BOTH, expand=True)

        # Thêm frame chứa bảng gói tin vào PanedWindow
        self.paned_window.add(frame_tree)

        # Frame chứa nội dung chi tiết gói tin
        frame_text = tk.Frame(self.paned_window, bg="#282C34")

        # Khu vực hiển thị chi tiết gói tin với thanh cuộn
        self.text_area = scrolledtext.ScrolledText(frame_text, height=5, bg="#21252B", fg="white", font=("Courier", 10))
        self.text_area.pack(fill=tk.BOTH, expand=True)

        frame_text.pack(fill=tk.BOTH, expand=True)

        # Thêm frame chứa nội dung chi tiết gói tin vào PanedWindow
        self.paned_window.add(frame_text)
        self.sniffing = False
        self.packets = []
        self.tree.bind("<ButtonRelease-1>", self.display_packet_details)

    def get_network_interfaces(self):
        try:
            interfaces = psutil.net_if_addrs()
            return list(interfaces.keys())  # Chỉ lấy tên giao diện mạng
        except Exception as e:
            messagebox.showerror("Error", f"Cannot get interfaces: {e}")
            return []

    def start_sniffing(self):
        iface = self.interface_var.get()
        if not iface:
            messagebox.showerror("Error", "Please select an interface!")
            return
        self.sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        # self.update_visualization()
        threading.Thread(target=self.sniff_packets, args=(iface,), daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def sniff_packets(self, iface):
        sniff(iface=iface, prn=self.process_packet, store=True)

    def process_packet(self, packet):
        if not self.sniffing:
            return
        src = packet[IP].src if packet.haslayer(IP) else "Unknown"
        dst = packet[IP].dst if packet.haslayer(IP) else "Unknown"
        timestamp = time.strftime('%H:%M:%S')
        protocol = self.identify_protocol(packet)
        
        dns_info = ""
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]

            if dns_layer.qr == 0:  # DNS Query
                query_name = dns_layer.qd.qname.decode() if dns_layer.qd else "Unknown"
                dns_info = f"DNS Query: {query_name}"
            
            elif dns_layer.qr == 1:  # DNS Response
                response_name = dns_layer.an.rdata if dns_layer.an else "Unknown"
                dns_info = f"DNS Response: {response_name}"
            
            else:
                dns_info = "Unknown DNS Packet"
        self.tree.insert("", tk.END, values=(timestamp, src, dst, protocol))
        self.packets.append(packet)
    
        
    def identify_protocol(self , packet): 
        if packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(HTTPRequest):
            return "HTTP"
        elif packet.haslayer(DNS):
            return "DNS"
        elif packet.haslayer(TCP):
            dport = packet[TCP].dport if packet.haslayer(TCP) else 0
            if dport == 21:
                return "FTP"
            elif dport == 110:
                return "POP3"
            elif dport == 25:
                return "SMTP"
            elif dport == 23:
                return "Telnet"
            elif dport == 22:
                return "SSH"
            elif dport == 445:
                return "SMB"
            elif dport == 443:
                return "HTTPS"
            elif dport == 853:
                return "DNS over TLS"
            elif dport == 4433 or dport == 784 or dport == 8443:
                return "QUIC"
            elif dport == 1883:
                return "MQTT"
            return "TCP"
        elif packet.haslayer(UDP):
            dport = packet[UDP].dport if packet.haslayer(UDP) else 0
            if dport == 123:
                return "NTP"
            elif dport == 5353:
                return "MDNS"
            elif dport == 1900:
                return "SSDP"
            elif dport == 3702:
                return "WS-Discovery"
            elif dport == 5683:
                return "CoAP"
            elif dport == 1812:
                return "RADIUS"
            elif dport == 4789:
                return "VXLAN"
            return "UDP"
        elif packet.haslayer(ICMP):
            return "ICMP"
        elif packet.haslayer(ICMPv6ND_NS):
            return "ICMPv6"
        elif packet.haslayer(IP):
            proto = packet[IP].proto
            if proto == 41:
                return "IPv6"
            elif proto == 2:
                return "IGMP"
            elif proto == 89:
                return "OSPF"
            return "Other IP"
        elif packet.haslayer(IPv6):
            return "IPv6"
        elif packet.haslayer(Ether):
            return "Ethernet"
        return "Other"


    def display_packet_details(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            index = self.tree.index(selected_item[0])
            packet = self.packets[index]
            self.text_area.delete("1.0", tk.END)
            self.text_area.insert(tk.END, packet.show(dump=True))

    def save_pcap(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            wrpcap(file_path, self.packets)
            messagebox.showinfo("Save", "Packets saved successfully!")

    def load_pcap(self):
        file_path = filedialog.askopenfilename(filetypes=[("PCAP files", "*.pcap")])
        if file_path:
            self.packets = rdpcap(file_path)
            self.tree.delete(*self.tree.get_children())
            for packet in self.packets:
                src, dst = packet.src, packet.dst
                timestamp = time.strftime('%H:%M:%S')
                protocol = self.identify_protocol(packet)
                self.tree.insert("", tk.END, values=(timestamp, src, dst, protocol))
            # self.update_visualization
            messagebox.showinfo("Load", "Packets loaded successfully!")

    def show_destination_stats(self):
        if not self.packets:
            messagebox.showwarning("Cảnh báo", "Không có gói tin để thống kê!")
            return

        df = pd.DataFrame({"Destination": [p[IP].dst for p in self.packets if p.haslayer(IP)]})
        destination_frequency = df["Destination"].value_counts()
        destination_frequency = destination_frequency[destination_frequency >= 10]

        if destination_frequency.empty:
            messagebox.showinfo("Thông báo", "Không có địa chỉ đích nào có tần suất trên 5000!")
            return

        plt.figure(figsize=(10, 5))
        destination_frequency.plot(kind="bar", color="skyblue")
        plt.xlabel("Destination")
        plt.ylabel("Frequency")
        plt.title("Tần suất các địa chỉ đích xuất hiện")
        plt.xticks(rotation=45)
        plt.show()
        
    def show_source_stats(self):
        if not self.packets:
            messagebox.showwarning("Cảnh báo", "Không có gói tin để thống kê!")
            return

        df = pd.DataFrame({"Source": [p[IP].src for p in self.packets if p.haslayer(IP)]})
        frequency = df["Source"].value_counts()
        frequency = frequency[frequency >= 20]

        if frequency.empty:
            messagebox.showinfo("Thông báo", "Không có địa chỉ nguồn nào có tần suất trên 500!")
            return

        plt.figure(figsize=(10, 5))
        frequency.plot(kind="bar", color="lightcoral")
        plt.xlabel("Source")
        plt.ylabel("Frequency")
        plt.title("Tần suất các địa chỉ nguồn xuất hiện")
        plt.xticks(rotation=45)
        plt.show()
    
    def show_protocol_stats(self):
        if not self.packets:
            messagebox.showwarning("Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Tạo cửa sổ mới để hiển thị biểu đồ
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Thống kê Giao thức")
        stats_window.geometry("600x400")

        df = pd.DataFrame({"protocol": [self.identify_protocol(p) for p in self.packets]})
        protocol_counts = df["protocol"].value_counts()

        
        # Tạo figure mới
        fig, ax = plt.subplots(figsize=(6, 4))
        protocol_counts.plot(kind="bar", ax=ax, color="skyblue")
        ax.set_title("Phân phối Giao thức")
        ax.set_xlabel("Giao thức")
        ax.set_ylabel("Số lượng")
        ax.set_xticklabels(ax.get_xticklabels(), rotation=0, ha="center")
        # Hiển thị biểu đồ trong cửa sổ mới
        canvas = FigureCanvasTkAgg(fig, master=stats_window)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        canvas.draw()
        
    def show_packet_size_stats(self):
        if not self.packets:
            messagebox.showwarning("Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Tạo cửa sổ mới để hiển thị biểu đồ
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Thống kê Kích thước Gói tin")
        stats_window.geometry("600x400")

        # Lấy danh sách kích thước gói tin
        packet_sizes = [len(packet) for packet in self.packets]

        # Tạo figure mới
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.hist(packet_sizes, bins=30, color="blue", alpha=0.7)
        ax.set_title("Phân phối Kích thước Gói tin")
        ax.set_xlabel("Kích thước (bytes)")
        ax.set_ylabel("Số lượng")

        # Hiển thị biểu đồ trong cửa sổ mới
        canvas = FigureCanvasTkAgg(fig, master=stats_window)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        canvas.draw()

    def show_hourly_traffic_stats(self):
        if not self.packets:
            messagebox.showwarning("Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Tạo cửa sổ mới để hiển thị biểu đồ
        stats_window = tk.Toplevel(self.root)
        stats_window.title("Thống kê Lưu lượng theo Giờ")
        stats_window.geometry("600x400")

        # Xử lý dữ liệu
        df = pd.DataFrame({"time": pd.to_datetime(pd.Series(range(len(self.packets))), unit="s")})
        hourly_traffic = df.groupby(df["time"].dt.hour).size()

        # Tạo figure mới
        fig, ax = plt.subplots(figsize=(6, 4))
        if not hourly_traffic.empty:
            hourly_traffic.plot(kind="line", marker="o", ax=ax, title="Lưu lượng theo Giờ")
            ax.set_xlabel("Giờ")
            ax.set_ylabel("Số lượng gói tin")

        # Hiển thị biểu đồ trong cửa sổ mới
        canvas = FigureCanvasTkAgg(fig, master=stats_window)
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        canvas.draw()

    def reset_sniffing(self):
        self.stop_sniffing()
        self.packets.clear()
        self.tree.delete(*self.tree.get_children())
        self.text_area.delete("1.0", tk.END)        
        self.start_button.config(state=tk.NORMAL)
        messagebox.showinfo("Reset", "Sniffer đã được reset thành công!")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()