import sys
from PyQt6 import uic, QtGui
from PyQt6.QtGui import QFont, QAction
from PyQt6.QtCore import Qt, QTimer, QCoreApplication
from PyQt6.QtWidgets import QApplication, QMainWindow, QTextEdit, QPushButton, QFileDialog, QMessageBox, QTableWidgetItem, QDialog, QVBoxLayout, QMenu, QInputDialog ,QWidget, QTableWidget, QHeaderView, QTabWidget
from PyQt6.QtWebEngineWidgets import QWebEngineView
import threading
import time
import psutil
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from mpl_toolkits.mplot3d import Axes3D
import numpy as np
import plotly.io as pio
import plotly.graph_objects as go
from scipy.spatial import distance
from scapy.all import *
from scapy.layers.http import HTTPRequest
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP, UDP, IP
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6
from scapy.all import ARP, ICMP, ICMPv6ND_NS, Raw
from ModelAI import ModelAI
import requests
import webbrowser
from PyQt6 import QtWidgets, QtGui
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar
from PyQt6.QtWidgets import QApplication, QMainWindow, QFileDialog, QMessageBox, QTableWidgetItem, QDialog, QScrollArea,QVBoxLayout, QMenu,QVBoxLayout, QLabel, QDialog
import socket
from PyQt6.QtWidgets import QComboBox
from PyQt6.QtWidgets import QLineEdit
from PyQt6.QtGui import QColor
warnings.filterwarnings("ignore")

def get_mac_vendor(mac_address):
    """Tra cứu vendor của MAC Address từ API"""
    try:
        response = requests.get(f"https://api.macvendors.com/{mac_address}", timeout=3)
        return response.text if response.status_code == 200 else "Unknown Vendor"
    except:
        return "Unknown Vendor"

# Hàm lấy thông tin vị trí địa lý của IP
def get_ip_geolocation(ip_address):
    """Lấy thông tin vị trí địa lý của IP bằng ipinfo.io"""
    try:
        response = requests.get(f"http://ipinfo.io/{ip_address}/json", timeout=3)
        data = response.json()
        
        return {
            "City": data.get("city", "Unknown"),
            "Region": data.get("region", "Unknown"),
            "Country": data.get("country", "Unknown"),
            "Location": data.get("loc", "Unknown"),
            "ISP": data.get("org", "Unknown")
        }
    except:
        return {"City": "Unknown", "Region": "Unknown", "Country": "Unknown", "Location": "Unknown", "ISP": "Unknown"}
def is_http_packet(pkt):
    return pkt.haslayer(TCP) and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80) and bytes(pkt[TCP].payload)

def parse_http_payload(pkt):
    try:
        payload = bytes(pkt[TCP].payload)
        http_text = payload.decode("utf-8", errors="replace")
        return http_text
    except Exception as e:
        print(f"Lỗi giải mã HTTP: {e}")
        return None
    
class InfoDialog(QDialog):
    def __init__(self, ip_src, ip_dst, protocol, mac_src, mac_dst, src_port, dst_port,  parent=None):
        super().__init__(parent)
        self.setWindowTitle("Thông tin chi tiết gói tin")

        # Tạo layout và thêm các label cho thông tin
        layout = QVBoxLayout()
        src_geo, dst_geo, src_vendor, dst_vendor=get_ip_geolocation(ip_src),get_ip_geolocation(ip_dst),get_mac_vendor(mac_src),get_mac_vendor(mac_dst)
        # Thêm thông tin IP và vị trí
        layout.addWidget(QLabel(f"📡 Source IP: {ip_src} ({src_geo['City']}, {src_geo['Country']} - {src_geo['ISP']})"))
        layout.addWidget(QLabel(f"🎯 Destination IP: {ip_dst} ({dst_geo['City']}, {dst_geo['Country']} - {dst_geo['ISP']})"))
        layout.addWidget(QLabel(f"📦 Protocol: {protocol}"))

        # Thêm thông tin MAC và nhà cung cấp
        layout.addWidget(QLabel(f"🔗 Source MAC: {mac_src} ({src_vendor}) → Destination MAC: {mac_dst} ({dst_vendor})"))
        
        # Thêm thông tin cổng nguồn và đích
        layout.addWidget(QLabel(f"🔗 Source Port: {src_port} → Destination Port: {dst_port}"))

        # Thiết lập layout cho dialog
        self.setLayout(layout)
        self.resize(400, 300)

class HTTPDialog(QDialog):
    def __init__(self, http_text, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Thông tin chi tiết gói tin HTTP")

        layout = QVBoxLayout()

        # Hiển thị nội dung HTTP Request
        http_text_label = QLabel(f"<pre>{http_text}</pre>")
        http_text_label.setWordWrap(True)

        # Đặt HTTP request vào trong một scroll area nếu nội dung dài
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(http_text_label)

        layout.addWidget(scroll_area)

        # Thiết lập layout cho dialog
        self.setLayout(layout)
        self.resize(600, 400)
        
last_time = None
last_size = None
# connection_states, src_dport_counts, dst_sport_counts, dst_src_counts
connection_states = {}  # You can define this as a dictionary or list, depending on your needs
src_dport_counts = {}  # Example initialization
dst_sport_counts = {}  # Example initialization
dst_src_counts = {}    # Example initialization
        
class WireBabyShark(QMainWindow):
    def __init__(self):
        super().__init__()
        uic.loadUi("untitled.ui", self)  # Đường dẫn tới file UI
        self.setWindowTitle("WireBabyShark")
        self.tableWidget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tableWidget.customContextMenuRequested.connect(self.show_table_context_menu)
        self.tableWidget.cellDoubleClicked.connect(self.on_item_double_click)
        # setup ban đầu
        self.stop_button.setEnabled(False)
        self.sniffing = False
        self.packets = []
        self.tableWidget.cellClicked.connect(self.on_table_row_clicked)
        self.textEdit.setReadOnly(True)
        self.AI = ModelAI(
            "./Binary_model_randomforest.pkl",
            "./Multi_model_randomforest.pkl"
        )



        # Điều chỉnh 1 tí giao diện
        font = QFont()
        font.setBold(True)
        header = self.tableWidget.horizontalHeader()
        header.setFont(font)
        self.tableWidget.setColumnWidth(0, 20)  
        self.tableWidget.setColumnWidth(1, 60) 
        self.tableWidget.setColumnWidth(2, 100) 
        self.tableWidget.setColumnWidth(3, 100) 
        self.tableWidget.setColumnWidth(4, 60) 
        self.tableWidget.setColumnWidth(5, 80) 
        self.tableWidget.setColumnWidth(6, 540) 


        self.comboBox.addItems(self.get_network_interfaces())
        self.start_button.clicked.connect(self.start_sniffing)
        self.stop_button.clicked.connect(self.stop_sniffing)
        self.save_button.clicked.connect(self.save_pcap)
        self.load_button.clicked.connect(self.load_pcap)
        self.reset_button.clicked.connect(self.reset_sniffing)

       # Tạo menu cho nút Thống kê
        self.stats_menu = QMenu(self)
        self.stats_menu.addAction("Thống kê nguồn", self.show_source_stats)
        self.stats_menu.addAction("Thống kê đích", self.show_destination_stats)
        self.stats_menu.addAction("Thống kê giao thức", self.show_protocol_stats)
        self.stats_menu.addAction("Thống kê kích thước", self.show_packet_size_stats)  # Tách riêng cho kích thước
        self.stats_menu.addAction("Cuộc hội thoại", self.show_conversation_stats_table)
        
        self.endpoints_submenu = QMenu("Thống kê điểm cuối", self)
        self.endpoints_submenu.addAction("Ethernet", lambda: self.show_endpoint_stats("ethernet"))
        self.endpoints_submenu.addAction("IPv4", lambda: self.show_endpoint_stats("ipv4"))
        self.endpoints_submenu.addAction("IPv6", lambda: self.show_endpoint_stats("ipv6"))
        self.endpoints_submenu.addAction("TCP", lambda: self.show_endpoint_stats("tcp"))
        self.endpoints_submenu.addAction("UDP", lambda: self.show_endpoint_stats("udp"))
        self.stats_menu.addMenu(self.endpoints_submenu)
        
        self.stats_button.setMenu(self.stats_menu)  # Gắn menu vào nút
        self.pushButton_9.clicked.connect(self.filter_packets)
        self.pushButton_10.clicked.connect(self.show_ip_relations)
        self.show_io_graph_button.clicked.connect(self.show_io_graphs)
        self.packets = []
        self.packets_filter=[]
        self.sniffing = False
        self.start_time = None
        self.packet_counts = {} # Dictionary để lưu trữ số lượng gói tin theo thời gian
        self.tcp_error_counts = {} 
        
    def on_item_double_click(self, row,column):
        packet = self.packets_filter[row]
        ip_src, ip_dst, protocol = "Unknown", "Unknown", "Unknown"
        mac_src, mac_dst = "Unknown MAC", "Unknown MAC"
        src_port, dst_port = "N/A", "N/A"
    
    # Kiểm tra nếu gói tin có lớp Ethernet để lấy địa chỉ MAC
        if Ether in packet:
            mac_src = packet[Ether].src
            mac_dst = packet[Ether].dst

    # Kiểm tra nếu gói tin có lớp IP để lấy thông tin IP và giao thức
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            

    # Kiểm tra nếu gói tin là TCP hoặc UDP để lấy cổng
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
          
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        protocol=self.identify_protocol(packet)
        info_dialog = InfoDialog(ip_src, ip_dst, protocol, mac_src, mac_dst, src_port, dst_port)
        info_dialog.exec()
    
        
    def show_endpoint_stats(self, stats_type="ethernet"):
        if not self.packets:
            QMessageBox.warning(self, "Warning", "Không có gói tin nào để thống kê điểm cuối.")
            return

        endpoint_stats = defaultdict(lambda: {'packets': 0, 'bytes': 0, 'tx_packets': 0, 'tx_bytes': 0, 'rx_packets': 0, 'rx_bytes': 0})
        my_mac = None
        my_ip_v4 = None
        my_ip_v6 = None

        # Xác định địa chỉ MAC và IP của interface đang bắt gói tin (nếu có)
        iface_name = str(self.comboBox.currentText())
        try:
            interfaces = psutil.net_if_addrs()
            if iface_name in interfaces and interfaces[iface_name]:
                for addr in interfaces[iface_name]:
                    if addr.family == socket.AF_LINK:
                        my_mac = addr.address
                    elif addr.family == socket.AF_INET:
                        my_ip_v4 = addr.address
                    elif addr.family == socket.AF_INET6:
                        my_ip_v6 = addr.address
        except Exception as e:
            print(f"Không thể lấy địa chỉ của interface: {e}")

        for packet in self.packets:
            packet_len = len(packet)
            if stats_type == "ethernet" and Ether in packet:
                src = packet[Ether].src
                dst = packet[Ether].dst
                self.update_endpoint_stats_data(endpoint_stats, src, dst, packet_len, my_mac)
            elif stats_type == "ipv4" and IP in packet:
                src = packet[IP].src
                dst = packet[IP].dst
                self.update_endpoint_stats_data(endpoint_stats, src, dst, packet_len, my_ip_v4)
            elif stats_type == "ipv6" and IPv6 in packet:
                src = packet[IPv6].src
                dst = packet[IPv6].dst
                self.update_endpoint_stats_data(endpoint_stats, src, dst, packet_len, my_ip_v6)
            elif stats_type == "tcp" and TCP in packet and IP in packet:
                src = (packet[IP].src, packet[TCP].sport)
                dst = (packet[IP].dst, packet[TCP].dport)
                my_endpoint_src = (my_ip_v4, packet[TCP].sport) if my_ip_v4 and hasattr(packet[TCP], 'sport') else None
                my_endpoint_dst = (my_ip_v4, packet[TCP].dport) if my_ip_v4 and hasattr(packet[TCP], 'dport') else None
                self.update_tcp_udp_endpoint_stats(endpoint_stats, src, dst, packet_len, my_endpoint_src, my_endpoint_dst)
            elif stats_type == "udp" and (UDP in packet) and (IP in packet or IPv6 in packet):
                if IP in packet:  # Handle IPv4 packets
                    src = (packet[IP].src, packet[UDP].sport)
                    dst = (packet[IP].dst, packet[UDP].dport)
                    my_endpoint_src = (my_ip_v4, packet[UDP].sport) if my_ip_v4 and hasattr(packet[UDP], 'sport') else None
                    my_endpoint_dst = (my_ip_v4, packet[UDP].dport) if my_ip_v4 and hasattr(packet[UDP], 'dport') else None
                elif IPv6 in packet:  # Handle IPv6 packets
                    src = (packet[IPv6].src, packet[UDP].sport)
                    dst = (packet[IPv6].dst, packet[UDP].dport)
                    my_endpoint_src = (my_ip_v6, packet[UDP].sport) if my_ip_v6 and hasattr(packet[UDP], 'sport') else None
                    my_endpoint_dst = (my_ip_v6, packet[UDP].dport) if my_ip_v6 and hasattr(packet[UDP], 'dport') else None
                
                self.update_tcp_udp_endpoint_stats(endpoint_stats, src, dst, packet_len, my_endpoint_src, my_endpoint_dst)

        self.show_endpoint_stats_table(endpoint_stats, stats_type)

    def show_conversation_stats_table(self):
        if not self.packets:
            QMessageBox.warning(self, "Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Tạo cửa sổ thống kê
        stats_window = QDialog(self)
        stats_window.setWindowTitle("Conversation Statistics")
        stats_window.resize(1100, 600)

        layout = QVBoxLayout(stats_window)
        tab_widget = QTabWidget()
        layout.addWidget(tab_widget)

        protocols = {
            "Ethernet": lambda pkt: Ether in pkt and not (IP in pkt or IPv6 in pkt),
            "IPv4": lambda pkt: IP in pkt,
            "IPv6": lambda pkt: IPv6 in pkt,
            "TCP": lambda pkt: TCP in pkt,
            "UDP": lambda pkt: UDP in pkt
        }

        for proto_name, condition in protocols.items():
            filtered_packets = [pkt for pkt in self.packets if condition(pkt)]

            # Lấy dữ liệu conversation
            conversation_data = {}

            for pkt in filtered_packets:
                if IP in pkt:
                    src = pkt[IP].src
                    dst = pkt[IP].dst
                elif IPv6 in pkt:
                    src = pkt[IPv6].src
                    dst = pkt[IPv6].dst
                elif Ether in pkt:
                    src = pkt[Ether].src
                    dst = pkt[Ether].dst
                else:
                    continue

                length = len(pkt)
                key = tuple(sorted([src, dst]))

                if key not in conversation_data:
                    conversation_data[key] = {
                        "A": src,
                        "B": dst,
                        "packets_A_B": 0,
                        "packets_B_A": 0,
                        "bytes_A_B": 0,
                        "bytes_B_A": 0,
                        "start_time": pkt.time,
                        "end_time": pkt.time
                    }

                entry = conversation_data[key]
                if src == entry["A"] and dst == entry["B"]:
                    entry["packets_A_B"] += 1
                    entry["bytes_A_B"] += length
                else:
                    entry["packets_B_A"] += 1
                    entry["bytes_B_A"] += length

                entry["start_time"] = min(entry["start_time"], pkt.time)
                entry["end_time"] = max(entry["end_time"], pkt.time)

            rows = []
            for conv in conversation_data.values():
                duration = conv["end_time"] - conv["start_time"]
                bits_a_b = (conv["bytes_A_B"] * 8 / duration) if duration > 0 else 0
                bits_b_a = (conv["bytes_B_A"] * 8 / duration) if duration > 0 else 0

                rows.append({
                    "Address A": conv["A"],
                    "Address B": conv["B"],
                    "Total Packets": conv["packets_A_B"] + conv["packets_B_A"],
                    "Packets A → B": conv["packets_A_B"],
                    "Bytes A → B": int(conv["bytes_A_B"]),
                    "Packets B → A": conv["packets_B_A"],
                    "Bytes B → A": int(conv["bytes_B_A"]),
                    "Duration (s)": round(duration, 4),
                    "Bits/s A → B": int(bits_a_b),
                    "Bits/s B → A": int(bits_b_a)
                })

            df = pd.DataFrame(rows)

            tab = QWidget()
            tab_layout = QVBoxLayout(tab)

            table = QTableWidget(len(df), len(df.columns))
            table.setHorizontalHeaderLabels(df.columns.tolist())

            for i, row in df.iterrows():
                for j, val in enumerate(row):
                    item = QTableWidgetItem(str(val))
                    table.setItem(i, j, item)

            table.resizeColumnsToContents()
            table.setSortingEnabled(True)
            table.horizontalHeader().setSortIndicatorShown(True)
            table.horizontalHeader().setSectionsClickable(True)
            table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

            # Sort toggle logic
            sort_order = {}

            def make_sort_handler(tbl, local_order):
                def on_header_clicked(index):
                    local_order[index] = not local_order.get(index, True)
                    order = Qt.SortOrder.AscendingOrder if local_order[index] else Qt.SortOrder.DescendingOrder
                    tbl.sortItems(index, order)
                    tbl.horizontalHeader().setSortIndicator(index, order)
                return on_header_clicked

            table.horizontalHeader().sectionClicked.connect(make_sort_handler(table, sort_order))
            tab_layout.addWidget(table)
            tab_widget.addTab(tab, proto_name)

        stats_window.setLayout(layout)
        stats_window.exec()

    def update_endpoint_stats_data(self, stats_dict, src, dst, packet_len, my_address):
        # Update statistics for source
        stats_dict[src]['packets'] += 1
        stats_dict[src]['bytes'] += packet_len
        if my_address and src == my_address:
            stats_dict[src]['tx_packets'] += 1
            stats_dict[src]['tx_bytes'] += packet_len
        else:
            stats_dict[src]['rx_packets'] += 1
            stats_dict[src]['rx_bytes'] += packet_len

        # Update statistics for destination
        stats_dict[dst]['packets'] += 1
        stats_dict[dst]['bytes'] += packet_len
        if my_address and dst == my_address:
            stats_dict[dst]['rx_packets'] += 1
            stats_dict[dst]['rx_bytes'] += packet_len
        else:
            stats_dict[dst]['tx_packets'] += 1
            stats_dict[dst]['tx_bytes'] += packet_len

    def update_tcp_udp_endpoint_stats(self, stats_dict, src, dst, packet_len, my_endpoint_src, my_endpoint_dst):
        # Update statistics for source
        stats_dict[src]['packets'] += 1
        stats_dict[src]['bytes'] += packet_len
        if my_endpoint_src and src == my_endpoint_src:
            stats_dict[src]['tx_packets'] += 1
            stats_dict[src]['tx_bytes'] += packet_len
        else:
            stats_dict[src]['rx_packets'] += 1
            stats_dict[src]['rx_bytes'] += packet_len

        # Update statistics for destination
        stats_dict[dst]['packets'] += 1
        stats_dict[dst]['bytes'] += packet_len
        if my_endpoint_dst and dst == my_endpoint_dst:
            stats_dict[dst]['rx_packets'] += 1
            stats_dict[dst]['rx_bytes'] += packet_len
        else:
            stats_dict[dst]['tx_packets'] += 1
            stats_dict[dst]['tx_bytes'] += packet_len

    def show_endpoint_stats_table(self, endpoint_stats, stats_type):
        self.endpoint_stats_window = QMainWindow(self)
        title = f"Thống kê điểm cuối ({stats_type.capitalize()})"
        address_count = len(endpoint_stats)
        self.endpoint_stats_window.setWindowTitle(f"{title} - Tổng số địa chỉ: {address_count}")
        central_widget = QWidget()
        self.endpoint_stats_window.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        table_widget = QtWidgets.QTableWidget()
        table_widget.setFont(QFont("Arial", 10))
        header_font = QFont("Arial", 10, QFont.Weight.Bold)
        header = table_widget.horizontalHeader()
        header.setFont(header_font)

        column_headers = []
        column_widths = []

        if stats_type == "ethernet":
            column_headers = ["Address", "Packets", "Bytes", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes"]
            column_widths = [200, 80, 100, 100, 100, 100, 100]
            table_widget.setColumnCount(len(column_headers))
            table_widget.setHorizontalHeaderLabels(column_headers)
            for i, width in enumerate(column_widths):
                table_widget.setColumnWidth(i, width)
            row_count = 0
            for endpoint, stats in endpoint_stats.items():
                table_widget.insertRow(row_count)
                table_widget.setItem(row_count, 0, QTableWidgetItem(str(endpoint)))
                table_widget.setItem(row_count, 1, QTableWidgetItem(str(stats['packets'])))
                table_widget.setItem(row_count, 2, QTableWidgetItem(str(stats['bytes'])))
                table_widget.setItem(row_count, 3, QTableWidgetItem(str(stats['tx_packets'])))
                table_widget.setItem(row_count, 4, QTableWidgetItem(str(stats['tx_bytes'])))
                table_widget.setItem(row_count, 5, QTableWidgetItem(str(stats['rx_packets'])))
                table_widget.setItem(row_count, 6, QTableWidgetItem(str(stats['rx_bytes'])))
                row_count += 1
        elif stats_type == "ipv4" or stats_type == "ipv6":
            column_headers = ["Address", "Packets", "Bytes", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes"]
            column_widths = [200, 80, 100, 100, 100, 100, 100]
            table_widget.setColumnCount(len(column_headers))
            table_widget.setHorizontalHeaderLabels(column_headers)
            for i, width in enumerate(column_widths):
                table_widget.setColumnWidth(i, width)
            row_count = 0
            for endpoint, stats in endpoint_stats.items():
                table_widget.insertRow(row_count)
                table_widget.setItem(row_count, 0, QTableWidgetItem(str(endpoint)))
                table_widget.setItem(row_count, 1, QTableWidgetItem(str(stats['packets'])))
                table_widget.setItem(row_count, 2, QTableWidgetItem(str(stats['bytes'])))
                table_widget.setItem(row_count, 3, QTableWidgetItem(str(stats['tx_packets'])))
                table_widget.setItem(row_count, 4, QTableWidgetItem(str(stats['tx_bytes'])))
                table_widget.setItem(row_count, 5, QTableWidgetItem(str(stats['rx_packets'])))
                table_widget.setItem(row_count, 6, QTableWidgetItem(str(stats['rx_bytes'])))
                row_count += 1
        elif stats_type == "tcp" or stats_type == "udp":
            column_headers = ["Address", "Port", "Packets", "Bytes", "Tx Packets", "Tx Bytes", "Rx Packets", "Rx Bytes"]
            column_widths = [150, 80, 80, 100, 100, 100, 100, 100]
            table_widget.setColumnCount(len(column_headers))
            table_widget.setHorizontalHeaderLabels(column_headers)
            for i, width in enumerate(column_widths):
                table_widget.setColumnWidth(i, width)
            row_count = 0
            for endpoint, stats in endpoint_stats.items():
                table_widget.insertRow(row_count)
                table_widget.setItem(row_count, 0, QTableWidgetItem(endpoint[0]))  # Address
                table_widget.setItem(row_count, 1, QTableWidgetItem(str(endpoint[1])))  # Port
                table_widget.setItem(row_count, 2, QTableWidgetItem(str(stats['packets'])))
                table_widget.setItem(row_count, 3, QTableWidgetItem(str(stats['bytes'])))
                table_widget.setItem(row_count, 4, QTableWidgetItem(str(stats['tx_packets'])))
                table_widget.setItem(row_count, 5, QTableWidgetItem(str(stats['tx_bytes'])))
                table_widget.setItem(row_count, 6, QTableWidgetItem(str(stats['rx_packets'])))
                table_widget.setItem(row_count, 7, QTableWidgetItem(str(stats['rx_bytes'])))
                row_count += 1

        layout.addWidget(table_widget)
        table_widget.setSortingEnabled(True)
        self.endpoint_stats_window.setGeometry(300, 300, 950, 400)
        self.endpoint_stats_window.show()
        
    def show_io_graphs(self):
        if not self.packets:
            QMessageBox.warning(self, "Warning", "No packets captured to show I/O graphs.")
            return

        self.io_graph_window = QtWidgets.QMainWindow(self)
        self.io_graph_window.setWindowTitle("I/O Graphs")
        central_widget = QWidget()
        self.io_graph_window.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Tính toán số lượng gói tin theo thời gian
        time_series = {}
        tcp_errors = {}
        for packet in self.packets:
            timestamp = int(packet.time - self.start_time)
            time_series[timestamp] = time_series.get(timestamp, 0) + 1
            if packet.haslayer(TCP) and hasattr(packet[TCP], 'flags') and packet[TCP].flags & 0x01: # Kiểm tra cờ FIN (ví dụ về một loại "lỗi" hoặc sự kiện kết thúc)
                tcp_errors[timestamp] = tcp_errors.get(timestamp, 0) + 1

        times = sorted(time_series.keys())
        all_packets_count = [time_series.get(t, 0) for t in times]
        tcp_error_count = [tcp_errors.get(t, 0) for t in times]

        # Tạo figure và axes
        self.figure = plt.figure(figsize=(10, 6))
        self.axes = self.figure.add_subplot(111)

        # Vẽ biểu đồ
        self.axes.plot(times, all_packets_count, label='All Packets')
        self.axes.bar(times, tcp_error_count, label='TCP Errors', color='red', alpha=0.7)

        self.axes.set_xlabel("Time (s)")
        self.axes.set_ylabel("Packets/sec")
        self.axes.set_title("I/O Graphs")
        self.axes.legend()
        self.axes.grid(True)

        self.canvas = FigureCanvas(self.figure)
        layout.addWidget(self.canvas)

        self.toolbar = NavigationToolbar(self.canvas, self.io_graph_window)
        layout.addWidget(self.toolbar)

        self.io_graph_window.setGeometry(200, 200, 800, 600)
        self.io_graph_window.show()
    

    def show_table_context_menu(self, position):
        index = self.tableWidget.indexAt(position)
        if not index.isValid():
            return

        row = index.row()
        print(row)
        if row >= len(self.packets_filter):
            return

        packet = self.packets_filter[row]

        # Tạo menu
        menu = QMenu(self)

        action_info = QAction("🔍 Xem Info (Wireshark-style)", self)
        action_hexdump = QAction("📄 Hex Dump", self)
        action_full = QAction("🧬 Chi tiết đầy đủ", self)
        action_http = QAction("🧬 Xem gói tin http", self)
        action_follow_http = QAction("📡 Theo dõi luồng HTTP", self) 
        action_follow_tcp = QAction("📡 Theo dõi luồng TCP", self)
        action_follow_udp = QAction("📡 Theo dõi luồng UDP", self)
        action_info.triggered.connect(lambda: self.show_packet_info(packet))
        action_hexdump.triggered.connect(lambda: self.show_packet_hexdump(packet))
        action_full.triggered.connect(lambda: self.show_packet_details(packet))
        action_http.triggered.connect(lambda: self.show_packet_http(packet))
        action_follow_http.triggered.connect(lambda: self.show_http_stream(packet))
        action_follow_tcp.triggered.connect(self.follow_tcp_stream)
        action_follow_udp.triggered.connect(self.follow_udp_stream)
        
        menu.addAction(action_info)
        menu.addAction(action_hexdump)
        menu.addAction(action_full)

        # Kiểm tra nếu gói tin là HTTP
        if packet.haslayer(TCP) and packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode("utf-8", errors="ignore")
                if "HTTP" in payload:
                    menu.addAction(action_http)
                    menu.addAction(action_follow_http)
            except:
                pass

        # Kiểm tra nếu gói tin là TCP
        if packet.haslayer(TCP):
            menu.addAction(action_follow_tcp)

        # Kiểm tra nếu gói tin là UDP
        if packet.haslayer(UDP):
            menu.addAction(action_follow_udp)

        # Hiển thị menu nếu có tùy chọn hợp lệ
        if menu.actions():
            menu.exec(self.tableWidget.viewport().mapToGlobal(position))


    def show_packet_info(self, packet):
        info = self.generate_packet_info(packet) 
        self.textEdit.setPlainText(info)

    def show_packet_hexdump(self, packet):
        from scapy.utils import hexdump
        hex_str = hexdump(packet, dump=True)
        self.textEdit.setPlainText(hex_str)

    def show_packet_details(self, packet):
        details = packet.show(dump=True)
        self.textEdit.setPlainText(details)

    def get_network_interfaces(self):
        try:
            interfaces = psutil.net_if_addrs()
            return list(interfaces.keys())  
        except Exception as e:
            QMessageBox.warning(self, "Cảnh báo", "Không có gói tin để thống kê!")
            return []
        
    from PyQt6.QtWidgets import QMessageBox, QFileDialog

    def start_sniffing(self):
        self.start_time = time.time()
        iface = str(self.comboBox.currentText())
        if not iface:
            QMessageBox.critical(self, "Error", "Please select an interface!")
            return

        # Nếu đã có dữ liệu trước đó → hỏi có muốn lưu hay không
        if hasattr(self, "packets") and self.packets:
            reply = QMessageBox.question(
                self,
                "Save Capture?",
                "Bạn có muốn lưu lại dữ liệu gói tin trước đó (PCAP)?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.Yes:
                file_path, _ = QFileDialog.getSaveFileName(self, "Lưu File", "", "PCAP Files (*.pcap)")
                if file_path:
                    self.save_pcap = True
                    self.pcap_file_path = file_path
                    from scapy.utils import wrpcap
                    wrpcap(file_path, self.packets)
                    QMessageBox.information(self, "Đã Lưu", f"Đã lưu file tại:\n{file_path}")
                else:
                    QMessageBox.information(self, "Không Lưu", "Không chọn đường dẫn lưu file. Dữ liệu sẽ bị xóa.")
            # Dù chọn Yes hay No, nếu tới đây là tiếp tục bắt gói → xóa dữ liệu cũ
            self.packets = []
            self.packets_filter=[]

        # Nếu chưa có gì, hoặc vừa xử lý xong lưu → bắt đầu lại
        self.save_pcap = False
        self.pcap_file_path = None

        self.sniffing = True
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.tableWidget.setRowCount(0)
        self.packet_counts = {}
        self.tcp_error_counts = {}

        threading.Thread(target=self.sniff_packets, args=(iface,), daemon=True).start()


    def generate_packet_info(self, packet):
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = packet.sprintf("%TCP.flags%")
            payload_len = len(packet[Raw]) if packet.haslayer(Raw) else 0
            return f"{tcp.sport} → {tcp.dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={payload_len}"

        elif packet.haslayer(UDP):
            udp = packet[UDP]
            payload_len = len(packet[Raw]) if packet.haslayer(Raw) else 0
            return f"{udp.sport} → {udp.dport} Len={payload_len}"

        elif packet.haslayer(DNS):
            dns = packet[DNS]
            if dns.qr == 0:  # Query
                if dns.qd and dns.qd.qname:
                    return f"DNS Query: {dns.qd.qname.decode(errors='ignore')}"
                else:
                    return "DNS Query"
            elif dns.qr == 1:  # Response
                if dns.an:
                    try:
                        answers = []
                        if isinstance(dns.an, list):
                            for ans in dns.an:
                                if hasattr(ans, "rdata"):
                                    answers.append(str(ans.rdata))
                        else:
                            if hasattr(dns.an, "rdata"):
                                answers.append(str(dns.an.rdata))
                        return "DNS Response: " + ", ".join(answers) if answers else "DNS Response"
                    except Exception:
                        return "DNS Response"
                else:
                    return "DNS Response"

        elif packet.haslayer(HTTPRequest):
            http = packet[HTTPRequest]
            method = http.Method.decode() if http.Method else "?"
            host = http.Host.decode() if http.Host else "?"
            path = http.Path.decode() if http.Path else "/"
            return f"HTTP {method} http://{host}{path}"

        elif packet.haslayer(ICMP):
            icmp = packet[ICMP]
            return f"ICMP Type={icmp.type} Code={icmp.code}"

        else:
            return "Unknown or unsupported protocol"
    def filter_packets(self):
        """
        Lọc gói tin dựa trên danh sách `self.packets` và bộ lọc nhập vào.
        """
        filter_text = self.plainTextEdit_4.toPlainText().strip()  # Lấy bộ lọc từ ô nhập liệu
        self.tableWidget.setRowCount(0)  # Xóa dữ liệu cũ trong bảng
        ctest = 0  # Biến đếm số gói tin phù hợp
        self.packets_filter=[]    
        # Xử lý các gói tin trong danh sách self.packets
        try:
            for i, packet in enumerate(self.packets):
                try:
                    # Lấy thông tin gói tin: IP, thời gian, chiều dài, giao thức
                    src_ip = packet[IP].src if packet.haslayer(IP) else (packet[Ether].src if packet.haslayer(Ether) else "Unknown")
                    dst_ip = packet[IP].dst if packet.haslayer(IP) else (packet[Ether].dst if packet.haslayer(Ether) else "Unknown")
                    length = len(packet)
                    timestamp = packet.time
                    protocol = self.identify_protocol(packet)

                    # Sao chép gói tin để tránh thay đổi gói gốc
                    packet_copy = Ether(raw(packet))

                    # Nếu có filter và gói tin không khớp, bỏ qua
                    if filter_text and not self.packet_matches_filter(packet_copy, filter_text):
                        continue

                    # Nếu gói tin phù hợp với filter, thêm vào mảng packets_filter
                    self.packets_filter.append(packet)
                    ctest += 1

                    # Thêm gói tin vào bảng
                    row = self.tableWidget.rowCount()
                    self.tableWidget.insertRow(row)
                    self.tableWidget.setItem(row, 0, self.make_item(str(i + 1)))  # STT
                    self.tableWidget.setItem(row, 1, self.make_item(str(timestamp)))  # Thời gian
                    self.tableWidget.setItem(row, 2, self.make_item(src_ip))  # Nguồn
                    self.tableWidget.setItem(row, 3, self.make_item(dst_ip))  # Đích
                    self.tableWidget.setItem(row, 4, self.make_item(protocol))  # Giao thức
                    self.tableWidget.setItem(row, 5, self.make_item(str(length)))  # Chiều dài
                    self.tableWidget.setItem(row, 6, self.make_item(self.generate_packet_info(packet)))  # Thông tin

                except Exception as e_inner:
                    print(f"Lỗi xử lý gói tin: {e_inner}")

        except Exception as e_outer:
            QMessageBox.critical(self, "Lỗi", f"Lỗi khi lọc gói tin: {str(e_outer)}")
    def packet_matches_filter(self, packet, filter_text):
        """
        Kiểm tra xem gói tin có khớp với bộ lọc không.
        Hỗ trợ lọc theo IP nguồn, IP đích, giao thức, độ dài gói tin, nội dung, cờ TCP và các giao thức DNS, HTTP, ICMP.
        """
        src_ip = packet[IP].src if packet.haslayer(IP) else (packet[Ether].src if packet.haslayer(Ether) else "Unknown")
        dst_ip = packet[IP].dst if packet.haslayer(IP) else (packet[Ether].dst if packet.haslayer(Ether) else "Unknown")
        packet_length = len(packet)
        protocol=self.identify_protocol(packet)
        try:
            if "ip.src==" in filter_text:
                ip_src_filter = filter_text.split("ip.src==")[1].strip()
                if src_ip == ip_src_filter:
                    return True

            if "ip.dst==" in filter_text:
                ip_dst_filter = filter_text.split("ip.dst==")[1].strip()
                if dst_ip == ip_dst_filter:
                    return True

            if "tcp" in filter_text.lower() and protocol=="TCP":
                return True
            
            if "udp" in filter_text.lower() and protocol=="UDP":
                return True
            
            if "icmp" in filter_text.lower() and protocol=="ICMP":
                return True
            
            if "dns" in filter_text.lower() and protocol=="DNS":
                return True
            
            if "http" in filter_text.lower() and  protocol=="HTTP" :
                if is_http_packet(packet):
                    return True
            
            if "frame.len>" in filter_text:
                length_threshold = int(filter_text.split("frame.len>")[1].strip())
                if packet_length > length_threshold:
                    return True
            
            if "frame contains" in filter_text:
                keyword = filter_text.split("frame contains")[1].strip().strip('"')
                if keyword.encode() in bytes(packet):
                    return True
            
            
            if "tcp.flags" in filter_text:
                flag_type = filter_text.split("tcp.flags==")[1].strip()
                if packet.haslayer(TCP):
                    flags = packet[TCP].flags
                    if flag_type.lower() == "syn" and flags & 0x02:
                        return True
                    if flag_type.lower() == "ack" and flags & 0x10:
                        return True
                    if flag_type.lower() == "fin" and flags & 0x01:
                        return True
                    if flag_type.lower() == "rst" and flags & 0x04:
                        return True
                    if flag_type.lower() == "psh" and flags & 0x08:
                        return True
            
        except Exception as e:
            print(f"Lỗi khi kiểm tra bộ lọc: {e}")
            return False
        
        return False
        
    def follow_tcp_stream(self): 
        selected_row = self.tableWidget.currentRow()
        if selected_row >= 0:
            packet_index = int(self.tableWidget.item(selected_row, 0).text()) - 1

            # Clear previous bold formatting (if any)
            for row in range(self.tableWidget.rowCount()):
                for column in range(self.tableWidget.columnCount()):
                    item = self.tableWidget.item(row, column)
                    if item:
                        font = item.font()
                        font.setBold(False)  # Set the font to normal
                        item.setFont(font)

            if 0 <= packet_index < len(self.packets):
                initial_packet = self.packets[packet_index]
                if initial_packet.haslayer(TCP) and initial_packet.haslayer(IP):
                    tcp_layer = initial_packet[TCP]
                    ip_layer = initial_packet[IP]

                    def is_same_stream(pkt):
                        if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                            return False
                        pkt_ip = pkt[IP]
                        pkt_tcp = pkt[TCP]

                        # Check two-way communication (client -> server and server -> client)
                        return (
                            (pkt_ip.src == ip_layer.src and pkt_ip.dst == ip_layer.dst and
                            pkt_tcp.sport == tcp_layer.sport and pkt_tcp.dport == tcp_layer.dport)
                            or
                            (pkt_ip.src == ip_layer.dst and pkt_ip.dst == ip_layer.src and
                            pkt_tcp.sport == tcp_layer.dport and pkt_tcp.dport == tcp_layer.sport)
                        )

                    # Filter packets for the same stream
                    stream_packets = []
                    seen_packets = set()  # Set to check duplicates
                    
                    for pkt in self.packets:
                        if is_same_stream(pkt):
                            # Create a unique identifier for the packet using tuple of relevant fields
                            pkt_id = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, pkt.time)
                            
                            if pkt_id not in seen_packets:
                                stream_packets.append(pkt)
                                seen_packets.add(pkt_id)

                    # Sort the stream packets by time and length
                    stream_packets.sort(key=lambda p: (p.time, len(p)))

                    # Store the original indices for STT (keep original sequence)
                    original_indices = [self.packets.index(pkt) + 1 for pkt in stream_packets]

                    # Update the table with the filtered stream packets
                    self.tableWidget.setRowCount(0)  # Clear previous data before adding new

                    for i, pkt in enumerate(stream_packets):
                        try:
                            if not pkt.haslayer(Raw):  # Skip packets without Raw data
                                continue
                            
                            # Retrieve packet details
                            src_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown"
                            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "Unknown"
                            length = len(pkt)
                            timestamp = pkt.time
                            protocol = self.identify_protocol(pkt)

                            # Add the packet to the table
                            row = self.tableWidget.rowCount()
                            self.tableWidget.insertRow(row)
                            self.tableWidget.setItem(row, 0, self.make_item(str(original_indices[i])))  # STT with original order
                            self.tableWidget.setItem(row, 1, self.make_item(str(timestamp)))   # Timestamp
                            self.tableWidget.setItem(row, 2, self.make_item(src_ip))   # Source IP
                            self.tableWidget.setItem(row, 3, self.make_item(dst_ip))   # Destination IP
                            self.tableWidget.setItem(row, 4, self.make_item(protocol))   # Protocol
                            self.tableWidget.setItem(row, 5, self.make_item(str(length)))   # Length
                            self.tableWidget.setItem(row, 6, self.make_item(self.generate_packet_info(pkt)))   # Packet info

                        except Exception as e_inner:
                            print(f"Error processing TCP stream packet: {e_inner}")

                    # Create a dialog to show the stream details
                    dialog = QDialog(self)
                    dialog.setWindowTitle("📡 Follow TCP Stream")
                    layout = QVBoxLayout()

                    text_edit = QTextEdit()
                    text_edit.setReadOnly(True)
                    text_edit.setFontFamily("Courier New")

                    format_combo = QComboBox()
                    format_combo.addItems(["ASCII", "UTF-8", "Raw Bytes", "Hex Dump"])
                    current_format = "ASCII"

                    def to_hex_dump(payload):
                        hex_string = ""
                        ascii_string = ""
                        line_length = 16
                        for i, byte in enumerate(payload):
                            hex_string += f"{byte:02x} "
                            if 32 <= byte <= 126:
                                ascii_string += chr(byte)
                            else:
                                ascii_string += "."
                            if (i + 1) % line_length == 0:
                                hex_string += f"  {ascii_string}\n"
                                ascii_string = ""
                            elif (i + 1) % 8 == 0:
                                hex_string += " "
                        if len(payload) % line_length != 0:
                            padding = " " * (3 * (line_length - (len(payload) % line_length)))
                            hex_string += padding + f"  {ascii_string}\n"
                        return hex_string

                    def to_printable_ascii(payload):
                        ascii_string = ""
                        for byte in payload:
                            if 32 <= byte <= 126:
                                ascii_string += chr(byte)
                            else:
                                ascii_string += "."
                        return ascii_string

                    def update_text_edit():
                        nonlocal current_format
                        current_format = format_combo.currentText()
                        stream_data = ""
                        ip_src_init = initial_packet[IP].src
                        port_src_init = initial_packet[TCP].sport
                        ip_dst_init = initial_packet[IP].dst
                        port_dst_init = initial_packet[TCP].dport

                        for i, pkt in enumerate(stream_packets):
                            if pkt.haslayer(Raw):
                                payload = pkt[Raw].load
                                decoded_payload = ""
                                direction = ""
                                # Determine packet direction and assign STT (Sequence Number)
                                if pkt[IP].src == ip_src_init and pkt[TCP].sport == port_src_init and \
                                pkt[IP].dst == ip_dst_init and pkt[TCP].dport == port_dst_init:
                                    direction = f"[Client -> Server] STT: {original_indices[i]}"
                                elif pkt[IP].src == ip_dst_init and pkt[TCP].sport == port_dst_init and \
                                    pkt[IP].dst == ip_src_init and pkt[TCP].dport == port_src_init:
                                    direction = f"[Server -> Client] STT: {original_indices[i]}"
                                else:
                                    direction = f"[Unknown Direction] STT: {original_indices[i]}"

                                stream_data += f"{direction}\n"

                                if current_format == "ASCII":
                                    decoded_payload = to_printable_ascii(payload)
                                elif current_format == "UTF-8":
                                    try:
                                        decoded_payload = payload.decode('utf-8', errors='replace')
                                    except UnicodeDecodeError:
                                        decoded_payload = repr(payload)
                                elif current_format == "Raw Bytes":
                                    decoded_payload = repr(payload)
                                elif current_format == "Hex Dump":
                                    decoded_payload = to_hex_dump(payload)

                                stream_data += decoded_payload + "\n"
                                stream_data += ("-" * 60) + "\n"

                        text_edit.setPlainText(stream_data)

                    format_combo.currentIndexChanged.connect(update_text_edit)
                    update_text_edit()  # Initial update

                    btn_close = QPushButton("Đóng")
                    btn_close.clicked.connect(dialog.close)

                    layout.addWidget(format_combo)
                    layout.addWidget(text_edit)
                    layout.addWidget(btn_close)

                    dialog.setLayout(layout)
                    dialog.resize(800, 600)
                    dialog.show()  # Show dialog

                else:
                    QMessageBox.warning(self, "Warning", "The selected packet is not a TCP/IP packet.")
            else:
                QMessageBox.warning(self, "Warning", "No packet is selected.")
        else:
            QMessageBox.warning(self, "Warning", "No row selected in the table.")

    def follow_udp_stream(self):
        selected_row = self.tableWidget.currentRow()
        if selected_row >= 0:
            packet_index = int(self.tableWidget.item(selected_row, 0).text()) - 1

            # Clear previous bold formatting (if any)
            for row in range(self.tableWidget.rowCount()):
                for column in range(self.tableWidget.columnCount()):
                    item = self.tableWidget.item(row, column)
                    if item:
                        font = item.font()
                        font.setBold(False)  # Set the font to normal
                        item.setFont(font)

            if 0 <= packet_index < len(self.packets):
                initial_packet = self.packets[packet_index]
                if initial_packet.haslayer(UDP) and initial_packet.haslayer(IP):
                    udp_layer = initial_packet[UDP]
                    ip_layer = initial_packet[IP]

                    def is_same_stream(pkt):
                        if not pkt.haslayer(UDP) or not pkt.haslayer(IP):
                            return False
                        pkt_ip = pkt[IP]
                        pkt_udp = pkt[UDP]

                        # Check if the source and destination IP and ports match the initial packet
                        return (
                            (pkt_ip.src == ip_layer.src and pkt_ip.dst == ip_layer.dst and
                             pkt_udp.sport == udp_layer.sport and pkt_udp.dport == udp_layer.dport)
                            or
                            (pkt_ip.src == ip_layer.dst and pkt_ip.dst == ip_layer.src and
                             pkt_udp.sport == udp_layer.dport and pkt_udp.dport == udp_layer.sport)
                        )

                    # Filter packets for the same stream
                    stream_packets = []
                    seen_packets = set()  # Set to check duplicates

                    for pkt in self.packets:
                        if is_same_stream(pkt):
                            # Create a unique identifier for the packet using tuple of relevant fields
                            pkt_id = (pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, pkt.time)

                            if pkt_id not in seen_packets:
                                stream_packets.append(pkt)
                                seen_packets.add(pkt_id)

                    # Sort the stream packets by time
                    stream_packets.sort(key=lambda p: p.time)

                    # Store the original indices for STT (keep original sequence)
                    original_indices = [self.packets.index(pkt) + 1 for pkt in stream_packets]

                    # Update the table with the filtered stream packets
                    self.tableWidget.setRowCount(0)  # Clear previous data before adding new

                    for i, pkt in enumerate(stream_packets):
                        try:
                            if not pkt.haslayer(Raw):  # Skip packets without Raw data
                                continue

                            # Retrieve packet details
                            src_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown"
                            dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "Unknown"
                            length = len(pkt)
                            timestamp = pkt.time
                            protocol = self.identify_protocol(pkt)

                            # Add the packet to the table
                            row = self.tableWidget.rowCount()
                            self.tableWidget.insertRow(row)
                            self.tableWidget.setItem(row, 0, self.make_item(str(original_indices[i])))  # STT with original order
                            self.tableWidget.setItem(row, 1, self.make_item(str(timestamp)))  # Timestamp
                            self.tableWidget.setItem(row, 2, self.make_item(src_ip))  # Source IP
                            self.tableWidget.setItem(row, 3, self.make_item(dst_ip))  # Destination IP
                            self.tableWidget.setItem(row, 4, self.make_item(protocol))  # Protocol
                            self.tableWidget.setItem(row, 5, self.make_item(str(length)))  # Length
                            self.tableWidget.setItem(row, 6, self.make_item(self.generate_packet_info(pkt)))  # Packet info

                        except Exception as e_inner:
                            print(f"Error processing UDP stream packet: {e_inner}")

                    # Create a dialog to show the stream details
                    dialog = QDialog(self)
                    dialog.setWindowTitle("📡 Follow UDP Stream")
                    layout = QVBoxLayout()

                    text_edit = QTextEdit()
                    text_edit.setReadOnly(True)
                    text_edit.setFontFamily("Courier New")

                    format_combo = QComboBox()
                    format_combo.addItems(["ASCII", "UTF-8", "Raw Bytes", "Hex Dump"])
                    current_format = "ASCII"

                    def to_hex_dump(payload):
                        hex_string = ""
                        ascii_string = ""
                        line_length = 16
                        for i, byte in enumerate(payload):
                            hex_string += f"{byte:02x} "
                            if 32 <= byte <= 126:
                                ascii_string += chr(byte)
                            else:
                                ascii_string += "."
                            if (i + 1) % line_length == 0:
                                hex_string += f"  {ascii_string}\n"
                                ascii_string = ""
                            elif (i + 1) % 8 == 0:
                                hex_string += " "
                        if len(payload) % line_length != 0:
                            padding = " " * (3 * (line_length - (len(payload) % line_length)))
                            hex_string += padding + f"  {ascii_string}\n"
                        return hex_string

                    def to_printable_ascii(payload):
                        ascii_string = ""
                        for byte in payload:
                            if 32 <= byte <= 126:
                                ascii_string += chr(byte)
                            else:
                                ascii_string += "."
                        return ascii_string

                    def update_text_edit():
                        nonlocal current_format
                        current_format = format_combo.currentText()
                        stream_data = ""
                        ip_src_init = initial_packet[IP].src
                        port_src_init = initial_packet[UDP].sport
                        ip_dst_init = initial_packet[IP].dst
                        port_dst_init = initial_packet[UDP].dport

                        for i, pkt in enumerate(stream_packets):
                            if pkt.haslayer(Raw):
                                payload = pkt[Raw].load
                                decoded_payload = ""
                                direction = ""
                                # Determine packet direction and assign STT (Sequence Number)
                                if pkt[IP].src == ip_src_init and pkt[UDP].sport == port_src_init and \
                                   pkt[IP].dst == ip_dst_init and pkt[UDP].dport == port_dst_init:
                                    direction = f"[Source -> Destination] STT: {original_indices[i]}"
                                elif pkt[IP].src == ip_dst_init and pkt[UDP].sport == port_dst_init and \
                                     pkt[IP].dst == ip_src_init and pkt[UDP].dport == port_src_init:
                                    direction = f"[Destination -> Source] STT: {original_indices[i]}"
                                else:
                                    direction = f"[Unknown Direction] STT: {original_indices[i]}"

                                stream_data += f"{direction}\n"

                                if current_format == "ASCII":
                                    decoded_payload = to_printable_ascii(payload)
                                elif current_format == "UTF-8":
                                    try:
                                        decoded_payload = payload.decode('utf-8', errors='replace')
                                    except UnicodeDecodeError:
                                        decoded_payload = repr(payload)
                                elif current_format == "Raw Bytes":
                                    decoded_payload = repr(payload)
                                elif current_format == "Hex Dump":
                                    decoded_payload = to_hex_dump(payload)

                                stream_data += decoded_payload + "\n"
                                stream_data += ("-" * 60) + "\n"

                        text_edit.setPlainText(stream_data)

                    format_combo.currentIndexChanged.connect(update_text_edit)
                    update_text_edit()  # Initial update

                    btn_close = QPushButton("Đóng")
                    btn_close.clicked.connect(dialog.close)

                    layout.addWidget(format_combo)
                    layout.addWidget(text_edit)
                    layout.addWidget(btn_close)

                    dialog.setLayout(layout)
                    dialog.resize(800, 600)
                    dialog.show()  # Show dialog

                else:
                    QMessageBox.warning(self, "Warning", "The selected packet is not a UDP/IP packet.")
            else:
                QMessageBox.warning(self, "Warning", "No packet is selected.")
        else:
            QMessageBox.warning(self, "Warning", "No row selected in the table.")
        
    
    def show_http_stream(self, selected_packet):
        if not is_http_packet(selected_packet):
            return

        tcp_layer = selected_packet[TCP]
        ip_layer = selected_packet[IP]

        # Hàm lọc các packet thuộc cùng một stream TCP
        def is_same_stream(pkt):
            if not pkt.haslayer(TCP) or not pkt.haslayer(IP):
                return False

            pkt_ip = pkt[IP]
            pkt_tcp = pkt[TCP]

            return (
                (pkt_ip.src == ip_layer.src and pkt_ip.dst == ip_layer.dst and
                 pkt_tcp.sport == tcp_layer.sport and pkt_tcp.dport == tcp_layer.dport)
                or
                (pkt_ip.src == ip_layer.dst and pkt_ip.dst == ip_layer.src and
                 pkt_tcp.sport == tcp_layer.dport and pkt_tcp.dport == tcp_layer.sport)
            )

        # Lọc tất cả các gói tin thuộc cùng stream
        http_stream_packets = list(filter(is_same_stream, self.packets))

        # Ghép nội dung stream
        stream_data = ""
        for pkt in http_stream_packets:
            payload=parse_http_payload(pkt)
            stream_data += payload + "\n"

        # Hiển thị cửa sổ với QTextEdit
        dialog = QDialog(self)
        dialog.setWindowTitle("📡 Follow HTTP Stream")
        layout = QVBoxLayout()

        text_edit = QTextEdit()
        text_edit.setPlainText(stream_data)
        text_edit.setReadOnly(True)

        btn_close = QPushButton("Đóng")
        btn_close.clicked.connect(dialog.close)

        layout.addWidget(text_edit)
        layout.addWidget(btn_close)

        dialog.setLayout(layout)
        dialog.resize(800, 600)
        dialog.exec()
 
    def sniff_packets(self, iface):
        sniff(iface=iface, prn=self.process_packet, store=True)

    def make_item(self,text):
        item = QTableWidgetItem(str(text))
        item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        return item
  
    def update_connection_counts(self,packet, src_ip, dst_ip, src_port, dst_port, proto):
        global connection_states, src_dport_counts, dst_sport_counts, dst_src_counts

        # Cập nhật số lượng kết nối theo giao thức
        if proto == 6:  # TCP
            tcp_layer = packet.getlayer(TCP)
            if tcp_layer:
                flags = tcp_layer.sprintf('%TCP.flags%')
                connection_states[(src_ip, dst_ip)] = flags
                src_dport_counts[(src_ip, dst_port)] = src_dport_counts.get((src_ip, dst_port), 0) + 1
                dst_sport_counts[(dst_ip, src_port)] = dst_sport_counts.get((dst_ip, src_port), 0) + 1
                dst_src_counts[(src_ip, dst_ip)] = dst_src_counts.get((src_ip, dst_ip), 0) + 1

                # Cập nhật các bộ đếm thời gian tồn tại của kết nối
                ttl = packet[IP].ttl if IP in packet else 0
                connection_states[(src_ip, dst_ip, "ct_state_ttl")] = ttl
                connection_states[(src_ip, dst_ip, "ct_src_dport_ltm")] = tcp_layer.sport
                connection_states[(src_ip, dst_ip, "ct_dst_sport_ltm")] = tcp_layer.dport
                connection_states[(src_ip, dst_ip, "ct_dst_src_ltm")] = dst_src_counts[(src_ip, dst_ip)]

        elif proto == 17:  # UDP
            connection_states[(src_ip, dst_ip)] = 0  # Trạng thái 0 cho UDP
            src_dport_counts[(src_ip, dst_port)] = src_dport_counts.get((src_ip, dst_port), 0) + 1
            dst_sport_counts[(dst_ip, src_port)] = dst_sport_counts.get((dst_ip, src_port), 0) + 1
            dst_src_counts[(src_ip, dst_ip)] = dst_src_counts.get((src_ip, dst_ip), 0) + 1
        elif proto == 1:  # ICMP
            connection_states[(src_ip, dst_ip)] = 0  # Trạng thái 0 cho ICMP
            src_dport_counts[(src_ip, dst_port)] = src_dport_counts.get((src_ip, dst_port), 0) + 1
            dst_sport_counts[(dst_ip, src_port)] = dst_sport_counts.get((dst_ip, src_port), 0) + 1
            dst_src_counts[(src_ip, dst_ip)] = dst_src_counts.get((src_ip, dst_ip), 0) + 1

    def calculate_dload(self,packet):
        global last_time, last_size
        current_time = time.time()
        size = len(packet)
        if last_time is None:
            last_time = current_time
            last_size = size
            return 0.0
        else:
            # Tính tốc độ tải xuống tính bằng bit/giây
            dload = abs((size - last_size) / (current_time - last_time))
            last_time = current_time
            last_size = size
            return dload
    
    def process_packet(self, packet):
        if not self.sniffing:
            return
        try:
            if len(self.packets) == 0:
                hex_str = hexdump(packet, dump=True)
                QTimer.singleShot(0, lambda: self.textEdit.setPlainText(hex_str))


            src = packet[IP].src if packet.haslayer(IP) else "Unknown"
            dst = packet[IP].dst if packet.haslayer(IP) else "Unknown"
            timestamp = time.strftime('%H:%M:%S')
            timestamp = f"{packet.time - self.start_time:.6f}"
            info = self.generate_packet_info(packet)
            protocol = self.identify_protocol(packet)

            global last_time, last_size

            printed_something = False  # Biến kiểm tra xem có in ra dữ liệu không
        
            dns_info = ""
            if packet.haslayer(DNS):
                dns_layer = packet[DNS]
                if dns_layer.qr == 0:  # DNS Query
                    query_name = dns_layer.qd.qname.decode() if dns_layer.qd else "Unknown"
                    dns_info = f"DNS Query: {query_name}"
                elif dns_layer.qr == 1:  # DNS Response
                    response_name = str(dns_layer.an.rdata) if hasattr(dns_layer.an, "rdata") else "No RDATA"
                    dns_info = f"DNS Response: {response_name}"
                else:
                    dns_info = "Unknown DNS Packet"

            # Thêm dòng mới vào table
            row_pos = self.tableWidget.rowCount()

            self.tableWidget.insertRow(row_pos)
            self.tableWidget.setItem(row_pos, 0, self.make_item(str(row_pos+1)))
            self.tableWidget.setItem(row_pos, 1, self.make_item(timestamp))
            self.tableWidget.setItem(row_pos, 2, self.make_item(src))
            self.tableWidget.setItem(row_pos, 3, self.make_item(dst))
            self.tableWidget.setItem(row_pos, 4, self.make_item(protocol))
            self.tableWidget.setItem(row_pos, 5, self.make_item(len(packet)))
            self.tableWidget.setItem(row_pos, 6, self.make_item(info))

            # Lưu lại packet nếu muốn dùng sau
            self.packets.append(packet)
            self.packets_filter.append(packet)
            if  protocol in ["TCP", "UDP"] : 
                if IP in packet:
                    
                        proto = packet[IP].proto
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst

                        # Xác định loại giao thức
                        protocol_label = "1" if proto == 6 else "2" if proto == 17 else "3" if proto == 1 else "0"
                        sttl = packet[IP].ttl if IP in packet else 0
                        swin, dwin = 0, 0
                        state_INT, state_CON, state_FIN = None, None, None
                        state = None

                        if proto == 6:  # TCP
                            state = packet[TCP].sprintf('%TCP.flags%')
                            state_INT = 1 if state == "INT" else 0
                            state_CON = 1 if state == "CON" else 0
                            state_FIN = 1 if state == "FIN" else 0
                            swin = packet[TCP].window
                            dwin = packet[TCP].options[3][1] if packet[TCP].options and len(packet[TCP].options) > 3 else 0
                        
                        src_port, dst_port = (packet.sport, packet.dport) if proto in [6, 17] else (None, None)
                        dload = self.calculate_dload(packet)

                        self.update_connection_counts(packet, src_ip, dst_ip, src_port, dst_port, proto)

                        data = {
                            "sttl": sttl,
                            "state_INT": state_INT,
                            "ct_state_ttl": 0,
                            "proto_tcp": 1 if proto == 6 else 0,
                            "swin": swin,
                            "dload": dload,
                            "state_CON": state_CON,
                            "dwin": dwin,
                            "state_FIN": state_FIN
                        }

                        if self.AI.predict_anomaly(data) == 1:
                            printed_something = True
                            print("Tấn công!")
                            print("Loại bất thường:", self.AI.predict_attack(data))
                            msg = f"Bản ghi {row_pos+1} xuất hiện bất thường!\nLoại bất thường: {self.AI.predict_attack(data)}"
                            with open("log_tan_cong.txt", "a", encoding="utf-8") as f:
                                f.write(msg + "\n")
                            for col in range(self.tableWidget.columnCount()):
                                self.tableWidget.item(row_pos, col).setBackground(QtGui.QColor("red"))
                                self.tableWidget.item(row_pos, col).setForeground(QtGui.QColor("white"))
                        print(f"PROTO: {protocol_label}, IPSRC: {src_ip} : SPORT: {src_port}, IPDST: {dst_ip} : DPORT: {dst_port}, STATE: {state}, STTL: {sttl}, DLOAD: {dload}, SWIN: {swin}, DWIN: {dwin}, STATE_INT: {state_INT}, STATE_CON: {state_CON}, STATE_FIN: {state_FIN}")



                if not printed_something:
                    print("Bình thường...")
    
        except Exception as e:
            print(e)

    def identify_protocol(self , packet): 
        if packet.haslayer(ARP):
            return "ARP"
        elif packet.haslayer(DNS):
            return "DNS"
        elif packet.haslayer(TCP):
            dport = packet[TCP].dport if packet.haslayer(TCP) else 0
            sport = packet[TCP].sport if packet.haslayer(TCP) else 0
            if dport == 80 or  sport==80 :
                return "HTTP"
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
            # elif dport == 443:
            #     return "HTTPS"
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

    def stop_sniffing(self):
        self.sniffing = False
        self.stop_button.setEnabled(False)
        self.start_button.setEnabled(True)

    def save_pcap(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Packet Capture",
            "",
            "PCAP files (*.pcap)"
        )
        if file_path:
            try:
                wrpcap(file_path, self.packets)
                QMessageBox.information(self, "Save", "Packets saved successfully!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file:\n{e}")

    def load_pcap(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open PCAP File",
            "",
            "PCAP files (*.pcap)"
        )
        if file_path:
            try:
                self.packets = rdpcap(file_path)
                self.tableWidget.setRowCount(0)  # Xoá hết dữ liệu cũ

                self.start_time = self.packets[0].time if self.packets else time.time()

                for idx, packet in enumerate(self.packets):
                    # Thông tin gói
                    timestamp = f"{packet.time - self.start_time:.6f}"
                    src_ip = packet[IP].src if packet.haslayer(IP) else (packet[Ether].src if packet.haslayer(Ether) else "Unknown")
                    dst_ip = packet[IP].dst if packet.haslayer(IP) else (packet[Ether].dst if packet.haslayer(Ether) else "Unknown")
                    protocol = self.identify_protocol(packet)
                    length = len(packet)
                    info = self.generate_packet_info(packet)

                    row_pos = self.tableWidget.rowCount()
                    self.tableWidget.insertRow(row_pos)
                    self.tableWidget.setItem(row_pos, 0, self.make_item(str(row_pos + 1)))
                    self.tableWidget.setItem(row_pos, 1, self.make_item(timestamp))
                    self.tableWidget.setItem(row_pos, 2, self.make_item(src_ip))
                    self.tableWidget.setItem(row_pos, 3, self.make_item(dst_ip))
                    self.tableWidget.setItem(row_pos, 4, self.make_item(protocol))
                    self.tableWidget.setItem(row_pos, 5, self.make_item(str(length)))
                    self.tableWidget.setItem(row_pos, 6, self.make_item(info))

                QMessageBox.information(self, "Load", "Packets loaded successfully!")

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load file:\n{e}")

    def reset_sniffing(self):
        self.stop_sniffing()
        self.packets.clear()
        self.packets_filter.clear()
        # Xoá bảng gói tin
        self.tableWidget.setRowCount(0)

        # Xoá nội dung text (nếu có vùng hiển thị chi tiết gói tin)
        self.textEdit.clear()

        # Bật lại nút Start
        self.start_button.setEnabled(True)

        QMessageBox.information(self, "Reset", "Sniffer đã được reset thành công!")

    def show_packet_size_stats(self):
        if not self.packets:
            QMessageBox.warning(self, "Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Lấy danh sách kích thước gói tin
        packet_sizes = [len(packet) for packet in self.packets]

        # Tạo cửa sổ mới
        stats_window = QDialog(self)
        stats_window.setWindowTitle("Thống kê Kích thước Gói tin")
        stats_window.resize(600, 400)

        layout = QVBoxLayout(stats_window)

        # Tạo biểu đồ
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.hist(packet_sizes, bins=30, color="blue", alpha=0.7)
        ax.set_title("Phân phối Kích thước Gói tin")
        ax.set_xlabel("Kích thước (bytes)")
        ax.set_ylabel("Số lượng")

        # Gắn biểu đồ vào canvas PyQt
        canvas = FigureCanvas(fig)
        layout.addWidget(canvas)
        canvas.draw()

        stats_window.exec()

    def show_destination_stats(self):
        if not self.packets:
            QMessageBox.warning(self, "Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Tạo DataFrame từ các gói IP
        df = pd.DataFrame({
            "Destination": [p[IP].dst for p in self.packets if p.haslayer(IP)]
        })

        # Đếm tần suất
        destination_frequency = df["Destination"].value_counts()
        destination_frequency = destination_frequency[destination_frequency >= 10]

        if destination_frequency.empty:
            QMessageBox.information(self, "Thông báo", "Không có địa chỉ đích nào có tần suất trên 10!")
            return

        # Tạo cửa sổ thống kê
        stats_window = QDialog(self)
        stats_window.setWindowTitle("Thống kê Địa chỉ Đích")
        stats_window.resize(800, 500)

        layout = QVBoxLayout(stats_window)

        # Tạo biểu đồ
        fig, ax = plt.subplots(figsize=(10, 5))
        destination_frequency.plot(kind="bar", color="skyblue", ax=ax)
        ax.set_xlabel("Địa chỉ đích")
        ax.set_ylabel("Tần suất")
        ax.set_title("Tần suất các địa chỉ đích xuất hiện")
        ax.tick_params(axis='x', rotation=45)

        # Thêm vào PyQt canvas
        canvas = FigureCanvas(fig)
        layout.addWidget(canvas)
        canvas.draw()

        stats_window.exec()

    def show_source_stats(self):
        if not self.packets:
            QMessageBox.warning(self, "Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Lọc IP có lớp IP
        df = pd.DataFrame({
            "Source": [p[IP].src for p in self.packets if p.haslayer(IP)]
        })

        # Thống kê tần suất
        frequency = df["Source"].value_counts()
        frequency = frequency[frequency >= 20]  # 👈 Chỉnh điều kiện tùy yêu cầu

        if frequency.empty:
            QMessageBox.information(self, "Thông báo", "Không có địa chỉ nguồn nào có tần suất trên 20!")
            return

        # Tạo cửa sổ thống kê
        stats_window = QDialog(self)
        stats_window.setWindowTitle("Thống kê Địa chỉ Nguồn")
        stats_window.resize(800, 500)

        layout = QVBoxLayout(stats_window)

        # Tạo biểu đồ
        fig, ax = plt.subplots(figsize=(10, 5))
        frequency.plot(kind="bar", color="lightcoral", ax=ax)
        ax.set_xlabel("Địa chỉ nguồn")
        ax.set_ylabel("Tần suất")
        ax.set_title("Tần suất các địa chỉ nguồn xuất hiện")
        ax.tick_params(axis='x', rotation=45)

        # Thêm canvas vào PyQt
        canvas = FigureCanvas(fig)
        layout.addWidget(canvas)
        canvas.draw()

        stats_window.exec()

    def show_protocol_stats(self):
        if not self.packets:
            QMessageBox.warning(self, "Cảnh báo", "Không có gói tin để thống kê!")
            return

        # Tạo DataFrame chứa tên giao thức
        df = pd.DataFrame({
            "protocol": [self.identify_protocol(p) for p in self.packets]
        })

        protocol_counts = df["protocol"].value_counts()

        # Tạo cửa sổ thống kê
        stats_window = QDialog(self)
        stats_window.setWindowTitle("Thống kê Giao thức")
        stats_window.resize(600, 400)

        layout = QVBoxLayout(stats_window)

        # Tạo biểu đồ
        fig, ax = plt.subplots(figsize=(6, 4))
        protocol_counts.plot(kind="bar", ax=ax, color="skyblue")
        ax.set_title("Phân phối Giao thức")
        ax.set_xlabel("Giao thức")
        ax.set_ylabel("Số lượng")
        ax.set_xticklabels(ax.get_xticklabels(), rotation=0, ha="center")

        # Gắn biểu đồ vào PyQt
        canvas = FigureCanvas(fig)
        layout.addWidget(canvas)
        canvas.draw()

        stats_window.exec()

    def on_table_row_clicked(self, row, column):
        if 0 <= row < len(self.packets):
            packet = self.packets_filter[row]
            hex_str = hexdump(packet, dump=True)
            self.textEdit.setPlainText(hex_str)
                    
    def is_far_enough(self, new_pos, pos, min_distance=150):
        if not pos:
            return True
        positions = np.array(list(pos.values()))
        distances = distance.cdist(np.array([new_pos]), positions)
        return np.all(distances >= min_distance)

    def generate_positions(self, nodes, min_distance=100):
        positions = {}
        for node in nodes:
            while True:
                new_pos = np.random.uniform(-100, 100, size=3)
                if self.is_far_enough(new_pos, positions, min_distance): 
                    positions[node] = new_pos
                    break
        return positions

    def show_ip_relations(self):
        ip_address, ok = QInputDialog.getText(self, "Nhập địa chỉ IP", "Nhập địa chỉ IP:")
        if not ok or not ip_address:
            return

        related_ips = set()
        edges = {}

        # Màu sắc cho các giao thức
        protocol_colors = {
            1: 'green',    # ICMP
            6: 'red',      # TCP
            17: 'blue',    # UDP
            'ARP': 'yellow', # ARP
            'Other': 'purple' # Các giao thức khác
        }

        for packet in self.packets:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet[IP].proto

                if protocol == 1:
                    protocol_color = protocol_colors[1]  # ICMP
                elif protocol == 6:
                    protocol_color = protocol_colors[6]  # TCP
                elif protocol == 17:
                    protocol_color = protocol_colors[17]  # UDP
                elif protocol == "ARP":
                    protocol_color = protocol_colors['ARP']
                else:
                    protocol_color = protocol_colors['Other']

                if ip_address == src_ip:
                    related_ips.add(dst_ip)
                    if (src_ip, dst_ip) not in edges:
                        edges[(src_ip, dst_ip)] = {'color': protocol_color, 'weight': 1}
                    else:
                        edges[(src_ip, dst_ip)]['weight'] += 1

                elif ip_address == dst_ip:
                    related_ips.add(src_ip)
                    if (dst_ip, src_ip) not in edges:
                        edges[(dst_ip, src_ip)] = {'color': protocol_color, 'weight': 1}
                    else:
                        edges[(dst_ip, src_ip)]['weight'] += 1

            elif packet.haslayer(DNS) and packet[DNS].qr == 0:
                if packet[DNS].qd and packet[DNS].qd.qname:
                    domain = packet[DNS].qd.qname.decode(errors="ignore")
                    if ip_address in domain:
                        src_ip = packet[IP].src if packet.haslayer(IP) else "Unknown"
                        related_ips.add(domain)
                        if (src_ip, domain) not in edges:
                            edges[(src_ip, domain)] = {'color': 'yellow', 'weight': 1}
                        else:
                            edges[(src_ip, domain)]['weight'] += 1

        if not related_ips:
            QMessageBox.information(self, "Thông báo", f"Không tìm thấy quan hệ nào cho IP {ip_address}")
            return

        G = nx.Graph()
        G.add_node(ip_address)
        G.add_nodes_from(related_ips)
        G.add_edges_from(edges.keys())

        pos = self.generate_positions(G.nodes())

        edge_x, edge_y, edge_z = [], [], []
        edge_text = []
        edge_colors = []  # Danh sách lưu màu sắc cho các cạnh
        for (u, v), edge_info in edges.items():
            protocol_color = edge_info['color']  # Màu sắc của giao thức
            if protocol_color == 'green':
                protocol_text = "ICMP"
            elif protocol_color == 'red':
                protocol_text = "TCP"
            elif protocol_color == 'blue':
                protocol_text = "UDP"
            elif protocol_color == 'yellow':
                protocol_text = "ARP"
            else:
                protocol_text = "Other"

            weight = edge_info['weight']
            x0, y0, z0 = pos[u]
            x1, y1, z1 = pos[v]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
            edge_z.extend([z0, z1, None])
            print(f"Edge text: Giao thức: {protocol_text}, Trọng số: {weight}")
            edge_text.append(f"Giao thức: {protocol_text}, Trọng số: {weight}")

            # Thêm màu sắc cho các cạnh
            edge_colors.extend([protocol_color, protocol_color, 'rgba(0,0,0,0)'])

        edge_trace = go.Scatter3d(
            x=edge_x, y=edge_y, z=edge_z,
            line=dict(width=5, color=edge_colors),  # Cung cấp màu sắc cho từng cạnh
            hoverinfo='text',
            text=edge_text,
            mode='lines'
        )

        node_x, node_y, node_z, node_text = [], [], [], []
        for node, (x, y, z) in pos.items():
            node_x.append(x)
            node_y.append(y)
            node_z.append(z)
            node_text.append(str(node))

        node_trace = go.Scatter3d(
            x=node_x, y=node_y, z=node_z,
            mode='markers+text',
            marker=dict(size=10, color='skyblue'),
            text=node_text,
            textposition="top center",
            hoverinfo="text"
        )

        fig = go.Figure(data=[edge_trace, node_trace])  
        fig.update_layout(
            title=f"Quan hệ IP 3D: {ip_address}",
            showlegend=False,
            scene=dict(
                xaxis=dict(visible=False),
                yaxis=dict(visible=False),
                zaxis=dict(visible=False),
            ),
            dragmode='orbit',  
        )

        html = pio.to_html(fig, full_html=False)

        if not html.strip():
            QMessageBox.warning(self, "Lỗi", "Không thể tạo HTML cho đồ thị.")
            return

        with open("plot.html", "w", encoding="utf-8") as f:
            f.write(html)
        QMessageBox.information(self, "Thông báo", "Đồ thị quan hệ IP đã được tạo thành công!")

    def show_packet_http(self, packet):
        if is_http_packet(packet):
            http_text = parse_http_payload(packet)
            if http_text:
                dialog = HTTPDialog(http_text)
                dialog.exec()
            else:
                print("Không tìm thấy HTTP request trong gói tin này.")
        else:
            print("Đây không phải là gói HTTP.")

if __name__ == "__main__":
    QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts)
    app = QApplication(sys.argv)
    window = WireBabyShark()
    window.show()
    sys.exit(app.exec())