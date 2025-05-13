import csv
import threading
import tkinter as tk
from tkinter import messagebox, ttk
from scapy.all import DNS, sniff, wrpcap
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import joblib
import os
import time

# File paths
csv_file = "dns_features.csv"
model_file = 'dns_classifier.pkl'
pcap_file = "detected_dns_tunnel_packets.pcap"

# Load trained model
if not os.path.exists(model_file):
    print("❌ Error: Model file not found! Please train the model using test_script_dns.py.")
    exit()

def load_model():
    return joblib.load(model_file)

model = load_model()

# Packet flow data
packet_sizes = []
sniff_thread = None
stop_sniffing = threading.Event()

# Feature Extraction for DNS Packets
def extract_packet_features(packet):
    if DNS in packet and packet[DNS].qr == 0:
        query_name = packet[DNS].qd.qname.decode(errors='ignore')
        return {
            "query_length": len(query_name),
            "subdomain_count": query_name.count('.') - 1,
            "packet_size": len(packet),
            "packet": packet
        }
    return None

# Save extracted features to CSV
def append_to_csv(features, label=0):
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([features["query_length"], features["subdomain_count"], features["packet_size"], label])

# Save detected tunneled packets to PCAP
def save_packet_to_pcap(packet):
    wrpcap(pcap_file, packet, append=True)

# Alert Handling
def alert_dns_tunnel():
    if root.winfo_exists():
        print("⚠️ ALERT: Potential DNS Tunnel Attack Detected!")
        alert_label.config(text="⚠️ ALERT: DNS Tunnel Attack!", bg="red", fg="white")
        root.after(0, messagebox.showwarning, "Alert!", "Potential DNS Tunnel Attack Detected!")

# Update Packet Graph Safely
def update_graph():
    if root.winfo_exists():
        root.after(100, redraw_graph)

def redraw_graph():
    ax.clear()
    ax.plot(packet_sizes, marker='o', linestyle='-')
    ax.set_title("Real-Time DNS Packet Flow")
    ax.set_xlabel("Packet Number")
    ax.set_ylabel("Packet Size")
    canvas.draw()

# Capture and Process DNS Packets
def capture_dns(packet):
    if stop_sniffing.is_set():
        return
    
    features = extract_packet_features(packet)
    if features:
        packet_sizes.append(features["packet_size"])
        update_graph()
        
        prediction = model.predict([[features["query_length"], features["subdomain_count"], features["packet_size"]]])[0]
        append_to_csv(features, prediction)
        
        if prediction == 1:
            alert_dns_tunnel()
            save_packet_to_pcap(features["packet"])

# GUI Setup
def setup_gui():
    global root, alert_label, status_label, canvas, ax
    root = tk.Tk()
    root.title("DNS Tunneling IDS")
    root.geometry("600x400")
    
    title_label = tk.Label(root, text="DNS IDS", font=("Arial", 16, "bold"))
    title_label.pack(pady=10)
    
    status_label = tk.Label(root, text="Status: Idle", font=("Arial", 12))
    status_label.pack(pady=5)
    
    alert_label = tk.Label(root, text="No Alerts", width=30, height=2, bg="#27AE60", fg="white")
    alert_label.pack(pady=10)
    
    start_button = ttk.Button(root, text="Start Capture", command=start_capture)
    start_button.pack(pady=10)
    
    stop_button = ttk.Button(root, text="Stop Capture", command=stop_capture)
    stop_button.pack(pady=10)
    
    # Packet Flow Graph
    fig, ax = plt.subplots()
    canvas = FigureCanvasTkAgg(fig, master=root)
    canvas.get_tk_widget().pack()
    
    root.mainloop()

# Start Packet Capture
def start_capture():
    global sniff_thread
    stop_sniffing.clear()
    print("🚀 Starting DNS Packet Capture...")
    status_label.config(text="Status: Capturing...", fg="blue")
    root.update()
    
    sniff_thread = threading.Thread(target=sniff, kwargs={
        'filter': "udp port 53",
        'prn': capture_dns,
        'store': 0
    }, daemon=True)
    sniff_thread.start()

# Stop Packet Capture
def stop_capture():
    global sniff_thread
    stop_sniffing.set()
    if sniff_thread and sniff_thread.is_alive():
        print("🛑 Stopping DNS Packet Capture...")
        sniff_thread = None
    if root.winfo_exists():
        status_label.config(text="Status: Stopped", fg="red")
        root.update()

if __name__ == "__main__":
    setup_gui()
