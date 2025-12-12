# ==============================================================
#  Network Scanner
#  Author: Mohammad Shahazaad Ahmed
#
#  LEGAL DISCLAIMER:
#  This software is provided for educational and research purposes only.
#  It is NOT intended for use on production environments or
#  unauthorized systems.
#
#  Any damage, misconfiguration, or security impact caused by
#  using this tool is solely the user's responsibility.
#
#  Proceed with caution.
# ==============================================================

import customtkinter as ctk
import scapy.all as scapy
import threading
import socket
from tkinter import messagebox
from concurrent.futures import ThreadPoolExecutor

scanning_thread = None
scan_stop = False
executor = None

def scan_network(network):
    ips = []
    def scan_ip(i):
        if scan_stop:
            return
        ip = f"{network}.{i}"
        arp = scapy.ARP(pdst=ip)
        ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        pkt = ether/arp
        ans, _ = scapy.srp(pkt, timeout=2, verbose=False)
        if ans:
            for response in ans:
                ip_address = response[1].psrc
                mac_address = response[1].hwsrc
                ips.append((ip_address, mac_address))
            update_status(f"Device found: {ip_address} ({mac_address})")
        else:
            update_status(f"No response from IP: {ip}")
        set_progress(i / 255)

    with ThreadPoolExecutor(max_workers=20) as executor:
        for i in range(1, 255):
            executor.submit(scan_ip, i)
    
    return ips

def scan_ports(ip):
    open_ports = []
    def scan_port(port):
        if scan_stop:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()

    with ThreadPoolExecutor(max_workers=20) as executor:
        for port in range(20, 1024):
            executor.submit(scan_port, port)
    
    return open_ports

def update_status(text):
    status_label.configure(text=f"Status: {text}")
    status_label.update()

def set_progress(value):
    progress.set(value)
    progress_label.configure(text=f"{int(value * 100)}%")
    progress.update()

def stop_scan():
    global scan_stop
    scan_stop = True
    update_status("Scan Stopped")
    scan_button.configure(text="Start Scan", command=start_scan)
    set_progress(0)

def start_scan():
    global scan_stop
    scan_stop = False
    network = entry.get()
    output.delete("0.0", "end")
    if network:
        update_status("Scanning...")
        progress.set(0)
        scan_button.configure(text="Stop", command=stop_scan)
        devices = scan_network(network)
        if devices:
            set_progress(0.5)
            for ip, mac in devices:
                update_status(f"Found Device: {ip}")
                output.insert("end", f"IP: {ip}, MAC: {mac}\n")
                output.update()
                ports = scan_ports(ip)
                if ports:
                    output.insert("end", f"Open Ports on {ip}: {', '.join(map(str, ports))}\n")
                else:
                    output.insert("end", f"No open ports on {ip}\n")
                output.update()
            set_progress(1)
        else:
            output.insert("end", "No active devices found.\n")
    else:
        messagebox.showwarning("Input Error", "Please enter a valid network.")
        update_status("Idle")

def run_scan():
    global scanning_thread
    scanning_thread = threading.Thread(target=start_scan, daemon=True)
    scanning_thread.start()

def clear_output():
    output.delete("0.0", "end")
    update_status("Idle")
    set_progress(0)
    scan_button.configure(text="Start Scan", command=start_scan)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

app = ctk.CTk()
app.title("Network Scanner")
app.geometry("820x520")
app.iconbitmap("icon/network_icon.ico")
app.grid_rowconfigure(0, weight=1)
app.grid_columnconfigure(0, weight=1)
app.grid_columnconfigure(1, weight=2)

left_panel = ctk.CTkFrame(app, corner_radius=12, fg_color="#1f2327")
left_panel.grid(row=0, column=0, sticky="nsew", padx=(20,10), pady=20)
left_panel.grid_rowconfigure(6, weight=1)

header = ctk.CTkFrame(left_panel, corner_radius=8, fg_color="#2a2f33")
header.pack(fill="x", padx=12, pady=(12,8))
title_label = ctk.CTkLabel(header, text="Network Scanner", font=("Helvetica", 18, "bold"))
title_label.pack(side="left", padx=10, pady=10)
sub_label = ctk.CTkLabel(header, text="By Shahazaad Ahmed", font=("Helvetica", 10))
sub_label.pack(side="right", padx=10)

instruction_label = ctk.CTkLabel(left_panel, text="Enter Network (e.g., 192.168.1)", anchor="w", font=("Helvetica", 12))
instruction_label.pack(fill="x", padx=12, pady=(8,4))

entry = ctk.CTkEntry(left_panel, placeholder_text="192.168.1", width=260, font=("Helvetica", 13), corner_radius=8)
entry.pack(padx=12, pady=(0,12))

btns = ctk.CTkFrame(left_panel, fg_color="#1b1e20")
btns.pack(fill="x", padx=12, pady=(0,12))
scan_button = ctk.CTkButton(btns, text="Start Scan", command=run_scan, fg_color="#3D4354", hover_color="#5B6580", corner_radius=8)
scan_button.grid(row=0, column=0, padx=6, pady=12)
clear_button = ctk.CTkButton(btns, text="Clear", fg_color="#9a9a9a", hover_color="#8b8b8b", command=clear_output)
clear_button.grid(row=0, column=1, padx=6, pady=12)

status_label = ctk.CTkLabel(left_panel, text="Status: Idle", font=("Helvetica", 10), anchor="w")
status_label.pack(fill="x", padx=14, pady=(4,12))

right_panel = ctk.CTkFrame(app, corner_radius=12, fg_color="#121416")
right_panel.grid(row=0, column=1, sticky="nsew", padx=(10,20), pady=20)

result_header = ctk.CTkLabel(right_panel, text="Scan Results", font=("Helvetica", 16, "bold"))
result_header.grid(row=0, column=0, sticky="w", padx=12, pady=(12,8))

output_frame = ctk.CTkFrame(right_panel, fg_color="#0f1112")
output_frame.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0,12))
output_frame.grid_rowconfigure(0, weight=1)
output_frame.grid_columnconfigure(0, weight=1)

output = ctk.CTkTextbox(output_frame, font=("Consolas", 11), corner_radius=8, wrap="word")
output.grid(row=0, column=0, sticky="nsew", padx=(8,0), pady=8)
scroll = ctk.CTkScrollbar(output_frame, orientation="vertical", command=output.yview)
scroll.grid(row=0, column=1, sticky="ns", padx=(0,8), pady=8)
output.configure(yscrollcommand=scroll.set)

progress_frame = ctk.CTkFrame(right_panel, fg_color="#0f1112")
progress_frame.grid(row=2, column=0, sticky="ew", padx=12, pady=(0,12))
progress_frame.grid_columnconfigure(0, weight=1)

progress = ctk.CTkProgressBar(progress_frame, mode="determinate")
progress.grid(row=0, column=0, sticky="ew", padx=8, pady=10)
progress_label = ctk.CTkLabel(progress_frame, text="0%", width=60, anchor="e")
progress_label.grid(row=0, column=1, padx=(6,8))

footer_label = ctk.CTkLabel(app, text="© Network Scanner", font=("Helvetica", 9))
footer_label.grid(row=1, column=0, columnspan=2, pady=(0,10))

app.mainloop()
