# RapidNet Scanner

## Description

The **RapidNet Scanner** is a GUI-based network discovery and port‑scanning tool built using **Python**, **CustomTkinter**, **Scapy**, and **Socket**. It enables users to quickly enumerate devices on a local network, identify active hosts, and detect open ports. The interface is designed to be clean, modern, and beginner‑friendly while still offering core scanning functionality.

This project demonstrates skills in:

* Python networking and automation
* GUI development with CustomTkinter
* Multithreaded scanning using `ThreadPoolExecutor`
* ARP-based host discovery
* Basic TCP port scanning

The tool is intended for **educational and research purposes** and should only be used on networks you own or are authorized to test.

---

## Features

### Network Scanning

* Scans a full `/24` subnet (1–254).
* Uses ARP requests to identify active devices.
* Displays IP and MAC addresses.
* Updates progress in real time.

### Port Scanning

* Automatically scans ports **20–1023** on each discovered host.
* Identifies open TCP ports.

### Multithreaded Engine

* Fast scanning using Python's `ThreadPoolExecutor`.
* Responsive GUI during scans.

### Modern CustomTkinter GUI

* Dark theme interface.
* Real‑time status output.
* Scrollable results panel.
* Progress bar with percentage indicator.

### Safe Controls

* "Start Scan" and "Stop Scan" toggle.
* Clear output button.
* Status indicator for each action.

---

## Requirements

Ensure you have the following installed:

* **Python 3.8+**
* **CustomTkinter**
* **Scapy**

Install dependencies:

```bash
pip install customtkinter scapy
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/your-username/RapidNet-Scanner.git
cd RapidNet-Scanner
```

Run the tool:

```bash
python netscan.py
```

---

## Usage

### 1. Enter Network Prefix

Example:

```
192.168.1
```

The scanner will test all hosts from `192.168.1.1` to `192.168.1.254`.

### 2. Start the Scan

The scanner will:

* Send ARP requests to identify active hosts.
* Log devices in real time.
* Scan ports 20–1023 for each discovered host.

### 3. View Results

The right results panel will display:

* Active devices (IP + MAC)
* Open ports per device
* Status updates

### 4. Stop or Clear

* Use **Stop** to halt scanning mid‑process.
* Use **Clear** to reset the interface.

---

## Troubleshooting

### Missing Scapy or Permission Issues

If ARP scanning fails, run with elevated privileges:

```bash
sudo python netscan.py
```

### No Devices Detected

* Ensure you're scanning the correct network.
* Verify your firewall is not blocking ARP responses.

### Slow Scanning

* ARP timeouts may prolong results.
* Network congestion can affect responses.

---

## Project Structure

```
.
├── netscan.py             
└── icon/network_icon.ico
```

---

## How It Works Internally

### 1. ARP Scanning

The tool constructs:

* An ARP request (`scapy.ARP`)
* Encapsulated in a broadcast Ethernet frame

All active devices reply with their IP and MAC.

### 2. Port Scanning

For each active device:

* Attempts TCP connection to ports 20–1023
* Ports responding with `connect_ex == 0` are listed as open

### 3. Multithreaded Execution

Both host and port scanning use threads to ensure:

* Faster scan times
* No UI freezing

---
## Legal Disclaimer

This tool is for **authorized testing only**. Using it on networks without permission may be illegal.
The author is not responsible for any misuse or damages.

---
## License

This project is licensed under the **MIT License**.
