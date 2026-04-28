# 🔐 CodeAlpha — Basic Network Sniffer

A Python-based network packet sniffer built using **Scapy** that captures 
and analyzes live network traffic in real time.

Built as part of the **CodeAlpha Cybersecurity Internship — Task 1**

---

## 📌 Features
- Captures live network packets in real time
- Detects protocols: TCP, UDP, ICMP
- Displays source and destination IP addresses
- Shows port numbers for TCP and UDP
- Extracts and displays payload data
- Timestamps every captured packet

---

## 🛠️ Technologies Used
- Python 3.14
- Scapy 2.7.0
- Npcap (Windows packet capture driver)

---

## ⚙️ Installation & Setup

### 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/CodeAlpha_NetworkSniffer.git
cd CodeAlpha_NetworkSniffer

### 2. Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

### 3. Install dependencies
python -m pip install scapy

### 4. Install Npcap (Windows only)
Download from: https://npcap.com/#download
Check "WinPcap API-compatible Mode" during installation.

---

## ▶️ Usage
Run PowerShell as Administrator, then:
python network_sniffer.py

---

## 📸 Sample Output
[14:23:01] Protocol: TCP
  SRC IP  : 192.168.1.5
  DST IP  : 142.250.77.14
  SRC Port: 52341 → DST Port: 443
  TCP Flags: PA
  Payload  : No payload

---

## ⚠️ Legal Disclaimer
**This tool is intended for educational purposes only**.
**Run it only on your own network and devices**.
**Unauthorized packet sniffing is illegal**.

---

## 👨‍💻 Author
- **Barath k**
- CodeAlpha Cybersecurity Intern
- GitHub: https://github.com/barath-css
- LinkedIn: https://linkedin.com/in/barath-k-11461633b
