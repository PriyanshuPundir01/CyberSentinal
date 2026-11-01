<div align="center">

<h1 style="font-family: 'Cooper Black', 'Arial Black', serif; font-size: 4rem; letter-spacing: 2px; color: #00ff99; margin-bottom: 2px; text-shadow: 0 0 25px rgba(0, 255, 153, 0.45);">
  🛡️ CYBERSENTINAL 🛡️
</h1>

<h3 style="font-family: 'Bookman Old Style', 'URW Bookman', 'Georgia', serif; font-weight: 500; color: #00d4ff; margin-top: 6px; letter-spacing: 0.8px;">
  ◈ <i>Next-Gen Network Threat & SOC Anomaly Analyzer</i> ◈
</h3>

<br/>

[![Python](https://img.shields.io/badge/Python-3.8%2B-00ff99?style=for-the-badge&logo=python&logoColor=0a0c10)](https://python.org)
[![CustomTkinter](https://img.shields.io/badge/GUI-CustomTkinter-00d4ff?style=for-the-badge&logo=tcl&logoColor=0a0c10)](https://github.com/TomSchimansky/CustomTkinter)
[![Matplotlib](https://img.shields.io/badge/Telemetry-Matplotlib-ff007f?style=for-the-badge&logo=databricks&logoColor=ffffff)](https://matplotlib.org/)
[![Scapy](https://img.shields.io/badge/Sniffer-Scapy_Enabled-ffb703?style=for-the-badge&logo=wireshark&logoColor=0a0c10)](https://scapy.net/)
[![Status](https://img.shields.io/badge/Engine-Active_Monitoring-00ff66?style=for-the-badge&logo=statuspage&logoColor=0a0c10)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-a78bfa?style=for-the-badge&logo=open-source-initiative&logoColor=0a0c10)](LICENSE)

<br/>

<p align="center" style="font-family: 'Bookman Old Style', 'URW Bookman', serif; font-size: 1.05rem;">
  <b>✦ <a href="#01-system-overview">Overview</a> ✦</b> &nbsp;•&nbsp;
  <b>✦ <a href="#02-soc-console-preview">Console Preview</a> ✦</b> &nbsp;•&nbsp;
  <b>✦ <a href="#03-traffic-telemetry--metrics">Telemetry Charts</a> ✦</b> &nbsp;•&nbsp;
  <b>✦ <a href="#04-threat-detection-heuristics">Detection Rules</a> ✦</b> &nbsp;•&nbsp;
  <b>✦ <a href="#05-system-architecture">Architecture</a> ✦</b> &nbsp;•&nbsp;
  <b>✦ <a href="#06-installation--quick-start">Quick Start</a> ✦</b> &nbsp;•&nbsp;
  <b>✦ <a href="#07-forensic-export-formats">Data Export</a> ✦</b>
</p>

---

</div>

<h2 id="01-system-overview" style="font-family: 'Bookman Old Style', 'URW Bookman', 'Georgia', serif; color: #00ff99;">🌌 01. System Overview</h2>

<p style="font-family: 'Bookman Old Style', 'URW Bookman', serif; font-size: 1.05rem; line-height: 1.7;">
<b>CyberSentinal</b> is a high-performance desktop Security Operations Center (SOC) analyzer engineered for real-time packet inspection, threat classification, and network anomaly visualization. Powered by <b>CustomTkinter</b> and <b>Matplotlib</b>, it unifies non-blocking packet ingestion with continuous telemetry graphing and structured forensic logging into a cohesive, dark cyberpunk analyst terminal.
</p>

```
  ┌─────────────────────────┐      ┌─────────────────────────┐      ┌─────────────────────────┐
  │  📡 Ingestion Daemon    │ ──❯  │ 🧠 Heuristics Engine   │ ──❯  │ 🖥️ Dual-Chart SOC HUD   │
  │   (Simulated / Scapy)   │      │   Port Scan / DoS / Tel │      │    (PPS + Protocol Pie) │
  └─────────────────────────┘      └─────────────────────────┘      └─────────────────────────┘
```

> [!NOTE]
> **Dual Engine Architecture**: CyberSentinal runs in **Simulation Mode** (generating realistic benign corporate flows and adversarial attack vectors) or in **Live Mode** using Scapy network interface hooks.

---

<h2 id="02-soc-console-preview" style="font-family: 'Bookman Old Style', 'URW Bookman', 'Georgia', serif; color: #00ff99;">📸 02. SOC Console Preview</h2>

<div align="center">

<kbd>
  <img src="Cybersentinal%20%20ss.png" alt="CyberSentinal Analyst Console" width="94%" style="border-radius: 8px; border: 2px solid #00ff99; box-shadow: 0 0 30px rgba(0, 255, 153, 0.25);" />
</kbd>

<br/>
<sub style="font-family: 'Bookman Old Style', 'URW Bookman', serif;"><b>◈ Figure 1.0:</b> Real-time CyberSentinal HUD featuring live traffic terminal, rolling PPS line chart, and protocol breakdown donut chart.</sub>

</div>

---

<h2 id="03-traffic-telemetry--metrics" style="font-family: 'Bookman Old Style', 'URW Bookman', 'Georgia', serif; color: #00ff99;">📊 03. Traffic Telemetry & Metrics</h2>

### 🥧 Network Ingress Composition & Attack Signatures
```mermaid
pie title Captured Traffic Breakdown
    "Encrypted Web (HTTPS 443)" : 45
    "Raw TCP Streams & Services" : 20
    "Standard Web (HTTP 80)" : 15
    "UDP Datagrams & DNS Queries" : 10
    "Port Scanning Probes (Recon)" : 5
    "High-Volume UDP Floods (DoS)" : 4
    "Insecure Admin (Telnet 23)" : 1
```

### 🛰️ Subsystem Execution Profile
```mermaid
pie title Subsystem Resource Allocation
    "CustomTkinter GUI & Event Loop" : 40
    "Matplotlib Real-Time Canvas Redraws" : 28
    "Ingestion & Anomaly Detection Thread" : 22
    "Forensic Logging & File I/O" : 10
```

---

<h2 id="04-threat-detection-heuristics" style="font-family: 'Bookman Old Style', 'URW Bookman', 'Georgia', serif; color: #00ff99;">⚡ 04. Threat Detection Heuristics</h2>

<p style="font-family: 'Bookman Old Style', 'URW Bookman', serif; font-size: 1.02rem;">
Incoming packets are evaluated across dedicated rule sets in real time:
</p>

| Threat Class | Trigger Condition | Severity Level | Target Indicators / Ports | Live HUD Tag |
| :--- | :--- | :---: | :--- | :--- |
| **Port Reconnaissance** | Multi-port scanning sequence | <span style="color:#ff3366"><b>CRITICAL</b></span> | Ports `21, 22, 23, 80, 443, 445, 3389, 8080, 4444` | `● PORT SCAN PROBE` |
| **DoS / UDP Flood** | High-volume burst (>1200 Bytes) | <span style="color:#ffb703"><b>WARN</b></span> | Source: Suspicious C2 (`45.33.32.156`) | `▲ UDP BURST (FLOOD)` |
| **Cleartext Protocol** | Unencrypted administrative session | <span style="color:#ffb703"><b>WARN</b></span> | Destination: Telnet Port `23` (`10.0.4.88`) | `▲ INSECURE TELNET` |
| **Traffic Volumetrics** | Sustained rate exceeding 25 PPS | <span style="color:#00d4ff"><b>ELEVATED</b></span> | Network bandwidth spike | `◆ HIGH VOLUME` |
| **Benign Telemetry** | Verified DNS, TLS, and web streams | <span style="color:#00ff99"><b>NORMAL</b></span> | Certified CDNs & internal hosts | `✔ Routine Transmission` |

---

<h2 id="05-system-architecture" style="font-family: 'Bookman Old Style', 'URW Bookman', 'Georgia', serif; color: #00ff99;">🧬 05. System Architecture</h2>

```mermaid
flowchart TD
    subgraph Ingestion ["📡 INGESTION ENGINE"]
        A1["Simulation Daemon"] --> B["_process_packet_record()"]
        A2["Live Scapy Sniff Daemon"] --> B
    end

    subgraph Classifier ["🧠 HEURISTIC CLASSIFIER"]
        B --> C{"Rule Matcher"}
        C -->|Port Scan / DoS / Telnet| D1["Tag: WARN / CRITICAL\nAlert Counter Increment"]
        C -->|Standard Payload| D2["Tag: NORMAL\nProtocol Categorization"]
        D1 & D2 --> E["packet_data Memory Buffer"]
    end

    subgraph Presentation ["🖥️ ANALYST CONSOLE"]
        E --> F["Live Filtered Terminal Feed"]
        E --> G["Real-Time SOC Stat Cards"]
        E --> H1["Matplotlib Line: 60s PPS History"]
        E --> H2["Matplotlib Donut: Protocol Share"]
    end

    subgraph Export ["💾 FORENSIC PERSISTENCE"]
        E --> I1["CSV Spreadsheet Export"]
        E --> I2["JSON Data Document"]
    end

    style Ingestion fill:#0a0c10,stroke:#00d4ff,stroke-width:2px,color:#00d4ff
    style Classifier fill:#0a0c10,stroke:#ff007f,stroke-width:2px,color:#ff007f
    style Presentation fill:#0a0c10,stroke:#00ff99,stroke-width:2px,color:#00ff99
    style Export fill:#0a0c10,stroke:#ffb703,stroke-width:2px,color:#ffb703
```

---

<h2 id="06-installation--quick-start" style="font-family: 'Bookman Old Style', 'URW Bookman', 'Georgia', serif; color: #00ff99;">🚀 06. Installation & Quick Start</h2>

### 📋 Prerequisites
- **Python 3.8+**
- Operating System: Windows / Linux / macOS
- Network permissions (required only for Live Scapy Sniff mode)

### 🔧 Setup & Execution

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/CyberSentinal.git
cd CyberSentinal

# 2. Install required GUI and graphing libraries
pip install customtkinter matplotlib

# 3. (Optional) Install Scapy for live network interface capture
pip install scapy

# 4. Launch the application
python CyberSentinal.py
```

---

<h2 id="07-forensic-export-formats" style="font-family: 'Bookman Old Style', 'URW Bookman', 'Georgia', serif; color: #00ff99;">💾 07. Forensic Export Formats</h2>

<details open>
<summary><b>📄 JSON Data Document (<code>CyberSentinal_Log_*.json</code>)</b></summary>

```json
[
  {
    "timestamp": "12:05:42",
    "protocol": "TCP",
    "source": "185.220.101.5 (Tor Exit Node)",
    "destination": "192.168.1.15",
    "src_port": 51234,
    "dst_port": 4444,
    "size_bytes": 64,
    "threat_tag": "CRITICAL",
    "info": "PORT SCAN PROBE -> Port 4444"
  }
]
```
</details>

<details>
<summary><b>📊 CSV Spreadsheet Format (<code>CyberSentinal_Log_*.csv</code>)</b></summary>

```csv
Timestamp,Protocol,Source,Destination,Src_Port,Dst_Port,Size_Bytes,Threat_Level,Info
12:05:42,TCP,185.220.101.5 (Tor Exit Node),192.168.1.15,51234,4444,64,CRITICAL,PORT SCAN PROBE -> Port 4444
```
</details>

---

<h2 id="08-ethical-disclosure" style="font-family: 'Bookman Old Style', 'URW Bookman', 'Georgia', serif; color: #00ff99;">🛡️ 08. Ethical Disclosure</h2>

> [!CAUTION]
> **FOR AUTHORIZED SECURITY AUDITING & RESEARCH ONLY.**  
> CyberSentinal is intended exclusively for educational demonstrations, self-monitoring, and authorized network analysis. Unauthorized packet inspection on third-party networks without explicit consent violates applicable privacy and cybersecurity statutes.

---

<h2 id="09-license" style="font-family: 'Bookman Old Style', 'URW Bookman', 'Georgia', serif; color: #00ff99;">📜 09. License</h2>

Distributed under the **[MIT License](LICENSE)**.

<div align="center">

---

⭐ **Star this repository if you find CyberSentinal valuable for your security research!** ⭐

<p style="font-family: 'Bookman Old Style', 'URW Bookman', serif; color: #64748b; margin-top: 8px;">
  Crafted with 🛡️ by <b>Priyanshu Pundir</b>
</p>

</div>
