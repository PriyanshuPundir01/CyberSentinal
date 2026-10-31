import logging
import threading
import time
import random
import datetime
import csv
import json
import os
from collections import deque, defaultdict
import customtkinter as ctk
from tkinter import filedialog, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")

COLOR_BG = "#0a0c10"
COLOR_PANEL = "#12171f"
COLOR_CARD = "#18202c"
COLOR_ACCENT = "#00ff99"
COLOR_CYAN = "#00d4ff"
COLOR_WARN = "#ffb703"
COLOR_ERR = "#ff3366"
COLOR_TEXT = "#e2e8f0"
COLOR_MUTED = "#64748b"


class CyberSentinalApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("CYBERSENTINAL // Next-Gen Network Threat & Anomaly Analyzer")
        self.geometry("1320x760")
        self.minsize(1100, 650)
        self.configure(fg_color=COLOR_BG)

        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.sniffing = False
        self.capture_mode = "Simulation"
        self.packet_data = []
        self.protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0, "HTTPS": 0, "DNS": 0, "OTHER": 0}
        self.traffic_history = deque([0]*60, maxlen=60)
        self.bandwidth_history = deque([0]*60, maxlen=60)
        self.stop_event = threading.Event()
        
        self.packet_count_second = 0
        self.bytes_count_second = 0
        self.total_bytes = 0
        self.total_threats_detected = 0
        self.current_threat_status = "NORMAL"
        
        self.ip_request_window = defaultdict(lambda: deque(maxlen=30))
        self.port_scan_tracker = defaultdict(set)
        
        self.auto_scroll = True
        self.filter_protocol = "ALL"
        self.search_query = ""

        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=0)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_sidebar()
        self._build_main_terminal()
        self._build_viz_panel()

    def _build_header(self):
        self.header_frame = ctk.CTkFrame(self, fg_color=COLOR_PANEL, corner_radius=0, height=54)
        self.header_frame.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 2))

        title_box = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        title_box.pack(side="left", padx=16)

        ctk.CTkLabel(title_box, text="🛡️ CYBERSENTINAL", font=("Consolas", 19, "bold"), text_color=COLOR_ACCENT).pack(side="left")
        ctk.CTkLabel(title_box, text=" | SOC THREAT MONITOR v2.0", font=("Consolas", 12), text_color=COLOR_MUTED).pack(side="left", padx=8)

        self.status_badge = ctk.CTkLabel(
            self.header_frame, 
            text="● SYSTEM IDLE", 
            font=("Consolas", 12, "bold"), 
            text_color=COLOR_MUTED
        )
        self.status_badge.pack(side="right", padx=20)

    def _build_sidebar(self):
        self.sidebar = ctk.CTkScrollableFrame(self, fg_color=COLOR_PANEL, width=230, corner_radius=10)
        self.sidebar.grid(row=1, column=0, sticky="nsew", padx=(10, 5), pady=10)

        ctk.CTkLabel(self.sidebar, text="CONTROLS", font=("Consolas", 11, "bold"), text_color=COLOR_MUTED).pack(anchor="w", padx=10, pady=(5, 2))

        self.mode_menu = ctk.CTkOptionMenu(
            self.sidebar, 
            values=["Simulation Mode", "Live Sniff (Scapy)"],
            fg_color=COLOR_CARD, 
            button_color="#222c3c", 
            text_color=COLOR_TEXT,
            command=self._on_mode_change
        )
        self.mode_menu.set("Simulation Mode")
        self.mode_menu.pack(pady=5, padx=8, fill="x")

        self.btn_start = ctk.CTkButton(
            self.sidebar, text="▶ INITIATE SCAN", 
            fg_color=COLOR_BG, border_color=COLOR_ACCENT, border_width=1,
            hover_color="#003322", text_color=COLOR_ACCENT, 
            font=("Consolas", 12, "bold"), command=self.start_scan
        )
        self.btn_start.pack(pady=(8, 4), padx=8, fill="x")

        self.btn_stop = ctk.CTkButton(
            self.sidebar, text="⏹ TERMINATE", 
            fg_color=COLOR_BG, border_color=COLOR_ERR, border_width=1,
            hover_color="#330b14", text_color=COLOR_ERR, 
            font=("Consolas", 12, "bold"), state="disabled", command=self.stop_scan
        )
        self.btn_stop.pack(pady=4, padx=8, fill="x")

        ctk.CTkLabel(self.sidebar, text="REAL-TIME METRICS", font=("Consolas", 11, "bold"), text_color=COLOR_MUTED).pack(anchor="w", padx=10, pady=(15, 2))
        
        self.create_stat_card("TOTAL PACKETS", "0", "lbl_total", COLOR_TEXT)
        self.create_stat_card("THREAT LEVEL", "NORMAL", "lbl_threat", COLOR_ACCENT)
        self.create_stat_card("ALERTS FIRED", "0", "lbl_alerts", COLOR_WARN)
        self.create_stat_card("DATA VOLUME", "0.0 KB", "lbl_volume", COLOR_CYAN)

        ctk.CTkLabel(self.sidebar, text="OPERATIONS", font=("Consolas", 11, "bold"), text_color=COLOR_MUTED).pack(anchor="w", padx=10, pady=(15, 2))

        self.btn_save = ctk.CTkButton(
            self.sidebar, text="💾 EXPORT LOGS", 
            fg_color=COLOR_CARD, hover_color="#273347", text_color=COLOR_TEXT,
            font=("Consolas", 11, "bold"), command=self.save_logs_dialog
        )
        self.btn_save.pack(pady=4, padx=8, fill="x")

        self.btn_reset = ctk.CTkButton(
            self.sidebar, text="🔄 RESET STATS", 
            fg_color=COLOR_CARD, hover_color="#273347", text_color=COLOR_TEXT,
            font=("Consolas", 11, "bold"), command=self.reset_statistics
        )
        self.btn_reset.pack(pady=4, padx=8, fill="x")

    def create_stat_card(self, title, value, attr_name, text_color=COLOR_TEXT):
        frame = ctk.CTkFrame(self.sidebar, fg_color=COLOR_CARD, corner_radius=8)
        frame.pack(pady=4, padx=8, fill="x")
        ctk.CTkLabel(frame, text=title, font=("Consolas", 9, "bold"), text_color=COLOR_MUTED).pack(pady=(4, 0))
        lbl = ctk.CTkLabel(frame, text=value, font=("Consolas", 18, "bold"), text_color=text_color)
        lbl.pack(pady=(0, 4))
        setattr(self, attr_name, lbl)

    def _build_main_terminal(self):
        self.log_frame = ctk.CTkFrame(self, fg_color=COLOR_PANEL, corner_radius=10)
        self.log_frame.grid(row=1, column=1, sticky="nsew", padx=5, pady=10)

        filter_bar = ctk.CTkFrame(self.log_frame, fg_color="transparent")
        filter_bar.pack(fill="x", padx=10, pady=(10, 4))

        ctk.CTkLabel(filter_bar, text="LIVE TRAFFIC FEED", font=("Consolas", 13, "bold"), text_color=COLOR_ACCENT).pack(side="left")

        self.search_entry = ctk.CTkEntry(
            filter_bar, placeholder_text="🔍 Filter IP / Port...", 
            width=170, height=28, fg_color=COLOR_BG, font=("Consolas", 11)
        )
        self.search_entry.pack(side="right", padx=(6, 0))
        self.search_entry.bind("<KeyRelease>", self._on_search_change)

        self.proto_filter_menu = ctk.CTkOptionMenu(
            filter_bar, 
            values=["ALL", "TCP", "UDP", "ICMP", "HTTPS", "HTTP", "DNS", "THREATS ONLY"],
            width=120, height=28, fg_color=COLOR_CARD, button_color="#222c3c",
            font=("Consolas", 11),
            command=self._on_filter_change
        )
        self.proto_filter_menu.pack(side="right", padx=(6, 0))

        self.chk_autoscroll = ctk.CTkCheckBox(
            filter_bar, text="Auto-Scroll", font=("Consolas", 11),
            command=self._toggle_autoscroll, fg_color=COLOR_ACCENT, text_color=COLOR_TEXT
        )
        self.chk_autoscroll.select()
        self.chk_autoscroll.pack(side="right", padx=10)

        btn_clear = ctk.CTkButton(
            filter_bar, text="🧹 CLEAR", width=70, height=26,
            fg_color=COLOR_CARD, hover_color="#273347", font=("Consolas", 10, "bold"),
            command=self.clear_logs
        )
        btn_clear.pack(side="right", padx=(0, 6))

        self.log_box = ctk.CTkTextbox(
            self.log_frame, 
            font=("Consolas", 11), 
            fg_color="#07090e", 
            text_color=COLOR_TEXT, 
            wrap="none"
        )
        self.log_box.pack(fill="both", expand=True, padx=10, pady=(4, 10))
        
        self._configure_text_tags()
        self.log_box.insert("end", ">> SYSTEM READY. AWAITING INITIATION...\n", "INFO")

    def _configure_text_tags(self):
        tk_text = self.log_box._textbox
        tk_text.tag_config("INFO", foreground=COLOR_CYAN)
        tk_text.tag_config("NORMAL", foreground=COLOR_ACCENT)
        tk_text.tag_config("WARN", foreground=COLOR_WARN)
        tk_text.tag_config("CRITICAL", foreground=COLOR_ERR)
        tk_text.tag_config("MUTED", foreground=COLOR_MUTED)

    def _build_viz_panel(self):
        self.viz_frame = ctk.CTkFrame(self, fg_color=COLOR_BG, width=320)
        self.viz_frame.grid(row=1, column=2, sticky="nsew", padx=(5, 10), pady=10)

        self.chart1_frame = ctk.CTkFrame(self.viz_frame, fg_color=COLOR_PANEL, corner_radius=10)
        self.chart1_frame.pack(fill="both", expand=True, pady=(0, 8))
        self.setup_line_chart()

        self.chart2_frame = ctk.CTkFrame(self.viz_frame, fg_color=COLOR_PANEL, corner_radius=10)
        self.chart2_frame.pack(fill="both", expand=True)
        self.setup_donut_chart()

    def setup_line_chart(self):
        plt.style.use('dark_background')
        self.fig1, self.ax1 = plt.subplots(figsize=(4.2, 2.8), dpi=80)
        self.fig1.patch.set_facecolor(COLOR_PANEL)
        self.ax1.set_facecolor(COLOR_PANEL)

        self.line, = self.ax1.plot([], [], color=COLOR_ACCENT, linewidth=1.8, label="PPS")
        self.ax1.set_title("NETWORK TRAFFIC RATE (PPS)", fontsize=9, color=COLOR_CYAN, fontweight="bold", pad=8)
        self.ax1.set_xlim(0, 60)
        self.ax1.set_ylim(0, 40)
        self.ax1.tick_params(colors=COLOR_MUTED, labelsize=8)
        self.ax1.grid(True, color="#1e293b", linestyle='--', linewidth=0.6)

        self.canvas1 = FigureCanvasTkAgg(self.fig1, master=self.chart1_frame)
        self.canvas1.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

    def setup_donut_chart(self):
        self.fig2, self.ax2 = plt.subplots(figsize=(4.2, 2.8), dpi=80)
        self.fig2.patch.set_facecolor(COLOR_PANEL)
        self.ax2.set_facecolor(COLOR_PANEL)
        self.ax2.text(0, 0, "WAITING FOR DATA", ha='center', va='center', color=COLOR_MUTED, fontsize=8, fontweight="bold")
        self.ax2.axis('off')

        self.canvas2 = FigureCanvasTkAgg(self.fig2, master=self.chart2_frame)
        self.canvas2.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

    def _on_mode_change(self, choice):
        if "Live Sniff" in choice:
            self.capture_mode = "Live (Scapy)"
        else:
            self.capture_mode = "Simulation"

    def traffic_engine_simulation(self):
        """Generates enterprise network events with benign and anomalous behavior."""
        ips_internal = ["192.168.1.15", "192.168.1.42", "192.168.1.108", "10.0.4.12", "10.0.4.88"]
        ips_external = [
            "142.250.190.46 (Google)",
            "13.107.42.14 (Microsoft)",
            "140.82.121.4 (GitHub)",
            "104.16.132.229 (Cloudflare)",
            "185.199.108.153 (CDN)",
            "45.33.32.156 (Suspicious C2)",
            "185.220.101.5 (Tor Exit Node)"
        ]

        port_map = {
            "HTTPS": 443, "HTTP": 80, "DNS": 53, "SSH": 22,
            "TELNET": 23, "RDP": 3389, "SMB": 445, "C2_PORT": 4444
        }

        while not self.stop_event.is_set():
            time.sleep(random.uniform(0.04, 0.35))

            roll = random.random()
            is_anomaly = False
            threat_tag = "NORMAL"
            info = "OK"

            if roll < 0.05:
                src = "185.220.101.5 (Tor Exit Node)"
                dst = random.choice(ips_internal)
                proto = "TCP"
                src_port = random.randint(40000, 65000)
                dst_port = random.choice([21, 22, 23, 80, 443, 445, 3389, 8080, 4444])
                size = random.randint(40, 70)
                threat_tag = "CRITICAL"
                info = f"PORT SCAN PROBE -> Port {dst_port}"
                is_anomaly = True

            elif roll < 0.09:
                src = "45.33.32.156 (Suspicious C2)"
                dst = "192.168.1.15"
                proto = "UDP"
                src_port = 53
                dst_port = random.randint(1024, 65535)
                size = random.randint(1200, 1500)
                threat_tag = "WARN"
                info = "HIGH VOLUME UDP BURST (POSSIBLE FLOOD)"
                is_anomaly = True

            elif roll < 0.13:
                src = random.choice(ips_internal)
                dst = "10.0.4.88"
                proto = "TCP"
                src_port = random.randint(40000, 60000)
                dst_port = 23
                size = random.randint(100, 400)
                threat_tag = "WARN"
                info = "INSECURE PROTOCOL (TELNET DETECTED)"
                is_anomaly = True

            else:
                src = random.choice(ips_internal)
                dst = random.choice(ips_external[:5])
                proto = random.choices(["HTTPS", "HTTP", "TCP", "UDP", "DNS", "ICMP"], weights=[45, 15, 20, 10, 8, 2])[0]
                src_port = random.randint(49152, 65535)
                dst_port = port_map.get(proto, random.randint(1024, 9999))
                size = random.randint(64, 1500)
                threat_tag = "NORMAL"
                info = "Routine Payload Transmission"

            self._process_packet_record(proto, src, dst, src_port, dst_port, size, threat_tag, info, is_anomaly)

    def _process_packet_record(self, proto, src, dst, src_port, dst_port, size, threat_tag, info, is_anomaly=False):
        now = datetime.datetime.now()
        ts = now.strftime("%H:%M:%S")

        if is_anomaly or threat_tag in ["WARN", "CRITICAL"]:
            self.total_threats_detected += 1
            self.current_threat_status = "CRITICAL" if threat_tag == "CRITICAL" else "ELEVATED"
        elif self.packet_count_second > 25:
            self.current_threat_status = "HIGH VOLUME"
        else:
            self.current_threat_status = "SECURE"

        self.packet_count_second += 1
        self.bytes_count_second += size
        self.total_bytes += size

        if proto in self.protocol_counts:
            self.protocol_counts[proto] += 1
        else:
            self.protocol_counts["OTHER"] += 1

        record = [ts, proto, src, dst, src_port, dst_port, size, threat_tag, info]
        self.packet_data.append(record)

        log_line = f"[{ts}] {proto:<6} | {src:<28} -> {dst:<28} | {size:>4} B | {info}\n"
        self.after(0, lambda r=record, l=log_line: self.append_log_to_ui(r, l))

    def append_log_to_ui(self, record, line_text):
        ts, proto, src, dst, src_port, dst_port, size, threat_tag, info = record

        if not self._matches_filter(proto, src, dst, info, threat_tag):
            return

        tag = "CRITICAL" if threat_tag == "CRITICAL" else ("WARN" if threat_tag == "WARN" else "NORMAL")
        self.log_box.insert("end", line_text, tag)

        if int(self.log_box.index("end-1c").split('.')[0]) > 400:
            self.log_box.delete("1.0", "100.0")

        if self.auto_scroll:
            self.log_box.see("end")

        total_pkts = sum(self.protocol_counts.values())
        self.lbl_total.configure(text=f"{total_pkts:,}")
        self.lbl_alerts.configure(text=f"{self.total_threats_detected:,}")

        if self.total_bytes < 1024 * 1024:
            vol_str = f"{self.total_bytes / 1024:.1f} KB"
        else:
            vol_str = f"{self.total_bytes / (1024 * 1024):.2f} MB"
        self.lbl_volume.configure(text=vol_str)

        if self.current_threat_status == "CRITICAL":
            self.lbl_threat.configure(text="CRITICAL", text_color=COLOR_ERR)
            self.status_badge.configure(text="● THREAT DETECTED", text_color=COLOR_ERR)
        elif self.current_threat_status == "ELEVATED":
            self.lbl_threat.configure(text="WARNING", text_color=COLOR_WARN)
            self.status_badge.configure(text="● ANOMALY OBSERVED", text_color=COLOR_WARN)
        elif self.current_threat_status == "HIGH VOLUME":
            self.lbl_threat.configure(text="SPIKE", text_color=COLOR_CYAN)
            self.status_badge.configure(text="● HIGH TRAFFIC RATE", text_color=COLOR_CYAN)
        else:
            self.lbl_threat.configure(text="SECURE", text_color=COLOR_ACCENT)
            self.status_badge.configure(text="● MONITORING - ALL CLEAR", text_color=COLOR_ACCENT)

    def _matches_filter(self, proto, src, dst, info, threat_tag):
        if self.filter_protocol == "THREATS ONLY":
            if threat_tag == "NORMAL": return False
        elif self.filter_protocol != "ALL" and proto != self.filter_protocol:
            return False

        if self.search_query:
            combined = f"{proto} {src} {dst} {info}".lower()
            if self.search_query not in combined:
                return False

        return True

    def _on_filter_change(self, choice):
        self.filter_protocol = choice
        self._rebuild_terminal_view()

    def _on_search_change(self, event=None):
        self.search_query = self.search_entry.get().strip().lower()
        self._rebuild_terminal_view()

    def _rebuild_terminal_view(self):
        """Refreshes visible log entries based on current filter settings."""
        self.log_box.delete("1.0", "end")
        matched_records = [
            r for r in self.packet_data[-300:] 
            if self._matches_filter(r[1], r[2], r[3], r[8], r[7])
        ]
        for r in matched_records:
            ts, proto, src, dst, src_port, dst_port, size, threat_tag, info = r
            line_text = f"[{ts}] {proto:<6} | {src:<28} -> {dst:<28} | {size:>4} B | {info}\n"
            tag = "CRITICAL" if threat_tag == "CRITICAL" else ("WARN" if threat_tag == "WARN" else "NORMAL")
            self.log_box.insert("end", line_text, tag)
        
        if self.auto_scroll:
            self.log_box.see("end")

    def _toggle_autoscroll(self):
        self.auto_scroll = self.chk_autoscroll.get() == 1

    def update_graphs(self):
        if not self.sniffing:
            return

        pps = self.packet_count_second
        kb_s = self.bytes_count_second / 1024.0
        self.traffic_history.append(pps)
        self.bandwidth_history.append(kb_s)

        self.packet_count_second = 0
        self.bytes_count_second = 0

        self.line.set_data(range(len(self.traffic_history)), self.traffic_history)
        self.ax1.set_xlim(0, 60)
        max_pps = max(max(self.traffic_history, default=0) + 5, 25)
        self.ax1.set_ylim(0, max_pps)
        self.canvas1.draw_idle()

        self.ax2.clear()
        self.ax2.axis('off')

        non_zero_items = {k: v for k, v in self.protocol_counts.items() if v > 0}
        if non_zero_items:
            labels = list(non_zero_items.keys())
            vals = list(non_zero_items.values())
            palette = ['#00ff99', '#00d4ff', '#ff3366', '#ffb703', '#a78bfa', '#38bdf8', '#94a3b8']
            
            wedges, texts = self.ax2.pie(
                vals, 
                labels=None, 
                startangle=90,
                colors=palette[:len(vals)],
                wedgeprops=dict(width=0.42, edgecolor=COLOR_PANEL, linewidth=1.5)
            )
            self.ax2.legend(
                wedges, labels, 
                loc="center", 
                fontsize=7.5, 
                frameon=False, 
                labelcolor=COLOR_TEXT
            )

        self.canvas2.draw_idle()
        self.after(1000, self.update_graphs)

    def start_scan(self):
        self.sniffing = True
        self.stop_event.clear()

        self.btn_start.configure(state="disabled", fg_color="#111822")
        self.btn_stop.configure(state="normal", fg_color=COLOR_BG)
        self.status_badge.configure(text="● MONITORING ACTIVE", text_color=COLOR_ACCENT)

        self.log_box.insert("end", "\n>> [ENGINE STARTED] INITIATING PACKET CAPTURE...\n", "INFO")
        self.log_box.insert("end", f">> [MODE]: {self.capture_mode.upper()}\n\n", "INFO")

        threading.Thread(target=self.traffic_engine_simulation, daemon=True).start()
        self.update_graphs()

    def stop_scan(self):
        self.sniffing = False
        self.stop_event.set()

        self.btn_start.configure(state="normal", fg_color=COLOR_BG)
        self.btn_stop.configure(state="disabled", fg_color="#111822")
        self.status_badge.configure(text="● SYSTEM HALTED", text_color=COLOR_MUTED)
        self.log_box.insert("end", "\n>> [CAPTURE TERMINATED] ENGINE SHUTDOWN COMPLETED.\n", "WARN")

    def clear_logs(self):
        self.log_box.delete("1.0", "end")
        self.log_box.insert("end", ">> TERMINAL CLEARED. WAITING FOR NEXT PACKET...\n", "INFO")

    def reset_statistics(self):
        self.packet_data.clear()
        for k in self.protocol_counts:
            self.protocol_counts[k] = 0
        self.traffic_history = deque([0]*60, maxlen=60)
        self.bandwidth_history = deque([0]*60, maxlen=60)
        self.total_bytes = 0
        self.total_threats_detected = 0
        self.current_threat_status = "NORMAL"

        self.lbl_total.configure(text="0")
        self.lbl_threat.configure(text="NORMAL", text_color=COLOR_ACCENT)
        self.lbl_alerts.configure(text="0")
        self.lbl_volume.configure(text="0.0 KB")
        self.clear_logs()

        self.setup_line_chart()
        self.setup_donut_chart()
        messagebox.showinfo("Reset Completed", "All real-time counters and logs have been reset.")

    def save_logs_dialog(self):
        if not self.packet_data:
            messagebox.showwarning("No Data", "There are no captured packet logs to export.")
            return

        default_filename = f"CyberSentinal_Log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Spreadsheet", "*.csv"), ("JSON Document", "*.json"), ("All Files", "*.*")],
            initialfile=default_filename,
            title="Export Security Logs"
        )

        if not filepath:
            return

        try:
            if filepath.endswith(".json"):
                data_dicts = [
                    {
                        "timestamp": r[0], "protocol": r[1], "source": r[2],
                        "destination": r[3], "src_port": r[4], "dst_port": r[5],
                        "size_bytes": r[6], "threat_tag": r[7], "info": r[8]
                    }
                    for r in self.packet_data
                ]
                with open(filepath, "w", encoding="utf-8") as f:
                    json.dump(data_dicts, f, indent=2)
            else:
                with open(filepath, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "Timestamp", "Protocol", "Source", "Destination", 
                        "Src_Port", "Dst_Port", "Size_Bytes", "Threat_Level", "Info"
                    ])
                    writer.writerows(self.packet_data)

            self.log_box.insert("end", f"\n>> [LOGS EXPORTED SUCCESSFULLY]: {os.path.basename(filepath)}\n", "NORMAL")
            messagebox.showinfo("Export Successful", f"Saved {len(self.packet_data)} records to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save log file:\n{str(e)}")

    def on_close(self):
        """Ensures threads and Tkinter window exit gracefully when user closes GUI."""
        self.sniffing = False
        self.stop_event.set()
        self.destroy()


if __name__ == "__main__":
    app = CyberSentinalApp()
    app.mainloop()