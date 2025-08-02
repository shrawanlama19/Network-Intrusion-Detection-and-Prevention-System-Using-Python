import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import scapy.all as scapy
import threading
import logging
import os
import shutil
import subprocess
import platform
from datetime import datetime
from logging.handlers import RotatingFileHandler
import ttkbootstrap as ttkb  # Modern themed widgets

# Import AsyncSniffer for asynchronous packet capture.
from scapy.all import AsyncSniffer

# === File Paths and Logging Setup ===
LOG_DIR = os.path.expanduser("~/Desktop/LOG_files/")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
LOG_FILE = os.path.join(LOG_DIR, "ids_log.log")

logger = logging.getLogger()
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(LOG_FILE, maxBytes=5 * 1024 * 1024, backupCount=5)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# === Tooltip Class ===
class ToolTip:
    """Simple tooltip for a widget."""
    def __init__(self, widget, text='widget info'):
        self.widget = widget
        self.text = text
        self.tipwindow = None
        widget.bind("<Enter>", self.enter)
        widget.bind("<Leave>", self.leave)

    def enter(self, event=None):
        self.showtip()

    def leave(self, event=None):
        self.hidetip()

    def showtip(self):
        if self.tipwindow or not self.text:
            return
        x, y, cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + self.widget.winfo_rooty() + 20
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify=tk.LEFT,
                         background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        if self.tipwindow:
            self.tipwindow.destroy()
        self.tipwindow = None

# === IDS Application Class ===
class IDSApp(ttkb.Window):
    def __init__(self):
        # Choose your theme: "superhero", "cyborg", "litera", etc.
        super().__init__(themename="superhero")
        self.title("Advanced Network IDS")
        self.geometry("1300x850")
        try:
            self.iconbitmap(default="icon.ico")
        except Exception:
            pass

        # IDS state variables and thresholds.
        self.sniffing = False
        self.paused = False
        self.sniffer = None  # Will hold our AsyncSniffer instance
        self.packet_count = {}  # For per-IP timestamp tracking
        self.ip_ports = {}      # For tracking ports per IP (for scan detection)
        self.blocked_ips = set()  # Set of blocked IP addresses

        # Statistics counters.
        self.total_packets = 0
        self.total_anomalies = 0

        # Threshold settings (default values).
        self.time_threshold = 60       # seconds
        self.count_threshold = 10      # connections in time_threshold
        self.scan_threshold = 5        # unique ports

        self.load_blocked_ips()
        self.create_menu()
        self.create_widgets()

    def create_menu(self):
        """Build the menu bar with File, Settings, and Help menus."""
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="View Blocked IPs", command=self.view_blocked_ips)
        file_menu.add_command(label="Open Log File", command=self.open_log_file)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Configure Thresholds", command=self.open_settings)
        menubar.add_cascade(label="Settings", menu=settings_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About", "Advanced Network IDS\nby Your Name"))
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def open_log_file(self):
        """Open the log file using the default text editor."""
        try:
            if platform.system() == "Darwin":
                subprocess.run(["open", LOG_FILE])
            else:
                os.startfile(LOG_FILE)
        except Exception as e:
            messagebox.showerror("Error", f"Could not open log file: {e}")

    def view_blocked_ips(self):
        """Open a window listing all blocked IP addresses."""
        win = tk.Toplevel(self)
        win.title("Blocked IPs")
        win.geometry("400x300")
        listbox = tk.Listbox(win, font=("Arial", 12))
        listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = tk.Scrollbar(win, orient="vertical", command=listbox.yview)
        listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        for ip in sorted(self.blocked_ips):
            listbox.insert(tk.END, ip)

    def load_blocked_ips(self):
        """Load persisted blocked IPs from a file."""
        self.blocked_ips_file = os.path.join(LOG_DIR, "blocked_ips.txt")
        if os.path.exists(self.blocked_ips_file):
            try:
                with open(self.blocked_ips_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            blocked_ip = line.split(" - ")[0]
                            self.blocked_ips.add(blocked_ip)
                logging.info("Loaded blocked IPs from file.")
            except Exception as e:
                logging.error("Error loading blocked IPs: %s", e)

    def save_blocked_ip(self, ip):
        """Persist a blocked IP along with a timestamp."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line = f"{ip} - Blocked on {timestamp}\n"
            with open(self.blocked_ips_file, "a") as f:
                f.write(line)
            logging.info("Persisted blocked IP: %s", ip)
        except Exception as e:
            logging.error("Error saving blocked IP %s: %s", ip, e)

    def create_widgets(self):
        """Creates and arranges the main GUI components."""
        # --- Controls Frame (top) ---
        controls_frame = ttkb.Frame(self, padding=(10, 10))
        controls_frame.grid(row=0, column=0, sticky="ew")
        controls_frame.columnconfigure(7, weight=1)

        ttkb.Label(controls_frame, text="Select Network Interface:", font=("Arial", 12)).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.interface_var = tk.StringVar()
        self.interface_dropdown = ttkb.Combobox(controls_frame, textvariable=self.interface_var, width=30)
        self.interface_dropdown.grid(row=0, column=1, padx=5, pady=5, sticky="w")
        ToolTip(self.interface_dropdown, "Select the network interface to monitor.")
        self.load_interfaces()

        self.promisc_var = tk.BooleanVar(value=True)
        self.promisc_check = ttkb.Checkbutton(controls_frame, text="Promiscuous Mode", variable=self.promisc_var)
        self.promisc_check.grid(row=0, column=2, padx=5, pady=5, sticky="w")
        ToolTip(self.promisc_check, "Enable promiscuous mode to capture all packets.")

        ttkb.Label(controls_frame, text="Filter Traffic:", font=("Arial", 12)).grid(row=0, column=3, padx=5, pady=5, sticky="w")
        self.filter_var = tk.StringVar(value="All")
        self.filter_dropdown = ttkb.Combobox(controls_frame, textvariable=self.filter_var,
                                             values=["All", "HTTP", "TCP", "UDP", "ICMP"], width=15)
        self.filter_dropdown.grid(row=0, column=4, padx=5, pady=5, sticky="w")
        ToolTip(self.filter_dropdown, "Select the protocol to filter traffic.")

        self.start_button = ttkb.Button(controls_frame, text="Start IDS", bootstyle="success", command=self.start_sniffing)
        self.start_button.grid(row=0, column=5, padx=5, pady=5)
        self.stop_button = ttkb.Button(controls_frame, text="Stop IDS", bootstyle="danger", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=6, padx=5, pady=5)
        # New Pause/Resume button.
        self.pause_button = ttkb.Button(controls_frame, text="Pause IDS", bootstyle="warning", command=self.toggle_pause, state=tk.DISABLED)
        self.pause_button.grid(row=0, column=7, padx=5, pady=5)
        self.clear_button = ttkb.Button(controls_frame, text="Clear Table", bootstyle="secondary", command=self.clear_table)
        self.clear_button.grid(row=0, column=8, padx=5, pady=5)
        ToolTip(self.clear_button, "Clear the packet table and reset anomaly tracking.")
        self.manual_block_button = ttkb.Button(controls_frame, text="Block Selected IP", bootstyle="warning", command=self.manual_block_ip)
        self.manual_block_button.grid(row=0, column=9, padx=5, pady=5)
        ToolTip(self.manual_block_button, "Manually block the selected suspicious IP.")

        # --- Notebook (middle): Three tabs (Packets, Log Output, Statistics) ---
        self.notebook = ttkb.Notebook(self)
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        self.rowconfigure(1, weight=1)
        self.columnconfigure(0, weight=1)

        # Tab 1: Packets Table
        tab_packets = ttkb.Frame(self.notebook)
        self.notebook.add(tab_packets, text="Packets")
        self.create_packet_table(tab_packets)

        # Tab 2: Log Output
        tab_logs = ttkb.Frame(self.notebook)
        self.notebook.add(tab_logs, text="Log Output")
        self.create_log_panel(tab_logs)

        # Tab 3: Statistics
        tab_stats = ttkb.Frame(self.notebook)
        self.notebook.add(tab_stats, text="Statistics")
        self.create_statistics_panel(tab_stats)

        # --- Status Bar (bottom) ---
        self.status_label = ttkb.Label(self, text="Status: Idle", font=("Arial", 12, "italic"))
        self.status_label.grid(row=2, column=0, sticky="ew", padx=10, pady=5)

    def create_packet_table(self, parent):
        """Creates the packet table using a Treeview widget."""
        columns = ("Source", "Destination", "Protocol", "Port", "Threat", "Threat Details", "Status")
        self.packet_table = ttkb.Treeview(parent, columns=columns, show="headings", bootstyle="info")
        col_specs = {
            "Source": {"width": 150, "anchor": "center"},
            "Destination": {"width": 150, "anchor": "center"},
            "Protocol": {"width": 100, "anchor": "center"},
            "Port": {"width": 100, "anchor": "center"},
            "Threat": {"width": 100, "anchor": "center"},
            "Threat Details": {"width": 250, "anchor": "center"},
            "Status": {"width": 150, "anchor": "center"}
        }
        for col in columns:
            self.packet_table.heading(col, text=col)
            self.packet_table.column(col, **col_specs.get(col, {}))
        vsb = ttkb.Scrollbar(parent, orient="vertical", command=self.packet_table.yview)
        self.packet_table.configure(yscrollcommand=vsb.set)
        self.packet_table.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)
        # Bind double-click to open detailed view.
        self.packet_table.bind("<Double-1>", self.on_packet_double_click)

    def create_log_panel(self, parent):
        """Creates a log panel with a scrolled text widget and buttons to clear or export the log."""
        top_frame = ttkb.Frame(parent)
        top_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        ttkb.Label(top_frame, text="Live Log Output:", font=("Arial", 12, "bold")).pack(side=tk.LEFT)
        clear_log_btn = ttkb.Button(top_frame, text="Clear Log", bootstyle="secondary", command=self.clear_log)
        clear_log_btn.pack(side=tk.RIGHT, padx=5)
        export_log_btn = ttkb.Button(top_frame, text="Export Log", bootstyle="info", command=self.export_log)
        export_log_btn.pack(side=tk.RIGHT, padx=5)
        self.log_text = scrolledtext.ScrolledText(parent, height=15, font=("Consolas", 10))
        self.log_text.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        parent.rowconfigure(1, weight=1)
        parent.columnconfigure(0, weight=1)
        self.log_text.config(state=tk.DISABLED)

    def create_statistics_panel(self, parent):
        """Creates a statistics panel showing live packet counts, anomalies, and blocked IPs."""
        self.stats_total_packets_label = ttkb.Label(parent, text="Total Packets Processed: 0", font=("Arial", 12))
        self.stats_total_packets_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.stats_total_anomalies_label = ttkb.Label(parent, text="Total Anomalies Detected: 0", font=("Arial", 12))
        self.stats_total_anomalies_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.stats_total_blocked_label = ttkb.Label(parent, text="Total Blocked IPs: 0", font=("Arial", 12))
        self.stats_total_blocked_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        reset_stats_btn = ttkb.Button(parent, text="Reset Statistics", bootstyle="secondary", command=self.reset_statistics)
        reset_stats_btn.grid(row=3, column=0, padx=10, pady=10, sticky="w")

    def update_statistics(self):
        """Update the statistics panel labels."""
        self.stats_total_packets_label.config(text=f"Total Packets Processed: {self.total_packets}")
        self.stats_total_anomalies_label.config(text=f"Total Anomalies Detected: {self.total_anomalies}")
        self.stats_total_blocked_label.config(text=f"Total Blocked IPs: {len(self.blocked_ips)}")

    def reset_statistics(self):
        """Reset packet and anomaly counters and update the statistics panel."""
        self.total_packets = 0
        self.total_anomalies = 0
        self.update_statistics()
        self.append_log("[INFO] Statistics reset.")

    def clear_log(self):
        """Clear the live log text widget."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)

    def export_log(self):
        """Export the live log to a file chosen by the user."""
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, "w") as f:
                    log_content = self.log_text.get("1.0", tk.END)
                    f.write(log_content)
                messagebox.showinfo("Export Log", "Log exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export log: {e}")

    def load_interfaces(self):
        """Populate the network interface dropdown using scapy."""
        try:
            interfaces = scapy.get_if_list()
            self.interface_dropdown['values'] = interfaces
            if interfaces:
                self.interface_var.set(interfaces[0])
            else:
                messagebox.showerror("Error", "No network interfaces found!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load interfaces: {e}")
            logging.error("Failed to load interfaces: %s", e)

    def on_packet_double_click(self, event):
        """Open a window with detailed information when a packet row is double-clicked."""
        selected_item = self.packet_table.focus()
        if not selected_item:
            return
        row_values = self.packet_table.item(selected_item, "values")
        detail_win = tk.Toplevel(self)
        detail_win.title("Packet Details")
        detail_win.geometry("500x300")
        text = tk.Text(detail_win, wrap="word")
        text.pack(expand=True, fill="both")
        detail_str = "\n".join([f"{col}: {val}" for col, val in zip(
            ("Source", "Destination", "Protocol", "Port", "Threat", "Threat Details", "Status"), row_values)])
        text.insert("end", detail_str)
        text.config(state="disabled")

    def open_settings(self):
        """Open a settings dialog to configure threshold values."""
        settings_win = tk.Toplevel(self)
        settings_win.title("IDS Settings")
        settings_win.geometry("400x200")
        ttkb.Label(settings_win, text="Connection Time Threshold (seconds):").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        time_entry = ttkb.Entry(settings_win)
        time_entry.insert(0, str(self.time_threshold))
        time_entry.grid(row=0, column=1, padx=5, pady=5)
        ttkb.Label(settings_win, text="Connection Count Threshold:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        count_entry = ttkb.Entry(settings_win)
        count_entry.insert(0, str(self.count_threshold))
        count_entry.grid(row=1, column=1, padx=5, pady=5)
        ttkb.Label(settings_win, text="Unique Ports Threshold (Port Scan):").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        scan_entry = ttkb.Entry(settings_win)
        scan_entry.insert(0, str(self.scan_threshold))
        scan_entry.grid(row=2, column=1, padx=5, pady=5)
        def save_settings():
            try:
                self.time_threshold = float(time_entry.get())
                self.count_threshold = int(count_entry.get())
                self.scan_threshold = int(scan_entry.get())
                messagebox.showinfo("Settings", "Settings saved successfully!")
                settings_win.destroy()
            except Exception as e:
                messagebox.showerror("Error", f"Invalid input: {e}")
        save_btn = ttkb.Button(settings_win, text="Save", command=save_settings)
        save_btn.grid(row=3, column=0, columnspan=2, pady=10)

    def packet_callback(self, packet):
        """
        Called by AsyncSniffer in a background thread.
        Processes each packet and schedules an update in the main thread.
        """
        try:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                protocol = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(packet[scapy.IP].proto, "Other")
                try:
                    if packet.haslayer(scapy.TCP):
                        port = packet[scapy.TCP].dport
                    elif packet.haslayer(scapy.UDP):
                        port = packet[scapy.UDP].dport
                    else:
                        port = "N/A"
                except Exception as e:
                    port = "N/A"
                    logging.error("Error accessing port information: %s", e)
                if self.filter_var.get() != "All" and self.filter_var.get() != protocol:
                    return
                threat_level, threat_details = self.detect_anomaly(src_ip, protocol, port)
                self.after(0, lambda: self.process_packet_ui(src_ip, dst_ip, protocol, port, threat_level, threat_details))
        except Exception as e:
            logging.error("Error processing packet: %s", e)

    def process_packet_ui(self, src_ip, dst_ip, protocol, port, threat_level, threat_details):
        """
        Runs in the main thread:
          - Blocks suspicious IPs automatically.
          - Updates the packet table, log, and statistics.
        """
        self.total_packets += 1
        if threat_level in ["Suspicious", "High Threat"]:
            self.total_anomalies += 1
            if src_ip not in self.blocked_ips:
                if self.block_ip(src_ip):
                    self.append_log(f"[BLOCKED] Auto-blocked suspicious IP: {src_ip}")
                else:
                    self.append_log(f"[ERROR] Failed to block IP: {src_ip}")
        ip_status = "Blocked" if src_ip in self.blocked_ips else "Not Blocked"
        log_message = (f"[{protocol}] {src_ip} -> {dst_ip} | Port: {port} | "
                       f"Threat: {threat_level} | Details: {threat_details} | Status: {ip_status}")
        logging.info(log_message)
        self.append_log(log_message)
        self.update_table(src_ip, dst_ip, protocol, port, threat_level, threat_details, ip_status)
        self.update_statistics()

    def detect_anomaly(self, src_ip, protocol, port):
        """
        Performs basic anomaly detection based on:
          - Connection frequency (using self.time_threshold and self.count_threshold)
          - Suspicious port usage (e.g., Telnet, RDP, VNC)
          - Port scanning (using self.scan_threshold)
        Returns a threat level and details.
        """
        anomalies = 0
        rules_triggered = []
        now = datetime.now()
        # Frequency rule
        self.packet_count.setdefault(src_ip, [])
        self.packet_count[src_ip].append(now)
        recent = [t for t in self.packet_count[src_ip] if (now - t).total_seconds() < self.time_threshold]
        self.packet_count[src_ip] = recent
        if len(recent) > self.count_threshold:
            anomalies += 1
            rules_triggered.append(f"High connection frequency ({len(recent)} in {self.time_threshold}s)")
        # Suspicious port rule
        suspicious_ports = {23: "Telnet", 3389: "RDP", 5900: "VNC"}
        if protocol in ["TCP", "UDP"] and port != "N/A":
            try:
                port_int = int(port)
            except Exception:
                port_int = None
            if port_int is not None and port_int in suspicious_ports:
                anomalies += 1
                rules_triggered.append(f"Suspicious port {port_int} ({suspicious_ports[port_int]})")
        # Port scan rule
        self.ip_ports.setdefault(src_ip, [])
        self.ip_ports[src_ip].append((now, port))
        self.ip_ports[src_ip] = [(t, p) for (t, p) in self.ip_ports[src_ip] if (now - t).total_seconds() < self.time_threshold]
        unique_ports = {p for (t, p) in self.ip_ports[src_ip] if p != "N/A"}
        if len(unique_ports) > self.scan_threshold:
            anomalies += 1
            rules_triggered.append(f"Port scanning detected ({len(unique_ports)} unique ports)")
        if anomalies >= 2:
            threat_level = "High Threat"
        elif anomalies == 1:
            threat_level = "Suspicious"
        else:
            threat_level = "Normal"
        threat_details = "; ".join(rules_triggered) if rules_triggered else "None"
        return threat_level, threat_details

    def block_ip(self, ip):
        """
        Blocks an IP using system firewall commands:
          - macOS: Uses PF (requires PF enabled with a table like <blocklist>)
          - Windows: Uses netsh
          - Linux/Unix: Uses ufw or iptables.
        """
        if ip in self.blocked_ips:
            return False
        firewall_cmd = None
        system_name = platform.system()
        if system_name == 'Darwin':
            firewall_cmd = f"sudo pfctl -t blocklist -T add {ip}"
        elif system_name == "Windows":
            firewall_cmd = f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}'
        else:
            if shutil.which("ufw") is not None:
                firewall_cmd = f"sudo ufw deny from {ip}"
            elif shutil.which("iptables") is not None:
                firewall_cmd = f"sudo iptables -A INPUT -s {ip} -j DROP"
        if firewall_cmd:
            try:
                result = subprocess.run(firewall_cmd, shell=True, capture_output=True, text=True)
                if result.returncode != 0:
                    logging.error("Failed to block IP: %s\nCommand: %s\nError: %s", ip, firewall_cmd, result.stderr)
                    return False
                else:
                    self.blocked_ips.add(ip)
                    self.save_blocked_ip(ip)
                    logging.info("Blocked IP: %s", ip)
                    return True
            except Exception as e:
                logging.error("Exception while blocking IP %s: %s", ip, e)
                return False
        else:
            logging.error("No firewall command available to block IP: %s", ip)
            return False

    def manual_block_ip(self):
        """Manually block selected IP(s) from the packet table."""
        selection = self.packet_table.selection()
        if not selection:
            messagebox.showerror("Error", "No IP selected.")
            return
        for sel in selection:
            row = self.packet_table.item(sel, "values")
            ip = row[0]
            if ip in self.blocked_ips:
                messagebox.showinfo("Info", f"IP {ip} is already blocked.")
            else:
                if self.block_ip(ip):
                    messagebox.showinfo("Info", f"IP {ip} has been manually blocked.")
                    new_row = list(row)
                    new_row[-1] = "Blocked"
                    self.packet_table.item(sel, values=new_row)
                    self.append_log(f"[MANUAL BLOCK] Blocked IP: {ip}")
                else:
                    messagebox.showerror("Error", f"Failed to block IP {ip}.")

    def update_table(self, src, dst, proto, port, threat, threat_details, status):
        """Insert a new row into the packet table and auto-scroll to it."""
        self.packet_table.insert("", "end", values=(src, dst, proto, port, threat, threat_details, status))
        children = self.packet_table.get_children()
        if children:
            self.packet_table.see(children[-1])

    def clear_table(self):
        """Clear the packet table and reset internal anomaly tracking."""
        for item in self.packet_table.get_children():
            self.packet_table.delete(item)
        self.packet_count.clear()
        self.ip_ports.clear()
        self.append_log("[INFO] Cleared packet table and reset anomaly tracking.")

    def append_log(self, message):
        """Append a timestamped message to the live log output."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}\n"
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, full_message)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def start_sniffing(self):
        """Start IDS sniffing on the selected network interface using AsyncSniffer."""
        interface = self.interface_var.get().strip()
        if not interface:
            messagebox.showerror("Error", "No network interface selected!")
            return
        self.sniffing = True
        self.paused = False
        self.status_label.config(text="Status: Sniffing...", bootstyle="success")
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.pause_button.config(state=tk.NORMAL, text="Pause IDS")
        self.sniffer = AsyncSniffer(iface=interface, prn=self.packet_callback, store=False, promisc=self.promisc_var.get())
        self.sniffer.start()
        self.append_log("[INFO] IDS started.")

    def stop_sniffing(self):
        """Stop packet sniffing completely."""
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        self.sniffing = False
        self.paused = False
        self.status_label.config(text="Status: Stopped", bootstyle="danger")
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.pause_button.config(state=tk.DISABLED, text="Pause IDS")
        self.append_log("[INFO] IDS stopped. Logs saved.")
        messagebox.showinfo("Info", "IDS Stopped. Logs saved.")

    def toggle_pause(self):
        """Toggle between pausing and resuming packet sniffing."""
        if not self.paused:
            # Pause the sniffer
            if self.sniffer:
                self.sniffer.stop()
                self.sniffer = None
            self.paused = True
            self.pause_button.config(text="Resume IDS")
            self.status_label.config(text="Status: Paused", bootstyle="warning")
            self.append_log("[INFO] IDS paused.")
        else:
            # Resume sniffing: create a new sniffer instance.
            interface = self.interface_var.get().strip()
            if interface:
                self.sniffer = AsyncSniffer(iface=interface, prn=self.packet_callback, store=False, promisc=self.promisc_var.get())
                self.sniffer.start()
                self.paused = False
                self.pause_button.config(text="Pause IDS")
                self.status_label.config(text="Status: Sniffing...", bootstyle="success")
                self.append_log("[INFO] IDS resumed.")

if __name__ == "__main__":
    app = IDSApp()
    app.mainloop()
