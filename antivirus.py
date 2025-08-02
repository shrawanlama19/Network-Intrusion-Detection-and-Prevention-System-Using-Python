import os
import hashlib
import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import logging
from pathlib import Path
import time
import platform
import shutil

# -------------------- Setup Logging --------------------
logging.basicConfig(filename="scan_log.txt", level=logging.INFO,
                    format="%(asctime)s - %(message)s")

# -------------------- Constants --------------------
SIGNATURE_DB = "signatures.json"
QUARANTINE_DIR = "quarantine"

# -------------------- Ensure Signature DB and Quarantine Folder --------------------
if not os.path.exists(SIGNATURE_DB):
    with open(SIGNATURE_DB, "w") as f:
        json.dump({"malware_hashes": []}, f)

if not os.path.exists(QUARANTINE_DIR):
    os.makedirs(QUARANTINE_DIR)

with open(SIGNATURE_DB, "r") as file:
    signature_data = json.load(file)
KNOWN_HASHES = set(signature_data.get("malware_hashes", []))

# -------------------- Heuristic Rules --------------------
def heuristic_check(file_path):
    suspicious = []
    size = os.path.getsize(file_path)
    ext = os.path.splitext(file_path)[1].lower()

    if size > 50 * 1024 * 1024:
        suspicious.append("Large file size")
    if ext in [".exe", ".bat", ".cmd", ".scr", ".js", ".vbs", ".jar"]:
        suspicious.append("Executable or script file extension")
    if "autorun" in file_path.lower():
        suspicious.append("Possible autorun behavior")
    if file_path.lower().endswith('.zip') and size > 100 * 1024 * 1024:
        suspicious.append("Large compressed archive")

    return suspicious

# -------------------- Hash Calculation --------------------
def compute_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return None

# -------------------- Quarantine --------------------
def quarantine_file(file_path):
    try:
        base_name = os.path.basename(file_path)
        timestamp = int(time.time())
        new_path = os.path.join(QUARANTINE_DIR, f"{timestamp}_{base_name}")
        shutil.copy2(file_path, new_path)
        logging.info(f"File quarantined: {new_path}")
        return new_path
    except Exception as e:
        logging.error(f"Error quarantining file {file_path}: {e}")
        return None

# -------------------- File Scanner --------------------
def scan_file(file_path):
    file_hash = compute_hash(file_path)
    if not file_hash:
        return "Error", []

    if file_hash in KNOWN_HASHES:
        quarantine_file(file_path)
        return "Malicious", []
    heuristics = heuristic_check(file_path)
    if heuristics:
        return "Suspicious", heuristics
    return "Clean", []

# -------------------- Firewall Stub --------------------
def block_ip(ip_address):
    system_name = platform.system()
    try:
        if system_name == 'Windows':
            os.system(f'netsh advfirewall firewall add rule name="Block {ip_address}" dir=in action=block remoteip={ip_address}')
        elif system_name == 'Linux':
            os.system(f'sudo iptables -A INPUT -s {ip_address} -j DROP')
        elif system_name == 'Darwin':
            os.system(f'sudo pfctl -t blocklist -T add {ip_address}')
        logging.info(f"Blocked IP: {ip_address}")
    except Exception as e:
        logging.error(f"Error blocking IP {ip_address}: {e}")

# -------------------- GUI App --------------------
class AntivirusApp:
    def __init__(self, master):
        self.master = master
        master.title("Python Antivirus v1.0")
        master.geometry("800x550")
        master.resizable(False, False)

        self.label = ttk.Label(master, text="Antivirus Scanner", font=("Helvetica", 18))
        self.label.pack(pady=10)

        self.frame = ttk.Frame(master)
        self.frame.pack(pady=10)

        self.scan_btn = ttk.Button(self.frame, text="Scan File", command=self.scan_file)
        self.scan_btn.grid(row=0, column=0, padx=10)

        self.scan_folder_btn = ttk.Button(self.frame, text="Scan Folder", command=self.scan_folder)
        self.scan_folder_btn.grid(row=0, column=1, padx=10)

        self.result_box = tk.Text(master, height=20, width=100, state=tk.DISABLED, font=("Courier", 10))
        self.result_box.pack(pady=10)

        self.clear_btn = ttk.Button(master, text="Clear", command=self.clear_results)
        self.clear_btn.pack(pady=5)

        self.quit_btn = ttk.Button(master, text="Exit", command=master.quit)
        self.quit_btn.pack()

    def log_result(self, file_path, status, details):
        with open("results.log", "a") as f:
            f.write(f"{file_path} => {status} ({', '.join(details) if details else 'No extra details'})\n")

    def display_result(self, message):
        self.result_box.configure(state=tk.NORMAL)
        self.result_box.insert(tk.END, message + "\n")
        self.result_box.configure(state=tk.DISABLED)

    def clear_results(self):
        self.result_box.configure(state=tk.NORMAL)
        self.result_box.delete(1.0, tk.END)
        self.result_box.configure(state=tk.DISABLED)

    def scan_file(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return

        status, details = scan_file(file_path)
        result_msg = f"File: {file_path}\nStatus: {status}"
        if details:
            result_msg += f"\nDetails: {', '.join(details)}"
        if status == "Malicious":
            result_msg += "\nAction: File moved to quarantine!"
        elif status == "Suspicious":
            result_msg += "\nAction: Manual review recommended."

        logging.info(result_msg)
        self.log_result(file_path, status, details)
        self.display_result(result_msg)

    def scan_folder(self):
        folder_path = filedialog.askdirectory()
        if not folder_path:
            return

        result_summary = []
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                status, details = scan_file(file_path)
                result_msg = f"File: {file_path}\nStatus: {status}"
                if details:
                    result_msg += f"\nDetails: {', '.join(details)}"
                if status == "Malicious":
                    result_msg += "\nAction: Quarantined"
                elif status == "Suspicious":
                    result_msg += "\nAction: Review"

                logging.info(result_msg)
                self.log_result(file_path, status, details)
                result_summary.append(result_msg)

        for res in result_summary:
            self.display_result(res)

# -------------------- Start GUI --------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = AntivirusApp(root)
    root.mainloop()
