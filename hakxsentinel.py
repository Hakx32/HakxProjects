import os
import sys
import json
import logging
import platform
import subprocess
import socket
import psutil
import smtplib
from email.mime.text import MIMEText
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import messagebox, ttk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Logging setup
os.makedirs("logs", exist_ok=True)
log_path = os.path.join("logs", "activity.log")
logging.basicConfig(filename=log_path, level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Load config
CONFIG_PATH = os.path.join("config", "settings.json")
def load_config():
    if not os.path.exists(CONFIG_PATH):
        logging.warning("settings.json not found.")
        return {}
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

# Modules
def iptracker(config):
    try:
        import requests
        ip = requests.get("https://api.ipify.org?format=json").json().get("ip", "Unknown")
        log = f"[IPTracker] Public IP: {ip}"
        logging.info(log)
        with open("logs/iptracker.txt", "a") as f:
            f.write(f"{datetime.now()} - {log}\n")
    except Exception as e:
        logging.error(f"[IPTracker] Error: {e}")

def alertbot(config):
    try:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        message = config.get("_message_override") or f"[AlertBot] System check-in at {now}"
        with open("logs/alerts.txt", "a") as f:
            f.write(message + "\n")
        logging.info(message)

        email_cfg = config.get("alert_email")
        if email_cfg:
            msg = MIMEText(message)
            msg["Subject"] = "HakxSentinel Alert"
            msg["From"] = email_cfg["from"]
            msg["To"] = email_cfg["to"]
            with smtplib.SMTP(email_cfg["smtp_server"], email_cfg["smtp_port"]) as server:
                if email_cfg.get("use_tls"): server.starttls()
                server.login(email_cfg["username"], email_cfg["password"])
                server.send_message(msg)
    except Exception as e:
        logging.error(f"[AlertBot] Error: {e}")

def filewatcher(config):
    try:
        class Handler(FileSystemEventHandler):
            def dispatch(self, event):
                action = event.event_type.upper()
                path = event.src_path
                alert = f"[FileWatcher] {action}: {path}"
                with open("logs/filewatcher.txt", "a") as f:
                    f.write(f"{datetime.now()} - {alert}\n")
                alertbot({"alert_email": config.get("alert_email"), "_message_override": alert})

        path = config.get("watch_path", "./watched")
        os.makedirs(path, exist_ok=True)
        observer = Observer()
        observer.schedule(Handler(), path, recursive=True)
        observer.start()
    except Exception as e:
        logging.error(f"[FileWatcher] Error: {e}")

def autoharden(config):
    try:
        results = []
        if os.geteuid() != 0:
            results.append("[✗] Must run as root to perform system hardening.")
        elif os.name == 'nt':
            cmds = [
                ("Enable firewall", "netsh advfirewall set allprofiles state on"),
                ("Disable RemoteRegistry", "sc config RemoteRegistry start= disabled && sc stop RemoteRegistry"),
                ("Disable TlntSvr", "sc config TlntSvr start= disabled && sc stop TlntSvr")
            ]
            for label, cmd in cmds:
                try:
                    subprocess.call(cmd, shell=True)
                    results.append(f"[✓] {label}")
                except:
                    results.append(f"[✗] {label}")
        else:
            cmds = []
            if subprocess.call("which ufw", shell=True, stdout=subprocess.DEVNULL) == 0:
                cmds.append(("Enable firewall", "ufw enable"))
            if os.path.exists("/lib/systemd/system/telnet.socket"):
                cmds.append(("Disable Telnet", "systemctl disable --now telnet.socket"))
            if os.path.exists("/lib/systemd/system/vsftpd.service"):
                cmds.append(("Disable FTP", "systemctl disable --now vsftpd"))
            if os.path.exists("/etc/ssh/sshd_config"):
                cmds.append(("Disable SSH root login", "sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl restart ssh"))
            for label, cmd in cmds:
                try:
                    subprocess.call(cmd, shell=True)
                    results.append(f"[✓] {label}")
                except:
                    results.append(f"[✗] {label}")

        with open("logs/autoharden_status.txt", "w") as f:
            f.write("
".join(results))
    except Exception as e:
        logging.error(f"[AutoHarden] Error: {e}")

def netwatcher(config):
    try:
        connections = psutil.net_connections(kind='inet')
        with open("logs/netwatcher.txt", "w") as f:
            for c in connections:
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                status = c.status
                pid = c.pid
                pname = psutil.Process(pid).name() if pid else ""
                f.write(f"{laddr} -> {raddr} [{status}] PID: {pid} ({pname})\n")
    except Exception as e:
        logging.error(f"[NetWatcher] Error: {e}")

# Run all modules
def run_modules():
    config = load_config()
    iptracker(config)
    alertbot(config)
    filewatcher(config)
    autoharden(config)
    netwatcher(config)

# GUI
def open_log_viewer(log_file, title):
    win = tk.Toplevel()
    win.title(title)
    text = tk.Text(win)
    text.pack(expand=True, fill="both")
    if os.path.exists(log_file):
        with open(log_file) as f:
            text.insert(tk.END, f.read())
    else:
        text.insert(tk.END, "Log file not found.")

def trace_ip_gui():
    import requests
    from tkinter import simpledialog
    ip = simpledialog.askstring("Trace IP", "Enter IP address to trace:")
    if not ip:
        return
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}").json()
        details = f"""IP: {response.get('query')}
ISP: {response.get('isp')}
City: {response.get('city')}
Region: {response.get('regionName')}
Country: {response.get('country')}
Lat/Lon: {response.get('lat')}, {response.get('lon')}"""
        messagebox.showinfo("Trace Result", details)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to trace IP: {e}")

def live_net_gui():
    window = tk.Toplevel()
    window.title("Live Network Monitor")
    window.geometry("800x400")

    columns = ("Local Address", "Remote Address", "Status", "PID", "Process Name")
    table = ttk.Treeview(window, columns=columns, show="headings")
    for col in columns:
        table.heading(col, text=col)
        table.column(col, width=160)
    table.pack(expand=True, fill=tk.BOTH)

    def refresh():
        for row in table.get_children():
            table.delete(row)
        for conn in psutil.net_connections(kind='inet'):
            try:
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                status = conn.status
                pid = conn.pid
                pname = psutil.Process(pid).name() if pid else ""
                table.insert("", tk.END, values=(laddr, raddr, status, pid, pname))
            except:
                continue
        window.after(5000, refresh)

    refresh()

def start_gui():
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import matplotlib.pyplot as plt
    from tkinter import Frame
    from tkinter import font as tkfont
    root = tk.Tk() # KEEP THIS FIRST INITIALIZATION
    root.title("HakxSentinel Dashboard")
    root.geometry("900x800")
    root.configure(bg="#1e1e1e")
    heading_font = tkfont.Font(size=18, weight="bold")
    heading = tk.Label(root, text="HakxSentinel", font=heading_font, fg="white", bg="#1e1e1e")
    heading.pack(pady=10)

    # Mini graph frame
    graph_frame = tk.Frame(root, bg="#2e2e2e")
    graph_frame.pack(padx=20, pady=5, fill=tk.BOTH)

    fig, ax = plt.subplots(figsize=(6, 1.5), dpi=100)
    ax.set_title("Network Events (Past 10)", fontsize=10)
    ax.set_xticks([])
    ax.set_yticks([])
    line, = ax.plot([], [], marker='o', color='blue')
    canvas = FigureCanvasTkAgg(fig, master=graph_frame)
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # System resource widget frame
    resource_frame = tk.Frame(root, bg="#1e1e1e")
    resource_frame.pack(padx=20, pady=10, fill=tk.X)

    # Network usage graph frame
    net_usage_frame = tk.Frame(root, bg="#1e1e1e")
    net_usage_frame.pack(padx=20, pady=5, fill=tk.X)
    fig_net, ax_net = plt.subplots(figsize=(6, 1.5), dpi=100)
    ax_net.set_title("Network Usage (KB/s)", fontsize=10)
    net_line, = ax_net.plot([], [], color='lime', marker='o')
    net_canvas = FigureCanvasTkAgg(fig_net, master=net_usage_frame)
    net_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    net_usage_data = []
    def update_net_usage():
        try:
            net_io = psutil.net_io_counters()
            update_net_usage.last_bytes = getattr(update_net_usage, 'last_bytes', net_io.bytes_recv)
            current = net_io.bytes_recv
            upload_rate = (net_io.bytes_sent - getattr(update_net_usage, 'last_sent', net_io.bytes_sent)) / 1024
            update_net_usage.last_sent = net_io.bytes_sent
            rate = (current - update_net_usage.last_bytes) / 1024  # KB/s
            update_net_usage.last_bytes = current
            net_usage_data.append(rate)
            if len(net_usage_data) > 20:
                net_usage_data.pop(0)
            net_line.set_ydata(net_usage_data)
            net_line.set_xdata(range(len(net_usage_data)))
            ax_net.clear()
            ax_net.set_title("Network Usage (KB/s)", fontsize=10)
            ax_net.plot(range(len(net_usage_data)), net_usage_data, color='lime', marker='o')
            ax_net.set_ylim(0, max(net_usage_data + [1]))
            net_canvas.draw()
            with open("logs/net_usage_log.txt", "a") as log:
                log.write(f"{datetime.now()} - Download: {rate:.2f} KB/s, Upload: {upload_rate:.2f} KB/s\n")
        except Exception as e:
            print("Net usage update error:", e)
        root.after(5000, update_net_usage)

    update_net_usage()
    cpu_label = tk.Label(resource_frame, text="CPU: 0%", fg="white", bg="#1e1e1e")
    mem_label = tk.Label(resource_frame, text="RAM: 0%", fg="white", bg="#1e1e1e")
    disk_label = tk.Label(resource_frame, text="Disk: 0%", fg="white", bg="#1e1e1e")
    cpu_label.pack(side=tk.LEFT, padx=10)
    mem_label.pack(side=tk.LEFT, padx=10)
    disk_label.pack(side=tk.LEFT, padx=10)

    def update_resources():
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        disk = psutil.disk_usage("/").percent
        cpu_label.config(text=f"CPU: {cpu}%")
        mem_label.config(text=f"RAM: {mem}%")
        disk_label.config(text=f"Disk: {disk}%")
        root.after(5000, update_resources)

    update_resources() 

    def update_graph():
        try:
            with open("logs/netwatcher.txt") as f:
                lines = f.readlines()[-10:]
            y = list(range(1, len(lines)+1))
            x = []
            colors = []
            for line_content in lines: 
                label = line_content.split("->")[-1].strip()[:15]
                x.append(label)
                flagged = any(threat in label for threat in [".ru", ".cn", ".ir", "185.", "45.", "146."])
                if flagged:
                    colors.append("red")
                    with open("logs/flagged_ips.txt", "a") as flagged_log:
                        flagged_log.write(f"{datetime.now()} - {label}\n")
                    alertbot({"_message_override": f"[Threat Alert] Suspicious IP Detected: {label}"})
                    if os.name != 'nt':
                        ip_part = label.split(':')[0]
                        subprocess.call(f"iptables -A INPUT -s {ip_part} -j DROP", shell=True)
                else:
                    colors.append("blue")
            line.set_xdata(range(len(x)))
            line.set_ydata(y)
            ax.clear()
            ax.set_title("Network Events (Past 10)", fontsize=10)
            ax.set_xticks(range(len(x)))
            ax.set_xticklabels(x, rotation=45, fontsize=7)
            ax.set_ylim(0, max(y)+1)
            ax.set_xlim(-0.5, len(x)-0.5)
            for i, (xi, yi) in enumerate(zip(range(len(x)), y)):
                ax.plot(xi, yi, 'o', color=colors[i])
            canvas.draw()
        except Exception as e:
            print("Graph update error:", e)
        root.after(10000, update_graph)

    update_graph()

    grid = Frame(root, bg="#2e2e2e")
    grid.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)

    tk.Button(grid, text="Run All Modules", command=run_modules, width=25).grid(row=0, column=0, padx=10, pady=5)
    tk.Label(grid, text="IP:", fg="white", bg="#2e2e2e").grid(row=1, column=0, sticky='w')
    ip_var = tk.StringVar()
    ip_label = tk.Label(grid, textvariable=ip_var, fg="lime", bg="#2e2e2e", text="🟢 IP")
    ip_label.grid(row=2, column=0, sticky='w')
    def run_ip():
        iptracker(load_config())
        try:
            with open("logs/iptracker.txt") as f:
                last_line = f.readlines()[-1]
                ip_var.set(last_line.strip())
        except:
            ip_var.set("Failed to load IP")
    tk.Button(grid, text="Run IP Tracker", command=run_ip, width=25).grid(row=3, column=0, padx=10, pady=5)
    alert_var = tk.StringVar()
    tk.Label(grid, textvariable=alert_var, fg="orange", bg="#2e2e2e", text="🟠 Alert").grid(row=4, column=0, sticky='w')
    def run_alert():
        alertbot(load_config())
        try:
            with open("logs/alerts.txt") as f:
                last_line = f.readlines()[-1]
                alert_var.set(last_line.strip())
        except:
            alert_var.set("Failed to load alerts")
    tk.Button(grid, text="Run AlertBot", command=run_alert, width=25).grid(row=5, column=0, padx=10, pady=5)
    net_var = tk.StringVar()
    tk.Label(grid, textvariable=net_var, fg="cyan", bg="#2e2e2e", text="🔵 Network").grid(row=6, column=0, sticky='w')
    def run_net():
        netwatcher(load_config())
        try:
            with open("logs/netwatcher.txt") as f:
                lines = f.readlines()
                if lines:
                    net_var.set(lines[-1].strip())
                else:
                    net_var.set("No connections logged")
        except:
            net_var.set("Netwatcher error")
    tk.Button(grid, text="Run Netwatcher", command=run_net, width=25).grid(row=7, column=0, padx=10, pady=5)
    filewatcher_var = tk.StringVar()
    tk.Label(grid, textvariable=filewatcher_var, fg="yellow", bg="#2e2e2e", text="🟡 Filewatcher").grid(row=8, column=0, sticky='w')
    def run_filewatcher():
        filewatcher(load_config())
        try:
            with open("logs/filewatcher.txt") as f:
                last_line = f.readlines()[-1]
                filewatcher_var.set(last_line.strip())
        except:
            filewatcher_var.set("No file events yet")
    tk.Button(grid, text="Run Filewatcher", command=run_filewatcher, width=25).grid(row=9, column=0, padx=10, pady=5)
    harden_var = tk.StringVar()
    tk.Label(grid, textvariable=harden_var, fg="violet", bg="#2e2e2e", text="🟣 Hardening").grid(row=10, column=0, sticky='w')
    def run_harden():
        autoharden(load_config())
        try:
            with open("logs/autoharden_status.txt") as f:
                last_line = f.readlines()[-1]
                harden_var.set(last_line.strip())
        except:
            harden_var.set("Hardening report not available")
    tk.Button(grid, text="Run AutoHarden", command=run_harden, width=25).grid(row=11, column=0, padx=10, pady=5)
    tk.Button(grid, text="View IP Tracker", command=lambda: open_log_viewer("logs/iptracker.txt", "IP Tracker Log"), width=25).grid(row=0, column=1, padx=10, pady=5)
    tk.Button(grid, text="View Alerts", command=lambda: open_log_viewer("logs/alerts.txt", "Alerts Log"), width=25).grid(row=1, column=1, padx=10, pady=5)
    tk.Button(grid, text="View Netwatcher", command=lambda: open_log_viewer("logs/netwatcher.txt", "Network Monitor"), width=25).grid(row=2, column=1, padx=10, pady=5)
    tk.Button(grid, text="View Filewatcher", command=lambda: open_log_viewer("logs/filewatcher.txt", "File Monitor"), width=25).grid(row=3, column=1, padx=10, pady=5)
    tk.Button(grid, text="View Hardening Report", command=lambda: open_log_viewer("logs/autoharden_status.txt", "System Hardening Report"), width=25).grid(row=4, column=1, padx=10, pady=5)

    tk.Button(grid, text="Live Net Monitor", command=live_net_gui, width=25).grid(row=5, column=1, padx=10, pady=5)
    tk.Button(grid, text="Trace IP", command=trace_ip_gui, width=25).grid(row=6, column=1, padx=10, pady=5)
    tk.Button(grid, text="View Flagged IPs", command=lambda: open_log_viewer("logs/flagged_ips.txt", "Flagged IPs"), width=25)
    tk.Button(grid, text="View Net Usage Log", command=lambda: open_log_viewer("logs/net_usage_log.txt", "Network Usage Log"), width=25).grid(row=8, column=1, padx=10, pady=5)
    tk.Button(grid, text="Exit", command=root.quit, width=25).grid(row=9, column=1, padx=10, pady=20)
    root.mainloop()

if __name__ == "__main__":
    start_gui()
