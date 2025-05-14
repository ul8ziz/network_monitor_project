import tkinter as tk
from threading import Thread
import time
import config
import scanner
import notifier
import os

class NetworkMonitorApp:
    def __init__(self, master):
        self.master = master
        master.title("Network & Printer Monitor")
        master.geometry("700x600")

        self.label_network = tk.Label(master, text=f"Network: {config.NETWORK_IP}", font=("Arial", 14))
        self.label_network.pack(pady=5)

        self.label_gateway = tk.Label(master, text=f"Gateway: {config.GATEWAY_IP}", font=("Arial", 14))
        self.label_gateway.pack(pady=5)

        # Button Frame
        self.button_frame = tk.Frame(master)
        self.button_frame.pack(pady=5)

        # Menu Bar
        menubar = tk.Menu(master)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Configure", command=self.open_config_popup)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=master.quit)
        menubar.add_cascade(label="Change setings", menu=filemenu)
        master.config(menu=menubar)

        # Config Button
        #self.config_button = tk.Button(master, text="⚙️ Configure", command=self.open_config_popup, font=("Arial", 12), padx=10, pady=5)
        #self.config_button.pack(pady=5)

        # Refresh Devices Button
        self.refresh_devices_button = tk.Button(self.button_frame, text="🔄 Refresh Devices", command=self.update_devices,  bg="#4CAF50", fg="white", font=("Arial", 12), padx=10, pady=5)
        self.refresh_devices_button.pack(side=tk.LEFT, padx=5)

        self.refresh_printers_button = tk.Button(self.button_frame, text="🔄 Refresh Printers", command=self.update_printers, bg="#2196F3", fg="white", font=("Arial", 12), padx=10, pady=5)
        self.refresh_printers_button.pack(side=tk.LEFT, padx=5)

        self.refresh_network_gateway_button = tk.Button(self.button_frame, text="🔄 Refresh Network/Gateway", command=self.update_network_gateway, bg="#f44336", fg="white", font=("Arial", 12), padx=10, pady=5)
        self.refresh_network_gateway_button.pack(side=tk.LEFT, padx=5)

        self.printers_frame = tk.LabelFrame(master, text="Printers Status", font=("Arial", 12))
        self.printers_frame.pack(pady=10, fill="x", padx=20)

        self.printer_labels = {}
        for ip in config.PRINTER_IPS:
            frame = tk.Frame(self.printers_frame)
            frame.pack(fill="x", padx=10, pady=2)

            lbl = tk.Label(frame, text=f"Printer {ip}: Checking...", font=("Arial", 12), anchor="w")
            lbl.pack(side=tk.LEFT, fill="x", expand=True)
            self.printer_labels[ip] = lbl

        self.devices_frame = tk.LabelFrame(master, text="Connected Devices", font=("Arial", 12))
        self.devices_frame.pack(pady=10, fill="both", expand=True, padx=20)

        self.devices_scrollbar = tk.Scrollbar(self.devices_frame)
        self.devices_listbox = tk.Listbox(self.devices_frame, font=("Arial", 11), yscrollcommand=self.devices_scrollbar.set)
        self.devices_scrollbar.config(command=self.devices_listbox.yview)
        self.devices_scrollbar.pack(side="right", fill="y")
        self.devices_listbox.pack(side="left", fill="both", expand=True, padx=10, pady=5)

      #  self.external_network_label = tk.Label(master, text="External Network: Checking...", font=("Arial", 12))
       # self.external_network_label.pack(pady=5)

        self.status_bar = tk.Label(master, text="Monitoring...", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

       # self.total_devices_label = tk.Label(master, text="Total Devices: 0", font=("Arial", 12))
       # self.total_devices_label.pack(pady=5)

        self.update_network_gateway()

        self.vlan_frame = tk.LabelFrame(master, text="VLAN Devices", font=("Arial", 12))
        self.vlan_frame.pack(pady=10, fill="both", expand=True, padx=20)

        self.vlan_scrollbar = tk.Scrollbar(self.vlan_frame)
        self.vlan_listbox = tk.Listbox(self.vlan_frame, font=("Arial", 11), yscrollcommand=self.vlan_scrollbar.set)
        self.vlan_scrollbar.config(command=self.vlan_listbox.yview)
        self.vlan_scrollbar.pack(side="right", fill="y")
        self.vlan_listbox.pack(side="left", fill="both", expand=True, padx=10, pady=5)

        vlan_button = tk.Button(self.button_frame, text="🔍 Scan VLANs", command=self.scan_vlans, bg="#9C27B0", fg="white", font=("Arial", 12), padx=10, pady=5)
        vlan_button.pack(side=tk.LEFT, padx=5)


    def load_icon(self, path):
        try:
            return tk.PhotoImage(file=path)
        except Exception as e:
            print(f"Error loading icon from {path}: {e}")
            return None

    def refresh_network(self):
        self.update_network_gateway()

    def update_devices(self):
        def task():
            # Update device list
            devices = scanner.discover_devices(config.NETWORK_IP, config.GATEWAY_IP)
            self.devices_listbox.delete(0, tk.END)
            for device in devices:
                self.devices_listbox.insert(tk.END, f"{device['ip']} - {device['type']} ({device['mac']})")
            self.status_bar.config(text=f"Total Devices: {len(devices)}")
        t = Thread(target=task, daemon=True)
        t.start()
    
    def scan_vlans(self):
        def task():
            from config import VLAN_NETWORKS
            results = scanner.scan_vlan_networks(VLAN_NETWORKS)

            self.vlan_listbox.delete(0, tk.END)

            if not results:
                self.vlan_listbox.insert(tk.END, "❌ لم يتم العثور على أي جهاز في VLANs.")
            else:
                vlan_map = {}
                for device in results:
                    vlan_map.setdefault(device["vlan"], []).append(device)

                for vlan, devices in vlan_map.items():
                    self.vlan_listbox.insert(tk.END, f"🔸 {vlan} ({len(devices)} جهاز):")
                    for dev in devices:
                        line = f"  • {dev['ip']} | {dev['hostname']} | {dev['mac']} | {dev['status']}"
                        self.vlan_listbox.insert(tk.END, line)
                    self.vlan_listbox.insert(tk.END, "")  # فراغ بين VLANs

            self.status_bar.config(text=f"VLAN Devices Found: {len(results)}")
        Thread(target=task, daemon=True).start()

    
    def open_config_popup(self):
        self.popup = tk.Toplevel(self.master)
        popup = self.popup
        popup.title("Configuration")
        popup.geometry("300x300")

        # Network Label and Entry
        network_label = tk.Label(popup, text="Network IP:", font=("Arial", 12))
        network_label.pack(pady=5)
        self.network_entry = tk.Entry(popup, font=("Arial", 12))
        self.network_entry.insert(0, config.NETWORK_IP)
        self.network_entry.pack(pady=5)

        # Gateway Label and Entry
        gateway_label = tk.Label(popup, text="Gateway IP:", font=("Arial", 12))
        gateway_label.pack(pady=5)
        self.gateway_entry = tk.Entry(popup, font=("Arial", 12))
        self.gateway_entry.insert(0, config.GATEWAY_IP)
        self.gateway_entry.pack(pady=5)

        # Printer IPs Label and Entries
        printer_ips_label = tk.Label(popup, text="Printer IPs (comma separated):", font=("Arial", 12))
        printer_ips_label.pack(pady=5)
        self.printer_ips_entry = tk.Entry(popup, font=("Arial", 12))
        self.printer_ips_entry.insert(0, ", ".join(config.PRINTER_IPS))
        self.printer_ips_entry.pack(pady=5)

        # Save Button
        save_button = tk.Button(popup, text="Save", command=lambda: self.save_config(popup), font=("Arial", 12), padx=10, pady=5)
        save_button.pack(pady=10)

    def open_printer_title_popup(self, printer_ip):
        self.printer_title_popup = tk.Toplevel(self.master)
        popup = self.printer_title_popup
        popup.title(f"Edit Printer Title - {printer_ip}")
        popup.geometry("300x150")

        # Title Label and Entry
        title_label = tk.Label(popup, text="Printer Title:", font=("Arial", 12))
        title_label.pack(pady=5)
        self.title_entry = tk.Entry(popup, font=("Arial", 12))
        self.title_entry.pack(pady=5)

        # Save Button
        save_button = tk.Button(popup, text="Save", command=lambda: self.save_printer_title(printer_ip, popup), font=("Arial", 12), padx=10, pady=5)
        save_button.pack(pady=10)

    def save_printer_title(self, printer_ip, popup):
        new_title = self.title_entry.get()
        config.PRINTER_TITLES[printer_ip] = new_title
        self.update_printer_labels()

        self.update_printers()

        # Save config to file
        config_content = f"""# إعدادات ثابتة
PRINTER_IPS = {config.PRINTER_IPS}
PRINTER_TITLES = {config.PRINTER_TITLES}

NETWORK_IP = "{config.NETWORK_IP}"
GATEWAY_IP = "{config.GATEWAY_IP}"
"""
        with open("config.py", "w", encoding="utf-8") as f:
            f.write(config_content)

        popup.destroy()

    def update_printer_labels(self):
        # Clear existing printer labels and frames
        for widget in self.printers_frame.winfo_children():
            widget.destroy()
        self.printer_labels.clear()

        # Re-create printer labels based on the updated PRINTER_IPS
        for ip in config.PRINTER_IPS:
            frame = tk.Frame(self.printers_frame)
            frame.pack(fill="x", padx=10, pady=2)

            lbl = tk.Label(frame, text=f"Printer {ip}: Checking...", font=("Arial", 12), anchor="w")
            lbl.pack(side=tk.LEFT, fill="x", expand=True)
            self.printer_labels[ip] = lbl

            edit_button = tk.Button(frame, text="✏️", command=lambda ip=ip: self.open_printer_title_popup(ip), font=("Arial", 12), padx=5, pady=0)
            edit_button.pack(side=tk.RIGHT)

    def save_config(self, popup):
        new_network_ip = self.network_entry.get()
        new_gateway_ip = self.gateway_entry.get()
        new_printer_ips_str = self.printer_ips_entry.get()
        new_printer_ips = [ip.strip() for ip in new_printer_ips_str.split(",")]

        # Update config.py
        config_content = f"""# إعدادات ثابتة
PRINTER_IPS = {new_printer_ips}
PRINTER_TITLES = {config.PRINTER_TITLES}

NETWORK_IP = "{new_network_ip}"
GATEWAY_IP = "{new_gateway_ip}"
"""
        with open("config.py", "w", encoding="utf-8") as f:
            f.write(config_content)

        # Update labels
        self.label_network.config(text=f"Network: {new_network_ip}")
        self.label_gateway.config(text=f"Gateway: {new_gateway_ip}")

        # Update printer labels
        self.update_printer_labels()

        # Close popup
        self.popup.destroy()

        # Update devices
        self.update_devices()

        # Re-import config module to reflect changes
        import importlib
        importlib.reload(config)

    def update_printers(self):
        def task(master):
            # Update printer statuses
            for ip, label in self.printer_labels.items():
                alive = scanner.is_device_alive(ip)
                if alive and alive["alive"]:
                    status = "✅ Connected"
                else:
                    status = "❌ Not Connected"
                master.after(0, label.config, {"text": f"Printer {ip}: {status}"})
                if not alive or not alive["alive"]:
                    notifier.show_alert("Printer Disconnected", f"Printer {ip} is offline!")
        t = Thread(target=task, args=(self.master,), daemon=True)
        t.start()

    def update_network_gateway(self):
        def task():
            # Update gateway status
            gateway_status = scanner.is_device_alive(config.GATEWAY_IP)
            if gateway_status and gateway_status["alive"]:
                gateway_text = f"Gateway: {config.GATEWAY_IP} ✅ (Time: {gateway_status['time']}, TTL: {gateway_status['ttl']}, Bytes: {gateway_status['bytes']})"
            else:
                gateway_text = f"Gateway: {config.GATEWAY_IP} ❌ Not Connected"
            self.label_gateway.config(text=gateway_text) #self.network_gateway_frame.label_gateway.config(text=gateway_text)

            #Check external network connection
            external_status = scanner.is_device_alive("8.8.8.8") # Google DNS
            if external_status and external_status["alive"]:
                external_text = f"External Network: ✅ (Time: {external_status['time']}, TTL: {external_status['ttl']}, Bytes: {external_status['bytes']})"
            else:
                external_text = "External Network: ❌ Not Connected"
           # self.external_network_label.config(text=external_text)
        t = Thread(target=task, daemon=True)
        t.start()
