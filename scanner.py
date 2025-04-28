from ping3 import ping
import subprocess
import re
import platform
import subprocess
import re
import platform

def is_device_alive(ip):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        result = subprocess.run(["ping", param, "1", "-w", "500", ip],
                                capture_output=True, text=True)
        output = result.stdout
        if result.returncode == 0:
            time = re.search(r"time=((\d+ms)|(\d+.\d+ms))", output)
            ttl = re.search(r"TTL=(\d+)", output)
            bytes_sent = re.search(r"bytes=(\d+)", output)

            time_value = time.group(1) if time else "N/A"
            ttl_value = ttl.group(1) if ttl else "N/A"
            bytes_value = bytes_sent.group(1) if bytes_sent else "N/A"

            return {"alive": True, "time": time_value, "ttl": ttl_value, "bytes": bytes_value}
        else:
            return {"alive": False}
    except Exception:
        return {"alive": False}

def get_mac_address(ip):
    try:
        arp_result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True)
        arp_output = arp_result.stdout
        mac_address_search = re.search(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", arp_output)
        if mac_address_search:
            return mac_address_search.group(0)
        else:
            return None
    except Exception:
        return None

def discover_devices(network_ip, gateway_ip):
    discovered = []
    known_ips = set()

    oui_database = {
        "00-50-56": "VMware Virtual NIC",
        "00-05-69": "Cisco-Linksys",
        "00-0D-88": "Apple, Inc.",
        "00-17-C4": "Cisco-Linksys",
        "00-19-E0": "Dell Inc",
        "00-1B-FC": "Hewlett Packard",
        "00-21-91": "Apple, Inc.",
        "00-22-68": "Cisco-Linksys",
        "00-23-69": "Cisco-Linksys",
        "00-24-D7": "Dell Inc",
        "00-25-00": "Cisco-Linksys",
        "00-26-B9": "Cisco-Linksys",
        "00-27-0D": "Hewlett Packard",
        "00-A0-C9": "Compaq Computer Corporation",
        "00-04-76": "Dell Inc",
    }

    try:
        arp_result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        arp_output = arp_result.stdout

        for line in arp_output.splitlines():
            match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})", line)
            if match:
                ip = match.group(1)
                mac_address = match.group(0).split()[1]
                known_ips.add(ip)

                device_type = "💻 Desktop"  # Default device type
                if mac_address:
                    oui = mac_address[:8].upper()
                    if oui in oui_database:
                        device_type = oui_database[oui]

                if ip == gateway_ip:
                    device_type = "🌐 Router"
                elif ip.endswith(".100"):
                    device_type = "🖨️ Printer"

                discovered.append({"ip": ip, "type": device_type, "mac": mac_address})
    except Exception as e:
        print(f"Error discovering devices from ARP table: {e}")

    # Ping the remaining IPs
    base_ip = '.'.join(network_ip.split('.')[:-1])
    for i in range(1, 255):
        ip = f"{base_ip}.{i}"
        if ip not in known_ips:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            result = subprocess.run(["ping", param, "1", "-w", "500", ip],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                mac_address = get_mac_address(ip)
                device_type = "💻 Desktop"  # Default device type
                if mac_address:
                    oui = mac_address[:8].upper()
                    if oui in oui_database:
                        device_type = oui_database[oui]

                if ip == gateway_ip:
                    device_type = "🌐 Router"
                elif ip.endswith(".100"):
                    device_type = "🖨️ Printer"
                discovered.append({"ip": ip, "type": device_type, "mac": mac_address})

    return discovered
