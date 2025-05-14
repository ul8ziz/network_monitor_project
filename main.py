import tkinter as tk
from ui import NetworkMonitorApp
import threading
from config import VLAN_NETWORKS
from scanner import scan_vlan_networks

# دالة فحص الشبكات الفرعية VLAN في خيط مستقل
def run_vlan_scan():
    try:
        vlan_results = scan_vlan_networks(VLAN_NETWORKS)
        for device in vlan_results:
            print(f"{device['vlan']} | {device['ip']} | {device['hostname']} | {device['mac']} | {device['status']}")
    except Exception as e:
        print(f"🔥 خطأ أثناء فحص VLANs: {e}")

# الدالة الرئيسية لتشغيل التطبيق
def main():
    root = tk.Tk()

    app = NetworkMonitorApp(root)

    # شغّل فحص VLAN في الخلفية
    threading.Thread(target=run_vlan_scan, daemon=True).start()

    # تحديث الأجهزة والطابعات وبوابة الشبكة
    app.update_devices()
    app.update_printers()
    app.update_network_gateway()

    # تشغيل واجهة المستخدم الرسومية
    root.mainloop()

# نقطة البداية
if __name__ == "__main__":
    main()
