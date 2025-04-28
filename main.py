import tkinter as tk
from ui import NetworkMonitorApp

def main():
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    app.update_devices()
    app.update_printers()
    app.update_network_gateway()
    root.mainloop()

if __name__ == "__main__":
    main()
