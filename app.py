"""
Entry point for the home-network IDS demo.
Starts the packet sniffer, scheduled network scans, and the Flask dashboard.
"""

import threading
import time

from rich.console import Console

from scanner import NetworkScanner
from sniffer import PacketSniffer
from dashboard import create_app
from config import get_settings

console = Console()


def main():
    console.rule("[bold green]Home IDS")
    settings = get_settings()

    scanner = NetworkScanner(
        interface=settings.interface,
        alert_log=settings.alert_log,
        known_hosts_path=settings.known_hosts,
        nmap_path=settings.nmap_path,
    )
    sniffer = PacketSniffer(interface=settings.interface, alert_log=settings.alert_log)

    # Background thread: packet sniffing
    sniff_thread = threading.Thread(target=sniffer.start_sniffing, daemon=True)
    sniff_thread.start()
    console.log("Packet sniffer started.")

    # Background thread: periodic network sweep + port scan
    def scheduled_scans():
        while True:
            console.log("Running scheduled host discovery + quick port scan...")
            scanner.discover_hosts(cidr=settings.cidr)
            scanner.quick_port_scan(target=settings.cidr)
            time.sleep(settings.scan_interval)  # configurable interval

    scan_thread = threading.Thread(target=scheduled_scans, daemon=True)
    scan_thread.start()

    # Flask dashboard (runs in main thread)
    app = create_app(settings.alert_log, settings.known_hosts)
    console.log(f"Starting Flask dashboard at http://{settings.flask_host}:{settings.flask_port}")
    app.run(host=settings.flask_host, port=settings.flask_port, debug=False)


if __name__ == "__main__":
    main()
