"""
NetworkScanner handles host discovery (ARP ping) and quick port scans using nmap.
"""

import json
import os
from datetime import datetime
from typing import Optional

import nmap
from rich.console import Console
from scapy.all import ARP, Ether, srp

console = Console()


def log_alert(message: str, alert_log: str):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "source": "scanner",
        "message": message,
    }
    with open(alert_log, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


class NetworkScanner:
    def __init__(
        self,
        interface: Optional[str] = None,
        alert_log: str = "alerts.log",
        known_hosts_path: str = "known_hosts.json",
        nmap_path: str = "nmap",
    ):
        self.interface = interface
        self.alert_log = alert_log
        self.known_hosts_path = known_hosts_path
        self.nmap_path = nmap_path
        os.environ["NMAP_PATH"] = self.nmap_path
        try:
            self.nm = nmap.PortScanner()
            self.nmap_available = True
        except nmap.PortScannerError as exc:
            console.log(f"[red]nmap unavailable: {exc}")
            log_alert("nmap not found in PATH; port scanning disabled", self.alert_log)
            self.nmap_available = False
            self.nm = None

    def discover_hosts(self, cidr: str = "192.168.1.0/24"):
        """Send ARP who-has to discover live hosts."""
        console.log(f"[cyan]ARP sweep on {cidr}...")
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        answered, _ = srp(packet, timeout=3, verbose=False, iface=self.interface)

        known_hosts = self._load_known_hosts(self.known_hosts_path)
        new_hosts = []

        for _, received in answered:
            ip = received.psrc
            mac = received.hwsrc
            if mac not in known_hosts:
                new_hosts.append({"ip": ip, "mac": mac})
                known_hosts[mac] = {"ip": ip, "first_seen": datetime.utcnow().isoformat()}

        if new_hosts:
            log_alert(f"New device(s) detected: {new_hosts}", self.alert_log)
            console.log(f"[bold yellow]New devices: {new_hosts}")

        self._save_known_hosts(self.known_hosts_path, known_hosts)
        return answered

    def quick_port_scan(self, target: str = "192.168.1.0/24"):
        """Run a fast nmap scan on common ports."""
        if not self.nmap_available:
            console.log("[yellow]Skipping port scan: nmap not available.")
            return None

        console.log(f"[cyan]Running nmap -F on {target}...")
        try:
            self.nm.scan(hosts=target, arguments="-F")
        except nmap.PortScannerError as exc:
            console.log(f"[red]nmap error: {exc}")
            return self.nm

        for host in self.nm.all_hosts():
            if self.nm[host].state() == "up":
                ports = [
                    (p, self.nm[host]["tcp"][p]["state"], self.nm[host]["tcp"][p].get("name", ""))
                    for p in self.nm[host].all_tcp()
                ]
                if any(state == "open" for _, state, _ in ports):
                    log_alert(f"Open ports on {host}: {ports}", self.alert_log)
        return self.nm

    @staticmethod
    def _load_known_hosts(path: str):
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}

    @staticmethod
    def _save_known_hosts(path: str, data: dict):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


if __name__ == "__main__":
    scanner = NetworkScanner()
    scanner.discover_hosts()
    scanner.quick_port_scan()
