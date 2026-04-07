"""
PacketSniffer watches traffic and applies simple rules to generate alerts.
"""

import json
from datetime import datetime
from typing import Optional

from rich.console import Console
from scapy.all import IP, TCP, UDP, sniff

console = Console()


def log_alert(message: str, alert_log: str):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "source": "sniffer",
        "message": message,
    }
    with open(alert_log, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


class PacketSniffer:
    def __init__(self, interface: Optional[str] = None, alert_log: str = "alerts.log"):
        self.interface = interface
        self.alert_log = alert_log

    def _process_packet(self, packet):
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst
            proto = packet[IP].proto

            # Simple suspicious heuristics
            if TCP in packet and packet[TCP].flags == "S":
                log_alert(f"TCP SYN from {src} to {dst}:{packet[TCP].dport}", self.alert_log)
            if UDP in packet and packet[UDP].dport in {53, 123} and packet[IP].ttl > 200:
                log_alert(f"Possible spoofed UDP from {src} -> {dst}:{packet[UDP].dport}", self.alert_log)
            if packet[IP].frag != 0:
                log_alert(f"Fragmented packet from {src}", self.alert_log)

    def start_sniffing(self):
        console.log("[cyan]Starting live packet capture (Ctrl+C to stop if run directly)...")
        sniff(prn=self._process_packet, store=False, iface=self.interface)


if __name__ == "__main__":
    PacketSniffer().start_sniffing()
