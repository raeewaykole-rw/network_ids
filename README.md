# Home Network IDS (Python + Scapy + Nmap + Flask)

A lightweight home-network intrusion detection demo that:
- Discovers new devices via ARP scan
- Runs quick port scans for open services (skips gracefully if nmap missing)
- Sniffs packets and flags suspicious patterns
- Logs alerts and shows them in a minimal Flask dashboard

## Prereqs
- Python 3.10+
- `npcap` / `winpcap` (Windows) or libpcap (Linux/macOS) so Scapy can capture
- Nmap installed and in PATH (needed by python-nmap)

## Quickstart (terminal)
```bash
python -m venv .venv
.venv\Scripts\activate  # or source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env
python app.py
```
Open http://127.0.0.1:5000 to view the dashboard.
The app auto-loads .env on startup.

## Configuration (env vars)
- `IDS_CIDR` (default `192.168.1.0/24`)
- `IDS_INTERFACE` (network interface name; leave empty for default)
- `IDS_SCAN_INTERVAL` (seconds between scheduled scans; default 300)
- `IDS_ALERT_LOG` (path to alerts log; default `alerts.log`)
- `IDS_KNOWN_HOSTS` (path to known hosts JSON; default `known_hosts.json`)
- `IDS_HOST` / `IDS_PORT` (Flask bind; defaults `0.0.0.0:5000`)
- `IDS_NMAP_PATH` (full path or command name for nmap; default `nmap`)

## VS Code setup
1. Open folder in VS Code: `File > Open Folder...` and pick this directory.
2. Create a venv: open the integrated terminal and run the Quickstart commands above.
3. When VS Code asks to use the virtualenv for the workspace, choose **Yes**.
4. Install the Python extension; then select the interpreter `.venv` via the Command Palette (`Python: Select Interpreter`).
5. Run/Debug: use `Run > Start Debugging` on `app.py` (launches Flask + threads). Stop with the red square.
6. Optional: add a launch config by letting VS Code create one when you hit Run; it will auto-detect `app.py`.

## How to test
- New device detection: connect a device to your LAN; check `alerts.log` and the dashboard.
- Port scan: ports open on LAN hosts will be logged; adjust `IDS_CIDR` if your subnet differs.
- Packet alerts: run `nmap -sS <target>` from another host to generate SYNs; they show up as alerts.

## Files
- `app.py` — orchestrates sniffer, scheduled scans, and starts Flask dashboard.
- `config.py` — env-driven settings for CIDR, interface, logging paths, host/port, nmap path.
- `scanner.py` — ARP host discovery and nmap quick scan; logs new hosts/open ports.
- `sniffer.py` — Scapy-based live packet capture with simple heuristics (SYN flood, spoofed UDP, fragments).
- `dashboard.py` — minimal Flask UI to show known hosts and alerts.
- `alerts.log` — JSONL alert log (created at runtime).
- `known_hosts.json` — remembered devices (created at runtime).

## Notes
- Sniffing and ARP scans require elevated privileges on many OSes (sudo/Administrator).
- If nmap isn’t on PATH, port scans will be skipped and a warning logged. Set `IDS_NMAP_PATH` to the full `nmap.exe` if needed.
- Keep this on a trusted network; do not scan networks you don't own/operate.
- This project does not require external API keys. Keep .env, alerts.log, and known_hosts.json out of Git (already handled by .gitignore).


