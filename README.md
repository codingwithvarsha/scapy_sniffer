# Simple Packet Sniffer (Python + Scapy)

This is a basic packet sniffer built with **Python** and **Scapy**.  
It captures **20 packets** and displays key information about each, including source/destination IPs, ports, and protocol types.

---

## Features
- Captures both **TCP**, **UDP**, and **ICMP** packets.
- Limits capture to **20 packets** for safety.
- Does **not** store packets in memory.
- Displays packet details in real time.

---

## Requirements
- Python 3.x
- [Scapy](https://scapy.readthedocs.io/en/latest/)

Install Scapy:
```bash
pip install scapy

# This tool is provided strictly for educational and authorized security testing purposes only.

Do not use this script on networks you do not own or have explicit permission to test.

Unauthorized packet sniffing may violate laws such as the Indian IT Act, Computer Fraud and Abuse Act (CFAA), or similar laws in your country.

The author is not responsible for any misuse or damages caused by this tool.

By using this tool, you agree to use it responsibly and legally.