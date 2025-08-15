from scapy.all import sniff, IP, TCP, UDP, ICMP

def handler(pkt):
    if IP not in pkt:
        return
    src = pkt[IP].src
    dst = pkt[IP].dst

    if TCP in pkt:
        print(f"[TCP ] {src}:{pkt[TCP].sport} -> {dst}:{pkt[TCP].dport}")
    elif UDP in pkt:
        print(f"[UDP ] {src}:{pkt[UDP].sport} -> {dst}:{pkt[UDP].dport}")
    elif ICMP in pkt:
        print(f"[ICMP] {src} -> {dst}")
    else:
        print(f"[IP  ] {src} -> {dst} (proto={pkt[IP].proto})")

def main():
    print("Sniffing... Capturing only 20 packets.")
    sniff(prn=handler, store=False, count=20)  # store=False avoids memory usage

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
