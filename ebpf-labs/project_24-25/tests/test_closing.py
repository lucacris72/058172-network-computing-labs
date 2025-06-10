#!/usr/bin/env python3
from scapy.all import *
import time

IP_CLIENT = "10.0.0.2"
IP_SERVER = "10.0.0.1"
IFACE_CLIENT = "veth2_"
PORT_CLIENT = 12345
PORT_SERVER = 54321
MAC_CLIENT = "46:e7:b8:81:88:f3"
MAC_SERVER = "e2:38:1d:d1:1d:42"

def add_padding(packet):
    padding_needed = 60 - len(packet)
    if padding_needed > 0:
        return packet / Raw(b'\x00' * padding_needed)
    return packet

def print_pkt(pkt):
    if pkt:
        if isinstance(pkt, tuple) and len(pkt) > 0:
            pkt = pkt[0][1]
        print(f"-> Received: {pkt.summary()}")

print("--- Starting Simultaneous TCP Close Test ---")

eth_layer = Ether(src=MAC_CLIENT, dst=MAC_SERVER)
eth_layer_rev = Ether(src=MAC_SERVER, dst=MAC_CLIENT)

print("\n[1] Performing 3-Way Handshake...")
ip_layer = IP(src=IP_CLIENT, dst=IP_SERVER)
client_isn = random.randint(0, (2**32)-1)

syn = TCP(sport=PORT_CLIENT, dport=PORT_SERVER, flags='S', seq=client_isn)
syn_pkt = add_padding(eth_layer/ip_layer/syn)
print(f"   -> Sending SYN (size: {len(syn_pkt)} bytes)")

syn_ack_response = srp1(syn_pkt, iface=IFACE_CLIENT, timeout=2, verbose=0)

if not syn_ack_response or not syn_ack_response.haslayer(TCP):
    print("Error: Did not receive SYN-ACK from server. Test failed.")
    exit(1)

print_pkt(syn_ack_response)
syn_ack = syn_ack_response[TCP]
server_isn = syn_ack.seq
client_ack = syn_ack.ack

ack = TCP(sport=PORT_CLIENT, dport=PORT_SERVER, flags='A', seq=client_ack, ack=server_isn + 1)
ack_pkt = add_padding(eth_layer/ip_layer/ack)
sendp(ack_pkt, iface=IFACE_CLIENT, verbose=0)

print("   -> Connection ESTABLISHED.")
client_seq = client_ack
server_seq = server_isn + 1

print("\n[2] Sending a data packet...")
payload = "test_data"
data_pkt_unpadded = eth_layer/ip_layer/TCP(sport=PORT_CLIENT, dport=PORT_SERVER, flags='PA', seq=client_seq, ack=server_seq)/payload
data_pkt = add_padding(data_pkt_unpadded)
data_ack_response = srp1(data_pkt, iface=IFACE_CLIENT, timeout=2, verbose=0)
print_pkt(data_ack_response)
client_seq += len(payload)

print("\n[3] Starting simultaneous close: sending FIN from both sides...")
ip_layer_rev = IP(src=IP_SERVER, dst=IP_CLIENT)

fin_client_unpadded = eth_layer/ip_layer/TCP(sport=PORT_CLIENT, dport=PORT_SERVER, flags='FA', seq=client_seq, ack=server_seq)
fin_client = add_padding(fin_client_unpadded)

fin_server_unpadded = eth_layer_rev/ip_layer_rev/TCP(sport=PORT_SERVER, dport=PORT_CLIENT, flags='FA', seq=server_seq, ack=client_seq)
fin_server = add_padding(fin_server_unpadded)

sendp(fin_server, iface=IFACE_CLIENT, verbose=0)
print("   -> FIN from Server (simulated) sent.")
time.sleep(0.1)
sendp(fin_client, iface=IFACE_CLIENT, verbose=0)
print("   -> FIN from Client sent.")

print("\n[4] Sending final ACKs to complete the close...")
ack_final_client_unpadded = eth_layer/ip_layer/TCP(sport=PORT_CLIENT, dport=PORT_SERVER, flags='A', seq=client_seq + 1, ack=server_seq + 1)
ack_final_client = add_padding(ack_final_client_unpadded)
sendp(ack_final_client, iface=IFACE_CLIENT, verbose=0)
print("   -> Final ACK from Client sent.")

ack_final_server_unpadded = eth_layer_rev/ip_layer_rev/TCP(sport=PORT_SERVER, dport=PORT_CLIENT, flags='A', seq=server_seq + 1, ack=client_seq + 1)
ack_final_server = add_padding(ack_final_server_unpadded)
sendp(ack_final_server, iface=IFACE_CLIENT, verbose=0)
print("   -> Final ACK from Server (simulated) sent.")

print("\n--- Test Completed ---")