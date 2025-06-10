#!/usr/bin/env python3
from scapy.all import *
import time

TARGET_IP = "10.0.0.1"
SOURCE_IP = "10.0.0.2"
SOURCE_IFACE = "veth2_"

MAC_SRC = "46:e7:b8:81:88:f3"
MAC_DST = "e2:38:1d:d1:1d:42"

LISTEN_PORT = 8080
CLOSED_PORT = 8081
SOURCE_PORT = 12345
TEST_PAYLOAD = "Conntrack test!"


def add_padding(packet):
    padding_needed = 60 - len(packet)
    if padding_needed > 0:
        return packet / Raw(b'\x00' * padding_needed)
    return packet

def print_test_case(name):
    print("\n" + "="*50)
    print(f" TEST CASE: {name}")
    print("="*50)
    time.sleep(2)

def test_successful_handshake_and_data():
    print_test_case("Correct TCP handshake and data send")
    eth = Ether(src=MAC_SRC, dst=MAC_DST)
    ip = IP(src=SOURCE_IP, dst=TARGET_IP)
    sport = SOURCE_PORT
    syn = TCP(sport=sport, dport=LISTEN_PORT, flags='S', seq=100)
    syn_pkt = add_padding(eth/ip/syn)
    print(" -> Sending SYN...")
    syn_ack_resp = srp1(syn_pkt, timeout=2, verbose=0, iface=SOURCE_IFACE)
    if not syn_ack_resp:
        print(" <- ERROR: No SYN-ACK response received.")
        return
    syn_ack = syn_ack_resp[TCP]
    print(" <- Received SYN-ACK.")
    ack = TCP(sport=sport, dport=LISTEN_PORT, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)
    ack_pkt = add_padding(eth/ip/ack)
    print(" -> Sending final ACK...")
    sendp(ack_pkt, verbose=0, iface=SOURCE_IFACE)
    print("Connection established (ESTABLISHED).")
    time.sleep(1)
    push_ack = TCP(sport=sport, dport=LISTEN_PORT, flags='PA', seq=ack.seq, ack=ack.ack)
    data_pkt = add_padding(eth/ip/push_ack/Raw(load=TEST_PAYLOAD))
    print(" -> Sending data packet (PSH+ACK)...")
    sendp(data_pkt, verbose=0, iface=SOURCE_IFACE)

def test_graceful_shutdown():
    print_test_case("Graceful shutdown (FIN)")
    eth = Ether(src=MAC_SRC, dst=MAC_DST)
    ip = IP(src=SOURCE_IP, dst=TARGET_IP)
    sport = SOURCE_PORT
    syn = TCP(sport=sport, dport=LISTEN_PORT, flags='S', seq=200)
    syn_ack_resp = srp1(add_padding(eth/ip/syn), timeout=2, verbose=0, iface=SOURCE_IFACE)
    if not syn_ack_resp: return
    syn_ack = syn_ack_resp[TCP]
    ack = TCP(sport=sport, dport=LISTEN_PORT, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)
    sendp(add_padding(eth/ip/ack), verbose=0, iface=SOURCE_IFACE)
    print("Connection established.")
    time.sleep(1)
    fin_ack_1 = TCP(sport=sport, dport=LISTEN_PORT, flags='FA', seq=ack.seq, ack=ack.ack)
    print(" -> Sending FIN,ACK to start shutdown...")
    server_ack_resp = srp1(add_padding(eth/ip/fin_ack_1), timeout=2, verbose=0, iface=SOURCE_IFACE)
    if not server_ack_resp:
        print(" <- ERROR: Did not receive ACK to my FIN.")
        return
    server_ack = server_ack_resp[TCP]
    print(" <- Received ACK from server.")
    last_ack = TCP(sport=sport, dport=LISTEN_PORT, flags='A', seq=server_ack.ack, ack=server_ack.seq + 1)
    print(" -> Sending last ACK.")
    sendp(add_padding(eth/ip/last_ack), verbose=0, iface=SOURCE_IFACE)

def test_rst_on_established_connection():
    print_test_case("Forced reset (RST) on active connection")
    eth = Ether(src=MAC_SRC, dst=MAC_DST)
    ip = IP(src=SOURCE_IP, dst=TARGET_IP)
    sport = SOURCE_PORT
    syn_ack_resp = srp1(add_padding(eth/ip/TCP(sport=sport, dport=LISTEN_PORT, flags='S', seq=300)), timeout=2, verbose=0, iface=SOURCE_IFACE)
    if not syn_ack_resp: return
    syn_ack = syn_ack_resp[TCP]
    ack = TCP(sport=sport, dport=LISTEN_PORT, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)
    sendp(add_padding(eth/ip/ack), verbose=0, iface=SOURCE_IFACE)
    print("Connection established.")
    time.sleep(1)
    rst = TCP(sport=sport, dport=LISTEN_PORT, flags='R', seq=ack.seq)
    print(" -> Sending RST packet...")
    sendp(add_padding(eth/ip/rst), verbose=0, iface=SOURCE_IFACE)

def test_rst_on_closed_port():
    print_test_case("Connection to closed port")
    eth = Ether(src=MAC_SRC, dst=MAC_DST)
    ip = IP(src=SOURCE_IP, dst=TARGET_IP)
    syn = TCP(dport=CLOSED_PORT, flags='S')
    print(f" -> Sending SYN to a closed port ({CLOSED_PORT})...")
    response = srp1(add_padding(eth/ip/syn), timeout=2, verbose=0, iface=SOURCE_IFACE)
    if response and response.haslayer(TCP) and response[TCP].flags.R:
        print(" <- OK: Received RST response as expected.")
    else:
        print(" <- ERROR: Did not receive an RST response.")

def test_invalid_first_packet():
    print_test_case("Non-SYN initial packet")
    eth = Ether(src=MAC_SRC, dst=MAC_DST)
    ip = IP(src=SOURCE_IP, dst=TARGET_IP)
    ack = TCP(dport=LISTEN_PORT, flags='A')
    print(" -> Sending ACK packet without connection...")
    sendp(add_padding(eth/ip/ack), verbose=0, iface=SOURCE_IFACE)

if __name__ == "__main__":
    print("Starting Test Bench for eBPF Conntrack...")
    test_successful_handshake_and_data()
    test_graceful_shutdown()
    test_rst_on_established_connection()
    test_rst_on_closed_port()
    test_invalid_first_packet()
    print("\n" + "="*50)
    print("Test Bench completed.")
    print("="*50)