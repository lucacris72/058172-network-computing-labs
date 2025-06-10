#!/usr/bin/env python3
from scapy.all import *
import time

# --- Configurazione del Test Bench ---
TARGET_IP = "10.0.0.2"    # Sostituisci con l'IP della macchina con XDP
SOURCE_IFACE = "veth2_"
LISTEN_PORT = 8080         # La porta su cui socat è in ascolto
CLOSED_PORT = 8081         # Una porta sicuramente chiusa
TEST_PAYLOAD = "Test di conntrack!"

# Funzione di utilità per stampare i casi di test
def print_test_case(name):
    print("\n" + "="*50)
    print(f" CASO DI TEST: {name}")
    print("="*50)
    # Diamo tempo di leggere l'output nei log
    time.sleep(2)

def test_successful_handshake_and_data():
    print_test_case("Handshake TCP corretto e invio dati")
    
    # 1. Handshake
    sport = RandShort()
    ip = IP(dst=TARGET_IP)
    syn = TCP(sport=sport, dport=LISTEN_PORT, flags='S', seq=100)
    print(" -> Invio SYN...")
    syn_ack = sr1(ip/syn, timeout=2, verbose=0, iface=SOURCE_IFACE)
    if not syn_ack:
        print(" <- ERRORE: Nessuna risposta SYN-ACK ricevuta.")
        return

    print(" <- Ricevuto SYN-ACK.")
    ack = TCP(sport=sport, dport=LISTEN_PORT, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)
    print(" -> Invio ACK finale...")
    send(ip/ack, verbose=0, iface=SOURCE_IFACE)
    print("Connessione stabilita (ESTABLISHED).")

    # 2. Invio dati
    time.sleep(1)
    push_ack = TCP(sport=sport, dport=LISTEN_PORT, flags='PA', seq=ack.seq, ack=ack.ack)
    print(" -> Invio pacchetto dati (PSH+ACK)...")
    send(ip/push_ack/Raw(load=TEST_PAYLOAD), verbose=0, iface=SOURCE_IFACE)

def test_graceful_shutdown():
    print_test_case("Chiusura Graziosa (FIN)")
    
    # 1. Stabilisci connessione (come prima)
    sport = RandShort()
    ip = IP(dst=TARGET_IP)
    syn = TCP(sport=sport, dport=LISTEN_PORT, flags='S', seq=200)
    syn_ack = sr1(ip/syn, timeout=2, verbose=0, iface=SOURCE_IFACE)
    if not syn_ack: return
    ack = TCP(sport=sport, dport=LISTEN_PORT, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)
    send(ip/ack, verbose=0, iface=SOURCE_IFACE)
    print("Connessione stabilita.")

    # 2. Avvia chiusura dal client
    time.sleep(1)
    fin_ack_1 = TCP(sport=sport, dport=LISTEN_PORT, flags='FA', seq=ack.seq, ack=ack.ack)
    print(" -> Invio FIN,ACK per iniziare la chiusura...")
    
    # Il server risponde con ACK al nostro FIN e poi con il suo FIN
    server_ack = sr1(ip/fin_ack_1, timeout=2, verbose=0, iface=SOURCE_IFACE)
    if not server_ack:
        print(" <- ERRORE: Non ho ricevuto l'ACK al mio FIN.")
        return
    print(" <- Ricevuto ACK dal server.")
    
    # In uno scenario reale, dovremmo aspettare il FIN del server. Per semplicità, lo saltiamo
    # e inviamo l'ultimo ACK, assumendo che la logica di timeout gestisca il resto.
    last_ack = TCP(sport=sport, dport=LISTEN_PORT, flags='A', seq=server_ack.ack, ack=server_ack.seq + 1)
    print(" -> Invio ultimo ACK.")
    send(ip/last_ack, verbose=0, iface=SOURCE_IFACE)


def test_rst_on_established_connection():
    print_test_case("Reset Forzato (RST) su connessione attiva")

    # 1. Stabilisci connessione
    sport = RandShort()
    ip = IP(dst=TARGET_IP)
    syn = TCP(sport=sport, dport=LISTEN_PORT, flags='S', seq=300)
    syn_ack = sr1(ip/syn, timeout=2, verbose=0, iface=SOURCE_IFACE)
    if not syn_ack: return
    ack = TCP(sport=sport, dport=LISTEN_PORT, flags='A', seq=syn_ack.ack, ack=syn_ack.seq + 1)
    send(ip/ack, verbose=0, iface=SOURCE_IFACE)
    print("Connessione stabilita.")

    # 2. Invia RST
    time.sleep(1)
    rst = TCP(sport=sport, dport=LISTEN_PORT, flags='R', seq=ack.seq)
    print(" -> Invio pacchetto RST...")
    send(ip/rst, verbose=0, iface=SOURCE_IFACE)

def test_rst_on_closed_port():
    print_test_case("Connessione a porta chiusa")
    
    ip = IP(dst=TARGET_IP)
    syn = TCP(dport=CLOSED_PORT, flags='S')
    print(f" -> Invio SYN a una porta chiusa ({CLOSED_PORT})...")
    response = sr1(ip/syn, timeout=2, verbose=0, iface=SOURCE_IFACE)

    if response and response.haslayer(TCP) and response[TCP].flags.R:
        print(" <- OK: Ricevuta risposta RST come atteso.")
    else:
        print(" <- ERRORE: Non ho ricevuto una risposta RST.")

def test_invalid_first_packet():
    print_test_case("Pacchetto iniziale non-SYN")
    
    ip = IP(dst=TARGET_IP)
    ack = TCP(dport=LISTEN_PORT, flags='A')
    print(" -> Invio pacchetto ACK senza connessione...")
    send(ip/ack, verbose=0, iface=SOURCE_IFACE)


if __name__ == "__main__":
    print("Avvio del Test Bench per eBPF Conntrack...")
    
    test_successful_handshake_and_data()
    test_graceful_shutdown()
    test_rst_on_established_connection()
    test_rst_on_closed_port()
    test_invalid_first_packet()
    
    print("\n" + "="*50)
    print("Test Bench completato.")
    print("="*50)