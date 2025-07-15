# attack_toolkit.py
#
# Scopo: Un toolkit unificato per generare vari tipi di traffico anomalo.
#        Questo script è self-contained: avvia automaticamente i server necessari
#        per i test che lo richiedono.
# NOTA: Per eseguire correttamente il Port Scanning, lanciare questo script
#       da un terminale con privilegi di Amministratore.

import socket
import time
import random
import string
import threading
from scapy.all import sr1, IP, TCP # <-- AGGIUNTO per il SYN Scan

# --- Configurazione Comune ---
HOST = '127.0.0.1' # Loopback

# ==============================================================================
# SEZIONE SERVER
# ==============================================================================
def run_simple_server(port, data_buffer_size=1024):
    """
    Un server TCP generico che accetta una singola connessione, riceve dati,
    e poi si spegne.
    """
    print(f"[SERVER THREAD] In avvio su porta {port}...")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((HOST, port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                print(f"[SERVER THREAD] Connessione accettata da {addr}")
                received_data = b''
                while True:
                    data = conn.recv(data_buffer_size)
                    if not data:
                        break
                    received_data += data
                print(f"[SERVER THREAD] Ricevuti {len(received_data)} bytes. Chiusura.")
    except Exception as e:
        print(f"[SERVER THREAD] Errore: {e}")
    finally:
        print(f"[SERVER THREAD] Terminato.")

# ==============================================================================
# TEST 1: PORT SCANNING AGGRESSIVO (SYN Scan) - MODIFICATO
# ==============================================================================
def test_syn_scan_scapy(port_range_start, port_range_end):
    """
    Esegue uno "stealth" SYN scan usando Scapy. Invia un singolo pacchetto SYN.
    Molto più anomalo di una connessione completa e richiede privilegi di admin.
    """
    print(f"\n--- ESEGUO TEST 1: Port Scanner Aggressivo (SYN Scan) sulle porte {port_range_start}-{port_range_end} ---")
    open_ports = []
    for port in range(port_range_start, port_range_end + 1):
        # Costruisce e invia un pacchetto TCP con solo il flag SYN attivo
        # sr1 invia e riceve una sola risposta
        response = sr1(IP(dst=HOST)/TCP(sport=random.randint(1024,65535), dport=port, flags="S"), timeout=0.5, verbose=0)
        
        if response is None:
            print(f"[-] Porta {port} è filtrata (nessuna risposta).")
        # Se la porta è aperta, risponde con SYN/ACK (flag 0x12)
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"[+] Porta {port} è APERTA.")
            open_ports.append(port)
            # Invia un RST per chiudere la connessione "educatamente"
            sr1(IP(dst=HOST)/TCP(dport=port, flags="R"), timeout=0.5, verbose=0)
        # Se risponde con RST/ACK (flag 0x14), la porta è chiusa
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x14:
            print(f"[-] Porta {port} è chiusa.")
        else:
            print(f"[?] Risposta inattesa dalla porta {port}.")
            
    print("--- TEST 1: Port Scanner completato ---")
    if open_ports:
        print(f"Porte aperte trovate: {open_ports}")

# ==============================================================================
# TEST 2: ESFILTRAZIONE DATI LENTA (Attacco "Low and Slow")
# ==============================================================================
def test_slow_exfiltration(port=9999):
    print(f"\n--- ESEGUO TEST 2: Esfiltrazione Dati Lenta sulla porta {port} ---")
    
    server_thread = threading.Thread(target=run_simple_server, args=(port,))
    server_thread.start()
    time.sleep(0.5)

    secret_data = "dati_riservati_rubati_dal_malware".encode('utf-8')
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, port))
            print("[CLIENT] Connesso al server C&C. Inizio invio lento...")
            for byte in secret_data:
                s.sendall(bytes([byte]))
                print(f"[CLIENT] Inviato byte: {chr(byte)}")
                time.sleep(1.5)
        print("[CLIENT] Esfiltrazione completata.")
    except ConnectionRefusedError:
        print(f"[CLIENT ERROR] Impossibile connettersi. Il server non è partito in tempo?")
    finally:
        server_thread.join()
        print("--- TEST 2: Esfiltrazione completata ---")

# ==============================================================================
# TEST 3: DATA BOMB (Anomalia Volumetrica)
# ==============================================================================
def test_data_bomb(port=8888, size_kb=256):
    print(f"\n--- ESEGUO TEST 3: Data Bomb sulla porta {port} ({size_kb} KB) ---")

    server_thread = threading.Thread(target=run_simple_server, args=(port, 65536))
    server_thread.start()
    time.sleep(0.5)

    payload = ''.join(random.choices(string.ascii_letters + string.digits, k=size_kb * 1024)).encode('utf-8')
    print(f"[CLIENT] Payload di {len(payload)} bytes generato.")
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((HOST, port))
            print("[CLIENT] Connesso. Invio Data Bomb...")
            s.sendall(payload)
        print("[CLIENT] Data Bomb inviata.")
    except Exception as e:
        print(f"[CLIENT ERROR] Errore durante il test Data Bomb: {e}")
    finally:
        server_thread.join()
        print("--- TEST 3: Data Bomb completato ---")

# ==============================================================================
# TEST 4: UDP FLOOD (Denial of Service)
# ==============================================================================
def test_udp_flood(port=5555, num_packets=500):
    print(f"\n--- ESEGUO TEST 4: UDP Flood sulla porta {port} ---")
    message = b'flood_data_packet'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            for i in range(num_packets):
                s.sendto(message, (HOST, port))
                if (i + 1) % 100 == 0:
                    print(f"[*] Inviati {i+1}/{num_packets} pacchetti UDP...")
                time.sleep(0.01)
        print("--- TEST 4: UDP Flood completato ---")
    except Exception as e:
        print(f"[ERROR] Errore durante il test UDP Flood: {e}")

# ==============================================================================
# MENU PRINCIPALE
# ==============================================================================
if __name__ == '__main__':
    while True:
        print("\n--- Toolkit Generazione Traffico Anomalo ---")
        print("Scegli un test da eseguire:")
        print("1. Port Scanner Aggressivo (SYN Scan)")
        print("2. Esfiltrazione Dati Lenta (low and slow)")
        print("3. Data Bomb (anomalia volumetrica)")
        print("4. UDP Flood (DoS)")
        print("0. Esci")

        choice = input(">> Scelta: ")

        if choice == '1':
            test_syn_scan_scapy(port_range_start=1, port_range_end=24)
        elif choice == '2':
            test_slow_exfiltration(port=9999)
        elif choice == '3':
            test_data_bomb(port=8888, size_kb=256)
        elif choice == '4':
            test_udp_flood(port=5555, num_packets=1000)
        elif choice == '0':
            print("Uscita in corso...")
            break
        else:
            print("Scelta non valida. Riprova.")

