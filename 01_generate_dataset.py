# 01_generate_dataset.py
#
# Scopo: Catturare il traffico di rete sulla loopback, estrarre feature 
#        basate sui flussi (flow-based) e salvare il tutto in un file CSV.
#        Lo script ora aggiunge i nuovi dati a un file esistente.

import time
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import argparse
import threading
import os # <-- AGGIUNTO: Necessario per controllare l'esistenza del file

# --- Configurazione Iniziale ---

# SU WINDOWS: Trova il nome della tua interfaccia di loopback.
# Esegui `get_windows_if_list()` da una shell scapy o python per trovarla.
# Di solito contiene la parola "Loopback".
# Esempio: LOOPBACK_IFACE = r'\Device\NPF_Loopback'
LOOPBACK_IFACE = 'lo'

# Timeout in secondi. Se un flusso non vede nuovi pacchetti per questo tempo,
# viene considerato concluso e processato.
FLOW_TIMEOUT = 15.0

# Dizionario per mantenere i flussi attivi.
# La chiave è una tupla (ip_src, port_src, ip_dst, port_dst, proto)
# Il valore è una lista di tuple (pacchetto, timestamp)
active_flows = defaultdict(list)

# Lista dove verranno salvate le feature dei flussi conclusi
completed_flows_features = []

# Variabile di controllo per fermare lo sniffer
stop_sniffing = threading.Event()

def get_flow_key(packet):
    """Crea una chiave univoca per identificare un flusso di rete."""
    if IP in packet and (TCP in packet or UDP in packet):
        proto = packet[IP].proto
        return (packet[IP].src, packet.sport, packet[IP].dst, packet.dport, proto)
    return None

def calculate_flow_features(flow_packets):
    """
    Calcola le 18 feature definite per un singolo flusso.
    Input: una lista di tuple (pacchetto, timestamp).
    Output: un dizionario contenente le feature del flusso.
    """
    if not flow_packets:
        return None

    # Ordina i pacchetti per timestamp
    flow_packets.sort(key=lambda x: x[1])
    
    # Feature di base
    first_packet, start_time = flow_packets[0]
    last_packet, end_time = flow_packets[-1]
    flow_key = get_flow_key(first_packet)
    
    # Feature Temporali
    flow_duration = (end_time - start_time) * 1_000_000 # in microsecondi
    
    fwd_packets = [p for p, ts in flow_packets if get_flow_key(p) == flow_key]
    bwd_packets = [p for p, ts in flow_packets if get_flow_key(p) != flow_key]

    fwd_timestamps = [ts for p, ts in flow_packets if get_flow_key(p) == flow_key]
    bwd_timestamps = [ts for p, ts in flow_packets if get_flow_key(p) != flow_key]

    fwd_iat = np.diff(fwd_timestamps) if len(fwd_timestamps) > 1 else np.array([0])
    bwd_iat = np.diff(bwd_timestamps) if len(bwd_timestamps) > 1 else np.array([0])
    
    # Feature Volumetriche e Statistiche
    features = {
        'protocol': flow_key[4],
        'src_port': flow_key[1],
        'dst_port': flow_key[3],
        'fwd_pkt_count': len(fwd_packets),
        'bwd_pkt_count': len(bwd_packets),
        'total_pkt_count': len(flow_packets),
        'fwd_bytes_sum': sum(len(p) for p in fwd_packets),
        'bwd_bytes_sum': sum(len(p) for p in bwd_packets),
        'total_bytes_sum': sum(len(p) for p, ts in flow_packets),
        'flow_duration': flow_duration,
        'fwd_iat_mean': np.mean(fwd_iat) * 1_000_000 if len(fwd_iat) > 0 else 0,
        'fwd_iat_std': np.std(fwd_iat) * 1_000_000 if len(fwd_iat) > 0 else 0,
        'bwd_iat_mean': np.mean(bwd_iat) * 1_000_000 if len(bwd_iat) > 0 else 0,
        'bwd_iat_std': np.std(bwd_iat) * 1_000_000 if len(bwd_iat) > 0 else 0,
        'fwd_pkt_len_mean': np.mean([len(p) for p in fwd_packets]) if fwd_packets else 0,
        'bwd_pkt_len_mean': np.mean([len(p) for p in bwd_packets]) if bwd_packets else 0,
        'pkt_len_max': max(len(p) for p, ts in flow_packets) if flow_packets else 0,
        'pkt_len_min': min(len(p) for p, ts in flow_packets) if flow_packets else 0,
    }
    
    return features

def process_packet(packet):
    """Funzione callback per ogni pacchetto catturato da Scapy."""
    flow_key = get_flow_key(packet)
    if flow_key:
        active_flows[flow_key].append((packet, time.time()))

def check_timed_out_flows():
    """Controlla e processa i flussi che sono scaduti."""
    current_time = time.time()
    timed_out_keys = []
    
    for key, packets in active_flows.items():
        # L'ultimo pacchetto è l'ultimo nella lista (non serve ordinarla qui)
        if current_time - packets[-1][1] > FLOW_TIMEOUT:
            timed_out_keys.append(key)

    for key in timed_out_keys:
        print(f"[INFO] Flusso {key[1]} -> {key[2]} scaduto. Lo processo...")
        features = calculate_flow_features(active_flows[key])
        if features:
            completed_flows_features.append(features)
        del active_flows[key] # Rimuove il flusso da quelli attivi

def main(capture_duration, output_file):
    """Funzione principale per orchestrare la cattura e la creazione del dataset."""
    
    print("--- Loopback Guardian: Generatore di Dataset ---")
    print(f"[*] Inizio cattura per {capture_duration} secondi.")
    print("[*] Genera traffico 'normale' ora (es. naviga su un server web locale).")

    # Avvia lo sniffer in un thread separato
    sniffer_thread = threading.Thread(
        target=sniff,
        kwargs={'iface': LOOPBACK_IFACE, 'prn': process_packet, 'store': False, 'stop_filter': lambda p: stop_sniffing.is_set()}
    )
    sniffer_thread.start()

    end_time = time.time() + capture_duration
    while time.time() < end_time:
        check_timed_out_flows()
        time.sleep(1)
        print(f"\r[*] Tempo rimanente: {int(end_time - time.time())}s. Flussi attivi: {len(active_flows)}.", end="")

    # Ferma lo sniffer
    print("\n[*] Tempo di cattura terminato. Fermo lo sniffer...")
    stop_sniffing.set()
    sniffer_thread.join()

    # Processa i flussi rimanenti
    print("[*] Processo i flussi rimanenti...")
    for key in list(active_flows.keys()):
        features = calculate_flow_features(active_flows[key])
        if features:
            completed_flows_features.append(features)
        del active_flows[key]

    # Crea e salva il DataFrame
    if not completed_flows_features:
        print("[ERROR] Nessun flusso catturato! Assicurati di generare traffico e che l'interfaccia sia corretta.")
        return

    df = pd.DataFrame(completed_flows_features)
    
    # ---- MODIFICA PRINCIPALE ----
    # Controlla se il file esiste già. Se sì, non scriveremo l'header.
    file_exists = os.path.exists(output_file)

    # Salva in modalità 'append' (a). L'header viene scritto solo se il file non esiste.
    df.to_csv(output_file, mode='a', header=not file_exists, index=False)

    if file_exists:
        print(f"\n[SUCCESS] Aggiunti {len(df)} flussi al dataset esistente '{output_file}'.")
    else:
        print(f"\n[SUCCESS] Creato nuovo dataset '{output_file}' con {len(df)} flussi.")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Cattura traffico di loopback e crea un dataset di flussi.")
    parser.add_argument('--duration', type=int, default=120, help="Durata della cattura in secondi.")
    parser.add_argument('--out', type=str, default="benign_flows.csv", help="Nome del file CSV di output.")
    args = parser.parse_args()
    
    main(args.duration, args.out)

