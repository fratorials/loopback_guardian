# Loopback Guardian: Rilevamento delle Intrusioni su Localhost tramite IA

![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-orange)
![Scapy](https://img.shields.io/badge/scapy-2.4-yellow)
![Pandas](https://img.shields.io/badge/pandas-1.x-brightgreen)
![Scikit-learn](https://img.shields.io/badge/scikit--learn-1.x-blueviolet)

**Loopback Guardian** è un sistema di rilevamento delle intrusioni (IDS) specializzato che utilizza una rete neurale di tipo autoencoder per monitorare il traffico di rete interno del tuo computer (sull'interfaccia di loopback `127.0.0.1`) e individuare attività anomale in tempo reale.

[cite_start]Questo progetto è stato sviluppato come tesina finale per il corso **IFTS Security Specialist** (Cod. Progetto FSE 315132)[cite: 2, 4].

## Il Problema: L'Autostrada Interna Non Sorvegliata

[cite_start]La maggior parte degli strumenti di sicurezza di rete si concentra sul traffico in entrata e in uscita da Internet[cite: 58]. [cite_start]Tuttavia, un'intensa attività di comunicazione avviene *all'interno* di ogni macchina tra processi diversi, attraverso l'interfaccia di loopback (`localhost`)[cite: 59, 60].

Un malware che ha già ottenuto un punto d'appoggio su un sistema può sfruttare questo canale interno per:
* [cite_start]Eseguire ricognizioni interne (come una scansione delle porte per trovare altri servizi vulnerabili)[cite: 61].
* [cite_start]Muoversi lateralmente all'interno del sistema[cite: 61].
* [cite_start]Preparare e organizzare i dati per un'esfiltrazione[cite: 61].

Tutto ciò avviene in modo invisibile ai tradizionali firewall di rete. [cite_start]"Loopback Guardian" è stato creato per colmare questa lacuna critica di visibilità[cite: 62, 64].

## Come Funziona: Analisi Comportamentale con un Autoencoder

[cite_start]Invece di basarsi su firme di minacce note (un approccio inefficace contro attacchi nuovi o "Zero-Day" [cite: 49][cite_start]), questo sistema adotta un approccio comportamentale[cite: 51, 52].

1.  [cite_start]**Impara la "Normalità"**: Il sistema viene addestrato esclusivamente su traffico benigno, catturato durante il normale utilizzo del computer (navigazione web, sviluppo, interazione con database, ecc.)[cite: 66, 83, 101].
2.  **Crea un Profilo Comportamentale**: Utilizzando `Scapy`, cattura i pacchetti di rete e li raggruppa in flussi. [cite_start]Per ogni flusso, estrae un "profilo" composto da 18 caratteristiche statistiche e temporali (come durata, numero di pacchetti, tempi di inter-arrivo, ecc.)[cite: 91, 92].
3.  [cite_start]**L'Autoencoder**: Una rete neurale chiamata **autoencoder** viene addestrata a comprimere e poi ricostruire questi profili "normali"[cite: 116, 117]. [cite_start]Diventa estremamente efficiente in questo compito, ma solo per i dati normali che ha già visto[cite: 122].
4.  [cite_start]**Rilevamento dell'Anomalia**: Quando si verifica un'attività malevola, come una scansione delle porte, il suo profilo comportamentale è radicalmente diverso da quello del traffico normale[cite: 213, 214]. [cite_start]L'autoencoder non riesce a ricostruire fedelmente questo nuovo profilo, generando un elevato "errore di ricostruzione"[cite: 123]. [cite_start]Questo errore, superata una certa soglia, fa scattare un allarme di anomalia[cite: 79, 113].

## Caratteristiche Principali

* [cite_start]**Monitoraggio in Tempo Reale**: Utilizza `Scapy` per catturare i pacchetti dall'interfaccia di loopback in tempo reale[cite: 107].
* [cite_start]**Rilevamento basato su IA**: Impiega un autoencoder sviluppato con TensorFlow/Keras per apprendere il comportamento normale e rilevare le deviazioni[cite: 65].
* [cite_start]**Feature Engineering Intelligente**: Trasforma i pacchetti grezzi in 18 feature significative che creano un'impronta comportamentale per ogni flusso di rete[cite: 77, 92].
* [cite_start]**Efficacia Comprovata**: Testato con successo contro attacchi simulati come scansioni di porte interne (`nmap`) e tecniche di esfiltrazione lenta dei dati[cite: 233, 234].
* [cite_start]**Consapevolezza Normativa**: Il progetto analizza le implicazioni di normative come il **GDPR** (Art. 32) e la **Direttiva NIS2**, proponendosi come una misura tecnica fondamentale per il rilevamento degli incidenti e la sicurezza dei sistemi[cite: 239, 240, 246, 248].

## Stack Tecnologico

* **Python**: Il linguaggio principale per tutti gli script.
* [cite_start]**Scapy**: Per la cattura e la manipolazione dei pacchetti[cite: 83].
* [cite_start]**Pandas**: Per la gestione dei dati e la creazione del dataset di feature[cite: 297].
* [cite_start]**Scikit-learn**: Utilizzato per la normalizzazione dei dati (`MinMaxScaler`)[cite: 297].
* [cite_start]**TensorFlow/Keras**: Per la costruzione e l'addestramento della rete neurale autoencoder[cite: 307].

## Struttura del Progetto

La repository contiene gli script Python fondamentali per eseguire l'intera pipeline:

* [cite_start]`01_generate_dataset.py`: Cattura il traffico di loopback per una durata specificata e lo elabora in un file `benign_flows.csv`, che fungerà da dataset di addestramento[cite: 40].
* [cite_start]`02_train_model.py`: Carica `benign_flows.csv`, normalizza i dati, costruisce l'autoencoder, lo addestra e salva il modello addestrato (`autoencoder_model.keras`) e lo scaler dei dati (`data_scaler.pkl`)[cite: 41].
* [cite_start]`03_calculate_threshold.py`: Analizza gli errori di ricostruzione sul dataset benigno per determinare statisticamente una soglia di anomalia ottimale[cite: 42].
* `04_realtime_detector.py`: L'applicazione finale. [cite_start]Carica il modello e lo scaler addestrati, cattura il traffico di loopback in tempo reale e segnala qualsiasi flusso il cui errore di ricostruzione superi la soglia calcolata[cite: 43].

## Installazione e Utilizzo

1.  **Clona la repository:**
    ```bash
    git clone [https://github.com/fratorials/loopback_guardian.git](https://github.com/fratorials/loopback_guardian.git)
    cd loopback_guardian
    ```

2.  **Installa le dipendenze:**
    È fortemente consigliato utilizzare un ambiente virtuale.
    ```bash
    # Crea un file requirements.txt con le seguenti librerie:
    # pandas, numpy, scapy, tensorflow, scikit-learn
    pip install -r requirements.txt
    ```

3.  **Passo 1: Genera il Dataset di Addestramento**
    Avvia le tue applicazioni tipiche (browser, database, IDE, ecc.). Quindi, esegui lo script di generazione dati. Potrebbero essere necessari i privilegi di root/amministratore per catturare il traffico di rete.
    ```bash
    sudo python 01_generate_dataset.py --duration 600
    ```
    Questo comando catturerà il traffico per 600 secondi e creerà il file `benign_flows.csv`.

4.  **Passo 2: Addestra il Modello**
    Ora, addestra l'autoencoder sul dataset appena creato.
    ```bash
    python 02_train_model.py --in_file benign_flows.csv --epochs 1500 --patience 20
    ```
    [cite_start]Questo genererà i file `autoencoder_model.keras` e `data_scaler.pkl`[cite: 294].

5.  **Passo 3: Calcola la Soglia di Anomalia**
    Determina la soglia per considerare un'attività come anomala.
    ```bash
    python 03_calculate_threshold.py
    ```
    Lo script stamperà la soglia raccomandata. Copia questo valore.

6.  **Passo 4: Avvia il Rilevatore in Tempo Reale**
    Lancia il rilevatore con la soglia calcolata. Anche in questo caso, sono necessari i privilegi per lo sniffing.
    ```bash
    sudo python 04_realtime_detector.py --threshold 0.000123
    ```
    (Sostituisci `0.000123` con la soglia effettiva ottenuta al passo precedente). Il sistema sta ora monitorando il tuo traffico di loopback!

## Sviluppi Futuri

Questo prototipo ha diversi margini di miglioramento per il futuro:
* [cite_start]**Ri-addestramento Periodico**: Implementare un meccanismo di apprendimento online o di ri-addestramento periodico per adattarsi ai cambiamenti del comportamento "normale" del sistema[cite: 278].
* [cite_start]**Ottimizzazione delle Performance**: Per ambienti di produzione, la parte di estrazione delle feature potrebbe essere riscritta in un linguaggio compilato come C++ o Rust per migliorare le prestazioni[cite: 280].
* [cite_start]**Risposta Attiva (IPS)**: Estendere il sistema da IDS (rilevamento) a IPS (prevenzione), ad esempio integrandolo con il firewall del sistema operativo per bloccare attivamente i flussi anomali[cite: 283].
* [cite_start]**Modelli più Complessi**: Esplorare architetture di rete più complesse come le **LSTM (Long Short-Term Memory)** per catturare meglio le dipendenze sequenziali e temporali nel traffico di rete[cite: 281].

---

Questo progetto è una dimostrazione pratica di come applicare il machine learning a un problema concreto di cybersecurity, unendo concetti di networking, statistica e intelligenza artificiale per creare uno strumento di difesa intelligente e proattivo.
