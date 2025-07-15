# 02_train_model.py
#
# Scopo: Caricare il dataset di flussi benigni, pre-processare i dati,
#        costruire un autoencoder neurale e addestrarlo.
#        Infine, salvare il modello addestrato e lo scaler dei dati per l'uso in real-time.

import pandas as pd
import numpy as np
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense
from tensorflow.keras.callbacks import EarlyStopping
import pickle
import argparse

def build_autoencoder(input_dim):
    """
    Costruisce l'architettura del modello autoencoder.
    La struttura è simmetrica: l'encoder comprime i dati, il decoder li ricostruisce.
    """
    # ENCODER
    input_layer = Input(shape=(input_dim,))
    # Aggiungiamo più complessità per catturare meglio le relazioni non lineari
    encoder = Dense(128, activation='relu')(input_layer)
    encoder = Dense(64, activation='relu')(encoder)
    encoder = Dense(32, activation='relu')(encoder) # Bottleneck: la rappresentazione compressa

    # DECODER
    decoder = Dense(64, activation='relu')(encoder)
    decoder = Dense(128, activation='relu')(decoder)
    decoder = Dense(input_dim, activation='sigmoid')(decoder) # Sigmoid perché i dati sono normalizzati [0, 1]

    autoencoder = Model(inputs=input_layer, outputs=decoder)
    autoencoder.compile(optimizer='adam', loss='mean_squared_error')
    
    print("--- Architettura Modello ---")
    autoencoder.summary()
    
    return autoencoder

def main(input_file, model_path, scaler_path, epochs, batch_size, patience):
    """Funzione principale per caricare, pre-processare e addestrare."""
    
    print("--- Loopback Guardian: Addestramento Modello ---")
    
    # 1. Caricamento Dati
    try:
        df = pd.read_csv(input_file)
        print(f"[*] Caricato '{input_file}' con {len(df)} campioni.")
    except FileNotFoundError:
        print(f"[ERROR] File '{input_file}' non trovato. Esegui prima '01_generate_dataset.py'.")
        return
        
    # Rimuove eventuali valori NaN che potrebbero essersi creati
    df.dropna(inplace=True)
    if df.empty:
        print("[ERROR] Il dataset è vuoto dopo la pulizia. Controlla i dati di origine.")
        return

    # 2. Pre-processing e Scaling
    scaler = MinMaxScaler()
    X_train = scaler.fit_transform(df)
    
    print(f"[*] Dati normalizzati. Numero di feature: {X_train.shape[1]}")

    with open(scaler_path, 'wb') as f:
        pickle.dump(scaler, f)
    print(f"[*] Scaler salvato in '{scaler_path}'.")

    # 3. Costruzione e Addestramento del Modello
    autoencoder = build_autoencoder(X_train.shape[1])
    
    # EarlyStopping ferma l'addestramento se non ci sono miglioramenti sulla loss di validazione.
    # 'patience' definisce quante epoche attendere prima di fermarsi.
    # 'restore_best_weights=True' assicura che il modello salvato sia quello con la loss migliore.
    early_stopping = EarlyStopping(monitor='val_loss', patience=patience, restore_best_weights=True, verbose=1)

    print(f"\n[*] Inizio addestramento del modello per {epochs} epoche (batch_size={batch_size}, patience={patience})...")
    history = autoencoder.fit(
        X_train, X_train, # L'autoencoder impara a ricostruire se stesso
        epochs=epochs,
        batch_size=batch_size,
        shuffle=True,
        validation_split=0.1, # Usiamo il 10% dei dati per la validazione
        callbacks=[early_stopping],
        verbose=1
    )

    # 4. Salvataggio del Modello
    autoencoder.save(model_path)
    print(f"\n[SUCCESS] Modello addestrato e salvato in '{model_path}'.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Addestra un autoencoder su dati di flussi di rete.")
    parser.add_argument('--in_file', type=str, default="benign_flows.csv", help="File CSV di input.")
    parser.add_argument('--out_model', type=str, default="autoencoder_model.keras", help="Percorso di salvataggio del modello.")
    parser.add_argument('--out_scaler', type=str, default="data_scaler.pkl", help="Percorso di salvataggio dello scaler.")
    parser.add_argument('--epochs', type=int, default=200, help="Numero massimo di epoche per l'addestramento.")
    parser.add_argument('--batch_size', type=int, default=64, help="Dimensione del batch per l'addestramento.")
    parser.add_argument('--patience', type=int, default=20, help="Numero di epoche senza miglioramenti prima di fermare l'addestramento.")
    args = parser.parse_args()
    
    main(args.in_file, args.out_model, args.out_scaler, args.epochs, args.batch_size, args.patience)

