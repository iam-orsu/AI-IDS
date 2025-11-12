#!/usr/bin/env python3
"""
AI-Powered Network Scan Detector - Training Module
===================================================
This script captures network traffic in real-time and trains an AI model
to distinguish between normal traffic and network scan attacks (nmap).

Author: Cybersecurity Research Team
Purpose: University Project - Host-Based Intrusion Detection System
"""

import time
import threading
from datetime import datetime
from scapy.all import sniff, IP, TCP
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

# ============================================================================
# GLOBAL VARIABLES (Thread-Safe Data Collection)
# ============================================================================

# This list stores all captured traffic samples
dataset = []

# Thread synchronization primitives
data_lock = threading.Lock()  # Protects the 'features' dictionary
stop_sniffing = threading.Event()  # Signals when to stop capture

# Current capture session features
features = {
    'unique_ports': set(),
    'syn_packets': 0,
    'fin_packets': 0,
    'xmas_packets': 0,
    'null_packets': 0,
    'total_packets': 0
}

# ============================================================================
# PACKET ANALYSIS CALLBACK
# ============================================================================

def packet_callback(packet):
    """
    Analyzes each captured packet and extracts scan-detection features.
    
    This function is called by Scapy's sniff() for every packet.
    It's designed to detect various nmap scan techniques:
    - SYN Scan (Stealth Scan)
    - FIN Scan
    - XMAS Scan
    - NULL Scan
    
    Args:
        packet: A Scapy packet object
    """
    global features
    
    # Only analyze TCP/IP packets (scans use TCP)
    if packet.haslayer(IP) and packet.haslayer(TCP):
        with data_lock:  # Thread-safe access
            features['total_packets'] += 1
            
            # Track unique destination ports (scans hit many ports)
            dst_port = packet[TCP].dport
            features['unique_ports'].add(dst_port)
            
            # Extract TCP flags to identify scan types
            flags = packet[TCP].flags
            
            # SYN Scan Detection (flags = 0x02 = only SYN bit set)
            if flags == 0x02:
                features['syn_packets'] += 1
            
            # FIN Scan Detection (flags = 0x01 = only FIN bit set)
            elif flags == 0x01:
                features['fin_packets'] += 1
            
            # XMAS Scan Detection (flags = 0x29 = FIN + PSH + URG)
            elif flags == 0x29:
                features['xmas_packets'] += 1
            
            # NULL Scan Detection (flags = 0x00 = no flags set)
            elif flags == 0x00:
                features['null_packets'] += 1

# ============================================================================
# THREADED PACKET CAPTURE
# ============================================================================

def capture_traffic(duration, label):
    """
    Captures network traffic for a specified duration in a background thread.
    
    This runs in a separate thread so the main thread can handle timing
    and user interaction without blocking.
    
    Args:
        duration: How many seconds to capture traffic
        label: 0 for Normal traffic, 1 for Attack traffic
    """
    global features, dataset
    
    print(f"\n{'='*70}")
    print(f"🎯 CAPTURING {'ATTACK' if label == 1 else 'NORMAL'} TRAFFIC FOR {duration} SECONDS...")
    print(f"{'='*70}")
    
    if label == 0:
        print("📌 ACTION REQUIRED: Generate normal traffic now!")
        print("   - Browse websites from this server")
        print("   - Ping this server from another machine")
        print("   - SSH into this server")
        print("   - Access any running web services")
    else:
        print("📌 ACTION REQUIRED: Launch nmap scans from your Kali Linux VM!")
        print("   - Example: nmap -sS <this_server_ip>  (SYN scan)")
        print("   - Example: nmap -sF <this_server_ip>  (FIN scan)")
        print("   - Example: nmap -sX <this_server_ip>  (XMAS scan)")
        print("   - Example: nmap -sN <this_server_ip>  (NULL scan)")
        print("   - Example: nmap -p- <this_server_ip>  (All ports)")
    
    print(f"\n⏱️  Starting capture in 3 seconds...\n")
    time.sleep(3)
    
    # Reset features for this capture session
    features = {
        'unique_ports': set(),
        'syn_packets': 0,
        'fin_packets': 0,
        'xmas_packets': 0,
        'null_packets': 0,
        'total_packets': 0
    }
    
    stop_sniffing.clear()
    
    # Start the packet sniffer in a background thread
    sniffer_thread = threading.Thread(
        target=lambda: sniff(
            prn=packet_callback,
            store=False,
            stop_filter=lambda x: stop_sniffing.is_set()
        )
    )
    sniffer_thread.daemon = True
    sniffer_thread.start()
    
    # Main thread handles timing with a countdown
    for remaining in range(duration, 0, -1):
        print(f"⏳ Time remaining: {remaining} seconds... (Packets captured: {features['total_packets']})", end='\r')
        time.sleep(1)
    
    # Signal the sniffer to stop
    stop_sniffing.set()
    sniffer_thread.join(timeout=2)
    
    # Process the captured data
    with data_lock:
        unique_port_count = len(features['unique_ports'])
        
        # Compute per-second rates to normalize across different window durations
        dur = max(1, int(duration))
        sample = {
            'unique_ports_contacted_rate': unique_port_count / dur,
            'syn_packets_rate': features['syn_packets'] / dur,
            'fin_packets_rate': features['fin_packets'] / dur,
            'xmas_packets_rate': features['xmas_packets'] / dur,
            'null_packets_rate': features['null_packets'] / dur,
            'total_packets_rate': features['total_packets'] / dur,
            'label': label  # 0 = Normal, 1 = Attack
        }
        
        dataset.append(sample)
    
    print(f"\n\n✅ CAPTURE COMPLETE!")
    print(f"   📊 Statistics:")
    print(f"      - Total Packets: {features['total_packets']}")
    print(f"      - Unique Ports: {unique_port_count}")
    print(f"      - SYN Packets: {features['syn_packets']}")
    print(f"      - FIN Packets: {features['fin_packets']}")
    print(f"      - XMAS Packets: {features['xmas_packets']}")
    print(f"      - NULL Packets: {features['null_packets']}")
    print(f"   🏷️  Label: {'ATTACK' if label == 1 else 'NORMAL'}")
    print(f"{'='*70}\n")

# ============================================================================
# MODEL TRAINING
# ============================================================================

def train_and_save_model():
    """
    Trains a Random Forest classifier on the captured data and saves it to disk.
    
    This is the "brain surgery" - we're teaching the AI to recognize
    the difference between normal traffic and scan attacks.
    """
    if len(dataset) < 2:
        print("\n❌ ERROR: Not enough data to train! You need at least 2 samples.")
        print("   Capture some NORMAL traffic and some ATTACK traffic first.")
        return
    
    print("\n" + "="*70)
    print("🧠 TRAINING AI MODEL...")
    print("="*70)
    
    # Convert our dataset to a pandas DataFrame
    df = pd.DataFrame(dataset)
    
    print("\n📊 Dataset Preview:")
    print(df.head(10))
    print("\n📈 Label Distribution:")
    print(df['label'].value_counts())
    print(f"   - 0 (Normal): {(df['label'] == 0).sum()} samples")
    print(f"   - 1 (Attack): {(df['label'] == 1).sum()} samples")
    
    # Separate features (X) from labels (y)
    X = df.drop('label', axis=1)
    y = df['label']
    
    # Split into training and testing sets (80/20 split)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if len(df) >= 10 else None
    )
    
    print(f"\n🔬 Training Set: {len(X_train)} samples")
    print(f"🔬 Testing Set: {len(X_test)} samples")
    
    # Train a Random Forest Classifier
    # Random Forest is excellent for this because:
    # 1. It's robust and doesn't overfit easily
    # 2. It can handle non-linear patterns
    # 3. It's interpretable (we can see feature importance)
    print("\n⚙️  Training Random Forest Classifier...")
    model = RandomForestClassifier(
        n_estimators=100,  # 100 decision trees
        random_state=42,
        max_depth=10,
        min_samples_split=2
    )
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\n✅ MODEL TRAINING COMPLETE!")
    print(f"\n📊 Model Performance:")
    print(f"   🎯 Accuracy: {accuracy * 100:.2f}%")
    
    # Only show detailed report if we have both classes in test set
    if len(set(y_test)) > 1:
        print("\n📋 Detailed Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
    else:
        print("\n⚠️  Note: Test set only contains one class (dataset is small)")
        print("   The model is still valid, but capture more samples for better evaluation.")
    
    # Show feature importance (what the AI thinks is most important)
    print("\n🔍 Feature Importance (What the AI learned):")
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    print(feature_importance.to_string(index=False))
    
    # Save the trained model to disk
    model_filename = 'nmap_detector_model.pkl'
    joblib.dump(model, model_filename)
    
    print(f"\n💾 MODEL SAVED: {model_filename}")
    print(f"   This file contains the 'brain' of your IDS.")
    print(f"   You can now run 'app.py' to start live detection!")
    print("="*70 + "\n")

# ============================================================================
# INTERACTIVE CLI
# ============================================================================

def main():
    """
    Main interactive command-line interface for the training tool.
    """
    print("\n" + "="*70)
    print("🛡️  AI-POWERED NETWORK SCAN DETECTOR - TRAINING MODULE")
    print("="*70)
    print("\n📚 WELCOME TO THE AI TRAINING TOOL!")
    print("\nThis tool will help you create the 'brain' of your IDS.")
    print("You'll capture real network traffic and teach the AI to spot attacks.")
    print("\n🎓 HOW IT WORKS:")
    print("   1. Capture NORMAL traffic (browsing, SSH, etc.)")
    print("   2. Capture ATTACK traffic (nmap scans from Kali Linux)")
    print("   3. Train the AI model to learn the difference")
    print("   4. Save the model and use it in the live detector (app.py)")
    print("\n⚠️  IMPORTANT: You must run this script with sudo!")
    print("   Example: sudo python3 train_model.py")
    print("\n" + "="*70)
    
    while True:
        print("\n📋 MENU:")
        print("   [n] Capture NORMAL traffic (30 seconds)")
        print("   [a] Capture ATTACK traffic (60 seconds)")
        print("   [q] Quit & Train the model")
        print(f"\n   Current dataset size: {len(dataset)} samples")
        
        choice = input("\n👉 Your choice: ").strip().lower()
        
        if choice == 'n':
            capture_traffic(duration=30, label=0)
        
        elif choice == 'a':
            capture_traffic(duration=60, label=1)
        
        elif choice == 'q':
            if len(dataset) == 0:
                print("\n⚠️  You haven't captured any data yet!")
                continue
            
            print("\n🏁 Proceeding to model training...")
            train_and_save_model()
            print("\n👋 Thank you for training the AI! Goodbye.\n")
            break
        
        else:
            print("\n❌ Invalid choice. Please enter 'n', 'a', or 'q'.")

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Training interrupted by user. Exiting...")
        print("   Your captured data has NOT been saved.\n")
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        print("   Please report this error to your instructor.\n")
