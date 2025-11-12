#!/usr/bin/env python3
"""
AI-Powered Network Scan Detector - Live Detection Application
==============================================================
This is the main 24/7 application that monitors network traffic in real-time
and uses the trained AI model to detect nmap scan attacks.

It runs two things simultaneously:
1. A Flask web server (dashboard at http://server_ip:5000)
2. A background packet sniffer that analyzes traffic every 5 seconds

Author: Cybersecurity Research Team
Purpose: University Project - Host-Based Intrusion Detection System
"""

import threading
import time
from datetime import datetime
from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP
import joblib
import pandas as pd

# ============================================================================
# GLOBAL VARIABLES (Thread-Safe Alert Storage)
# ============================================================================

# The trained AI model (loaded from disk)
model = None

# List of detected attacks (newest first)
alerts = []

# Thread lock to safely access 'alerts' from multiple threads
alerts_lock = threading.Lock()

# Flask application instance
app = Flask(__name__)

# ============================================================================
# FLASK WEB ROUTES
# ============================================================================

@app.route('/')
def index():
    """
    Serves the main dashboard HTML page.
    
    Returns:
        Rendered HTML template
    """
    return render_template('index.html')


@app.route('/api/alerts')
def get_alerts():
    """
    API endpoint that returns all detected alerts as JSON.
    
    This is called by the JavaScript in index.html every 3 seconds
    to update the dashboard with new alerts.
    
    Returns:
        JSON array of alert objects
    """
    with alerts_lock:
        # Return a copy of the alerts list (thread-safe)
        return jsonify(alerts[:])  # [:] creates a shallow copy

# ============================================================================
# LIVE PACKET ANALYSIS
# ============================================================================

def analyze_traffic_window():
    """
    Captures and analyzes network traffic in 5-second windows.
    
    This function:
    1. Sniffs packets for 5 seconds
    2. Extracts the same features used during training
    3. Feeds those features to the AI model
    4. If the AI predicts an attack, creates an alert
    
    Returns:
        dict: Features extracted from this traffic window
    """
    # Feature dictionary for this 5-second window
    features = {
        'unique_ports': set(),
        'syn_packets': 0,
        'fin_packets': 0,
        'xmas_packets': 0,
        'null_packets': 0,
        'total_packets': 0,
        'source_ips': set()  # Track attacker IPs
    }
    
    def packet_callback(packet):
        """
        Analyzes each packet in the current window.
        
        This is identical to the callback in train_model.py,
        but also tracks source IPs to identify attackers.
        """
        if packet.haslayer(IP) and packet.haslayer(TCP):
            features['total_packets'] += 1
            
            # Track the source IP (potential attacker)
            src_ip = packet[IP].src
            features['source_ips'].add(src_ip)
            
            # Track destination port
            dst_port = packet[TCP].dport
            features['unique_ports'].add(dst_port)
            
            # Analyze TCP flags to detect scan types
            flags = packet[TCP].flags
            
            if flags == 0x02:  # SYN Scan
                features['syn_packets'] += 1
            elif flags == 0x01:  # FIN Scan
                features['fin_packets'] += 1
            elif flags == 0x29:  # XMAS Scan
                features['xmas_packets'] += 1
            elif flags == 0x00:  # NULL Scan
                features['null_packets'] += 1
    
    # Sniff packets for 5 seconds
    # timeout=5 means sniff() will automatically stop after 5 seconds
    sniff(prn=packet_callback, store=False, timeout=5)
    
    return features


def determine_scan_type(features):
    """
    Determines the type of scan based on which feature is highest.
    
    Args:
        features: Dictionary of extracted features
        
    Returns:
        str: Human-readable scan type name
    """
    scan_counts = {
        'SYN Scan (Stealth)': features['syn_packets'],
        'FIN Scan': features['fin_packets'],
        'XMAS Scan': features['xmas_packets'],
        'NULL Scan': features['null_packets']
    }
    
    # Find the scan type with the highest count
    max_scan = max(scan_counts, key=scan_counts.get)
    
    # If all are zero, it's a generic scan
    if scan_counts[max_scan] == 0:
        return 'Unknown Scan Type'
    
    return max_scan


def live_detector():
    """
    Main background thread that continuously monitors network traffic.
    
    This function runs in an infinite loop:
    1. Analyze traffic for 5 seconds
    2. Extract features
    3. Ask the AI: "Is this an attack?"
    4. If yes, create an alert and add it to the dashboard
    
    This thread runs forever until the Flask app is shut down.
    """
    print("🔍 Background detector thread started!")
    print("   Analyzing traffic in 5-second windows...")
    print("   AI model is actively monitoring for scan attacks.\n")
    
    while True:
        try:
            # Capture and analyze a 5-second window of traffic
            features = analyze_traffic_window()
            
            # Debug: Print captured features
            if features['total_packets'] > 0:
                print(f"[DEBUG] Captured: {features['total_packets']} packets, "
                      f"{len(features['unique_ports'])} ports, "
                      f"SYN:{features['syn_packets']}, "
                      f"FIN:{features['fin_packets']}, "
                      f"XMAS:{features['xmas_packets']}, "
                      f"NULL:{features['null_packets']}")
            
            # Skip if no packets were captured
            if features['total_packets'] == 0:
                continue
            
            # Prepare features for the AI model (same format as training)
            feature_vector = {
                'unique_ports_contacted': len(features['unique_ports']),
                'syn_packets': features['syn_packets'],
                'fin_packets': features['fin_packets'],
                'xmas_packets': features['xmas_packets'],
                'null_packets': features['null_packets'],
                'total_packets': features['total_packets']
            }
            
            # Convert to DataFrame (required by scikit-learn)
            df = pd.DataFrame([feature_vector])
            
            # Ask the AI: "Is this an attack?"
            prediction = model.predict(df)[0]
            
            # Debug: Show prediction
            print(f"[DEBUG] AI Prediction: {prediction} (0=Normal, 1=Attack)")
            
            # If the AI says "YES, this is an attack!" (prediction == 1)
            if prediction == 1:
                # Determine what type of scan it is
                scan_type = determine_scan_type(features)
                
                # Get the attacker's IP (or "Multiple" if many sources)
                if len(features['source_ips']) == 1:
                    attacker_ip = list(features['source_ips'])[0]
                else:
                    attacker_ip = f"Multiple ({len(features['source_ips'])} IPs)"
                
                # Create the alert object
                alert = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'attacker_ip': attacker_ip,
                    'scan_type': scan_type,
                    'unique_ports': len(features['unique_ports']),
                    'total_packets': features['total_packets']
                }
                
                # Safely add the alert to the global list (thread-safe)
                with alerts_lock:
                    alerts.insert(0, alert)  # Insert at beginning (newest first)
                    
                    # Keep only the last 50 alerts to prevent memory issues
                    if len(alerts) > 50:
                        alerts.pop()
                
                # Log to console for debugging
                print(f"\n🚨 ALERT DETECTED!")
                print(f"   Time: {alert['timestamp']}")
                print(f"   Attacker IP: {alert['attacker_ip']}")
                print(f"   Scan Type: {alert['scan_type']}")
                print(f"   Unique Ports: {alert['unique_ports']}")
                print(f"   Total Packets: {alert['total_packets']}\n")
        
        except Exception as e:
            print(f"⚠️  Error in detector thread: {e}")
            time.sleep(1)  # Prevent rapid error loops

# ============================================================================
# APPLICATION STARTUP
# ============================================================================

def main():
    """
    Main entry point - starts both the detector and web server.
    """
    global model
    
    print("\n" + "="*70)
    print("🛡️  AI-POWERED NETWORK SCAN DETECTOR - LIVE DETECTION")
    print("="*70)
    
    # Step 1: Load the trained AI model
    print("\n[1/3] 🧠 Loading AI model...")
    try:
        model = joblib.load('nmap_detector_model.pkl')
        print("      ✅ Model loaded successfully!")
    except FileNotFoundError:
        print("\n❌ ERROR: Model file 'nmap_detector_model.pkl' not found!")
        print("   You must train the model first by running:")
        print("   sudo python3 train_model.py\n")
        return
    except Exception as e:
        print(f"\n❌ ERROR loading model: {e}\n")
        return
    
    # Step 2: Start the background detector thread
    print("\n[2/3] 🔍 Starting background detector thread...")
    detector_thread = threading.Thread(target=live_detector, daemon=True)
    detector_thread.start()
    print("      ✅ Detector thread running!")
    
    # Step 3: Start the Flask web server
    print("\n[3/3] 🌐 Starting Flask web server...")
    print("\n" + "="*70)
    print("✅ APPLICATION RUNNING!")
    print("="*70)
    print("\n📊 DASHBOARD ACCESS:")
    print("   🔗 Local: http://localhost:5000")
    print("   🔗 Network: http://<this_server_ip>:5000")
    print("\n💡 TIPS:")
    print("   - Open the dashboard in your web browser")
    print("   - Run nmap scans from your Kali Linux VM")
    print("   - Watch alerts appear in real-time!")
    print("\n⚠️  Press CTRL+C to stop the application")
    print("="*70 + "\n")
    
    # Start Flask (this blocks until CTRL+C)
    try:
        app.run(host='0.0.0.0', port=5000, debug=False)
    except KeyboardInterrupt:
        print("\n\n⚠️  Application stopped by user. Goodbye!\n")

# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()
