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
from flask import Flask, render_template, jsonify, request, Response
from scapy.all import sniff, IP, TCP, Raw
from collections import Counter
import joblib
import pandas as pd

# ============================================================================
# GLOBAL VARIABLES (Thread-Safe Alert Storage)
# ============================================================================

# The trained AI model (loaded from disk)
model = None
model_threshold = 0.80
model_feature_names = None

# List of detected attacks (newest first)
alerts = []
# Track recent alerts for deduplication: key -> last_timestamp
recent_alerts = {}

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


@app.route('/api/alerts/clear', methods=['POST'])
def clear_alerts():
    """Clears all alerts server-side so UI and server state match."""
    with alerts_lock:
        alerts.clear()
    return jsonify({"status": "cleared"})


@app.route('/api/alerts/export', methods=['GET'])
def export_alerts_csv():
    """Exports alerts as CSV for download."""
    import csv
    import io
    with alerts_lock:
        rows = alerts[:]
    if not rows:
        return Response("attacker_ip,total_packets,scan_type\n", mimetype='text/csv')
    # Build CSV in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["attacker_ip", "total_packets", "scan_type"])
    for r in rows:
        writer.writerow([r.get('attacker_ip',''), r.get('total_packets',0), r.get('scan_type','')])
    csv_data = output.getvalue()
    output.close()
    return Response(csv_data, mimetype='text/csv', headers={
        'Content-Disposition': 'attachment; filename=alerts_export.csv'
    })

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
        'source_ips': set(),  # Track attacker IPs (set)
        'source_ip_counts': Counter(),  # Count hits per source
        'http_nmap_probe': False,  # Detect Nmap HTTP-based probes (e.g., -A/-sV)
        'tcp_option_signatures': set(),  # Heuristic for OS fingerprinting (-O)
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
            
            # Track unique destination ports (scans hit many ports)
            dst_port = packet[TCP].dport
            features['unique_ports'].add(dst_port)

            # Extract TCP flags to identify scan types
            flags = packet[TCP].flags
            
            if flags == 0x02:  # SYN Scan
                features['syn_packets'] += 1
            elif flags == 0x01:  # FIN Scan
                features['fin_packets'] += 1
            elif flags == 0x29:  # XMAS Scan
                features['xmas_packets'] += 1
            elif flags == 0x00:  # NULL Scan
                features['null_packets'] += 1

            # Track TCP option signature (heuristic for -O OS detection)
            try:
                opts = tuple(packet[TCP].options)
                features['tcp_option_signatures'].add(opts)
            except Exception:
                pass

            # Count source IP
            try:
                src_ip = packet[IP].src
                features['source_ips'].add(src_ip)
                features['source_ip_counts'][src_ip] += 1
            except Exception:
                pass

            # Inspect payload for Nmap signatures (heuristic for -A/-sV HTTP probes)
            if packet.haslayer(Raw):
                payload = bytes(packet[Raw].load).lower()
                if b"nmap" in payload or b"nmaplowercheck" in payload or b"nmap scripting engine" in payload:
                    features['http_nmap_probe'] = True
    
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
                      f"NULL:{features['null_packets']}, "
                      f"HTTP_NMAP:{features['http_nmap_probe']}, "
                      f"TCP_OPT_SIGS:{len(features['tcp_option_signatures'])}")
            
            # Skip if no packets were captured
            if features['total_packets'] == 0:
                continue
            
            # Prepare per-second rate features (must match training)
            window_seconds = 5
            feature_vector = {
                'unique_ports_contacted_rate': len(features['unique_ports']) / window_seconds,
                'syn_packets_rate': features['syn_packets'] / window_seconds,
                'fin_packets_rate': features['fin_packets'] / window_seconds,
                'xmas_packets_rate': features['xmas_packets'] / window_seconds,
                'null_packets_rate': features['null_packets'] / window_seconds,
                'total_packets_rate': features['total_packets'] / window_seconds,
                'tcp_option_sig_count_rate': len(features['tcp_option_signatures']) / window_seconds,
                'http_nmap_probe_flag': 1 if features['http_nmap_probe'] else 0,
            }
            
            # Convert to DataFrame (required by scikit-learn)
            df = pd.DataFrame([feature_vector])
            # Align columns to model's expectation if available
            if model_feature_names:
                missing = [c for c in model_feature_names if c not in df.columns]
                for c in missing:
                    df[c] = 0
                df = df[model_feature_names]
            
            # Ask the AI: "Is this an attack?" with confidence threshold
            proba = None
            try:
                proba = float(model.predict_proba(df)[0][1])
            except Exception:
                pass
            prediction = model.predict(df)[0]
            
            # Debug: Show prediction
            if proba is not None:
                print(f"[DEBUG] AI Prediction: {prediction} proba={proba:.2f} (0=Normal, 1=Attack)")
            else:
                print(f"[DEBUG] AI Prediction: {prediction} (0=Normal, 1=Attack)")

            # Heuristic rules for OS/Version/Aggressive probes that may be light-weight per 5s window
            opt_sig_count = len(features['tcp_option_signatures'])
            http_probe = features['http_nmap_probe']
            # OS fingerprinting should show unusually high TCP option diversity plus activity
            os_probe_heuristic = (
                opt_sig_count >= 40 and (
                    len(features['unique_ports']) >= 15 or
                    features['syn_packets'] >= 20 or
                    features['total_packets'] >= 300
                )
            )
            # Version/Aggressive probe should include known payloads and non-trivial traffic
            version_probe_heuristic = bool(http_probe and features['total_packets'] >= 50)

            # Rule-based triggers to guarantee alerts for common scans
            syn_rate = features['syn_packets'] / window_seconds
            fin_present = features['fin_packets'] > 0
            xmas_present = features['xmas_packets'] > 0
            null_present = features['null_packets'] > 0
            unique_ports = len(features['unique_ports'])
            total_pkts = features['total_packets']
            suspicious_flags = (
                features['syn_packets'] + features['fin_packets'] +
                features['xmas_packets'] + features['null_packets']
            )
            suspicious_ratio = suspicious_flags / max(1, total_pkts)

            # Port sweep should show broad port coverage and/or high SYN rate
            port_sweep = (
                unique_ports >= 80 or
                (syn_rate >= 12 and unique_ports >= 15) or
                (total_pkts >= 600 and unique_ports >= 30)
            )

            rule_scan_type = None
            if xmas_present:
                rule_scan_type = 'XMAS Scan'
            elif null_present:
                rule_scan_type = 'NULL Scan'
            elif fin_present:
                rule_scan_type = 'FIN Scan'
            elif port_sweep:
                rule_scan_type = 'SYN Scan (Stealth)' if syn_rate >= 10 else 'Port Sweep'

            threshold = model_threshold if model_feature_names else 0.80
            ml_alert = (proba is not None and proba >= threshold) or (proba is None and prediction == 1)
            # Only allow rule-based alert when enough evidence exists (flag ratio or explicit FIN/XMAS/NULL)
            rule_evidence = (
                xmas_present or null_present or fin_present or (port_sweep and suspicious_ratio >= 0.05)
            )
            should_alert = bool(ml_alert or os_probe_heuristic or version_probe_heuristic or (rule_scan_type is not None and rule_evidence))

            if should_alert:
                # Determine what type of scan it is
                scan_type = rule_scan_type or determine_scan_type(features)

                # Enrich with capabilities
                capabilities = []
                if http_probe:
                    capabilities.append('Version/Script Probe (-sV/-A HTTP)')
                if os_probe_heuristic:
                    capabilities.append('OS Fingerprinting Heuristics (-O)')
                if prediction == 1:
                    capabilities.append('ML classification: Attack')
                else:
                    capabilities.append('Heuristic classification: Probe detected')
                if rule_scan_type:
                    capabilities.append(f'Rule trigger: {rule_scan_type}')
                if port_sweep and not rule_scan_type:
                    capabilities.append('Rule trigger: Port Sweep')
                
                # Get the attacker's IP (or "Multiple" if many sources)
                # Choose primary attacker (most packets)
                if features['source_ip_counts']:
                    attacker_ip = features['source_ip_counts'].most_common(1)[0][0]
                elif len(features['source_ips']) == 1:
                    attacker_ip = list(features['source_ips'])[0]
                else:
                    attacker_ip = f"Multiple ({len(features['source_ips'])} IPs)"
                
                # Create the alert object
                alert = {
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'attacker_ip': attacker_ip,
                    'scan_type': scan_type,
                    'unique_ports': len(features['unique_ports']),
                    'total_packets': features['total_packets'],
                    'details': "; ".join(capabilities) if capabilities else ''
                }
                # Deduplicate: do not add the same (attacker, scan_type) again within 15s
                dedup_key = (attacker_ip, scan_type)
                now_ts = time.time()
                last_ts = recent_alerts.get(dedup_key, 0)
                if now_ts - last_ts < 15:
                    # skip duplicate
                    continue
                recent_alerts[dedup_key] = now_ts

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
    print("[1/3] 🧠 Loading AI model...")
    try:
        loaded = joblib.load('nmap_detector_model.pkl')
        if isinstance(loaded, dict) and 'model' in loaded:
            model = loaded['model']
            model_threshold = float(loaded.get('threshold', model_threshold))
            model_feature_names = loaded.get('features')
        else:
            model = loaded
        print("      ✅ Model loaded successfully!")
        if model_feature_names:
            print(f"      ▶ Using calibrated threshold: {model_threshold:.2f}")
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
