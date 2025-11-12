# 🛡️ AI-Powered Network Scan Detector (H-IDS)

## 📚 Project Overview

This is a complete, production-ready **Host-Based Intrusion Detection System (H-IDS)** that uses **Machine Learning** to detect network scan attacks (nmap) in real-time. Built for university cybersecurity projects, it demonstrates practical AI applications in network security.

### 🎯 What This System Does

- **Monitors** network traffic 24/7 on your Ubuntu server
- **Detects** various nmap scan techniques (SYN, FIN, XMAS, NULL scans)
- **Alerts** you in real-time through a beautiful web dashboard
- **Uses AI** (Random Forest) to distinguish attacks from normal traffic

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    YOUR VIRTUAL LAB                          │
│                                                              │
│  ┌──────────────────┐              ┌──────────────────┐    │
│  │   Kali Linux     │              │  Ubuntu Server   │    │
│  │   (Attacker)     │─────nmap────▶│   (Victim)       │    │
│  │                  │   scans      │                  │    │
│  │  - nmap tool     │              │  - app.py        │    │
│  └──────────────────┘              │  - AI Model      │    │
│                                     │  - Flask Web     │    │
│                                     └──────────────────┘    │
│                                              │              │
│                                              ▼              │
│                                     ┌──────────────────┐    │
│                                     │  Your Browser    │    │
│                                     │  Dashboard       │    │
│                                     └──────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
AI-IDS/
│
├── train_model.py          # Step 1: Train the AI model
├── app.py                  # Step 2: Run the live detector
├── templates/
│   └── index.html          # Web dashboard UI
├── nmap_detector_model.pkl # Generated after training
└── README.md               # This file
```

---

## 🚀 Complete Setup Guide

### **Prerequisites**

#### 1. Virtual Machines Setup

You need **TWO** virtual machines:

**VM 1: Ubuntu Server (The Victim)**
- OS: Ubuntu Server 20.04 or later
- RAM: 2GB minimum
- Network: Bridged or NAT (must be able to communicate with Kali)

**VM 2: Kali Linux (The Attacker)**
- OS: Kali Linux (latest)
- RAM: 2GB minimum
- Network: Same network as Ubuntu
- Tools: nmap (pre-installed)

#### 2. Network Configuration

Both VMs must be on the same network and able to ping each other.

**Test connectivity:**
```bash
# On Ubuntu, find your IP
ip addr show

# On Kali, ping the Ubuntu IP
ping <ubuntu_ip>
```

---

## 📥 Installation Steps

### **PART A: Ubuntu Server Setup**

#### Step 1: Connect to Your Ubuntu Server

```bash
# If using SSH from your host machine
ssh your_username@<ubuntu_ip>

# Or use the VM console directly
```

#### Step 2: Update System

```bash
sudo apt update && sudo apt upgrade -y
```

#### Step 3: Install Python and Dependencies

```bash
# Install Python 3 and pip
sudo apt install python3 python3-pip -y

# Install required Python libraries
sudo pip3 install scapy flask pandas scikit-learn joblib --break-system-packages
sudo pip3 install --upgrade --ignore-installed blinker flask pandas scikit-learn scipy --break-system-packages


# Install tcpdump (required by Scapy)
sudo apt install tcpdump -y
```

#### Step 4: Download the Project Files

**Option A: If you have the files on your host machine**
```bash
# Use SCP to transfer files
scp -r /path/to/AI-IDS your_username@<ubuntu_ip>:~/
```

**Option B: Create files manually**
```bash
# Create project directory
mkdir -p ~/AI-IDS/templates
cd ~/AI-IDS

# Create the files using nano or vim
nano train_model.py
# (Paste the train_model.py code, then Ctrl+X, Y, Enter)

nano app.py
# (Paste the app.py code, then Ctrl+X, Y, Enter)

nano templates/index.html
# (Paste the index.html code, then Ctrl+X, Y, Enter)
```

#### Step 5: Make Scripts Executable

```bash
cd ~/AI-IDS
chmod +x train_model.py app.py
```

---

## 🎓 Training the AI Model

### **Step 1: Start the Training Script**

```bash
cd ~/AI-IDS
sudo python3 train_model.py
```

You'll see:
```
==================================================================
🛡️  AI-POWERED NETWORK SCAN DETECTOR - TRAINING MODULE
==================================================================

📚 WELCOME TO THE AI TRAINING TOOL!
...
```

### **Step 2: Capture NORMAL Traffic**

1. Press **`n`** in the training script
2. The script will capture for **30 seconds**
3. **During these 30 seconds**, generate normal traffic:

```bash
# Open a NEW terminal on Ubuntu or from your host machine
# Do normal activities:

# Browse a website
curl https://www.google.com

# Ping another server
ping 8.8.8.8 -c 10

# SSH to localhost
ssh localhost

# Check for updates
sudo apt update
```

#### Normal traffic recipes (one window = one command)

- Run each of the following in a separate 30-second NORMAL window. If a command finishes early, let the window idle or keep the same command pattern with the built-in sleeps.

```bash
# Window 1
sudo apt update; sleep 5

# Window 2
for i in {1..5}; do curl -I https://google.com >/dev/null; sleep 5; done

# Window 3
for i in {1..10}; do curl -s http://127.0.0.1:5000/ >/dev/null; sleep 2; done

# Window 4
ping -c 10 netflix.com; sleep 20

# Window 5
for i in {1..3}; do wget -qO- https://httpbin.org/get >/dev/null; sleep 8; done
```

4. Wait for the capture to complete

### **Step 3: Capture ATTACK Traffic**

1. Press **`a`** in the training script
2. The script will capture for **60 seconds**
3. **IMMEDIATELY switch to your Kali Linux VM**

**On Kali Linux, run these nmap scans:**

```bash
# Replace <ubuntu_ip> with your Ubuntu server's IP address

# SYN Scan (Stealth Scan)
sudo nmap -sS <ubuntu_ip>

# FIN Scan
sudo nmap -sF <ubuntu_ip>

# XMAS Scan
sudo nmap -sX <ubuntu_ip>

# NULL Scan
sudo nmap -sN <ubuntu_ip>

# Full port scan
sudo nmap -p- <ubuntu_ip>

# Aggressive scan
sudo nmap -A <ubuntu_ip>
```

#### Attack traffic recipes (one window = one scan family)

- Use separate 60-second ATTACK windows. Start the first command a second after pressing `a` so it lands inside the window. Keep small sleeps between commands in the same family.

```bash
# Window A: SYN sweep
sudo nmap -sS -p- <ubuntu_ip>
sleep 10
sudo nmap -sS <ubuntu_ip>

# Window B: FIN/NULL/XMAS
sudo nmap -sF <ubuntu_ip>
sleep 10
sudo nmap -sN <ubuntu_ip>
sleep 10
sudo nmap -sX <ubuntu_ip>

# Window C: Version/Aggressive
sudo nmap -sV <ubuntu_ip>
sleep 10
sudo nmap -A <ubuntu_ip>

# Window D: OS detection (treat host as up)
sudo nmap -O -Pn <ubuntu_ip>
sleep 15
sudo nmap -O -Pn <ubuntu_ip>
```

4. Let all scans complete during the 60-second window

### **Step 4: Repeat for Better Accuracy**

For best results:
- Capture **2-3 NORMAL** traffic samples (press `n` multiple times)
- Capture **3-5 ATTACK** traffic samples (press `a` multiple times)

### **Step 5: Train the Model**

1. Press **`q`** to quit and train
2. The AI will train and show you:
   - Dataset preview
   - Model accuracy (aim for >90%)
   - Feature importance
3. The model will be saved as **`nmap_detector_model.pkl`**

**Expected Output:**
```
✅ MODEL TRAINING COMPLETE!

📊 Model Performance:
   🎯 Accuracy: 95.00%

💾 MODEL SAVED: nmap_detector_model.pkl
```

---

## 🚀 Running the Live Detector

### **Step 1: Start the Application**

```bash
cd ~/AI-IDS
sudo python3 app.py
```

You'll see:
```
==================================================================
🛡️  AI-POWERED NETWORK SCAN DETECTOR - LIVE DETECTION
==================================================================

[1/3] 🧠 Loading AI model...
      ✅ Model loaded successfully!

[2/3] 🔍 Starting background detector thread...
      ✅ Detector thread running!

[3/3] 🌐 Starting Flask web server...

==================================================================
✅ APPLICATION RUNNING!
==================================================================

📊 DASHBOARD ACCESS:
   🔗 Local: http://localhost:5000
   🔗 Network: http://<ubuntu_ip>:5000
```

### **Step 2: Open the Dashboard**

**From your host machine (Windows/Mac):**

1. Open your web browser
2. Navigate to: `http://<ubuntu_ip>:5000`
   - Replace `<ubuntu_ip>` with your Ubuntu server's IP
   - Example: `http://192.168.1.100:5000`

You'll see the beautiful dashboard with:
- Live monitoring status
- Statistics cards
- Alert feed (empty initially)

---

## 🧪 Testing the System

### **Test 1: Launch a Real Attack**

**On your Kali Linux VM:**

```bash
# Run a SYN scan
sudo nmap -sS <ubuntu_ip>
```

**Watch the Dashboard:**
- Within **5-10 seconds**, an alert should appear
- The alert will show:
  - Timestamp
  - Attacker IP (your Kali IP)
  - Scan type (SYN Scan)
  - Ports scanned
  - Total packets

### **Test 2: Multiple Scan Types**

```bash
# On Kali, run different scans
sudo nmap -sF <ubuntu_ip>  # FIN scan
sudo nmap -sX <ubuntu_ip>  # XMAS scan
sudo nmap -sN <ubuntu_ip>  # NULL scan
```

Each should generate a separate alert with the correct scan type!

### **Test 3: Normal Traffic (Should NOT Alert)**

```bash
# On your host machine or another VM
ping <ubuntu_ip>
curl http://<ubuntu_ip>:5000
```

These should **NOT** trigger alerts (if they do, retrain with more normal traffic samples).

---

## 📊 Understanding the Dashboard

### **Statistics Cards**

1. **Total Alerts**: Count of all detected attacks
2. **Monitoring Since**: How long the system has been running
3. **AI Model**: Status of the AI (always "Active")

### **Alert Cards**

Each alert shows:
- **Timestamp**: When the attack was detected
- **Attacker IP**: Source of the scan
- **Scan Type**: Type of nmap scan detected
- **Ports Scanned**: Number of unique ports targeted
- **Total Packets**: Volume of scan traffic

### **Color Coding**

- 🔴 **Red Border**: SYN Scan (most common)
- 🟠 **Orange Border**: FIN Scan
- 🟡 **Yellow Border**: XMAS Scan
- 🟣 **Purple Border**: NULL Scan

---

## 🔧 Troubleshooting

### **Problem: "Model file not found"**

**Solution:**
```bash
# Make sure you trained the model first
cd ~/AI-IDS
sudo python3 train_model.py
# Complete the training process
```

### **Problem: "Permission denied" errors**

**Solution:**
```bash
# Always run with sudo (required for packet sniffing)
sudo python3 app.py
```

### **Problem: Can't access dashboard from browser**

**Solution:**
```bash
# Check Ubuntu firewall
sudo ufw status

# If firewall is active, allow port 5000
sudo ufw allow 5000/tcp

# Or disable firewall temporarily (for testing only)
sudo ufw disable
```

### **Problem: No alerts appearing**

**Checklist:**
1. ✅ Is `app.py` running with sudo?
2. ✅ Can you ping Ubuntu from Kali?
3. ✅ Are you running nmap scans from Kali?
4. ✅ Did you train the model with attack samples?
5. ✅ Is the dashboard auto-refreshing? (Check browser console)

**Debug:**
```bash
# Check if app.py is capturing packets
# You should see console output when scans happen
```

### **Problem: Low model accuracy (<80%)**

**Solution:**
```bash
# Retrain with MORE samples
sudo python3 train_model.py

# Capture at least:
# - 3 NORMAL traffic samples
# - 5 ATTACK traffic samples (with varied nmap scans)
```

---

## 🎯 How It Works (Technical Deep Dive)

### **1. Feature Extraction**

The AI learns from these features:
- **unique_ports_contacted**: Scans hit many ports (normal traffic hits 1-2)
- **syn_packets**: SYN-only packets (stealth scan indicator)
- **fin_packets**: FIN-only packets (FIN scan indicator)
- **xmas_packets**: FIN+PSH+URG packets (XMAS scan indicator)
- **null_packets**: No-flag packets (NULL scan indicator)
- **total_packets**: Volume of traffic

### **2. Machine Learning Model**

- **Algorithm**: Random Forest Classifier
- **Trees**: 100 decision trees
- **Training**: Supervised learning (labeled data)
- **Input**: 6 features per 5-second window
- **Output**: Binary classification (0=Normal, 1=Attack)

### **3. Real-Time Detection**

```
Every 5 seconds:
1. Capture packets with Scapy
2. Extract features
3. Feed to AI model
4. If prediction = 1 (Attack):
   - Create alert
   - Add to dashboard
   - Log to console
```

---

## 📚 Scan Types Explained

### **SYN Scan (Stealth Scan)**
```bash
nmap -sS <target>
```
- Most common scan
- Sends SYN packets without completing TCP handshake
- Hard to detect without AI

### **FIN Scan**
```bash
nmap -sF <target>
```
- Sends FIN packets to closed ports
- Bypasses some firewalls

### **XMAS Scan**
```bash
nmap -sX <target>
```
- Sets FIN, PSH, and URG flags
- Named because flags "light up like a Christmas tree"

### **NULL Scan**
```bash
nmap -sN <target>
```
- Sends packets with NO flags set
- Stealthy but detectable by AI

---

## 🎓 University Project Tips

### **For Your Report**

1. **Introduction**: Explain the threat of network scanning
2. **Methodology**: Describe the ML approach (Random Forest)
3. **Implementation**: Show the architecture diagram
4. **Results**: Include screenshots of:
   - Training output (accuracy scores)
   - Dashboard with live alerts
   - Kali running nmap scans
5. **Conclusion**: Discuss effectiveness and limitations

### **Demo Preparation**

1. **Pre-demo**: Train the model beforehand
2. **During demo**:
   - Show the dashboard (projected)
   - Run nmap from Kali
   - Watch alerts appear in real-time
3. **Explain**: Walk through the code and AI logic

### **Bonus Points**

- Add email/SMS alerts (using SMTP or Twilio)
- Log alerts to a database (SQLite)
- Add more scan types (UDP scans, OS detection)
- Create a mobile app version

---

## 🔒 Security Notes

### **⚠️ Important Warnings**

1. **Only use in your lab**: Never run nmap scans on networks you don't own
2. **Ethical hacking**: This is for educational purposes only
3. **VM isolation**: Keep your VMs isolated from production networks
4. **Firewall**: Don't expose port 5000 to the internet

### **Best Practices**

- Use strong passwords on your VMs
- Keep Ubuntu updated: `sudo apt update && sudo apt upgrade`
- Don't run as root (use sudo only when needed)
- Back up your trained model file

---

## 📞 Support & Resources

### **Learning Resources**

- **Scapy Tutorial**: https://scapy.readthedocs.io/
- **Nmap Guide**: https://nmap.org/book/man.html
- **Scikit-learn Docs**: https://scikit-learn.org/
- **Flask Tutorial**: https://flask.palletsprojects.com/

### **Common Questions**

**Q: Can I use this on a real network?**
A: Yes, but only on networks you own/manage. Get permission first!

**Q: Will it detect other attacks?**
A: Currently only nmap scans. You can extend it for other attacks.

**Q: How accurate is it?**
A: With proper training, 90-98% accuracy on test data.

**Q: Can I deploy this to production?**
A: This is a proof-of-concept. Production systems need more hardening.

---

## 🎉 Congratulations!

You've built a complete AI-powered intrusion detection system! This demonstrates:

✅ Machine Learning in cybersecurity  
✅ Real-time packet analysis  
✅ Full-stack development (Python + Flask + HTML/CSS/JS)  
✅ Network security fundamentals  
✅ Practical ethical hacking skills  

**Next Steps:**
- Experiment with different ML models (SVM, Neural Networks)
- Add more features (packet size, timing patterns)
- Create a distributed version (multiple sensors)
- Publish your findings!

---

## 📄 License

This project is for educational purposes. Use responsibly and ethically.

---

## 👨‍💻 Author

**Cybersecurity Research Team**  
University Project - Host-Based Intrusion Detection System

---

**Happy Hacking! 🛡️🔒**
