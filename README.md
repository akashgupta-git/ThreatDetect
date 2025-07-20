# ThreatDetect – Real-Time Intrusion Detection System (IDS)

## 🚀 Overview
ThreatDetect monitors real-time network traffic and raises alerts for suspicious activities such as SYN Flood attacks using signature-based rules.

## 📦 Features
- Packet sniffing using Scapy
- Rule-based attack detection
- Alert generation with logs
- Streamlit dashboard (optional)
- Easily extendable rule engine

## 🔧 Setup

```bash
git clone https://github.com/yourname/threatdetect
cd threatdetect
pip install -r requirements.txt
python run.py
```

## 🧪 Simulate Attacks

Use tools like `nmap` or `hping3`:
```bash
hping3 -S -p 80 -i u100 192.168.0.10
```

## 📊 Dashboard

```bash
cd dashboard
streamlit run app.py
```
