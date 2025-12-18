# PENTEST-IDS-ML

Behavior-Based Intrusion Detection System (IDS)  
for detecting SMB attacks (EternalBlue) using network traffic analysis.

## 📌 Project Overview
This project focuses on detecting **SMB-based attacks (EternalBlue)** by analyzing
network traffic behavior captured using Wireshark and processed into CSV format.

Unlike packet-based detection, this approach relies on **session/behavior-level features**
to identify malicious activity.

## 📂 Dataset Description
- Network traffic captured on Kali Linux
- Traffic exported from PCAP to CSV
- Two classes:
  - Normal traffic (label = 0)
  - SMB attack traffic (label = 1)

Final dataset:
