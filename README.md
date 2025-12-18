# Behavior-Based SMB Intrusion Detection System (EternalBlue)

## 📌 Project Overview
This project presents a **behavior-based Intrusion Detection System (IDS)** designed to detect
**SMB-based attacks**, specifically the **EternalBlue (MS17-010)** exploit, using machine learning
techniques.

Unlike traditional signature-based detection, this system focuses on **session-level behavioral
features** extracted from network traffic, enabling accurate detection of exploit behavior rather
than relying on packet signatures.

---

## 🎯 Objectives
- Detect EternalBlue attacks using behavioral network features
- Build a labeled dataset from real attack traffic
- Apply machine learning models for classification
- Evaluate detection performance with a strong focus on **Recall**
- Provide a reproducible and well-documented public repository

---

## 🧪 Lab Environment
- **Attacker Machine:** Kali Linux
- **Victim Machine:** Windows (SMBv1 enabled)
- **Traffic Capture:** Wireshark
- **Attack Tool:** EternalBlue exploit
- **Network Type:** Isolated virtual lab

---

## 🧨 Attack Scenario
1. Vulnerable Windows machine exposed to SMBv1
2. EternalBlue exploit executed from Kali Linux
3. Abnormal SMB behavior generated during exploitation
4. Network traffic captured using Wireshark
5. Traffic aggregated into sessions and labeled as normal or attack

Detailed attack steps, commands, and screenshots are available in the `docs/` directory.

---

## 📂 Project Structure
behavior-based-smb-ids/
│
├── attack_scripts/ # EternalBlue exploit scripts and attack execution tools
├── data/ # Raw and processed datasets (CSV files)
├── docs/ # Attack steps, screenshots, lab setup, topology
├── models/ # Trained ML models and feature scalers
├── notebooks/ # Jupyter notebooks (EDA, training, evaluation)
├── src/ # Feature extraction and detection source code
├── requirements.txt # Python dependencies
└── README.md

---

## 📊 Dataset Description
- **Source:** Network traffic captured from the lab environment
- **Format:** CSV
- **Classes:**
  - Normal SMB traffic (label = 0)
  - EternalBlue attack traffic (label = 1)
- **Labeling Method:** Session-based labeling after traffic aggregation

---

## 🧠 Feature Engineering
Behavioral features extracted from SMB sessions:
- `nt_count`: Number of SMB NT_TRANSACT commands
- `trans2_count`: Number of SMB TRANS2 commands
- `duration`: Session duration in seconds

These features represent the core behavioral stages of the EternalBlue exploit.

---

## 🤖 Machine Learning Models
The following machine learning models were evaluated:
- Logistic Regression (with SMOTE)
- Random Forest Classifier

Logistic Regression was selected for deployment because:
- It achieved the same detection performance as Random Forest
- It provides faster inference time
- It offers higher interpretability
- It is more suitable for real-time IDS deployment

---

## 📈 Evaluation Metrics
Models were evaluated using:
- Accuracy
- Precision
- Recall
- F1-score
- Confusion Matrix
- Balanced Accuracy

Recall was prioritized to minimize false negatives in attack detection.

---

## 🚀 Deployment
The trained Logistic Regression model and feature scaler were exported using `joblib` and
integrated into a local detection pipeline capable of analyzing PCAP and CSV inputs.

---

## 📎 Documentation
All attack execution steps, traffic capture screenshots, dataset creation details, and lab
topology diagrams are available in the `docs/` directory.

---

## ⚠️ Disclaimer
This project is intended strictly for educational and research purposes.
