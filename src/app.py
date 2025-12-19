# =====================================================
# MUST BE FIRST STREAMLIT COMMAND
# =====================================================
import streamlit as st

st.set_page_config(
    page_title="SMB EternalBlue Detector",
    layout="wide"
)

# =====================================================
# Imports
# =====================================================
import pandas as pd
import joblib
import io
import time
from scapy.all import rdpcap, IP, TCP

# =====================================================
# Load Model & Scaler
# =====================================================
@st.cache_resource
def load_assets():
    model = joblib.load("../models/eternalblue_model.joblib")
    scaler = joblib.load("../models/scaler.joblib")
    return model, scaler

model, scaler = load_assets()

# =====================================================
# Feature Engineering (UNCHANGED)
# =====================================================
def extract_session_features(df):
    df["time"] = pd.to_datetime(df["time"], unit="s", errors="coerce")

    df["session_id"] = (
        df["ip.src"].astype(str) + "_" +
        df["ip.dst"].astype(str) + "_" +
        df["tcp.srcport"].astype(str)
    )

    df["is_nt_trans"] = df["smb.cmd"] == "0xa0"
    df["is_trans2"]   = df["smb.cmd"] == "0x32"

    session_df = df.groupby("session_id").agg(
        nt_count=("is_nt_trans", "sum"),
        trans2_count=("is_trans2", "sum"),
        duration=("time", lambda x: (x.max() - x.min()).total_seconds())
    ).reset_index()

    return session_df.fillna(0)

# =====================================================
# UI
# =====================================================
st.title("🛡️ SMB EternalBlue Detector")

mode = st.radio(
    "Choose Mode",
    ["Detection", "🧪 Simulation (Real Data Flow)"]
)

# =====================================================
# SIMULATION MODE (REAL PIPELINE)
# =====================================================
if mode == "🧪 Simulation (Real Data Flow)":

    st.subheader("🧪 EternalBlue SMBv1 Realistic Simulation")

    col1, col2 = st.columns(2)

    with col1:
        nt_count = st.slider("NT_TRANSACT (0xA0) packets", 0, 10, 4)
        trans2_count = st.slider("TRANS2 (0x32) packets", 0, 5, 1)

    with col2:
        duration = st.slider("Session duration (seconds)", 1, 30, 5)
        attack_mode = st.checkbox("Simulate EternalBlue Attack", value=True)

    st.markdown("---")

    # ----------------------------
    # Generate REAL DataFrame
    # ----------------------------
    base_time = time.time()
    rows = []

    def add_packet(cmd, t):
        rows.append({
            "ip.src": "192.168.1.10",
            "ip.dst": "192.168.1.20",
            "tcp.srcport": 445,
            "time": t,
            "smb.cmd": cmd
        })

    # NT packets
    for i in range(nt_count):
        add_packet("0xa0", base_time + i)

    # TRANS2 packets
    for i in range(trans2_count):
        add_packet("0x32", base_time + nt_count + i)

    # Optional normal traffic
    if not attack_mode:
        add_packet("0x25", base_time + 20)  # harmless SMB cmd

    df_simulated = pd.DataFrame(rows)

    st.markdown("### 📥 Generated SMB Traffic")
    st.dataframe(df_simulated)

    # ----------------------------
    # SAME Feature Engineering
    # ----------------------------
    session_df = extract_session_features(df_simulated)

    st.markdown("### ⚙️ Extracted Session Features")
    st.dataframe(session_df)

    # ----------------------------
    # SAME ML PIPELINE
    # ----------------------------
    X = session_df[["nt_count", "trans2_count", "duration"]]
    X_scaled = scaler.transform(X)
    pred = model.predict(X_scaled)[0]

    st.markdown("### 🧠 Model Decision")

    if pred == 1:
        st.error("🚨 EternalBlue Detected (Simulation)")
    else:
        st.success("✅ Normal SMB Behavior")

    st.info("✔ This simulation goes through the **same data path** as real PCAP/CSV")

    st.stop()

# =====================================================
# DETECTION MODE (100% ORIGINAL – UNTOUCHED)
# =====================================================
st.write("Supports **PCAP** or **CSV (any PCAP-export format)**")

uploaded_file = st.file_uploader(
    "Upload PCAP or CSV",
    type=["pcap", "csv"]
)

if uploaded_file:
    st.info("🔍 Processing traffic...")

    if uploaded_file.name.endswith(".pcap"):
        packets = rdpcap(io.BytesIO(uploaded_file.read()))
        rows = []

        for pkt in packets:
            if IP in pkt and TCP in pkt:
                raw = bytes(pkt[TCP].payload)
                smb_cmd = "0x00"
                if b'\xffSMB' in raw:
                    idx = raw.find(b'\xffSMB')
                    if len(raw) > idx + 4:
                        smb_cmd = hex(raw[idx + 4])
                rows.append({
                    "ip.src": pkt[IP].src,
                    "ip.dst": pkt[IP].dst,
                    "tcp.srcport": pkt[TCP].sport,
                    "time": pkt.time,
                    "smb.cmd": smb_cmd
                })
        df_raw = pd.DataFrame(rows)

    else:
        df_raw = pd.read_csv(uploaded_file)
        df_raw.columns = df_raw.columns.str.strip().str.lower()
        rename_map = {
            "frame.time": "time",
            "frame.time_epoch": "time",
            "ip.src": "ip.src",
            "ip.dst": "ip.dst",
            "tcp.srcport": "tcp.srcport",
            "tcp.src_port": "tcp.srcport",
            "smb.cmd": "smb.cmd",
            "smb.command": "smb.cmd"
        }
        for col in rename_map:
            if col in df_raw.columns:
                df_raw.rename(columns={col: rename_map[col]}, inplace=True)
        if "smb.cmd" not in df_raw.columns:
            df_raw["smb.cmd"] = "0x00"

    required = {"ip.src", "ip.dst", "tcp.srcport", "time"}
    missing = required - set(df_raw.columns)
    if missing:
        st.error(f"❌ Missing columns: {', '.join(missing)}")
        st.stop()

    session_df = extract_session_features(df_raw)

    X = session_df[["nt_count", "trans2_count", "duration"]]
    X_scaled = scaler.transform(X)
    preds = model.predict(X_scaled)
    session_df["prediction"] = preds

    attacks = session_df[session_df["prediction"] == 1]

    if len(attacks) > 0:
        st.error(f"🚨 EternalBlue Detected ({len(attacks)} sessions)")
        st.dataframe(attacks)
    else:
        st.success("✅ No EternalBlue behavior detected")

    with st.expander("Show all sessions"):
        st.dataframe(session_df)
