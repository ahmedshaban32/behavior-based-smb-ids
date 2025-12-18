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
# PCAP → DataFrame
# =====================================================
def process_pcap(uploaded_file):
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

    return pd.DataFrame(rows)

# =====================================================
# Normalize CSV Columns (ANY FORMAT)
# =====================================================
def normalize_csv(df):
    df.columns = df.columns.str.strip().str.lower()

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
        if col in df.columns:
            df.rename(columns={col: rename_map[col]}, inplace=True)

    # SMB may not exist
    if "smb.cmd" not in df.columns:
        df["smb.cmd"] = "0x00"

    return df

# =====================================================
# Feature Engineering (Session-Based)
# =====================================================
def extract_session_features(df):
    df["time"] = pd.to_datetime(df["time"], unit="s", errors="coerce")

    df["session_id"] = (
        df["ip.src"].astype(str) + "_" +
        df["ip.dst"].astype(str) + "_" +
        df["tcp.srcport"].astype(str)
    )

    df["is_nt_trans"] = df["smb.cmd"] == "0xa0"   # NT_TRANSACT
    df["is_trans2"]   = df["smb.cmd"] == "0x32"   # TRANS2

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
st.write("Supports **PCAP** or **CSV (any PCAP-export format)**")

uploaded_file = st.file_uploader(
    "Upload PCAP or CSV",
    type=["pcap", "csv"]
)

if uploaded_file:
    st.info("🔍 Processing traffic...")

    # ---------- Load ----------
    if uploaded_file.name.endswith(".pcap"):
        df_raw = process_pcap(uploaded_file)
    else:
        df_raw = pd.read_csv(uploaded_file)
        df_raw = normalize_csv(df_raw)

    # ---------- Required minimal fields ----------
    required = {"ip.src", "ip.dst", "tcp.srcport", "time"}
    missing = required - set(df_raw.columns)

    if missing:
        st.error(f"❌ Missing columns: {', '.join(missing)}")
        st.stop()

    # ---------- Feature Engineering ----------
    session_df = extract_session_features(df_raw)

    if session_df.empty:
        st.warning("⚠️ No SMB sessions found")
        st.stop()

    # ---------- Model ----------
    X = session_df[["nt_count", "trans2_count", "duration"]]
    X_scaled = scaler.transform(X)

    preds = model.predict(X_scaled)
    session_df["prediction"] = preds

    attacks = session_df[session_df["prediction"] == 1]

    # ---------- Output ----------
    if len(attacks) > 0:
        st.error(f"🚨 EternalBlue Detected ({len(attacks)} sessions)")
        st.dataframe(attacks)
    else:
        st.success("✅ No EternalBlue behavior detected")

    with st.expander("Show all sessions"):
        st.dataframe(session_df)
