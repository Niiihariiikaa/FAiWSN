
import streamlit as st
st.set_page_config(layout="wide", page_title="Real-Time WSN Intrusion Detection")

import numpy as np
import pandas as pd
import time
import os
import joblib
import socket
import tempfile
from scapy.all import rdpcap
from tensorflow.keras.models import load_model
from tensorflow.keras.utils import to_categorical
from sklearn.preprocessing import StandardScaler
from scipy.spatial.distance import cosine


model = load_model("models/federated_ids_model.h5")
label_encoder = joblib.load("models\label_encoder (2).pkl")
num_classes = len(label_encoder.classes_)
timesteps = 10

def create_sequences(X, y=None, timesteps=10):
    X_seq, y_seq = [], []
    for i in range(len(X) - timesteps):
        X_seq.append(X[i:i+timesteps])
        if y is not None:
            y_seq.append(y[i+timesteps])
    return (np.array(X_seq), np.array(y_seq)) if y is not None else np.array(X_seq)

def ip_to_int(ip):
    try:
        return int.from_bytes(socket.inet_aton(ip), 'big')
    except:
        return 0

def extract_features_from_pcap(uploaded_file):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
    except Exception:
        os.remove(tmp_path)
        return pd.DataFrame()

    rows = []
    for pkt in packets:
        if pkt.haslayer("IP"):
            try:
                ip_layer = pkt["IP"]
                row = {
                    "src_ip": ip_to_int(ip_layer.src),
                    "dst_ip": ip_to_int(ip_layer.dst),
                    "protocol": ip_layer.proto,
                    "ttl": ip_layer.ttl,
                    "packet_len": len(pkt),
                    "flags": int(ip_layer.flags) if hasattr(ip_layer, 'flags') else 0,
                    "src_port": pkt.sport if hasattr(pkt, 'sport') else 0,
                    "dst_port": pkt.dport if hasattr(pkt, 'dport') else 0
                }
                rows.append(row)
            except:
                continue

    os.remove(tmp_path)
    return pd.DataFrame(rows)

st.title("🛡️ Real-Time WSN Intrusion Detection Dashboard")
st.markdown("Upload `.pcap` or run simulated data to detect intrusions using LSTM + drift detection.")

source_option = st.radio("📥 Select Data Source", ["Simulated CSV", "PCAP File"])
speed = st.slider("⏱️ Stream speed (sec/sample)", 0.1, 3.0, 1.0)
show_confidence = st.checkbox("📊 Show Confidence Scores", value=True)
drift_threshold = st.slider("⚠️ Drift Detection Threshold", 0.1, 1.0, 0.35)


if source_option == "Simulated CSV":
    @st.cache_data
    def load_simulated_data():
        df = pd.read_csv("UNSW_NB15_training-set.csv")
        df["attack_cat"] = df["attack_cat"].fillna("Normal")
        y = label_encoder.transform(df["attack_cat"])

        X = df.drop(columns=["id", "label", "attack_cat"], errors="ignore")
        X = X.select_dtypes(include=[np.number])
        X_scaled = StandardScaler().fit_transform(X)
        return X_scaled, y

    X_scaled, y = load_simulated_data()
    X_seq, y_seq = create_sequences(X_scaled, y, timesteps)

elif source_option == "PCAP File":
    uploaded_file = st.file_uploader("Upload PCAP File", type=["pcap"])
    if uploaded_file:
        with st.spinner("🔍 Extracting features from PCAP..."):
            df = extract_features_from_pcap(uploaded_file)

        if df.empty:
            st.error("❌ No valid IP packets found or file is corrupt.")
            st.stop()

        X = df.drop(columns=[], errors="ignore").select_dtypes(include=[np.number])
        X_scaled = StandardScaler().fit_transform(X)
        X_seq = create_sequences(X_scaled, timesteps)
        y_seq = None  

    else:
        st.stop()
if len(X_seq) == 0:
    st.error("❌ Not enough data to form sequences.")
else:
    st.success(f"✅ Prepared {len(X_seq)} sequences.")
    placeholder = st.empty()
    previous_window = None
    drift_count = 0

    for i in range(min(50, len(X_seq))):  
        x = X_seq[i].reshape(1, timesteps, X_seq.shape[2])
        pred_prob = model.predict(x, verbose=0)
        pred_cls = np.argmax(pred_prob)
        label = label_encoder.classes_[pred_cls]
        confidence = pred_prob[0][pred_cls]

        drift = False
        if previous_window is not None:
            drift_score = cosine(previous_window, pred_prob.flatten())
            if drift_score > drift_threshold:
                drift = True
                drift_count += 1
        previous_window = pred_prob.flatten()

        actual = label_encoder.classes_[y_seq[i]] if y_seq is not None else None
        is_correct = (pred_cls == y_seq[i]) if y_seq is not None else None

        with placeholder.container():
            st.markdown(f"### 🪟 Window {i+1}")
            st.markdown(f"**🧠 Predicted:** `{label}` {'✅' if is_correct else '❌' if is_correct is not None else ''}`")
            if actual:
                st.markdown(f"**🛡️ Actual:** `{actual}`")
            if drift:
                st.warning(f"⚠️ Drift Detected! Cosine distance = `{drift_score:.4f}`")
            if show_confidence:
                conf_df = pd.DataFrame(pred_prob, columns=label_encoder.classes_)
                st.bar_chart(conf_df.T)
            st.markdown(f"🌀 **Total Drifts Detected:** `{drift_count}`")

        time.sleep(speed)

    st.success("✅ Simulation complete.")
