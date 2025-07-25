
import streamlit as st
st.set_page_config(layout="wide", page_title="Real-Time WSN Intrusion Detection")

import numpy as np
import pandas as pd
import time
import os
import joblib
import socket
import tempfile
from scapy.all import sniff, IP
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
from scipy.spatial.distance import cosine
import tempfile


model = load_model("models/federated_ids_model.h5")
label_encoder = joblib.load("models/label_encoder (2).pkl")
num_classes = len(label_encoder.classes_)
timesteps = 10

def ip_to_int(ip):
    try:
        return int.from_bytes(socket.inet_aton(ip), 'big')
    except:
        return 0

live_buffer = []
def packet_callback(pkt):
    if IP in pkt:
        try:
            row = {
                "src_ip": ip_to_int(pkt[IP].src),
                "dst_ip": ip_to_int(pkt[IP].dst),
                "protocol": pkt[IP].proto,
                "ttl": pkt[IP].ttl,
                "packet_len": len(pkt),
                "flags": int(pkt[IP].flags) if hasattr(pkt[IP], 'flags') else 0,
                "src_port": pkt.sport if hasattr(pkt, 'sport') else 0,
                "dst_port": pkt.dport if hasattr(pkt, 'dport') else 0
            }
            live_buffer.append(row)
        except:
            pass

def extract_features_from_pcap(uploaded_file):
    from scapy.all import rdpcap
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP

    import tempfile
    import os


    with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp:
        tmp.write(uploaded_file.read())
        tmp_path = tmp.name

    rows = []

    try:
        packets = rdpcap(tmp_path)
        print(f"✅ Total packets read: {len(packets)}")

        for pkt in packets:
            row = {}

            if pkt.haslayer(IP) or pkt.haslayer(IPv6):
                ip_layer = pkt[IP] if pkt.haslayer(IP) else pkt[IPv6]

                row = {
                    "src_ip": ip_to_int(ip_layer.src),
                    "dst_ip": ip_to_int(ip_layer.dst),
                    "protocol": getattr(ip_layer, 'proto', 0),
                    "ttl": getattr(ip_layer, 'ttl', 0),
                    "packet_len": len(pkt),
                    "flags": int(getattr(ip_layer, 'flags', 0)),
                    "src_port": getattr(pkt, 'sport', 0),
                    "dst_port": getattr(pkt, 'dport', 0)
                }

            elif pkt.haslayer(ARP):
                arp_layer = pkt[ARP]
                row = {
                    "src_ip": ip_to_int(arp_layer.psrc),
                    "dst_ip": ip_to_int(arp_layer.pdst),
                    "protocol": 0,
                    "ttl": 0,
                    "packet_len": len(pkt),
                    "flags": 0,
                    "src_port": 0,
                    "dst_port": 0
                }

            if row:
                rows.append(row)

    except Exception as e:
        print(f"❌ Error reading PCAP: {e}")
        return pd.DataFrame()

    finally:
        try:
            os.remove(tmp_path)
        except:
            pass

    if not rows:
        print("❌ No IP or ARP packets found.")
        return pd.DataFrame()

    return pd.DataFrame(rows)

def create_sequences(X, y, timesteps):
    X_seq, y_seq = [], []
    for i in range(len(X) - timesteps):
        X_seq.append(X[i:i + timesteps])
        if y is not None:
            y_seq.append(y[i + timesteps])
    return np.array(X_seq), np.array(y_seq) if y is not None else None

@st.cache_data
def load_simulated_data():
    df = pd.read_csv("UNSW_NB15_training-set.csv")
    df["attack_cat"] = df["attack_cat"].fillna("Normal")
    y = label_encoder.fit_transform(df["attack_cat"])
    X = df.drop(columns=["id", "label", "attack_cat"], errors="ignore")
    X = X.select_dtypes(include=[np.number])
    X_scaled = StandardScaler().fit_transform(X)
    return X_scaled, y

st.title("🛡️ Real-Time WSN Intrusion Detection Dashboard")
st.markdown("Upload `.pcap`, simulate traffic or **capture live network packets** to detect intrusions.")

source_option = st.radio("📥 Select Data Source", ["Simulated CSV", "PCAP File", "Live Capture"])
speed = st.slider("⏱️ Stream speed (sec/sample)", 0.1, 3.0, 1.0)
show_confidence = st.checkbox("📊 Show Confidence Scores", value=True)
drift_threshold = st.slider("⚠️ Drift Detection Threshold", 0.1, 1.0, 0.35)

X_seq = None
y_seq = None

if source_option == "Simulated CSV":
    X_scaled, y = load_simulated_data()
    X_seq, y_seq = create_sequences(X_scaled, y, timesteps)

elif source_option == "PCAP File":
    uploaded_file = st.file_uploader("Upload PCAP File", type=["pcap"])
    if uploaded_file:
        df = extract_features_from_pcap(uploaded_file)
        if df.empty:
            st.error("❌ No valid IP packets found or file is corrupt.")
            st.stop()
        X = df.select_dtypes(include=[np.number])
        X_scaled = StandardScaler().fit_transform(X)
        X_seq, _ = create_sequences(X_scaled, None, timesteps)
    else:
        st.stop()

elif source_option == "Live Capture":
    st.warning("⚠️ Live capture must run locally and may need admin rights.")
    if st.button("▶️ Start Live Capture (60 packets)"):
        st.info("📡 Sniffing packets...")
        sniff(count=60, prn=packet_callback, filter="ip", timeout=10)
        df = pd.DataFrame(live_buffer)
        if df.empty:
            st.error("❌ No packets captured.")
            st.stop()

        REQUIRED_FEATURES = [
            "src_ip", "dst_ip", "protocol", "ttl", "packet_len",
            "flags", "src_port", "dst_port"
        ] + [f"feat_{i}" for i in range(8, 39)]  # Padding up to 39 features

        for col in REQUIRED_FEATURES:
            if col not in df.columns:
                df[col] = 0
        df = df[REQUIRED_FEATURES]

        if len(df) < timesteps:
            padding = pd.DataFrame(0, index=range(timesteps - len(df)), columns=df.columns)
            df = pd.concat([padding, df], ignore_index=True)
        else:
            df = df.tail(timesteps)

        X_seq = np.expand_dims(df.values, axis=0)
    else:
        st.stop()

if X_seq is None or len(X_seq) == 0:
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
        label = label_encoder.inverse_transform([pred_cls])[0]
        confidence = pred_prob[0][pred_cls]

        drift = False
        if previous_window is not None:
            drift_score = cosine(previous_window, pred_prob.flatten())
            if drift_score > drift_threshold:
                drift = True
                drift_count += 1
        previous_window = pred_prob.flatten()

        actual = label_encoder.inverse_transform([y_seq[i]])[0] if y_seq is not None else None
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
