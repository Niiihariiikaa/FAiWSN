
# 🛰️ FAiWSN
### Federated Adaptive Intrusion Detection for Wireless Sensor Networks

**FAiWSN** is a real-time, intelligent intrusion detection system for **Wireless Sensor Networks (WSNs)** that supports:
- ✅ Federated learning
- ✅ Adaptive model logic
- ✅ Concept drift detection
- ✅ Multiclass attack classification
- ✅ Input from `.pcap` files (Wireshark, NS-3, Cooja) or simulated `.csv`
- ✅ Real-time live dashboard using **Streamlit**

> ⚡ **Coming soon**: Full support for **live traffic capture from Wireshark**!



## 📌 Key Features

| Feature                         | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| 🧠 Federated Model             | Uses a trained LSTM model built for federated setups                       |
| 📂 Input Sources               | Supports `.pcap` (real traffic) and `.csv` (simulated WSN logs)            |
| 🧪 Multiclass Detection        | Classifies attacks like DoS, Fuzzers, Backdoor, Recon, Shellcode, etc.     |
| 🔄 Adaptive Sequences         | Real-time LSTM sequence generation from incoming packets                   |
| ⚠️ Concept Drift Detection     | Cosine distance-based drift detection between output windows               |
| 📊 Streamlit Dashboard         | Live visualization of predictions, confidence scores & drift alerts       |
| 🛰️ Real WSN-Ready              | Structured for real-time gateway deployment in WSN-based environments      |

(<img width="1882" height="792" alt="image" src="https://github.com/user-attachments/assets/f1dcf141-ad28-48e5-9323-eed2667237f3" />)










 Real `.pcap` File (Wireshark / NS-3 / Cooja)

1. Open **Wireshark** (or simulator)
2. Start packet capture on your active network interface
3. Stop and **export** as `.pcap`
4. Upload into the dashboard

> ✅ Internally parsed via **Scapy** for features like IPs, ports, TTL, protocol, etc.

---

## 📈 Drift Detection

* Drift is measured via **cosine distance** between output probability vectors of consecutive windows.
* Drift alert threshold can be adjusted via UI (`0.0 – 1.0`)

---

## 🧠 Model Architecture

| Layer  | Details                                    |
| ------ | ------------------------------------------ |
| Input  | `(timesteps, features)` (e.g., `(10, 39)`) |
| Model  | BiLSTM + Dense                             |
| Output | Softmax over `N` classes                   |
| Type   | Trained for **federated inference** setup  |


## 🔮 Future Roadmap

* [ ] 🔴 Real-time Wireshark traffic capture (live socket ingest)
* [ ] 📦 Docker support for easy deployment
* [ ] 📡 MQTT or LoRa interface for WSN device streams
* [ ] 🔁 Drift-triggered model updates
* [ ] 📊 Historical analytics view

---





