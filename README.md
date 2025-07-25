
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
| 🧠 Federated Model             | Uses a trained model built for federated setups                       |
| 📂 Input Sources               | Supports `.pcap` (real traffic) and `.csv` (simulated WSN logs)            |
| 🧪 Multiclass Detection        | Classifies attacks like DoS, Fuzzers, Backdoor, Recon, Shellcode, etc.     |
| 🔄 Adaptive Sequences         | Real-time LSTM sequence generation from incoming packets                   |
| ⚠️ Concept Drift Detection     | Cosine distance-based drift detection between output windows               |
| 📊 Streamlit Dashboard         | Live visualization of predictions, confidence scores & drift alerts       |
| 🛰️ Real WSN-Ready              | Structured for real-time gateway deployment in WSN-based environments      |

(<img width="1882" height="792" alt="image" src="https://github.com/user-attachments/assets/f1dcf141-ad28-48e5-9323-eed2667237f3" />)







. 🧠 Background
WSNs: Limited memory, processing, and battery.

IDS in WSNs: Need lightweight, accurate, and privacy-preserving solutions.

Federated Learning (FL): Local model training with only weight updates shared.

Objective: Evaluate and deploy the best-suited DL model for WSN IDS under a federated setup.

3. 📁 Dataset
We use a custom-labeled WSN-DS/NSL-KDD-inspired dataset with features derived from real packet capture data. Simulated attack types include:

DoS (Denial of Service)

Sybil Attack

Hello Flood Attack

Sinkhole

Wormhole

Blackhole

Normal Traffic

📄 Features
Feature	Description
dur	Duration of the packet/session
proto	Protocol used (TCP/UDP/ICMP)
sbytes, dbytes	Bytes sent/received
sttl, dttl	Time to Live (TTL) values
sload, dload	Data load per second
spkts, dpkts	Number of packets sent/received
rate, stcpb	Source rate and TCP base seq
flgs	TCP Flags
Label	Normal / Attack type

4. 🛠️ Feature Engineering
Converted proto and flgs into categorical integers.

Scaled all numerical features using StandardScaler.

Removed redundant features to reduce model complexity.

One-hot encoding for multiclass labels (Label).

5. 🧪 Model Exploration
5.1. 🧩 Convolutional Neural Network (CNN)
Input Shape: Reshaped vector to 2D matrix for CNN compatibility.

Observation: Overfitting. High training accuracy, poor generalization.

Conclusion: CNN not suitable due to lack of spatial patterns in tabular data.

5.2. 🔁 Recurrent Neural Network (LSTM)
Input Shape: Treated each feature vector as a time step.

Observation: Training stuck at zero or fluctuating loss.

Issues: Misalignment with sequence-based structure. Feature vector ≠ time sequence.

Conclusion: LSTM not ideal for non-sequential, tabular WSN data.

5.3. ✅ Multi-Layer Perceptron (Final Choice)
Why MLP?

Best suited for tabular feature-based data.

Lightweight, fast convergence, fewer parameters.

Performs well under federated training.

python
Copy
Edit
# MLP Model Architecture

<pre><code> ``` model = Sequential([
    Dense(64, activation='relu', input_shape=(num_features,)),
    Dropout(0.3),
    Dense(32, activation='relu'),
    Dropout(0.2),
    Dense(num_classes, activation='softmax')
])
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])```
 
</code></pre>



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



## 🔮 Future Roadmap

* [ ] 🔴 Real-time Wireshark traffic capture (live socket ingest)
* [ ] 📦 Docker support for easy deployment
* [ ] 📡 MQTT or LoRa interface for WSN device streams
* [ ] 🔁 Drift-triggered model updates
* [ ] 📊 Historical analytics view

---





