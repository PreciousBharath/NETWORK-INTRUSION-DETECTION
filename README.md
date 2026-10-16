<div align="center">

# 🛡️ SentinelNet — ML Network Intrusion Detection System

**A SOC-style dashboard that detects DoS, port scans, brute force and data exfiltration in network flows.**

![Python-3.10%2B](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white) ![Streamlit-App](https://img.shields.io/badge/Streamlit-App-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white) ![Plotly-Charts](https://img.shields.io/badge/Plotly-Charts-3F4F75?style=for-the-badge&logo=plotly&logoColor=white) ![Cybersecurity-IDS](https://img.shields.io/badge/Cybersecurity-IDS-B91C1C?style=for-the-badge&logo=letsencrypt&logoColor=white) ![scikit--learn-Random%20Forest](https://img.shields.io/badge/scikit--learn-Random%20Forest-F7931E?style=for-the-badge&logo=scikitlearn&logoColor=white)

`Cybersecurity · Machine Learning`

</div>

---

![NETWORK-INTRUSION-DETECTION](assets/screenshot.png)

## 📌 Problem Statement

Signature-based firewalls miss new and stealthy attacks. ML models learn traffic behaviour and flag both known attacks and anomalies.

## ✨ Key Features

- Network-flow simulator with **NSL-KDD / CIC-IDS style features** and stealthy low-and-slow attack variants
- **Random Forest** multi-class attack classifier (class-balanced)
- **Isolation Forest** anomaly detector trained only on normal traffic (zero-day detection)
- KPIs: detection rate, false-alarm rate, critical alerts
- Threat timeline, attack mix, live **alert feed with severity**, top offending IPs
- Confusion matrix, feature importance and CSV alert export

## 🏗️ Architecture

```mermaid
flowchart LR
    A[Network Flows] --> B[Preprocessing]
    B --> C[Random Forest<br/>Attack Classifier]
    B --> D[Isolation Forest<br/>Anomaly Detector]
    C --> E[Alert Engine + Severity]
    D --> E
    E --> F[SOC Dashboard]
```

## ⚙️ How It Works

1. Five traffic classes are generated from realistic flow statistics (packets, bytes, SYN-error rate, reject rate, failed logins…).
2. A `ColumnTransformer` scales numeric and one-hot encodes protocol / service / flag features.
3. The classifier labels each flow; an independent Isolation Forest flags flows that deviate from normal behaviour.
4. Alerts are mapped to severities and aggregated for the SOC view.

## 🧰 Tech Stack

| Layer | Tools |
|---|---|
| Language | Python 3.10+ |
| ML / Logic | pandas, numpy, scikit-learn |
| UI & Visualisation | Streamlit, Plotly |

## 📁 Project Structure

```
NETWORK-INTRUSION-DETECTION/
├── app.py             # SOC dashboard
├── ids.py             # Flow simulation, training, evaluation, scoring
├── assets/              # screenshots
├── requirements.txt
└── README.md
```

## 🚀 Getting Started

```bash
git clone https://github.com/PreciousBharath/NETWORK-INTRUSION-DETECTION.git
cd NETWORK-INTRUSION-DETECTION
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

Open **http://localhost:8501** in your browser.

> The project ships with a realistic built-in demo dataset, so it runs out of the box with no downloads or API keys.

## 🗺️ Roadmap

- [ ] Train on CIC-IDS2017 / UNSW-NB15
- [ ] Live capture with Scapy / Zeek logs
- [ ] Slack / email alerting

## 👨‍💻 Author

**Bharath** — Software Developer · Project Engineer · Technical Trainer

[![LinkedIn](https://img.shields.io/badge/LinkedIn-connectbharath-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/connectbharath)
[![Portfolio](https://img.shields.io/badge/Portfolio-Visit-00C7B7?style=for-the-badge&logo=netlify&logoColor=white)](https://itsbharathportfolio.netlify.app)
[![GitHub](https://img.shields.io/badge/GitHub-PreciousBharath-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/PreciousBharath)

⭐ If this project helped you, please give it a star!

## 📄 License

Released under the [MIT License](LICENSE).
