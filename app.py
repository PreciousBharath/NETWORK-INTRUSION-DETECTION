"""SentinelNet - ML-powered Network Intrusion Detection System (SOC dashboard).
Run:  streamlit run app.py
"""
import plotly.express as px
import streamlit as st

from ids import ATTACKS, score_traffic, simulate_flows, train

st.set_page_config(page_title="SentinelNet IDS", page_icon="🛡️", layout="wide")
COL = {"Normal": "#39D98A", "DoS": "#FF416C", "Port Scan": "#F7B32B", "Brute Force": "#8E2DE2", "Data Exfiltration": "#00C9FF"}


@st.cache_resource
def model():
    return train(simulate_flows())


M = model()
with st.sidebar:
    st.header("📡 Traffic capture")
    n = st.slider("Flows in monitoring window", 500, 5000, 2000, 250)
    seed = st.number_input("Capture seed", 0, 999, 21)
    attack_level = st.slider("Attack intensity", 0.05, 0.6, 0.25)
    st.caption("Simulated SOC feed. Plug in NSL-KDD / CIC-IDS2017 or live NetFlow for production.")

p_att = attack_level / 4
live = score_traffic(M, simulate_flows(n, seed=int(seed), mix=(1 - attack_level, p_att, p_att, p_att, p_att)))
alerts = live[live.predicted != "Normal"]

st.markdown("<h1 style='margin-bottom:0'>🛡️ SentinelNet — Intrusion Detection</h1>"
            "<p style='color:#888'>Random Forest attack classifier + Isolation Forest zero-day anomaly detector</p>",
            unsafe_allow_html=True)
k = st.columns(6)
k[0].metric("Flows analysed", f"{len(live):,}")
k[1].metric("Threat alerts", f"{len(alerts):,}", f"{len(alerts)/len(live):.1%}", delta_color="inverse")
k[2].metric("Critical", int((alerts.severity == "Critical").sum()))
k[3].metric("Anomalies (0-day)", int(live.anomaly.sum()))
k[4].metric("Detection rate", f"{M['detection_rate']:.1%}")
k[5].metric("False alarm rate", f"{M['false_alarm']:.2%}")

c1, c2 = st.columns([2, 1])
with c1:
    tl = live.set_index("timestamp").groupby("predicted").resample("10min").size().reset_index(name="flows")
    fig = px.area(tl[tl.predicted != "Normal"], x="timestamp", y="flows", color="predicted", color_discrete_map=COL,
                  title="Threat timeline (10-min buckets)")
    fig.update_layout(height=320, margin=dict(t=40, b=10), legend_title=None)
    st.plotly_chart(fig, width="stretch")
with c2:
    dist = alerts.predicted.value_counts().reset_index()
    fig = px.pie(dist, names="predicted", values="count", hole=.6, color="predicted", color_discrete_map=COL, title="Attack mix")
    fig.update_layout(height=320, margin=dict(t=40, b=10), showlegend=False)
    fig.update_traces(textinfo="label+percent")
    st.plotly_chart(fig, width="stretch")

c1, c2, c3 = st.columns([2, 1.2, 1.2])
with c1:
    st.subheader("🚨 Live alert feed")
    feed = alerts.sort_values("timestamp", ascending=False).head(10)[
        ["timestamp", "src_ip", "service", "predicted", "severity", "confidence", "anomaly"]]
    st.dataframe(feed, hide_index=True, width="stretch",
                 column_config={"timestamp": st.column_config.DatetimeColumn(format="HH:mm:ss"),
                                "confidence": st.column_config.ProgressColumn(min_value=0, max_value=1, format="%.2f")})
with c2:
    cm = M["cm"] / M["cm"].sum(axis=1, keepdims=True)
    short = ["Norm", "DoS", "Scan", "Brute", "Exfil"]
    fig = px.imshow(cm, x=short, y=short, text_auto=".2f", color_continuous_scale="Teal", title="Confusion matrix",
                    labels=dict(x="Predicted", y="Actual"))
    fig.update_layout(height=340, margin=dict(t=40, b=10), coloraxis_showscale=False)
    st.plotly_chart(fig, width="stretch")
with c3:
    imp = M["importance"].head(8).sort_values().reset_index()
    imp.columns = ["feature", "importance"]
    fig = px.bar(imp, x="importance", y="feature", orientation="h", title="Top detection features",
                 color="importance", color_continuous_scale="Plasma")
    fig.update_layout(height=340, margin=dict(t=40, b=10), coloraxis_showscale=False)
    st.plotly_chart(fig, width="stretch")

top_src = alerts.groupby(["src_ip", "predicted"]).size().reset_index(name="alerts").sort_values("alerts", ascending=False).head(15)
fig = px.bar(top_src, x="src_ip", y="alerts", color="predicted", color_discrete_map=COL, title="Top offending source IPs")
fig.update_layout(height=280, margin=dict(t=40, b=10), legend_title=None)
st.plotly_chart(fig, width="stretch")
st.download_button("⬇️ Export alerts (CSV)", alerts.to_csv(index=False), "ids_alerts.csv")
