"""ML-based Network Intrusion Detection: flow simulation, supervised classifier + anomaly detector.

Feature set follows NSL-KDD / CIC-IDS style flow statistics so you can swap in the real
datasets (NSL-KDD KDDTrain+.txt or CIC-IDS2017 CSVs) with minimal changes.
"""
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

ATTACKS = ["Normal", "DoS", "Port Scan", "Brute Force", "Data Exfiltration"]
SEVERITY = {"Normal": "—", "DoS": "Critical", "Port Scan": "Medium", "Brute Force": "High", "Data Exfiltration": "Critical"}
NUM = ["duration", "src_bytes", "dst_bytes", "packets", "conn_count", "srv_count", "syn_error_rate",
       "rej_rate", "same_srv_rate", "dst_host_count", "failed_logins"]
CAT = ["protocol", "service", "flag"]


def simulate_flows(n=20000, seed=5, mix=(.70, .10, .09, .06, .05)) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    labels = rng.choice(len(ATTACKS), n, p=mix)
    rows = []
    for y in labels:
        r = dict(
            duration=rng.exponential(2), src_bytes=rng.lognormal(6, 1.2), dst_bytes=rng.lognormal(7, 1.3),
            packets=rng.poisson(20) + 1, conn_count=rng.poisson(8), srv_count=rng.poisson(6),
            syn_error_rate=rng.beta(1, 30), rej_rate=rng.beta(1, 30), same_srv_rate=rng.beta(8, 2),
            dst_host_count=rng.poisson(30), failed_logins=rng.poisson(.3),
            protocol=rng.choice(["tcp", "udp", "icmp"], p=[.75, .2, .05]),
            service=rng.choice(["http", "https", "dns", "ssh", "ftp", "smtp"], p=[.3, .35, .15, .08, .05, .07]),
            flag=rng.choice(["SF", "S0", "REJ", "RSTO"], p=[.9, .04, .03, .03]),
        )
        base = dict(r)
        if y == 0 and rng.random() < .04:  # bursty but legitimate traffic (CDN, backups)
            r.update(conn_count=rng.poisson(70), packets=rng.poisson(150), src_bytes=rng.lognormal(10, 1))
        if y == 1:  # DoS / SYN flood
            r.update(duration=rng.exponential(.05), src_bytes=rng.lognormal(3, .5), dst_bytes=rng.lognormal(1, .5),
                     packets=rng.poisson(400), conn_count=rng.poisson(300), srv_count=rng.poisson(280),
                     syn_error_rate=rng.beta(20, 2), same_srv_rate=rng.beta(20, 1), flag=rng.choice(["S0", "SF"], p=[.85, .15]))
        elif y == 2:  # port scan
            r.update(duration=rng.exponential(.02), src_bytes=rng.lognormal(2, .5), dst_bytes=rng.lognormal(1, .7),
                     packets=rng.poisson(2) + 1, conn_count=rng.poisson(120), srv_count=rng.poisson(3),
                     rej_rate=rng.beta(15, 3), same_srv_rate=rng.beta(1, 15), dst_host_count=rng.poisson(200),
                     flag=rng.choice(["REJ", "S0", "RSTO"]))
        elif y == 3:  # brute force (ssh/ftp)
            r.update(service=rng.choice(["ssh", "ftp"]), failed_logins=rng.poisson(12) + 3, conn_count=rng.poisson(40),
                     srv_count=rng.poisson(38), duration=rng.exponential(1), same_srv_rate=rng.beta(30, 1))
        elif y == 4:  # data exfiltration: long sessions, huge outbound
            r.update(duration=rng.exponential(60) + 20, src_bytes=rng.lognormal(13, .8), dst_bytes=rng.lognormal(5, 1),
                     packets=rng.poisson(900), service=rng.choice(["https", "dns", "ftp"], p=[.5, .3, .2]))
        if y > 0 and rng.random() < .3:  # stealthy "low-and-slow" variant blends with normal traffic
            w = rng.uniform(.02, .2)
            r["flag"], r["protocol"] = base["flag"], base["protocol"]
            for k in NUM:
                r[k] = base[k] + w * (r[k] - base[k])
        r["label"] = ATTACKS[y]
        rows.append(r)
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.Timestamp("2026-01-01 09:00") + pd.to_timedelta(np.sort(rng.uniform(0, 8 * 3600, n)), unit="s")
    df["src_ip"] = [f"10.0.{rng.integers(0, 8)}.{rng.integers(2, 254)}" for _ in range(n)]
    return df


def train(df):
    X, y = df[NUM + CAT], df["label"]
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=.25, stratify=y, random_state=1)
    pre = ColumnTransformer([("num", StandardScaler(), NUM), ("cat", OneHotEncoder(handle_unknown="ignore"), CAT)])
    clf = Pipeline([("pre", pre), ("rf", RandomForestClassifier(200, max_depth=14, class_weight="balanced", random_state=1, n_jobs=-1))])
    clf.fit(Xtr, ytr)
    pred = clf.predict(Xte)
    # unsupervised detector trained on normal traffic only -> catches zero-day patterns
    iso = Pipeline([("pre", clone(pre)), ("iso", IsolationForest(n_estimators=200, contamination=.02, random_state=1))])
    iso.fit(Xtr[ytr == "Normal"])
    names = clf.named_steps["pre"].get_feature_names_out()
    imp = pd.Series(clf.named_steps["rf"].feature_importances_, index=[n.split("__")[1] for n in names]).sort_values(ascending=False)
    return {
        "clf": clf, "iso": iso,
        "cm": confusion_matrix(yte, pred, labels=ATTACKS),
        "report": classification_report(yte, pred, output_dict=True),
        "macro_f1": f1_score(yte, pred, average="macro"),
        "detection_rate": ((pred != "Normal") & (yte != "Normal")).sum() / (yte != "Normal").sum(),
        "false_alarm": ((pred != "Normal") & (yte == "Normal")).sum() / (yte == "Normal").sum(),
        "importance": imp,
    }


def score_traffic(model, flows):
    out = flows.copy()
    out["predicted"] = model["clf"].predict(flows[NUM + CAT])
    out["confidence"] = model["clf"].predict_proba(flows[NUM + CAT]).max(axis=1)
    out["anomaly"] = model["iso"].predict(flows[NUM + CAT]) == -1
    out["severity"] = out.predicted.map(SEVERITY)
    return out
