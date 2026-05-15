from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from math import log2

try:
    from sklearn.ensemble import IsolationForest
except Exception:  # pragma: no cover - optional dependency path
    IsolationForest = None  # type: ignore[assignment]

from app.services.analyzer import AUTH_FAILURE_PATTERN, COMMAND_PATTERN, CVE_PATTERN, HASH_PATTERN, IP_PATTERN, MALWARE_PATTERN


BENIGN_BASELINE_LOGS = [
    "Jan 14 08:00:01 cron[123]: scheduled backup completed successfully",
    "Jan 14 08:01:12 auth host sshd[2201]: Accepted publickey for analyst from 10.0.0.15 port 55122 ssh2",
    "Jan 14 08:02:03 web nginx[901]: GET /health 200 12ms from 10.0.0.25",
    "Jan 14 08:03:44 db postgres[1102]: checkpoint complete; no errors reported",
    "Jan 14 08:05:18 endpoint updater[77]: package refresh completed successfully",
    "Jan 14 08:06:59 security agent[81]: heartbeat received from host workstation-04",
    "Jan 14 08:08:20 mail postfix[331]: queue processed successfully",
    "Jan 14 08:09:31 monitoring prom[12]: metrics scrape succeeded with no alerts",
    "Jan 14 08:10:40 backup rsync[42]: replication finished successfully",
    "Jan 14 08:11:57 auth host sudo[502]: analyst ran approved maintenance command",
    "Jan 14 08:12:21 vpn gateway[77]: established tunnel from 10.0.0.15 to 10.0.0.25",
    "Jan 14 08:13:02 web proxy[88]: GET /status 200 from 10.0.0.25 via 10.0.0.15",
    "Jan 14 08:14:11 siem collector[44]: forwarded event from 10.0.0.25 to 10.0.0.30",
    "Jan 14 08:15:06 mail postfix[331]: queued message from 10.0.0.15 to 10.0.0.25",
    "Jan 14 08:16:44 ids sensor[19]: benign flow observed between 10.0.0.15 and 10.0.0.25",
]

FEATURE_ORDER = [
    "lines",
    "characters",
    "words",
    "unique_words",
    "failed_logins",
    "commands",
    "malware_terms",
    "unique_ips",
    "cves",
    "hashes",
    "privilege_terms",
    "urls",
    "base64_like",
    "error_terms",
    "digit_ratio",
    "special_ratio",
    "uppercase_ratio",
    "repetition_ratio",
    "entropy",
]


@dataclass(slots=True)
class AnomalyReport:
    score: int
    severity: str
    signals: list[str]
    features: dict[str, float]
    model_notes: str


def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _tokenize(text: str) -> list[str]:
    return re.findall(r"[A-Za-z0-9_.:/@-]+", text.lower())


def _entropy(tokens: list[str]) -> float:
    if not tokens:
        return 0.0
    counts = Counter(tokens)
    total = len(tokens)
    return -sum((count / total) * log2(count / total) for count in counts.values())


def _feature_map(log_text: str) -> dict[str, float]:
    lines = [line for line in log_text.splitlines() if line.strip()]
    tokens = _tokenize(log_text)
    letters = sum(1 for char in log_text if char.isalpha())
    digits = sum(1 for char in log_text if char.isdigit())
    special = sum(1 for char in log_text if not char.isalnum() and not char.isspace())
    uppercase = sum(1 for char in log_text if char.isupper())
    total_chars = len(log_text) or 1
    unique_words = len(set(tokens))
    token_counts = Counter(tokens)
    repetition_ratio = (max(token_counts.values()) / len(tokens)) if tokens else 0.0

    failed = len(AUTH_FAILURE_PATTERN.findall(log_text))
    commands = len(COMMAND_PATTERN.findall(log_text))
    malware = len(MALWARE_PATTERN.findall(log_text))
    ips = len(set(IP_PATTERN.findall(log_text)))
    cves = len(set(match.upper() for match in CVE_PATTERN.findall(log_text)))
    hashes = len(set(HASH_PATTERN.findall(log_text)))
    privilege = len(re.findall(r"\b(sudo|admin|privilege|root|wheel)\b", log_text, flags=re.IGNORECASE))
    urls = len(re.findall(r"https?://", log_text, flags=re.IGNORECASE))
    base64_like = len(re.findall(r"\b(?:[A-Za-z0-9+/]{20,}={0,2})\b", log_text))
    error_terms = len(re.findall(r"\b(error|fail|failed|denied|unauthorized|warning|critical)\b", log_text, flags=re.IGNORECASE))

    return {
        "lines": float(len(lines)),
        "characters": float(len(log_text)),
        "words": float(len(tokens)),
        "unique_words": float(unique_words),
        "failed_logins": float(failed),
        "commands": float(commands),
        "malware_terms": float(malware),
        "unique_ips": float(ips),
        "cves": float(cves),
        "hashes": float(hashes),
        "privilege_terms": float(privilege),
        "urls": float(urls),
        "base64_like": float(base64_like),
        "error_terms": float(error_terms),
        "digit_ratio": float(digits / total_chars),
        "special_ratio": float(special / total_chars),
        "uppercase_ratio": float(uppercase / (letters or 1)),
        "repetition_ratio": float(repetition_ratio),
        "entropy": float(_entropy(tokens)),
    }


def _feature_vector(feature_map: dict[str, float]) -> list[float]:
    return [feature_map[name] for name in FEATURE_ORDER]


@lru_cache(maxsize=1)
def _trained_model():
    if IsolationForest is None:
        return None
    baseline_vectors = [_feature_vector(_feature_map(text)) for text in BENIGN_BASELINE_LOGS]
    if not baseline_vectors:
        return None
    model = IsolationForest(n_estimators=200, contamination=0.15, random_state=42)
    model.fit(baseline_vectors)
    baseline_scores = model.decision_function(baseline_vectors)
    return model, min(baseline_scores), max(baseline_scores)


def _model_anomaly_score(feature_map: dict[str, float]) -> tuple[int, int, float] | None:
    model_bundle = _trained_model()
    if model_bundle is None:
        return None
    model, min_score, max_score = model_bundle
    vector = _feature_vector(feature_map)
    decision_score = float(model.decision_function([vector])[0])
    prediction = int(model.predict([vector])[0])
    span = max(max_score - min_score, 1e-6)
    normality = max(0.0, min(1.0, (decision_score - min_score) / span))
    anomaly_score = int(round((1.0 - normality) * 100))
    return anomaly_score, prediction, decision_score


def _heuristic_signals(feature_map: dict[str, float]) -> list[str]:
    signals: list[str] = []
    if feature_map["failed_logins"] >= 3:
        signals.append("Burst of authentication failures")
    if feature_map["commands"] > 0:
        signals.append("Suspicious command execution pattern")
    if feature_map["malware_terms"] > 0:
        signals.append("Malware-related terminology")
    if feature_map["cves"] > 0:
        signals.append("CVE references in log content")
    if feature_map["unique_ips"] >= 2:
        signals.append("Multiple unique IPs observed")
    if feature_map["privilege_terms"] > 0:
        signals.append("Privilege-related keywords present")
    if feature_map["hashes"] > 0:
        signals.append("Hash-like artifact observed")
    if feature_map["urls"] > 0:
        signals.append("Network URLs present in log content")
    if feature_map["base64_like"] > 0:
        signals.append("Encoded payload-like strings detected")
    if feature_map["error_terms"] >= 3:
        signals.append("Repeated error or failure language")
    if not signals:
        signals.append("No strong anomaly pattern detected")
    return signals


def _heuristic_score(feature_map: dict[str, float]) -> int:
    score = 8
    score += int(feature_map["failed_logins"] * 8)
    score += int(feature_map["commands"] * 12)
    score += int(feature_map["malware_terms"] * 15)
    score += int(feature_map["unique_ips"] * 5)
    score += int(feature_map["cves"] * 25)
    score += int(feature_map["privilege_terms"] * 4)
    score += int(feature_map["hashes"] * 4)
    score += int(feature_map["urls"] * 2)
    score += int(feature_map["base64_like"] * 8)
    score += int(feature_map["error_terms"] * 2)
    score += int(min(feature_map["repetition_ratio"] * 10, 10))
    return min(100, score)


def score_log_text(log_text: str) -> AnomalyReport:
    feature_map = _feature_map(log_text)
    signals = _heuristic_signals(feature_map)
    heuristic_score = _heuristic_score(feature_map)

    model_bundle = _trained_model()
    if model_bundle is None:
        return AnomalyReport(
            score=heuristic_score,
            severity=_severity(heuristic_score),
            signals=signals,
            features=feature_map,
            model_notes="Heuristic fallback only; scikit-learn unavailable.",
        )

    model_score, prediction, decision_score = _model_anomaly_score(feature_map) or (heuristic_score, 1, 0.0)
    if heuristic_score < 30:
        score = int(round((0.95 * heuristic_score) + (0.05 * model_score)))
    else:
        score = int(round((0.55 * heuristic_score) + (0.45 * model_score)))
    if prediction == -1 and "Deviation from baseline telemetry pattern" not in signals:
        signals.insert(0, "Deviation from baseline telemetry pattern")
    if decision_score < 0 and score < 50:
        score = min(100, score + 10)

    return AnomalyReport(
        score=min(score, 100),
        severity=_severity(min(score, 100)),
        signals=signals,
        features=feature_map,
        model_notes=f"IsolationForest baseline trained on {len(BENIGN_BASELINE_LOGS)} benign telemetry samples.",
    )



