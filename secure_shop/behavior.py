"""Lab 4 — Behavioural anomaly detection (keystroke rhythm + login hour).

Implements the z-score pipeline from the lab:

    history -> profile (mean + std per feature) -> z-score the new login
    -> average anomaly score -> decision (allow / step-up MFA).

Only the Python standard library is used, exactly as the lab prescribes.
"""
import statistics

# The lab's threshold: an average z-score above this flags an anomaly.
DEFAULT_THRESHOLD = 3.0
# Minimum number of past logins needed before a profile is trustworthy.
MIN_HISTORY = 3

# Features used for scoring. typing_speed / gap_mean come from the client
# keystroke timing on the login page; hour is computed server-side from its own
# clock (the client cannot choose it).
FEATURES = ("typing_speed", "gap_mean", "hour")

# A floor for std so a very steady typist does not get std ~ 0 (which would make
# any tiny deviation look enormous). Mirrors the lab's std floor.
STD_FLOOR = {"typing_speed": 0.3, "gap_mean": 0.04, "hour": 0.5}


def z_score(value, mean, std):
    """Distance of value from mean, in standard deviations."""
    if std == 0:
        std = 0.1
    return abs(value - mean) / std


def build_profile(rows, features=FEATURES):
    """Build {feature: {mean, std}} from a list of dict-like history rows."""
    profile = {}
    for f in features:
        values = [float(r[f]) for r in rows if r.get(f) is not None]
        if len(values) < 2:
            continue  # need at least 2 points for a meaningful std
        mean = statistics.mean(values)
        std = statistics.pstdev(values)
        std = max(std, STD_FLOOR.get(f, 0.1))
        profile[f] = {"mean": mean, "std": std}
    return profile


def anomaly_score(login, profile, features=FEATURES):
    """Average z-score over the features that are present in both login+profile."""
    scores = []
    for f in features:
        if f in profile and login.get(f) is not None:
            scores.append(z_score(float(login[f]), profile[f]["mean"], profile[f]["std"]))
    if not scores:
        return None
    return sum(scores) / len(scores)


def decide(score, threshold=DEFAULT_THRESHOLD):
    """Return True when the score exceeds the threshold (-> step-up MFA)."""
    if score is None:
        return False
    return score > threshold
