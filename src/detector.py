import pandas as pd


def detect_bruteforce(df: pd.DataFrame, threshold=10):
    """
    Detect IPs with failed attempts >= threshold.
    """
    failed_df = df[df["status"] == "FAILED"]

    brute_counts = (
        failed_df.groupby("ip")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values("failed_attempts", ascending=False)
    )

    brute_counts["severity"] = brute_counts["failed_attempts"].apply(severity_score)

    brute_force_ips = brute_counts[brute_counts["failed_attempts"] >= threshold]
    return brute_force_ips


def severity_score(count):
    """
    Simple SOC-like severity scoring.
    """
    if count >= 20:
        return "CRITICAL"
    elif count >= 15:
        return "HIGH"
    elif count >= 10:
        return "MEDIUM"
    else:
        return "LOW"


def detect_success_after_failures(df: pd.DataFrame, failure_threshold=5):
    """
    Detect suspicious pattern: multiple failures followed by success from same IP.
    """
    suspicious_events = []

    grouped = df.sort_values("timestamp").groupby("ip")

    for ip, group in grouped:
        failures = 0
        for _, row in group.iterrows():
            if row["status"] == "FAILED":
                failures += 1

            if row["status"] == "SUCCESS" and failures >= failure_threshold:
                suspicious_events.append({
                    "ip": ip,
                    "username": row["username"],
                    "failures_before_success": failures,
                    "success_time": row["timestamp"]
                })
                failures = 0  # reset after detection

    return pd.DataFrame(suspicious_events)


def get_top_usernames(df: pd.DataFrame, top_n=10):
    """
    Find most targeted usernames (failed attempts).
    """
    failed_df = df[df["status"] == "FAILED"]

    return (
        failed_df.groupby("username")
        .size()
        .reset_index(name="attempts")
        .sort_values("attempts", ascending=False)
        .head(top_n)
    )


def get_attack_activity_by_hour(df: pd.DataFrame):
    """
    Returns failed attempts grouped by hour.
    """
    failed_df = df[df["status"] == "FAILED"].copy()
    failed_df["hour"] = failed_df["timestamp"].dt.hour

    return (
        failed_df.groupby("hour")
        .size()
        .reset_index(name="failed_attempts")
        .sort_values("hour")
    )

