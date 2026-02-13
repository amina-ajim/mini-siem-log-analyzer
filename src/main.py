import os
import argparse
import pandas as pd

from parser import parse_auth_log
from detector import (
    detect_bruteforce,
    detect_success_after_failures,
    get_top_usernames,
    get_attack_activity_by_hour
)
from reporter import (
    save_csv_report,
    generate_graph_top_ips,
    generate_graph_attacks_by_hour,
    save_html_report
)


def main():
    parser = argparse.ArgumentParser(description="Mini SIEM - SSH Brute Force Detector")
    parser.add_argument("--log", required=True, help="Path to auth.log file")
    parser.add_argument("--output", default="reports", help="Output folder path")
    parser.add_argument("--threshold", type=int, default=10, help="Brute force detection threshold")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    graphs_dir = os.path.join(args.output, "graphs")
    os.makedirs(graphs_dir, exist_ok=True)

    print("[+] Parsing log file...")
    events = parse_auth_log(args.log)

    if not events:
        print("[-] No SSH login events found in log file.")
        return

    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"])

    total_events = len(df)
    total_failed = len(df[df["status"] == "FAILED"])
    total_success = len(df[df["status"] == "SUCCESS"])

    print("[+] Running brute force detection...")
    brute_df = detect_bruteforce(df, threshold=args.threshold)

    print("[+] Detecting suspicious success-after-failures...")
    suspicious_df = detect_success_after_failures(df, failure_threshold=5)

    print("[+] Extracting targeted usernames...")
    usernames_df = get_top_usernames(df)

    print("[+] Extracting hourly attack activity...")
    hourly_df = get_attack_activity_by_hour(df)

    csv_path = os.path.join(args.output, "report.csv")
    save_csv_report(brute_df, csv_path)

    graph_top_ips_path = os.path.join(graphs_dir, "top_ips.png")
    graph_by_hour_path = os.path.join(graphs_dir, "attacks_by_hour.png")

    if not brute_df.empty:
        generate_graph_top_ips(brute_df, graph_top_ips_path)

    if not hourly_df.empty:
        generate_graph_attacks_by_hour(hourly_df, graph_by_hour_path)

    html_path = os.path.join(args.output, "report.html")

    summary = {
        "total_events": total_events,
        "total_failed": total_failed,
        "total_success": total_success,
        "brute_table": brute_df.to_html(index=False),
        "suspicious_table": suspicious_df.to_html(index=False) if not suspicious_df.empty else "<p>No suspicious success-after-failure patterns found.</p>",
        "usernames_table": usernames_df.to_html(index=False),
        "graph_top_ips": "graphs/top_ips.png",
        "graph_by_hour": "graphs/attacks_by_hour.png",
    }

    save_html_report(summary, html_path)

    print("\n[+] Report generated successfully!")
    print(f"[+] CSV Report: {csv_path}")
    print(f"[+] HTML Report: {html_path}")
    print(f"[+] Graphs Folder: {graphs_dir}")
    print(f"[DEBUG] Parsed events count: {len(events)}")


if __name__ == "__main__":
    main()

