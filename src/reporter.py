import os
import pandas as pd
import matplotlib.pyplot as plt
from jinja2 import Template


def save_csv_report(df: pd.DataFrame, output_path: str):
    df.to_csv(output_path, index=False)


def generate_graph_top_ips(brute_df: pd.DataFrame, output_path: str):
    top10 = brute_df.head(10)

    plt.figure(figsize=(10, 6))
    plt.bar(top10["ip"], top10["failed_attempts"])
    plt.xticks(rotation=45, ha="right")
    plt.title("Top Attacking IPs (Failed SSH Logins)")
    plt.xlabel("IP Address")
    plt.ylabel("Failed Attempts")
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def generate_graph_attacks_by_hour(hour_df: pd.DataFrame, output_path: str):
    plt.figure(figsize=(10, 6))
    plt.plot(hour_df["hour"], hour_df["failed_attempts"], marker="o")
    plt.title("SSH Failed Login Attempts by Hour")
    plt.xlabel("Hour (0-23)")
    plt.ylabel("Failed Attempts")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()


def save_html_report(summary: dict, output_path: str):
    template_str = """
    <html>
    <head>
        <title>Mini SIEM Report</title>
        <style>
            body { font-family: Arial; margin: 30px; }
            h1 { color: #222; }
            table { border-collapse: collapse; width: 100%; margin-top: 10px; }
            th, td { border: 1px solid #ccc; padding: 8px; }
            th { background-color: #f2f2f2; }
            .critical { color: red; font-weight: bold; }
            .high { color: darkorange; font-weight: bold; }
            .medium { color: goldenrod; font-weight: bold; }
            .low { color: green; font-weight: bold; }
        </style>
    </head>
    <body>
        <h1>Mini SIEM - SSH Attack Report</h1>

        <h2>Summary</h2>
        <p><b>Total Events:</b> {{ total_events }}</p>
        <p><b>Total Failed Attempts:</b> {{ total_failed }}</p>
        <p><b>Total Successful Logins:</b> {{ total_success }}</p>

        <h2>Top Attacking IPs</h2>
        {{ brute_table | safe }}

        <h2>Suspicious Success After Failures</h2>
        {{ suspicious_table | safe }}

        <h2>Most Targeted Usernames</h2>
        {{ usernames_table | safe }}

        <h2>Graphs</h2>
        <img src="{{ graph_top_ips }}" width="800"><br><br>
        <img src="{{ graph_by_hour }}" width="800">

    </body>
    </html>
    """

    template = Template(template_str)
    html_content = template.render(**summary)

    with open(output_path, "w") as f:
        f.write(html_content)

