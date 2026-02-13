# Mini SIEM – SSH Log Analyzer

This project is a beginner-friendly cybersecurity mini SIEM tool that analyzes Linux SSH authentication logs to detect brute-force attacks and suspicious login behavior.

## Features
- Parses SSH auth logs
- Detects brute-force attacks by IP
- Identifies successful logins after repeated failures
- Generates CSV and HTML incident reports
- Visualizes attacker activity with graphs

## Tech Stack
- Python
- Pandas
- Matplotlib
- Regex log parsing

## How to Run

```bash
git clone https://github.com/amina-ajim/mini-siem-log-analyzer.git
cd mini-siem-log-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 src/main.py --log logs/sample_auth.log --output reports --threshold 10

