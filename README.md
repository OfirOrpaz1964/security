## Network Traffic Analyzer

This Python script uses `tshark` to capture live network traffic and analyzes each unique public IP address against the VirusTotal API to identify potential security threats. It's designed for network administrators and security professionals.

### Features

- **Traffic Capture**: Captures source IP addresses from network traffic for a user-specified duration.
- **Public IP Filtering**: Filters out private IP addresses to focus only on publicly accessible IPs.
- **VirusTotal Integration**: Checks each public IP against VirusTotal for reputational analysis, adhering to API rate limits.
- **Alert System**: Outputs alerts for IPs flagged as suspicious.

### Usage

To run the script, specify the duration of traffic capture in seconds:

```bash
python script.py <duration_in_seconds>
