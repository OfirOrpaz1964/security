import subprocess
import requests
import sys
import time
import ipaddress

# Your VirusTotal API Key
API_KEY = 'VIRUS TOTAL API KEY'

def capture_traffic(duration):
    """ Capture traffic for a specified duration using tshark """
    print(f"Starting traffic capture for {duration} seconds...")
    command = ['tshark', '-a', f'duration:{duration}', '-T', 'fields', '-e', 'ip.src', '-Y', 'ip.src']
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print("Error running tshark:", result.stderr)
        raise Exception("Failed to capture traffic with tshark")
    print("Traffic capture completed.")
    return set(result.stdout.strip().split('\n'))

def is_public_ip(ip):
    """ Check if an IP address is public (not part of a private range) """
    try:
        return not ipaddress.ip_address(ip).is_private
    except ValueError:
        return False  # Ignore invalid IP addresses

def check_virustotal(ip):
    """ Check an IP against VirusTotal API """
    print(f"Checking IP {ip} against VirusTotal...")
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)
    data = response.json()
    print(f"Received response from VirusTotal for IP {ip}.")
    return data

def analyze_ips(ips):
    """ Analyze a set of IPs and check each IP against VirusTotal """
    delay = 20  # Delay in seconds (15 seconds to stay under the rate limit of 4 requests per minute)
    public_ips = [ip for ip in ips if ip and is_public_ip(ip)]
    print(f"All unique public IPs to be scanned: {public_ips}")
    for ip in public_ips:
        result = check_virustotal(ip)
        try:
            malicious_votes = result['data']['attributes']['last_analysis_stats']['malicious']
            alert_msg = f"ALERT: IP {ip} is flagged as suspicious. Malicious votes: {malicious_votes}"
            print(alert_msg) if malicious_votes > 0 else print(f"IP {ip} appears to be clean.")
        except KeyError:
            print(f"IP {ip} could not be analyzed. May not exist in VirusTotal database.")
        print(f"Waiting for {delay} seconds before the next request...")
        time.sleep(delay)  # Ensure compliance with API rate limit

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: script.py <duration_in_seconds>")
        sys.exit(1)
    duration = sys.argv[1]
    try:
        ips = capture_traffic(duration)
        analyze_ips(ips)
    except Exception as e:
        print(f"Error: {e}")
