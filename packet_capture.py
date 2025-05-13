import csv
from scapy.all import DNS, sniff, wrpcap
import os
import re

# File to store the captured DNS features 
csv_file = 'dns_features.csv'

# Step 1: Initialize the CSV file with the appropriate header
def initialize_csv():
    if not os.path.exists(csv_file) or os.stat(csv_file).st_size == 0:
        with open(csv_file, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["query_length", "subdomain_count", "packet_size", "label"])

# Step 2: Feature Extraction for DNS Packets
def extract_packet_features(packet):
    if DNS in packet and packet[DNS].qr == 0:  # Only consider DNS queries
        query_name = packet[DNS].qd.qname.decode()
        query_length = len(query_name)
        subdomain_count = query_name.count('.') - 1
        packet_size = len(packet)

        # Advanced logic to detect malicious packets
        is_malicious = is_malicious_dns_query(query_name, query_length, subdomain_count, packet_size)

        # Return the features as a dictionary
        return {
            "query_length": query_length,
            "subdomain_count": subdomain_count,
            "packet_size": packet_size,
            "label": 1 if is_malicious else 0  # Label as 1 for malicious traffic, 0 for normal
        }
    return None

# Step 3: Sophisticated logic to detect malicious DNS queries
def is_malicious_dns_query(query_name, query_length, subdomain_count, packet_size):
    # Strip trailing dot from the query name (if present)
    query_name = query_name.rstrip('.')

    # Debug: Print the query name and features
    print(f"Checking query: {query_name}, Length: {query_length}, Subdomains: {subdomain_count}, Size: {packet_size}")

    
    # Rule 2: Check for unusually long domain names (common in DGA-generated domains)
    if query_length > 50:  # Lowered threshold for long domain names
        print(f"Long domain name detected: {query_name}")
        return True

    # Rule 3: Check for excessive subdomains (common in DNS tunneling or exfiltration)
    if subdomain_count > 3:  # Lowered threshold for excessive subdomains
        print(f"Excessive subdomains detected: {query_name}")
        return True

    # Rule 4: Check for unusual packet sizes (common in DNS amplification attacks)
    if packet_size > 1000:  # Increased threshold for large DNS packets
        print(f"Large packet size detected: {packet_size}")
        return True

    # Rule 5: Check for suspicious patterns in the domain name (e.g., random-looking strings)
    if re.search(r"[a-z0-9]{15,}", query_name):  # Detect long random-looking strings
        print(f"Suspicious pattern detected: {query_name}")
        return True

    # Rule 6: Check for domains with high entropy (common in DGA domains)
    if calculate_entropy(query_name) > 4.0:  # Lowered threshold for high entropy
        print(f"High entropy detected: {query_name}")
        return True

    # If none of the rules match, assume the query is normal
    print(f"Query is normal: {query_name}")
    return False

# Step 4: Load a list of known malicious domains (e.g., from a file or API)

# Step 5: Calculate the entropy of a string (used to detect random-looking domains)
def calculate_entropy(s):
    from collections import Counter
    import math
    counter = Counter(s)
    entropy = 0.0
    for count in counter.values():
        probability = count / len(s)
        entropy -= probability * math.log2(probability)
    return entropy

# Step 6: Append the extracted features to the CSV file
def append_to_csv(features):
    with open(csv_file, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([features["query_length"], features["subdomain_count"], features["packet_size"], features["label"]])

# Step 7: Capture DNS Packets and Extract Features
def capture_dns(packet):
    features = extract_packet_features(packet)
    if features:
        append_to_csv(features)
        print(f"Captured DNS packet - Query: {packet[DNS].qd.qname.decode()}, Size: {features['packet_size']}, Subdomains: {features['subdomain_count']}, Label: {features['label']}")

# Main execution
if __name__ == "__main__":
    # Initialize the CSV file with headers
    initialize_csv()

    print("Starting packet capture for DNS traffic... Press Ctrl+C to stop.")
    
    # Start sniffing DNS packets on UDP port 53 and save features to the CSV
    try:
        sniff(filter="udp port 53", prn=capture_dns, store=0)
    except KeyboardInterrupt:
        print("Packet capture stopped.")