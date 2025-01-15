import os
from datetime import datetime

import pyshark
import csv
import argparse

# Function to read CSV file and store entries in a set
def read_csv(csv_file):
    unique_entries = set()

    with open(csv_file, mode='r') as file:
        reader = csv.reader(file)
        # Skip header
        next(reader)
        for row in reader:
            entry = tuple(row[:9])  # Convert each row into a tuple for comparison
            unique_entries.add(entry)

    return unique_entries

# Function to check pcap file entries not in the CSV
def check_pcap_against_csv(pcap_file, csv_file, num_lines, output_csv):
    # Read entries from the CSV file
    csv_entries = read_csv(csv_file)

    print(f"Opening {pcap_file}")
    cap = pyshark.FileCapture(pcap_file)
    print(f"Opened {pcap_file}")

    # Set to store detected anomalies
    anomalies = set()

    line = 0

    # Loop through the packets in the pcapng file
    for packet in cap:
        eth_type = packet.eth.type
        eth_src = packet.eth.src
        eth_dst = packet.eth.dst
        protocol = packet.highest_layer
        ip_proto = 0
        ip_src = "0.0.0.0"
        ip_dst = "0.0.0.0"
        ip_dst_port = 0
        ip_src_port = 0

        if 'IP' in packet:
            ip_proto = packet.ip.proto
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst

            if 'TCP' in packet:
                ip_src_port = packet.tcp.srcport
                ip_dst_port = packet.tcp.dstport
            elif 'UDP' in packet:
                ip_src_port = packet.udp.srcport
                ip_dst_port = packet.udp.dstport

        entry = (str(eth_type), eth_src, eth_dst, protocol, ip_src, ip_dst, str(ip_proto), str(ip_src_port),
                 str(ip_dst_port))

        # Check if the entry from pcap is in the CSV entries
        if entry not in csv_entries and entry not in anomalies:
            anomalies.add(entry)
            print(f"New entry found: {entry}")

        line += 1
        if line % 50000 == 0:
            print("{}, {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), line))
        if line == num_lines:
            break

    cap.close()

    # Write the unique data to a CSV file
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["eth_type", "eth_src", "eth_dst", "protocol", "ip_src", "ip_dst", "ip_proto", "ip_src_port", "ip_dst_port"])
        for entry in anomalies:
            writer.writerow(entry)


# Main function to handle command-line arguments
def main():
    parser = argparse.ArgumentParser(
        description="Check for unique entries in a pcapng file that are not in the provided CSV file")

    parser.add_argument('pcap_file', type=str, help="Path to the pcapng file")
    parser.add_argument('csv_file', type=str, help="Path to the CSV file")
    parser.add_argument('num_lines', type=int, help="Number of lines (packets) to read from the pcap file")
    parser.add_argument('output_csv', type=str, help="CSV file to write anomalies to")

    args = parser.parse_args()

    check_pcap_against_csv(args.pcap_file, args.csv_file, args.num_lines, args.output_csv)


if __name__ == "__main__":
    main()
