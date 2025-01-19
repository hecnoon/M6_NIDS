from datetime import datetime
import os
import pyshark
import csv
import argparse
from entry import get_entry

# Function to extract the source, destination, and protocol information
def extract_data(pcap_dir, output_csv, num_lines):
    pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcapng')]

    # Set to store unique tuples
    unique_entries = {}

    # Loop through the files
    for pcap_file in pcap_files:
        file = os.path.join(pcap_dir, pcap_file)
        print("Opening {0}".format(file))
        # Open the pcapng file using pyshark
        cap = pyshark.FileCapture(file)
        print("Opened {0}".format(file))

        line = 0

        # Loop through the packets in the pcapng file
        for packet in cap:
            entry = get_entry(packet)
            if not entry:
                continue

            # Add entry when not existing
            if entry not in unique_entries:
                unique_entries[entry] = {"occurrences": 1,
                                      "capfiles": {pcap_file}}
                print(entry)
            else:
                entry = unique_entries[entry]
                entry["occurrences"] += 1
                if pcap_file not in entry["capfiles"]:
                    entry["capfiles"].add(pcap_file)

            # Logging and limitation
            line += 1
            if line % 50000 == 0:
                print("{}, {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), line))
            if line == num_lines:
                break

        # Close pcap
        cap.close()

    # Write the unique data to a CSV file
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["eth_type", "eth_src", "eth_dst", "protocol", "ip_src", "ip_dst", "ip_proto", "ip_src_port", "ip_dst_port", "occurrences", "capfiles"])
        for entry, metadata in unique_entries.items():
            row = entry + tuple({metadata["occurrences"]}) + tuple({'; '.join(metadata["capfiles"])})
            writer.writerow(row)

# Main function to handle command-line arguments
def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(
        description="Extract unique source, destination, and protocol from pcapng files")

    # Add arguments
    parser.add_argument('pcap_dir', type=str, help="Path to the pcapng directory")
    parser.add_argument('output_csv', type=str, help="Path to the output CSV file")
    parser.add_argument('num_lines', type=int, help="Number of lines (packets) to read from the pcap file")

    # Parse the arguments
    args = parser.parse_args()

    # Call the function with parsed arguments
    extract_data(args.pcap_dir, args.output_csv, args.num_lines)

if __name__ == "__main__":
    main()
