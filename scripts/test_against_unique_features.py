from datetime import datetime
import pyshark
import csv
import argparse
from entry import get_entry

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
    anomalies = {}

    line = 0

    # Loop through the packets in the pcapng file
    for packet in cap:
        entry = get_entry(packet)
        if not entry:
            continue

        # Check if the entry from pcap is in the CSV entries
        if entry not in csv_entries:
            if entry not in anomalies:
                anomalies[entry] = {"occurrences": 1,
                                    "first_occurence": datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
                print(entry)
            else:
                entry = anomalies[entry]
                entry["occurrences"] += 1

        line += 1
        if line % 50000 == 0:
            print("{}, {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), line))
        if line == num_lines:
            break

    cap.close()

    # Write the unique data to a CSV file
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["eth_type", "eth_src", "eth_dst", "protocol", "ip_src", "ip_dst", "ip_proto", "ip_src_port", "ip_dst_port", "occurrences", "first_occurence"])
        for entry, metadata in anomalies.items():
            row = entry + tuple({metadata["occurrences"]}) + tuple({metadata["first_occurence"]})
            writer.writerow(row)


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
