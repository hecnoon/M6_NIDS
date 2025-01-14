from datetime import datetime
import os

import pyshark
import csv
import argparse

# Function to extract the source, destination, and protocol information
def extract_data(pcap_dir, output_csv, num_lines):
    pcap_files = [f for f in os.listdir(pcap_dir) if f.endswith('.pcapng')]

    # Set to store unique tuples
    unique_entries = set()

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
            #print (packet)

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
                else:
                    ip_src_port = packet.udp.srcport
                    ip_dst_port = packet.udp.dstport

            # Add entry when not existing
            entry = (eth_type, eth_src, eth_dst, protocol, ip_src, ip_dst, ip_proto, ip_src_port, ip_dst_port)
            if (entry not in unique_entries):
                unique_entries.add(entry)
                print(entry)

            # Logging and limitation
            line += 1
            #if line % 1000 == 0:
                #print("{}, {}".format(datetime.now().strftime("%Y-%m-%d %H:%M:%S"), line))
            if line == num_lines:
                break

        # Close pcap
        cap.close()

    # Write the unique data to a CSV file
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["eth_type", "eth_src", "eth_dst", "protocol", "ip_src", "ip_dst", "ip_proto", "ip_src_port", "ip_dst_port"])
        for entry in unique_entries:
            writer.writerow(entry)

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
