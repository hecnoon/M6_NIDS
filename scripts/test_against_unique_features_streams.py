import datetime
import pyshark
import csv
import argparse
from entry import get_entry

consolidate = True
consolidate_threshold_seconds = 1

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

    ip_streams = []
    anomalies = {}

    line = 0

    # Loop through the packets in the pcapng file
    for packet in cap:
        eth_type = packet.eth.type
        eth_src = packet.eth.src
        eth_dst = packet.eth.dst

        # Skip host PC traffic
        if eth_src == "0c:37:96:c3:0c:f3" or eth_src == "9c:7b:ef:76:62:66" or eth_src == "08:00:27:54:05:b6":
            continue

        protocol = packet.highest_layer
        ip_src = "0.0.0.0"
        ip_dst = "0.0.0.0"
        ip_proto = '0'
        ip_dst_port = '0'
        ip_src_port = '0'
        ip_stream = -1

        if 'IP' in packet:
            ip_src = packet.ip.src
            ip_dst = packet.ip.dst
            ip_proto = packet.ip.proto

            if 'TCP' in packet:
                ip_stream = packet.tcp.stream
                if ip_stream in ip_streams:
                    continue

                # Set all the protocols to TCP for obvious reasons
                protocol = 'TCP'
                ip_dst_port = packet.tcp.dstport

            elif 'UDP' in packet:
                # UDP traffic which is profinet does not have a fixed portnr
                if protocol != "PN_IO_DEVICE" and protocol != "PN_IO_CONTROLLER":
                    ip_src_port = packet.udp.srcport
                    ip_dst_port = packet.udp.dstport

        entry = (eth_type, eth_src, eth_dst, protocol, ip_src, ip_dst, ip_proto, ip_src_port, ip_dst_port)

        # Check if the entry from pcap is in the CSV entries
        if entry in csv_entries:
            if ip_stream != -1:
                ip_streams.append(ip_stream)
        else:
            #At this point we know that the package is not in the unique features set
            already_detected = False

            if entry in anomalies:
                #We have an exact match
                already_detected = True
                entry = anomalies[entry]
                entry["occurrences"] += 1
            elif consolidate:
                #We are going to check for the same entry with differing ports
                # If we find it and it is within a few second we consider it to be the same "anomaly"
                entry_without_src_port = (entry[0], entry[1], entry[2], entry[3], entry[4], entry[5], entry[6], entry[8])
                entry_without_dst_port = (entry[0], entry[1], entry[2], entry[3], entry[4], entry[5], entry[6], entry[7])
                for anomaly, metadata in anomalies.items():
                    anomaly_without_src_port = (anomaly[0], anomaly[1], anomaly[2], anomaly[3], anomaly[4], anomaly[5], anomaly[6], anomaly[8])
                    anomaly_without_dst_port = (anomaly[0], anomaly[1], anomaly[2], anomaly[3], anomaly[4], anomaly[5], anomaly[6], anomaly[7])
                    previous_sniff_time = metadata["sniff_time"]
                    if packet.sniff_time < previous_sniff_time + datetime.timedelta(
                            seconds=consolidate_threshold_seconds):
                        if anomaly_without_dst_port == entry_without_dst_port:
                            # Source is same
                            already_detected = True
                            metadata["src_port_same"] += 1
                            metadata["sniff_time"] = packet.sniff_time
                            break
                        elif anomaly_without_src_port == entry_without_src_port:
                            #Destination is same
                            already_detected = True
                            metadata["dst_port_same"] += 1
                            metadata["sniff_time"] = packet.sniff_time
                            break

            if not already_detected:
                anomalies[entry] = {"occurrences": 1,
                                    "src_port_same": 0,
                                    "dst_port_same": 0,
                                    "sniff_time": packet.sniff_time}
                print(entry)

        line += 1
        if line % 50000 == 0:
            print("{}, {}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), line))
        if line == num_lines:
            break

    cap.close()

    # Write the unique data to a CSV file
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["eth_type", "eth_src", "eth_dst", "protocol", "ip_src", "ip_dst", "ip_proto", "ip_src_port", "ip_dst_port", "occurrences", "src_port_same", "dst_port_same"])
        for anomaly, metadata in anomalies.items():
            row = anomaly + tuple({metadata["occurrences"]}) + tuple({metadata["src_port_same"]}) + tuple({metadata["dst_port_same"]})
            writer.writerow(row)


# Main function to handle command-line arguments
def main():
    parser = argparse.ArgumentParser(
        description="Check for unique entries in a pcapng file that are not in the provided CSV file")

    parser.add_argument('pcap_file', type=str, help="Path to the pcapng file")
    parser.add_argument('csv_file', type=str, help="Path to the CSV file")
    parser.add_argument('num_lines', type=int, help="Number of lines (packets) to read from the pcap file")
    parser.add_argument('-o', type=str, help="CSV file to write anomalies to")

    args = parser.parse_args()

    if not args.o:
        args.o = args.pcap_file.replace(".pcapng", ".csv")

    check_pcap_against_csv(args.pcap_file, args.csv_file, args.num_lines, args.o)


if __name__ == "__main__":
    main()
