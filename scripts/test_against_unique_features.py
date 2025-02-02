import datetime
import pyshark
import csv
import argparse
from features import get_tuple

consolidate = True
consolidate_threshold_seconds = 2

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
    no_anomalies = {}

    line = 0

    # Loop through the packets in the pcapng file
    for packet in cap:
        ip_stream = -1
        if 'TCP' in packet:
            ip_stream = packet.tcp.stream
            if ip_stream in ip_streams:
                continue

        entry = get_tuple(packet)
        if entry is None:
            continue

        # Check if the entry from pcap is in the CSV entries
        if entry in csv_entries:
            #If it is then future packets within the same stream are valid
            if ip_stream != -1:
                ip_streams.append(ip_stream)

            #Here we should add it to the no_anomalies list
            if entry in no_anomalies:
                entry = no_anomalies[entry]
                entry["occurrences"] += 1
            else:
                no_anomalies[entry] = {"occurrences": 1}
        else:
            #At this point we know that the package is not in the unique features set
            already_detected_before = False

            if entry in anomalies:
                #We have an exact match with an earlier anomaly
                already_detected_before = True
                entry = anomalies[entry]
                entry["occurrences"] += 1
            elif consolidate and (entry[7] != '0' or entry[8] != '0'):
                #We are going to check for the same entry with differing ports
                # If we find it and it is within a few second we consider it to be the same "anomaly"
                entry_without_src_port = entry[0:7] + entry[8:1]
                entry_without_dst_port = entry[0:8]
                for anomaly, metadata in anomalies.items():
                    if anomaly[7] == '0' and anomaly[8] == '0':
                        continue

                    anomaly_without_src_port = anomaly[0:7] + anomaly[8:1]
                    anomaly_without_dst_port = anomaly[0:8]

                    previous_sniff_time = metadata["sniff_time"]
                    if packet.sniff_time < previous_sniff_time + datetime.timedelta(seconds=consolidate_threshold_seconds):
                        if anomaly_without_dst_port == entry_without_dst_port:
                            # Source is same
                            already_detected_before = True
                            metadata["src_port_same"] += 1
                            metadata["sniff_time"] = packet.sniff_time
                            break
                        elif anomaly_without_src_port == entry_without_src_port:
                            #Destination is same
                            already_detected_before = True
                            metadata["dst_port_same"] += 1
                            metadata["sniff_time"] = packet.sniff_time
                            break

            if not already_detected_before:
                #This is anew anomaly
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

    # Write the anomaly data to a CSV file
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Anomalies"])
        writer.writerow(["eth_type", "eth_src", "eth_dst", "protocol", "ip_src", "ip_dst", "ip_proto", "ip_src_port", "ip_dst_port", "occurrences", "src_port_same", "dst_port_same"])
        for anomaly, metadata in anomalies.items():
            row = anomaly + tuple({metadata["occurrences"]}) + tuple({metadata["src_port_same"]}) + tuple({metadata["dst_port_same"]})
            writer.writerow(row)

        writer.writerow([])
        writer.writerow(["Non anomalies"])
        writer.writerow(["eth_type", "eth_src", "eth_dst", "protocol", "ip_src", "ip_dst", "ip_proto", "ip_src_port", "ip_dst_port", "occurrences"])
        for anomaly, metadata in no_anomalies.items():
            row = anomaly + tuple({metadata["occurrences"]})
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
