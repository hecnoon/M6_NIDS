import datetime
import pyshark
import csv
import argparse

# Function to extract the source, destination, and protocol information
def extract_data(pcap_file, output_csv, num_lines):

    print("Opening {0}".format(pcap_file))
    # Open the pcapng file using pyshark
    cap = pyshark.FileCapture(pcap_file, display_filter="eth.type == PROFINET")
    print("Opened {0}".format(pcap_file))

    # Set to store unique (source, destination, protocol) tuples
    unique_entries = set()
    line = 0

    # Loop through the packets in the pcapng file
    for packet in cap:
        #print (packet)
        # Check if the protocol contains "PN"

        source = packet.eth.src
        destination = packet.eth.dst
        protocol = packet.highest_layer
        # Add the tuple of (source, destination, protocol) to the set
        unique_entries.add((source, destination, protocol))

        line += 1
        if line % 1000 == 0:
            print("{}, {}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), line))
        if line == num_lines:
            break


    # Write the unique data to a CSV file
    with open(output_csv, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Source", "Destination", "Protocol"])
        for entry in unique_entries:
            writer.writerow(entry)

    print(f"Unique source, destination, and protocol data has been written to {output_csv}")


# Main function to handle command-line arguments
def main():
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(
        description="Extract unique source, destination, and protocol from pcapng file where protocol contains 'PN'")

    # Add arguments
    parser.add_argument('pcap_file', type=str, help="Path to the input pcapng file")
    parser.add_argument('output_csv', type=str, help="Path to the output CSV file")
    parser.add_argument('num_lines', type=int, help="Number of lines (packets) to read from the pcap file")

    # Parse the arguments
    args = parser.parse_args()

    # Call the function with parsed arguments
    extract_data(args.pcap_file, args.output_csv, args.num_lines)


if __name__ == "__main__":
    main()
