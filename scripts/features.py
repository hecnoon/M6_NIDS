def get_tuple(packet):
    eth_type = packet.eth.type
    eth_src = packet.eth.src
    eth_dst = packet.eth.dst

    # Skip monitoring PC traffic
    if (eth_src == "08:00:27:3c:77:a5" or  # kali, eth0
            eth_src == "08:00:27:4f:bc:c1" or  # kali, eth1
            eth_src == "0c:37:96:c3:0c:f3" or  # USB dongle
            eth_src == "9c:7b:ef:76:62:66" or  # host machine
            eth_src == "08:00:27:54:05:b6" or  # kali, old eth0
            eth_dst == "08:00:27:3c:77:a5" or
            eth_dst == "08:00:27:4f:bc:c1" or
            eth_dst == "0c:37:96:c3:0c:f3" or
            eth_dst == "9c:7b:ef:76:62:66" or
            eth_dst == "08:00:27:54:05:b6"):
        return None

    protocol = packet.highest_layer
    ip_src = "0.0.0.0"
    ip_dst = "0.0.0.0"
    ip_proto = '0'
    ip_dst_port = '0'
    ip_src_port = '0'

    if 'ARP' in packet:
        ip_src = packet.arp.src_proto_ipv4
        ip_dst = packet.arp.dst_proto_ipv4
        # Skip monitoring PC traffic
        if (ip_src == "192.168.0.3" or  # kali, eth0
                ip_dst == "192.168.0.3"):  # kali, eth0
            return None

    if 'IP' in packet:
        ip_src = packet.ip.src
        ip_dst = packet.ip.dst
        ip_proto = packet.ip.proto

        if 'TCP' in packet:
            # Set all the protocols to TCP for obvious reasons
            protocol = 'TCP'
            ip_dst_port = packet.tcp.dstport

        elif 'UDP' in packet:
            # UDP traffic which is profinet does not have a fixed portnr
            if protocol != "PN_IO_DEVICE" and protocol != "PN_IO_CONTROLLER":
                ip_src_port = packet.udp.srcport
                ip_dst_port = packet.udp.dstport

    return eth_type, eth_src, eth_dst, protocol, ip_src, ip_dst, ip_proto, ip_src_port, ip_dst_port
