def get_entry(packet):
    eth_type = packet.eth.type
    eth_src = packet.eth.src
    eth_dst = packet.eth.dst

    # Skip host PC traffic
    if eth_src == "0c:37:96:c3:0c:f3" or eth_src == "9c:7b:ef:76:62:66" or eth_src == "08:00:27:54:05:b6":
        return

    protocol = packet.highest_layer
    ip_src = "0.0.0.0"
    ip_dst = "0.0.0.0"
    ip_proto = '0'
    ip_dst_port = '0'
    ip_src_port = '0'

    if 'IP' in packet:
        ip_src = packet.ip.src
        ip_dst = packet.ip.dst
        ip_proto = packet.ip.proto

        if 'TCP' in packet:
            # Download, should always be port 102 as src or destination
            if packet.tcp.srcport == "102":
                ip_src_port = packet.tcp.srcport
            elif packet.tcp.dstport == "102":
                ip_dst_port = packet.tcp.dstport
            else:
                ip_src_port = packet.tcp.srcport
                ip_dst_port = packet.tcp.dstport
        elif 'UDP' in packet:
            # UDP traffic which is profinet does not have a fixed portnr
            if protocol != "PN_IO_DEVICE" and protocol != "PN_IO_CONTROLLER":
                ip_src_port = packet.udp.srcport
                ip_dst_port = packet.udp.dstport

    entry = (eth_type, eth_src, eth_dst, protocol, ip_src, ip_dst, ip_proto, ip_src_port, ip_dst_port)
    return entry
