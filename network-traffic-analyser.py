import dpkt
import socket
import matplotlib.pyplot as plt
import datetime
import sys


def create_line_graph(timestamps, ports, title):
    """
    Creates a line graph of ports over time.

    Args:
        timestamps (list): List of timestamps for each data point.
        ports (list): List of port numbers corresponding to timestamps.
        title (str): Title for the graph.
    """

    plt.plot(timestamps, ports)
    plt.title(title)
    plt.xlabel('Time')
    plt.ylabel('Port')
    plt.show()


def analyze_tcp_traffic(pcap_file, malicious_ip):
    """
    Analyzes TCP traffic in a pcap file and creates graphs for source and destination ports
    of the malicious IP.

    Args:
        pcap_file (str): Path to the pcap file.
        malicious_ip (str): IP address to consider potentially malicious.
    """

    dest_port_list, dest_time_list = [], []
    source_port_list, source_time_list = [], []

    with open(pcap_file, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                l2 = dpkt.ethernet.Ethernet(buf)
                if l2.type not in (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6):
                    continue

                l3 = l2.data
                if l3.p != dpkt.ip.IP_PROTO_TCP:
                    continue

                source_ip = socket.inet_ntoa(l3.src)
                if source_ip != malicious_ip:
                    continue

                l4 = l3.data
                dest_port_list.append(l4.dport)
                source_port_list.append(l4.sport)
                dest_time_list.append(ts)
                source_time_list.append(ts)
            except (dpkt.dpkt.UnpackError,):
                pass  # Skip packets with decoding errors

    if dest_port_list:
        create_line_graph(dest_time_list, dest_port_list, f"{malicious_ip} TCP Destination Ports over Time")
    if source_port_list:
        create_line_graph(source_time_list, source_port_list, f"{malicious_ip} TCP Source Ports over Time")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python script.py <pcap_file> <malicious_ip>")
        sys.exit(1)
    pcap_file = sys.argv[1]
    malicious_ip = sys.argv[2]
    analyze_tcp_traffic(pcap_file, malicious_ip)