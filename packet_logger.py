from scapy.all import *
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Logging funciton
def log_packet(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    packet_info = f"{timestamp} - Packet received: {len(packet)} bytes"
    
    if IP in packet:
        packet_info += f", Source IP: {packet[IP].src}, Destination IP: {packet[IP].dst}"

    # Get more stuff from each packet
        if TCP in packet:
            packet_info += f", Source Port: {packet[TCP].sport}, Destination Port: {packet[TCP].dport}, Protocol: TCP"
        elif UDP in packet:
            packet_info += f", Source Port: {packet[UDP].sport}, Destination Port: {packet[UDP].dport}, Protocol: UDP"
        else:
            packet_info += f", Protcol: {packet[IP].proto}"
    
    else:
        packet_info += ", Non-IP packet"

    logging.info(packet_info)

# Replace 'Ethernet' with name of interface to monitor
interface = 'Ethernet'

# Do the thing
sniff(iface=interface, prn=lambda x: log_packet(x))