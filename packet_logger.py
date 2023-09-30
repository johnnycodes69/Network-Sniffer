from scapy.all import *

import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename='packet_log.txt', level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# Define a function to log packets
def log_packet(packet):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    packet_info = f"{timestamp} - Packet received: {len(packet)} bytes"
    logging.info(packet_info)

# Replace 'eth0' with your network interface name
interface = 'eth0'

# Capture packets and log them
sniff(iface=interface, prn=lambda x: log_packet(x))