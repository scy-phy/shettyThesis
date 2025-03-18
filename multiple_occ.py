### Get multiple occurrences in NIDS notifications format 
### with packet numbers for both allowed and not allowed rules as well as the packet_list.csv that contains the list of extracted pakets with keys
### and this file is used to then label the extracted packets with the corresponding predictions.

import pyshark
import csv
import re
from collections import defaultdict

# Define counters to store occurrences and corresponding packet numbers for each notification type
mac_counter = defaultdict(lambda: {'count': 0, 'packets': []})
mac_active_counter = defaultdict(lambda: {'count': 0, 'packets': []})
mac_protocol_counter = defaultdict(lambda: {'count': 0, 'packets': []})
mac_mac_counter = defaultdict(lambda: {'count': 0, 'packets': []})
mac_mac_protocol_counter = defaultdict(lambda: {'count': 0, 'packets': []})
mac_function_counter = defaultdict(lambda: {'count': 0, 'packets': []})
mac_mac_function_counter = defaultdict(lambda: {'count': 0, 'packets': []})

protocol_counter = defaultdict(lambda: {'count': 0, 'packets': []})
arp_gratuitous_counter = defaultdict(lambda: {'count': 0, 'packets': []})
ip_mac_counter = defaultdict(lambda: {'count': 0, 'packets': []})

tcp_retransmission_counter = defaultdict(lambda: {'count': 0, 'packets': []})
tcp_duplicate_ack_counter = defaultdict(lambda: {'count': 0, 'packets': []})

s7comm_program_counter = defaultdict(lambda: {'count': 0, 'packets': []})

# Same for IP-based notifications
ip_counter = defaultdict(lambda: {'count': 0, 'packets': []})
ip_active_counter = defaultdict(lambda: {'count': 0, 'packets': []})
ip_protocol_counter = defaultdict(lambda: {'count': 0, 'packets': []})
ip_ip_counter = defaultdict(lambda: {'count': 0, 'packets': []})
ip_ip_protocol_counter = defaultdict(lambda: {'count': 0, 'packets': []})
ip_function_counter = defaultdict(lambda: {'count': 0, 'packets': []})
ip_ip_function_counter = defaultdict(lambda: {'count': 0, 'packets': []})

# List to hold notification details
notifications = []

def get_protocol(pkt):
    protocol = None
    if hasattr(pkt, 'arp'):
        protocol = 'ARP'
    elif hasattr(pkt, 'lldp'):
        protocol = 'LLDP'
    elif pkt.highest_layer in ['PN_IO', 'PN_IO_DEVICE', 'PN_DCP', 'PN_IO_CONTROLLER', 'PN_PTCP']:
        protocol = 'Profinet'
    elif hasattr(pkt, 's7comm'):
        protocol = 'S7'
    elif hasattr(pkt, 'cotp'):
        protocol = 'S7'
        
    return protocol

def remove_ansi_escape_codes(text):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

def get_function(pkt):
    function = None
    if hasattr(pkt, 'arp'):
        opcode_value = pkt.arp.opcode.showname_value
        opcode_value_clean = opcode_value.split('(')[0].strip()
        function = opcode_value_clean

    elif hasattr(pkt, 'pn_io_device') or hasattr(pkt, 'pn_io_controller'):
        if hasattr(pkt, 'dcerpc'):
            if hasattr(pkt, 'pn_io_device'):
                p_layer_str = str(pkt.pn_io_device)
            else:
                p_layer_str = str(pkt.pn_io_controller)

            dce_layer_str = str(pkt.dcerpc)

            # Remove ANSI escape codes
            p_layer_str_clean = remove_ansi_escape_codes(p_layer_str)
            dce_layer_str_clean = remove_ansi_escape_codes(dce_layer_str)

            operation_match = re.search(r'Operation:\s*(\w+)\s*\(\d+\)', p_layer_str_clean)
            operation_value = operation_match.group(1) if operation_match else None

            packet_type_match = re.search(r'Packet type:\s*(\w+)\s*\(\d+\)', dce_layer_str_clean)
            packet_type_value = packet_type_match.group(1) if packet_type_match else None

            function = f"DCE RPC {operation_value} {packet_type_value}"

    elif hasattr(pkt, 'pn_dcp'):
        pn_dcp_layer_str = str(pkt.pn_dcp)
        pn_dcp_layer_str_clean = remove_ansi_escape_codes(pn_dcp_layer_str)

        service_id_match = re.search(r'ServiceID:\s*(\w+)\s*\(\d+\)', pn_dcp_layer_str_clean)
        service_id_value = service_id_match.group(1) if service_id_match else None

        service_type_match = re.search(r'ServiceType:\s*([\w\s]+)\s*\(\d+\)', pn_dcp_layer_str_clean)
        service_type_value = service_type_match.group(1) if service_type_match else None

        func = f"{service_id_value} {service_type_value}"
        funct = func.upper().strip()
        if funct == "IDENTIFY REQUEST":
            function = f"PN DCP {service_id_value} {service_type_value}"
        elif funct == "IDENTIFY RESPONSE SUCCESS":
            function = f"PN DCP {service_id_value} {service_type_value}"
        elif funct == "SET REQUEST":
            function = f"PN DCP {service_id_value} {service_type_value}"
        elif funct == "SET RESPONSE SUCCESS":
            function = f"PN DCP SET SUCCESS"

    elif hasattr(pkt, 'pn_ptcp'):
        if hasattr(pkt, 'pn_rt'):
            pn_rt_layer_str = str(pkt.pn_rt)
            
            # Remove ANSI escape sequences if necessary
            pn_rt_layer_str_clean = remove_ansi_escape_codes(pn_rt_layer_str)
            
            delay_match = re.search(r'FrameID:\s*0x\w+\s*\(.*?:\s*(Delay)\)', pn_rt_layer_str_clean)
            
            if delay_match:
                delay = delay_match.group(1)  # Extract the Delay description
                function = f"PTCP {delay} REQUEST"

    elif hasattr(pkt, 'lldp'):
        function = "CLIENT REPORT"

    elif hasattr(pkt, 's7comm'):
        # Convert the layer output to string to parse it
        s7_layer_str = str(pkt.s7comm)
        header = pkt.s7comm.header
        # Remove ANSI escape sequences using regex
        s7_layer_str_clean = remove_ansi_escape_codes(s7_layer_str)
        
        # Check if the "Parameter:" field is present
        if "Parameter:" in s7_layer_str_clean:
            # Extract the line containing the parameter
            parameter_line = [line for line in s7_layer_str_clean.splitlines() if "Parameter:" in line]
            
            # Ensure the list is not empty before trying to extract the function
            if parameter_line:
                # Use regex to extract the first value inside the parentheses
                match = re.search(r'\((.*?)\)', parameter_line[0])
                if match:
                    parameter_value = match.group(1).strip()  # Extract the value inside the parentheses
                    
                    # Map the parameter to the desired function
                    if parameter_value == "Setup communication":
                        function = "OPEN CONNECTION"
                    elif parameter_value == "Read Var":
                        function = "READ"
                    elif "->(Read SZL)" in parameter_line[0]:
                        function = "STATE LIST"
                    elif parameter_value == "Request download":
                        function = "DOWNLOAD REQUEST"
                    elif parameter_value == "Download block":
                        function = "DOWNLOAD"
                    elif parameter_value == "Download ended":
                        function = "DOWNLOAD END"
                    elif parameter_value == "PI-Service" and "P_PROGRAM()" not in parameter_line[0] and "(Job)" in header:
                        function = "PLC CONTROL"
                    elif parameter_value == "PLC Stop":
                        function = "PLC STOP"
                    else:
                        function = None


    elif hasattr(pkt, 'pn_rt'):
        pnrt_layer_str = str(pkt.pn_rt)
        pnrt_layer_str_clean = remove_ansi_escape_codes(pnrt_layer_str)

        if "FrameID:" in pnrt_layer_str_clean:
            FrameID_line = [line for line in pnrt_layer_str_clean.splitlines() if "FrameID:" in line]

            if FrameID_line:
                # Use regex to extract the first value inside the parentheses
                match = re.search(r'\((.*?)\)', FrameID_line[0])
                if match:
                    FrameID_value = match.group(1).strip()  # Extract the value inside the parentheses
                    if "low" in FrameID_value:
                        function = "ACYCLIC IO ALARM LOW"
                    elif "high" in FrameID_value:
                        function = "ACYCLIC IO ALARM HIGH"
                    else:
                        function = None

            
    elif hasattr(pkt, 'cotp'):
        cotp_layer_str = str(pkt.cotp)
        cotp_layer_str_clean = remove_ansi_escape_codes(cotp_layer_str)
        match = re.search(r'PDU Type: ([\w\s]+) \(', cotp_layer_str_clean)
        if match:
            func = match.group(1).strip()
            funct = func.upper()
        if funct == "CR CONNECT REQUEST":
            function = "PLUS_REQUEST"
        elif funct == "CC CONNECT CONFIRM":
            function = "PLUS_RESPONSE"
        elif funct == "DT DATA":
            function = "PLUS_DATA"

    if function == None:
        return function
    else:
        return function.upper().strip()

# Update the function to increment count and store packet numbers
def add_notification(packet_num, notification_type, ip_src, mac_src, ip_dst, mac_dst, protocol, mac, ip, function, counter, key):
    # Check if count is less than 10 and then add the notification
    if counter[key]['count'] < 10:
        notifications.append((packet_num, notification_type, ip_src, mac_src, ip_dst, mac_dst, protocol, mac, ip, function))
        counter[key]['count'] += 1
        counter[key]['packets'].append(packet_num)

def check_first_occurrences(packet):

    mac_src = None
    mac_dst = None
    ip_src = None
    ip_dst = None
    protocol = None
    function = None
    
    # Extract Ethernet Layer (MAC addresses)
    if 'eth' in packet:
        mac_src = packet.eth.src
        mac_dst = packet.eth.dst
    
    # Extract IP Layer
    if 'ip' in packet:
        ip_src = packet.ip.src
        ip_dst = packet.ip.dst
    
    # Extract protocol from IP or other layers
    protocol = get_protocol(packet)
    function = get_function(packet)

    if mac_src:
        add_notification(packet.number, 'MAC', None, mac_src, None, mac_dst, None, mac_src, None, None, mac_counter, mac_src)

    if mac_dst:
        add_notification(packet.number, 'MAC', None, mac_src, None, mac_dst, None, mac_dst, None, None, mac_counter, mac_dst)

    if protocol:
        add_notification(packet.number, 'PROTOCOL', ip_src, mac_src, ip_dst, mac_dst, protocol, None, None, None, protocol_counter, protocol)

    if mac_src:
        add_notification(packet.number, 'MAC_ACTIVE', None, mac_src, None, mac_dst, None, mac_src, None, None, mac_active_counter, mac_src)

    if mac_src and mac_dst:
        mac_pair = tuple(sorted([mac_src, mac_dst]))
        add_notification(packet.number, 'MAC_MAC', None, mac_src, None, mac_dst, protocol, None, None, None, mac_mac_counter, mac_pair)

    if ip_src and mac_src:
        add_notification(packet.number, 'IP_MAC', ip_src, mac_src, ip_dst, mac_dst, protocol, mac_src, ip_src, None, ip_mac_counter, (ip_src, mac_src))

    if ip_dst and mac_dst:
        add_notification(packet.number, 'IP_MAC', ip_src, mac_src, ip_dst, mac_dst, protocol, mac_dst, ip_dst, None, ip_mac_counter, (ip_dst, mac_dst))
    
    if 'ip' not in packet:
        if hasattr(packet, 'arp'):
            arp_layer_str = str(packet.arp)
            arp_layer_str_clean = remove_ansi_escape_codes(arp_layer_str)
            if 'Is gratuitous: True' in arp_layer_str_clean:
                if mac_src:
                    add_notification(packet.number, 'ARP_GRATUITOUS_REQUEST', None, mac_src, None, mac_dst, None, mac_src, None, None, arp_gratuitous_counter, mac_src)

        if mac_src and protocol:
            add_notification(packet.number, 'MAC_PROTOCOL', None, mac_src, None, mac_dst, protocol, mac_src, None, None, mac_protocol_counter, (mac_src, protocol))

        if mac_dst and protocol:
            add_notification(packet.number, 'MAC_PROTOCOL', None, mac_src, None, mac_dst, protocol, mac_dst, None, None, mac_protocol_counter, (mac_dst, protocol))

        if mac_src and function:
            add_notification(packet.number, 'MAC_FUNCTION', None, mac_src, None, mac_dst, protocol, mac_src, None, function, mac_function_counter, (mac_src, function))

        if mac_dst and function:
            add_notification(packet.number, 'MAC_FUNCTION', None, mac_src, None, mac_dst, protocol, mac_dst, None, function, mac_function_counter, (mac_dst, function))

        if mac_src and mac_dst and protocol:
            mac_protocol_pair = tuple(sorted([mac_src, mac_dst, protocol]))
            add_notification(packet.number, 'MAC_MAC_PROTOCOL', None, mac_src, None, mac_dst, protocol, None, None, None, mac_mac_protocol_counter, mac_protocol_pair)

        if mac_src and mac_dst and function:
            mac_function_pair = tuple(sorted([mac_src, mac_dst, function]))
            add_notification(packet.number, 'MAC_MAC_FUNCTION', None, mac_src, None, mac_dst, protocol, None, None, function, mac_mac_function_counter, mac_function_pair)

        return
    
    # TCP retransmission and duplicate ACK notifications
    if hasattr(packet, 'tcp'):
        reset = packet.tcp.flags_reset.get_default_value()
        ack = packet.tcp.flags_ack.get_default_value()
        if (reset == "True") and (ack == "True"):  # Check for duplicate ACK (RST and ACK flag)
            key = (ip_src, ip_dst, 'TCP_DUPLICATE_ACK')
            add_notification(packet.number, 'TCP_DUPLICATE_ACK', ip_src, mac_src, ip_dst, mac_dst, protocol, None, None, None, tcp_duplicate_ack_counter, key)
        elif reset == "True":  # Check for TCP retransmission (RST flag)
            key = (ip_src, ip_dst, 'TCP_RETRANSMISSION')
            add_notification(packet.number, 'TCP_RETRANSMISSION', ip_src, mac_src, ip_dst, mac_dst, protocol, None, None, None, tcp_retransmission_counter, key)
            
    if ip_src and ip_dst:
        if hasattr(packet, 's7comm') and hasattr(packet, 'cotp'):
            s7_layer_str = str(packet.s7comm)
            s7_layer_str_clean = remove_ansi_escape_codes(s7_layer_str)

            if "Parameter:" in s7_layer_str_clean:
                parameter_line = [line for line in s7_layer_str_clean.splitlines() if "Parameter:" in line]

                if parameter_line:
                    match = re.search(r'\((.*?)\)', parameter_line[0])
                    if match:
                        parameter_value = match.group(1).strip()

                        if parameter_value == "PI-Service" and "P_PROGRAM()" in parameter_line[0]:
                            key1 = (ip_src, 'PROGRAM_UPLOAD')
                            add_notification(packet.number, 'PROGRAM_UPLOAD', ip_src, mac_src, ip_dst, mac_dst, protocol, mac_src, ip_src, None, s7comm_program_counter, key1)
                            key2 = (ip_dst, 'PROGRAM_UPLOAD')
                            add_notification(packet.number, 'PROGRAM_UPLOAD', ip_src, mac_src, ip_dst, mac_dst, protocol, mac_dst, ip_dst, None, s7comm_program_counter, key2)

    
    if ip_src:
        add_notification(packet.number, 'IP', ip_src, None, ip_dst, None, None, None, ip_src, None, ip_counter, ip_src)

    if ip_dst:
        add_notification(packet.number, 'IP', ip_src, None, ip_dst, None, None, None, ip_dst, None, ip_counter, ip_dst)

    if ip_src and protocol:
        add_notification(packet.number, 'IP_PROTOCOL', ip_src, None, ip_dst, None, protocol, None, ip_src, None, ip_protocol_counter, (ip_src, protocol))

    if ip_src:
        add_notification(packet.number, 'IP_ACTIVE', ip_src, None, ip_dst, None, None, None, ip_src, None, ip_active_counter, ip_src)

    if ip_dst and protocol:
        add_notification(packet.number, 'IP_PROTOCOL', ip_src, None, ip_dst, None, protocol, None, ip_dst, None, ip_protocol_counter, (ip_dst, protocol))

    if ip_src and function:
        add_notification(packet.number, 'IP_FUNCTION', ip_src, None, ip_dst, None, protocol, None, ip_src, function, ip_function_counter, (ip_src, function))

    if ip_dst and function:
        add_notification(packet.number, 'IP_FUNCTION', ip_src, None, ip_dst, None, protocol, None, ip_dst, function, ip_function_counter, (ip_dst, function))
    
    if ip_src and ip_dst:
        ip_pair = tuple(sorted([ip_src, ip_dst]))
        add_notification(packet.number, 'IP_IP', ip_src, None, ip_dst, None, protocol, None, None, None, ip_ip_counter, ip_pair)

    if ip_src and ip_dst and protocol:
        ip_protocol_pair = tuple(sorted([ip_src, ip_dst, protocol]))
        add_notification(packet.number, 'IP_IP_PROTOCOL', ip_src, None, ip_dst, None, protocol, None, None, None, ip_ip_protocol_counter, ip_protocol_pair)

    if ip_src and ip_dst and function:
        ip_function_pair = tuple(sorted([ip_src, ip_dst, function]))
        add_notification(packet.number, 'IP_IP_FUNCTION', ip_src, None, ip_dst, None, protocol, None, None, function, ip_ip_function_counter, ip_function_pair)

# Open the pcap file using PyShark
pcap_file = 'filtered_attack.pcap'
capture = pyshark.FileCapture(pcap_file)
count = 0
start_frame = 1
end_frame = 18500001

for packet in capture:
    
    if count >= end_frame - start_frame:
        break

    if start_frame <= int(packet.number.get_default_value()) < end_frame:
        
        check_first_occurrences(packet)

        count += 1

output_csv = 'notifications_test_occurrences_10.csv'

with open(output_csv, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Packet Number', 'Type', 'SourceIP', 'SourceMAC', 'DestinationIP', 'DestinationMAC', 'Protocol', 'MAC', 'IP', 'Function'])
    writer.writerows(notifications)

print(f"Notifications for test occurrences saved to {output_csv}")

# Define the output CSV file for lists of packets
packets_csv = 'packets_list_10.csv'

# Define the list of counter dictionaries to iterate through
counters = [
    mac_counter, mac_active_counter, mac_protocol_counter, mac_mac_counter, mac_mac_protocol_counter, 
    mac_function_counter, mac_mac_function_counter, protocol_counter, arp_gratuitous_counter, 
    ip_mac_counter, tcp_retransmission_counter, tcp_duplicate_ack_counter, s7comm_program_counter, 
    ip_counter, ip_active_counter, ip_protocol_counter, ip_ip_counter, ip_ip_protocol_counter, 
    ip_function_counter, ip_ip_function_counter
]

# Open the CSV file and write each list of packet numbers
with open(packets_csv, mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Key', 'Packets'])

    for counter in counters:
        for key, value in counter.items():
            # Write each entry's notification type, key, and list of packets
            writer.writerow([key, value['packets']])

print(f"List of packets saved to {packets_csv}")