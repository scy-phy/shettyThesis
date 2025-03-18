### Get features mentioned in preprocessed_features. Make changes as per your requirement. Also adjust the ground truth ranges as required.

import argparse
import csv
import pyshark
import re

def remove_ansi_escape_codes(text):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

def get_function(pkt):
    function = 0
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

            # Use regex to extract 'Control' from 'Operation: Control (4)'
            operation_match = re.search(r'Operation:\s*(\w+)\s*\(\d+\)', p_layer_str_clean)
            operation_value = operation_match.group(1) if operation_match else None

            # Use regex to extract 'Response' from 'Packet type: Response (2)'
            packet_type_match = re.search(r'Packet type:\s*(\w+)\s*\(\d+\)', dce_layer_str_clean)
            packet_type_value = packet_type_match.group(1) if packet_type_match else None

            function = f"DCE RPC {operation_value} {packet_type_value}"

    elif hasattr(pkt, 'pn_dcp'):
        pn_dcp_layer_str = str(pkt.pn_dcp)
        # print(pn_dcp_layer_str)
        pn_dcp_layer_str_clean = remove_ansi_escape_codes(pn_dcp_layer_str)

        # Use regex to extract 'Set' from 'ServiceID: Set (4)'
        service_id_match = re.search(r'ServiceID:\s*(\w+)\s*\(\d+\)', pn_dcp_layer_str_clean)
        service_id_value = service_id_match.group(1) if service_id_match else None

        # Use regex to extract 'Response Success' from 'ServiceType: Response Success (1)'
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
            
            # Use regex to extract the Delay from FrameID
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
        
        # print(f"Cleaned S7COMM Layer:\n{s7_layer_str_clean}")  # Print cleaned string for debugging
        
        # Check if the "Parameter:" field is present
        if "Parameter:" in s7_layer_str_clean:
            # Extract the line containing the parameter
            parameter_line = [line for line in s7_layer_str_clean.splitlines() if "Parameter:" in line]
            # print(f"Extracted Parameter Line: {parameter_line}")  # Print the extracted parameter line for debugging
            
            # Ensure the list is not empty before trying to extract the function
            if parameter_line:
                # Use regex to extract the first value inside the parentheses
                match = re.search(r'\((.*?)\)', parameter_line[0])
                if match:
                    parameter_value = match.group(1).strip()  # Extract the value inside the parentheses
                    # print(f"Extracted S7 Function: {parameter_value}")
                    
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
                        function = 0

    elif hasattr(pkt, 'pn_rt'):
        pnrt_layer_str = str(pkt.pn_rt)
        pnrt_layer_str_clean = remove_ansi_escape_codes(pnrt_layer_str)

        if "FrameID:" in pnrt_layer_str_clean:
            FrameID_line = [line for line in pnrt_layer_str_clean.splitlines() if "FrameID:" in line]
            # print(f"Extracted Line: {FrameID_line}")  # Print the extracted FrameID line for debugging

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
                        function = 0

            
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

    if function == 0:
        return function
    else:
        return function.upper().strip()

def get_protocol(pkt):
    protocol = 0
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

### pcap_file = filtered_attack.pcap, csv_packet_file = packets_list_10.csv, output_csv_file = features_10.csv

def preprocessed_features(pcap_file, csv_packet_file, output_csv_file):
    # Read packet numbers from the input CSV
    packet_numbers = set()
    with open(csv_packet_file, 'r') as packet_csv:
        reader = csv.DictReader(packet_csv)
        for row in reader:
            packet_numbers.add(int(row['Packet Number']))

    cap = pyshark.FileCapture(pcap_file)
    
    # Define the fields (features) to extract
    eth_fields = ['eth.src', 'eth.dst']
    ip_fields_2 = ['ip.flags_df', 'ip.flags_mf', 'ip.flags_rb', 'ip.frag_offset', 'ip.hdr_len', 'ip.len', 'ip.ttl', 'ip.checksum']
    ip_fields = ['ip.src', 'ip.dst']
    tcp_fields_2 = ['tcp.checksum', 'tcp.dstport', 'tcp.srcport']
    tcp_fields = ['tcp.flags_ack','tcp.flags_fin', 'tcp.flags_reset', 'tcp.flags_syn', 'tcp.hdr_len', 'tcp.len', 'tcp.payload']
    udp_fields = ['udp.checksum', 'udp.dstport', 'udp.length', 'udp.payload', 'udp.srcport']
    profinet_rt_fields = ['pn_rt.cycle_counter']
    # profinet_io_fields = [
    #     'pn_io.frame_info_type', 'pn_io.frame_info_vendor', 'pn_io.frame_info_nameofstation'    
    # ]
    
    selected_fields = eth_fields + ip_fields + tcp_fields + ip_fields_2 + tcp_fields_2 + udp_fields + profinet_rt_fields

    # Track processed packet numbers
    processed_packets = set()

    # Open the output CSV file
    with open(output_csv_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        header = ['frame.number'] + ['protocol'] + ['function'] + eth_fields + ip_fields + tcp_fields + ip_fields_2 + tcp_fields_2 + udp_fields + profinet_rt_fields + ['ground_truth']
        writer.writerow(header)

        # Loop through packets in the PCAP
        for packet in cap:
            frame_number = int(packet.number.get_default_value())
            # print(frame_number)
            # Check if the packet number is in the list of packet numbers from the CSV
            if frame_number in packet_numbers:
                row = [packet.number]
                field_values = []

                protocol = get_protocol(packet)

                function = get_function(packet)

                # Extract values from selected fields
                for field in selected_fields:
                    layer_name, field_name = field.split('.', 1)
                    value = 0
                    if hasattr(packet, layer_name):
                        layer = getattr(packet, layer_name)
                        if field_name in layer.field_names:
                            value = layer.get_field_value(field_name)
                    field_values.append(value)

                # Add ground truth based on frame number ranges -- Adjust these ranges based on your dataset
                if (3102996 <= frame_number <= 3632614 or
                    4477319 <= frame_number <= 4775277 or
                    5630397 <= frame_number <= 6238671 or
                    7932972 <= frame_number <= 8680503 or
                    9543127 <= frame_number <= 11005350 or
                    13842803 <= frame_number <= 14595720 or
                    16663945 <= frame_number <= 18484168):
                    ground_truth = 1
                else:
                    ground_truth = 0

                # Write the extracted data to the output CSV
                row.append(protocol)
                row.append(function)
                row.extend(field_values)
                row.append(ground_truth)
                writer.writerow(row)

                # Add this packet number to processed set
                processed_packets.add(frame_number)

                if processed_packets == packet_numbers:
                    break

        cap.close()



def main():
    parser = argparse.ArgumentParser(description="Process pcap file and extract features to CSV")
    parser.add_argument("function", choices=["preprocessed_features"], help="Functions to run")
    parser.add_argument("pcap_file", help="Path to the pcap file")
    parser.add_argument("--start_frame", type=int, default=100, help="Start frame for filtering")
    parser.add_argument("--end_frame", type=int, default=150, help="End frame for filtering")
    parser.add_argument("--output_file", default="output.csv", help="Output CSV file")
    parser.add_argument("--packet_file", default="csv_packet_file.csv", help="CSV file with packet numbers")
    parser.add_argument("--eth_src")
    parser.add_argument("--eth_dst")

    args = parser.parse_args()

    if args.function == "preprocessed_features":
        preprocessed_features(args.pcap_file, args.packet_file, args.output_file)

if __name__ == "__main__":
    main()
