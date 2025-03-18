### Get packet numbers for NIDS notifications (notifications_inbox_)

import pyshark
import pandas as pd
import re

def remove_ansi_escape_codes(text):
    ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
    return ansi_escape.sub('', text)

def get_function(pkt):
    function = "unknown"
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
                    elif parameter_value == "PI-Service" and "P_PROGRAM()" not in parameter_line[0]:
                        function = "PLC CONTROL"
                    elif parameter_value == "PLC Stop":
                        function = "PLC STOP"
                    else:
                        function = "Unknown"

                    # print(f"Mapped S7 Function: {function}")

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
                        function = "unknown"

            
    elif hasattr(pkt, 'cotp'):
        cotp_layer_str = str(pkt.cotp)
        cotp_layer_str_clean = remove_ansi_escape_codes(cotp_layer_str)
        match = re.search(r'PDU Type: ([\w\s]+) \(', cotp_layer_str_clean)
        if match:
            func = match.group(1).strip()
            # print(f"cotp packet: {pkt.number}")
            # print(funct)
            funct = func.upper()
        if funct == "CR CONNECT REQUEST":
            function = "PLUS_REQUEST"
        elif funct == "CC CONNECT CONFIRM":
            function = "PLUS_RESPONSE"
        elif funct == "DT DATA":
            function = "PLUS_DATA"

    return function.upper().strip()

def get_protocol(pkt):
    # print(pkt)
    protocol = "unknown"
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


# df = pd.read_csv('notifications_inbox_A2.csv')
df = pd.read_csv('notifications_inbox_eval_packet_numbers_Copy.csv')

columns_to_drop = ['FirstOccurrence', 'Count', 'RiskScore', 'LastOccurrence', 'PCAPName']

df.drop(columns=columns_to_drop, inplace=True, errors='ignore')

df['Packet Number'] = None

# Load the pcap file using pyshark
# cap = pyshark.FileCapture('filtered_attack_17072024_v2.pcap')
cap = pyshark.FileCapture('eval.pcap')



cap2 = None
cap3 = None
offset = 0

# # Store packet numbers for each notification
# results = []

# Iterate over the notifications in the CSV
for index, row in df.iterrows():
    notification_type = row['Type']
    i = index+2
    print(f"Index Number: {i}")
    
    # # Set cap and offset based on index
    # # if i == 501: #### For A1
    # if i == 17:  ### For A2
    #     if cap2 is None:  # Open pcap2 only when needed
    #         cap.close()
    #         cap2 = pyshark.FileCapture('pcap2.pcap')
    #     cap = cap2
    #     offset = 3100000  

    # # if i == 527: ### For A1
    # if i == 43: ### For A2
    #     if cap3 is None:
    #         cap.close()
    #         cap3 = pyshark.FileCapture('pcap3.pcap')
    #     cap = cap3
    #     offset = 3625000

    # For MAC, search for the first occurrence of a MAC address
    if notification_type == 'MAC':
        mac_address = row['MAC']
        # Search for the first packet with this MAC address
        for pkt in cap:
            if 'eth' in pkt and (pkt.eth.src == mac_address or pkt.eth.dst == mac_address):
                # results.append((notification_type, mac_address, pkt.number))  # Packet number is pkt.number
                packet_number = int(pkt.number) + offset
                df.at[index, 'Packet Number'] = packet_number
                break

    elif notification_type == 'MAC_ACTIVE':
        mac_address = row['MAC']
        # Search for the first packet with this MAC address
        for pkt in cap:
            if 'eth' in pkt and (pkt.eth.src == mac_address or pkt.eth.dst == mac_address):
                # results.append((notification_type, mac_address, pkt.number))  # Packet number is pkt.number
                packet_number = int(pkt.number) + offset
                df.at[index, 'Packet Number'] = packet_number
                break

    elif notification_type == 'IP_MAC':
        mac_address_1 = row['SourceMAC']
        mac_address_2 = row['DestinationMAC']
        ip_address_1 = row['SourceIP']
        ip_address_2 = row['DestinationIP']

        for pkt in cap:
            if 'ip' in pkt and (pkt.eth.src == mac_address_1 and pkt.eth.dst == mac_address_2) and (pkt.ip.src == ip_address_1 and pkt.ip.dst == ip_address_2):
                # results.append((notification_type, mac_address, pkt.number))  # Packet number is pkt.number
                packet_number = int(pkt.number) + offset
                df.at[index, 'Packet Number'] = packet_number
                break
    
    # For IP, search for the first occurrence of an IP address
    elif notification_type == 'IP':
        ip_address = row['IP']
        for pkt in cap:
            if 'ip' in pkt and (pkt.ip.src == ip_address or pkt.ip.dst == ip_address):
                # results.append((notification_type, ip_address, pkt.number))
                packet_number = int(pkt.number) + offset
                df.at[index, 'Packet Number'] = packet_number
                break

    elif notification_type == 'IP_ACTIVE':
        ip_address = row['IP']
        
        for pkt in cap:
            if 'ip' in pkt and (pkt.ip.src == ip_address or pkt.ip.dst == ip_address):
                # results.append((notification_type, ip_address, pkt.number))
                packet_number = int(pkt.number) + offset
                df.at[index, 'Packet Number'] = packet_number
                break

    elif notification_type == 'ARP_GRATUITOUS_REQUEST':
        mac_address_1 = row['SourceMAC']
        mac_address_2 = row['DestinationMAC']

        ## Check in pkt.arp is gratuitous = true
        
        for pkt in cap:                    
            if hasattr(pkt, 'arp'):
                if (pkt.eth.src == mac_address_1 and pkt.eth.dst == mac_address_2):
                    arp_layer_str = str(pkt.arp)
                    arp_layer_str_clean = remove_ansi_escape_codes(arp_layer_str)
                    # print(f"{arp_layer_str_clean} for packet number {pkt.number}")
                    if 'Is gratuitous: True' in arp_layer_str_clean:
                        # results.append((notification_type, (mac_address_1, mac_address_2), pkt.number))
                        packet_number = int(pkt.number) + offset
                        df.at[index, 'Packet Number'] = packet_number
                        break

    elif notification_type == 'ARP_GRATUITOUS_REPLY':
        mac_address_1 = row['SourceMAC']
        mac_address_2 = row['DestinationMAC']

        for pkt in cap:                    
            if hasattr(pkt, 'arp'):
                if (pkt.eth.src == mac_address_1 and pkt.eth.dst == mac_address_2):
                    arp_layer_str = str(pkt.arp)
                    arp_layer_str_clean = remove_ansi_escape_codes(arp_layer_str)
                    # print(arp_layer_str_clean)
                    if 'Opcode: reply (2)' in arp_layer_str_clean:
                        # results.append((notification_type, (mac_address_1, mac_address_2), pkt.number))
                        packet_number = int(pkt.number) + offset
                        df.at[index, 'Packet Number'] = packet_number
                        break

    # Search for the 1st occurence of Protocol
    elif notification_type == 'PROTOCOL':
        protocol = row['Protocol']
        for pkt in cap:
            pro = get_protocol(pkt) 
            # print(f"pro : {pro}")
            if pro == 'unknown':
                continue
            if pro == protocol:
                # results.append((notification_type, (mac_address, protocol), pkt.number))
                packet_number = int(pkt.number) + offset
                df.at[index, 'Packet Number'] = packet_number
                break

    
    # For MAC_MAC, search for the first communication between two MAC addresses
    elif notification_type == 'MAC_MAC':
        mac_address_1 = row['SourceMAC']
        mac_address_2 = row['DestinationMAC']
        
        for pkt in cap:
            if 'eth' in pkt:
                if (pkt.eth.src == mac_address_1 and pkt.eth.dst == mac_address_2) or (pkt.eth.src == mac_address_2 and pkt.eth.dst == mac_address_1):
                    # results.append((notification_type, (mac_address_1, mac_address_2), pkt.number))
                    packet_number = int(pkt.number) + offset
                    df.at[index, 'Packet Number'] = packet_number
                    break
    
    # For IP_IP, search for the first communication between two IP addresses
    elif notification_type == 'IP_IP':
        ip_address_1 = row['SourceIP']
        ip_address_2 = row['DestinationIP']
        
        for pkt in cap:
            if 'ip' in pkt:
                if (pkt.ip.src == ip_address_1 and pkt.ip.dst == ip_address_2) or (pkt.ip.src == ip_address_2 and pkt.ip.dst == ip_address_1):
                    # print('IP_IP')
                    # results.append((notification_type, (ip_address_1, ip_address_2), pkt.number))
                    packet_number = int(pkt.number) + offset
                    df.at[index, 'Packet Number'] = packet_number
                    break
    
    # For MAC_PROTOCOL, search for the first time a MAC address uses a specific protocol
    elif notification_type == 'MAC_PROTOCOL':
        mac_address = row['MAC']
        protocol = row['Protocol']
        
        for pkt in cap:
            if 'eth' in pkt and (pkt.eth.src == mac_address or pkt.eth.dst == mac_address):
                pro = get_protocol(pkt) 
                # print(f"pro : {pro}")
                if pro == protocol:
                    # results.append((notification_type, (mac_address, protocol), pkt.number))
                    packet_number = int(pkt.number) + offset
                    df.at[index, 'Packet Number'] = packet_number
                    break
    
    # For IP_PROTOCOL, search for the first time an IP address uses a specific protocol
    elif notification_type == 'IP_PROTOCOL':
        ip_address = row['IP']
        protocol = row['Protocol']
        
        for pkt in cap:
            if 'ip' in pkt and (pkt.ip.src == ip_address or pkt.ip.dst == ip_address):
                pro = get_protocol(pkt)
                if pro == 'unknown':
                    continue
                # print(f"pro : {pro}")
                # print(f"protocol : {protocol}")
                if pro == protocol:
                    # print("ip_proto")
                    # results.append((notification_type, (ip_address, protocol), pkt.number))
                    packet_number = int(pkt.number) + offset
                    df.at[index, 'Packet Number'] = packet_number
                    break
    
    # For MAC_MAC_PROTOCOL, search for the first time two MAC addresses use a specific protocol
    elif notification_type == 'MAC_MAC_PROTOCOL':
        mac_address_1 = row['SourceMAC']
        mac_address_2 = row['DestinationMAC']
        protocol = row['Protocol']
        
        for pkt in cap:
            if 'eth' in pkt:
                if (pkt.eth.src == mac_address_1 and pkt.eth.dst == mac_address_2) or (pkt.eth.src == mac_address_2 and pkt.eth.dst == mac_address_1):
                    pro = get_protocol(pkt)
                    if pro == 'unknown':
                        continue
                    if pro == protocol:
                        # print("mac_mac_proto")
                        # results.append((notification_type, (mac_address_1, mac_address_2, protocol), pkt.number))
                        packet_number = int(pkt.number) + offset
                        df.at[index, 'Packet Number'] = packet_number
                        break
    
    # For IP_IP_PROTOCOL, search for the first time two IP addresses use a specific protocol
    elif notification_type == 'IP_IP_PROTOCOL':
        ip_address_1 = row['SourceIP']
        ip_address_2 = row['DestinationIP']
        protocol = row['Protocol']
        
        for pkt in cap:
            if 'ip' in pkt:
                if (pkt.ip.src == ip_address_1 and pkt.ip.dst == ip_address_2) or (pkt.ip.src == ip_address_2 and pkt.ip.dst == ip_address_1):
                    pro = get_protocol(pkt)
                    if pro == 'unknown':
                        continue
                    if pro == protocol:
                        # print("ip_ip_proto")
                        # results.append((notification_type, (ip_address_1, ip_address_2, protocol), pkt.number))
                        packet_number = int(pkt.number) + offset
                        df.at[index, 'Packet Number'] = packet_number
                        break
    
    # For MAC_FUNCTION, search for the first time a MAC address uses a function
    elif notification_type == 'MAC_FUNCTION':
        mac_address = row['MAC']
        function = row['Function']  

        for pkt in cap:
            # Need to add logic for RT CLASS 2, just to run the code completely appended the current packet. This packet does not reflect the function.
            if function == "RT CLASS 2 UNICAST":
                # results.append((notification_type, (mac_address_1, mac_address_2, function), pkt.number))
                packet_number = int(pkt.number) + offset
                df.at[index, 'Packet Number'] = packet_number
                break

            # Need to add logic for PN INVALID, just to run the code completely appended the current packet. This packet does not reflect the function.
            if function == "PN INVALID":
                # results.append((notification_type, (mac_address_1, mac_address_2, function), pkt.number))
                packet_number = int(pkt.number) + offset
                df.at[index, 'Packet Number'] = packet_number
                break


            if 'eth' in pkt and (pkt.eth.src == mac_address or pkt.eth.dst == mac_address):
                function_value = get_function(pkt)
                
                # print(f"Function Value: '{function_value}'")
                # print(f"Function: '{function}'")

                if function_value == "PN DCP IDENTIFY RESPONSE SUCCESS" or function_value == "UNKNOWN":
                    continue

                if function_value == function:
                    # results.append((notification_type, (mac_address, function), pkt.number))
                    packet_number = int(pkt.number) + offset
                    df.at[index, 'Packet Number'] = packet_number
                    break
                # else:
                #     print(f"Function {function} not found")

    # For IP_FUNCTION, search for the first time a IP address uses a function
    elif notification_type == 'IP_FUNCTION':
        ip_address = row['IP']
        function = row['Function']  

        for pkt in cap:
            if 'ip' in pkt and (pkt.ip.src == ip_address or pkt.ip.dst == ip_address):
                # print(f"packet number: {pkt.number}")
                function_value = get_function(pkt)
                
                # print(f"Function Value: '{function_value}'")
                # print(f"Function: '{function}'")

                if function_value == "PN DCP IDENTIFY RESPONSE SUCCESS" or function_value == "UNKNOWN":
                    continue

                if function in ['PLUS_DATA', 'PLUS_SETMULTIVAR', 'PLUS_DATA_FW1_5', 'PLUS_CREATEOBJECT'] and function_value == "PLUS_DATA":
                    function_value = function
                elif function in ['PLUS_CONNECT', 'PLUS_RESPONSE'] and function_value == "PLUS_RESPONSE":
                    function_value = function

                if function_value == function:
                    # print("ip_func")
                    # results.append((notification_type, (ip_address, function), pkt.number))
                    packet_number = int(pkt.number) + offset
                    df.at[index, 'Packet Number'] = packet_number
                    break
                # else:
                #     print(f"Function {function} not found")
    
    # For MAC_MAC_FUNCTION, search for the first time two MAC addresses use a function
    elif notification_type == 'MAC_MAC_FUNCTION':
        mac_address_1 = row['SourceMAC']
        mac_address_2 = row['DestinationMAC']
        function = row['Function']
        
        for pkt in cap:
            # Need to add logic for RT CLASS 2, just to run the code completely appended the current packet. This packet does not reflect the function.
            if function == "RT CLASS 2 UNICAST":
                # results.append((notification_type, (mac_address_1, mac_address_2, function), pkt.number))
                packet_number = int(pkt.number) + offset
                df.at[index, 'Packet Number'] = packet_number
                break

            # Need to add logic for PN INVALID, just to run the code completely appended the current packet. This packet does not reflect the function.
            if function == "PN INVALID":
                # results.append((notification_type, (mac_address_1, mac_address_2, function), pkt.number))
                packet_number = int(pkt.number) + offset
                df.at[index, 'Packet Number'] = packet_number
                break

            if 'eth' in pkt:
                if ((pkt.eth.src == mac_address_1 and pkt.eth.dst == mac_address_2) or (pkt.eth.src == mac_address_2 and pkt.eth.dst == mac_address_1)):
                    function_value = get_function(pkt)
                    # print(f"Function Value: '{function_value}'")
                    # print(f"Function: '{function}'")

                    if function_value == "PN DCP IDENTIFY RESPONSE SUCCESS" or function_value == "UNKNOWN":
                        continue

                    if function_value == function:
                        # print("mac_mac_func")
                        # print(f"packet number: {pkt.number}")
                        # results.append((notification_type, (mac_address_1, mac_address_2, function), pkt.number))
                        packet_number = int(pkt.number) + offset
                        df.at[index, 'Packet Number'] = packet_number
                        break
                    # else:
                    #     print(f"Function {function} not found")

    # For IP_IP_FUNCTION, search for the first time two IP addresses use a function
    elif notification_type == 'IP_IP_FUNCTION':
        ip_address_1 = row['SourceIP']
        ip_address_2 = row['DestinationIP']
        function = row['Function']
        
        for pkt in cap:
            if 'ip' in pkt:
                if ((pkt.ip.src == ip_address_1 and pkt.ip.dst == ip_address_2) or (pkt.ip.src == ip_address_2 and pkt.ip.dst == ip_address_1)):
                    # print(f"packet number: {pkt.number}")
                    function_value = get_function(pkt)
                    # print(f"Function Value: '{function_value}'")
                    # print(f"Function: '{function}'")

                    if function_value == "PN DCP IDENTIFY RESPONSE SUCCESS" or function_value == "UNKNOWN": 
                        continue

                    if function in ['PLUS_DATA', 'PLUS_SETMULTIVAR', 'PLUS_DATA_FW1_5', 'PLUS_CREATEOBJECT'] and function_value == "PLUS_DATA":
                        function_value = function
                    elif function in ['PLUS_CONNECT', 'PLUS_RESPONSE'] and function_value == "PLUS_RESPONSE":
                        function_value = function

                    if function_value == function:
                        # print("IP_IP_func")
                        # results.append((notification_type, (ip_address_1, ip_address_2, function), pkt.number))
                        packet_number = int(pkt.number) + offset
                        df.at[index, 'Packet Number'] = packet_number
                        break

    # For PROGRAM_UPLOAD, 
    elif notification_type == 'PROGRAM_UPLOAD':
        ip_address_1 = row['SourceIP']
        ip_address_2 = row['DestinationIP']
        
        for pkt in cap:
            if 'ip' in pkt and hasattr(pkt, 's7comm') and hasattr(pkt, 'cotp'):
                if ((pkt.ip.src == ip_address_1 and pkt.ip.dst == ip_address_2) or (pkt.ip.src == ip_address_2 and pkt.ip.dst == ip_address_1)):
                    # Convert the layer output to string to parse it
                    s7_layer_str = str(pkt.s7comm)
                    
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
                                if parameter_value == "PI-Service" and "P_PROGRAM()" in parameter_line[0]:
                                    # print(f"Parameter Line: {parameter_line}")  # Print the extracted parameter line for debugging
                                    # print(f"packet number = {pkt.number}")
                                    # results.append((notification_type, ip_address, pkt.number))
                                    packet_number = int(pkt.number) + offset
                                    df.at[index, 'Packet Number'] = packet_number
                                    break

            elif 'ip' in pkt and hasattr(pkt, 'cotp') and not hasattr(pkt, 's7comm'):
                if ((pkt.ip.src == ip_address_1 and pkt.ip.dst == ip_address_2) or (pkt.ip.src == ip_address_2 and pkt.ip.dst == ip_address_1)):
                    cotp_layer_str = str(pkt.cotp)
                    cotp_layer_str_clean = remove_ansi_escape_codes(cotp_layer_str)
                    match = re.search(r'PDU Type: ([\w\s]+) \(', cotp_layer_str_clean)
                    if match:
                        func = match.group(1).strip()
                        funct = func.upper()
                    if funct == "DT DATA":
                        # results.append((notification_type, ip_address, pkt.number))
                        packet_number = int(pkt.number) + offset
                        df.at[index, 'Packet Number'] = packet_number
                        break

    else:
        print(f"Notification {notification_type} not found for Index {i}")
        mac_address_1 = row['SourceMAC']
        mac_address_2 = row['DestinationMAC']
        
        for pkt in cap:
            if 'eth' in pkt:
                if (pkt.eth.src == mac_address_1 and pkt.eth.dst == mac_address_2) or (pkt.eth.src == mac_address_2 and pkt.eth.dst == mac_address_1):
                    # results.append((notification_type, (mac_address_1, mac_address_2), pkt.number))
                    packet_number = int(pkt.number) + offset
                    df.at[index, 'Packet Number'] = packet_number
                    break

    df.to_csv('notifications_inbox_eval_packet_numbers_Copy.csv', index=False)
    # df.to_csv('notifications_inbox_t.csv', index=False)


# Close the capture file
cap.close()

