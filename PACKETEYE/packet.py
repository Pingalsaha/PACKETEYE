import socket
import struct

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '



def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    collect_and_show_output(conn)


def collect_and_show_output(conn):
    file1 = open('./views/myfile.txt', 'w')
    while True:
        raw_data, addr = conn.recvfrom(65535)
        output = analyze_packet(raw_data)
        # print(output);
        file1.writelines(output)
    file1.close()
# Add Json
        # print(json.dumps(output))



def analyze_packet(raw_data):
    output = ""
    dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

    if eth_proto == 8:  # IPv4 protocol
        version, header_length, ttl, proto, src_ip, dst_ip, data = ipv4_packet(data)

        if proto == 6:  # TCP protocol
            src_port, dest_port, sequence, acknowledgment, flags, payload = tcp_segment(data)

            if payload:
                output += "\nTCP Packet:\n"
                output += f"Source IP: {src_ip}, Destination IP: {dst_ip}\n"
                output += f"Source Port: {src_port}, Destination Port: {dest_port}\n"
                output += "Decoded Payload:\n"
                try:
                    output += decrypt_payload(proto, payload) + "\n"  # Decrypt payload for analysis
                except UnicodeDecodeError:
                    output += "Unable to decode payload. Raw data:\n"
                    output += str(payload) + "\n"

        elif proto == 17:  # UDP protocol
            src_port, dest_port, size, payload = udp_segment(data)

            if payload:
                output += "\nUDP Packet:\n"
                output += f"Source IP: {src_ip}, Destination IP: {dst_ip}\n"
                output += f"Source Port: {src_port}, Destination Port: {dest_port}\n"
                output += "Decoded Payload:\n"
                try:
                    output += decrypt_payload(proto, payload) + "\n"  # Decrypt payload for analysis
                except UnicodeDecodeError:
                    output += "Unable to decode payload. Raw data:\n"
                    output += str(payload) + "\n"

    elif eth_proto == 1:  # ICMP protocol
        icmp_type, code, checksum, payload = icmp_packet(data)

        if payload:
            output += "\nICMP Packet:\n"
            output += f"Type: {icmp_type}, Code: {code}, Checksum: {checksum}\n"
            output += "Decoded Payload:\n"
            try:
                output += decrypt_payload(proto, payload) + "\n"  # Decrypt payload for analysis
            except UnicodeDecodeError:
                output += "Unable to decode payload. Raw data:\n"
                output += str(payload) + "\n"

    elif eth_proto == 6:  # ARP protocol
        hardware_type, protocol_type, hardware_size, protocol_size, opcode, sender_mac, sender_ip, target_mac, target_ip = arp_packet(data)

        output += "\nARP Packet:\n"
        output += f"Hardware Type: {hardware_type}, Protocol Type: {protocol_type}\n"
        output += f"Hardware Size: {hardware_size}, Protocol Size: {protocol_size}\n"
        output += f"Opcode: {opcode}\n"
        output += f"Sender MAC: {sender_mac}, Sender IP: {sender_ip}\n"
        output += f"Target MAC: {target_mac}, Target IP: {target_ip}\n"

    return output

    # Add more conditionals for handling other protocols like FTP, Telnet, SNMP, DHCP, etc.


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src_ip, dst_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src_ip), ipv4(dst_ip), data[header_length:]


def ipv4(addr):
    return '.'.join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H ', data[:4])
    return icmp_type, code, checksum, data[4:]


def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = {
        "URG": (offset_reserved_flags & 32) >> 5,
        "ACK": (offset_reserved_flags & 16) >> 4,
        "PSH": (offset_reserved_flags & 8) >> 3,
        "RST": (offset_reserved_flags & 4) >> 2,
        "SYN": (offset_reserved_flags & 2) >> 1,
        "FIN": offset_reserved_flags & 1
    }
    return src_port, dest_port, sequence, acknowledgment, flags, data[offset:]


def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


def arp_packet(data):
    hardware_type, protocol_type, hardware_size, protocol_size, opcode, sender_mac, sender_ip, target_mac, target_ip = struct.unpack('! H H B B H 6s 4s 6s 4s', data[:28])
    return hardware_type, protocol_type, hardware_size, protocol_size, opcode, get_mac_addr(sender_mac), ipv4(sender_ip), get_mac_addr(target_mac), ipv4(target_ip)


def decrypt_payload(proto, payload):
    # Add decryption logic based on the protocol type
    if proto == 6:  # TCP protocol
        # Check if payload contains HTTP or HTTPS data
        if b'HTTP' in payload:
            # Decrypt HTTP payload
            decrypted_payload = decrypt_http(payload)
            return decrypted_payload
        elif b'HTTPS' in payload:
            # Decrypt HTTPS payload
            decrypted_payload = decrypt_https(payload)
            return decrypted_payload
        elif b'FTP' in payload:
            # Decrypt FTP payload
            decrypted_payload = decrypt_ftp(payload)
            return decrypted_payload
        elif b'Telnet' in payload:
            # Decrypt Telnet payload
            decrypted_payload = decrypt_telnet(payload)
            return decrypted_payload
        elif b'SNMP' in payload:
            # Decrypt SNMP payload
            decrypted_payload = decrypt_snmp(payload)
            return decrypted_payload
        else:
            return payload.decode('utf-8', errors='replace')  # Default decoding for TCP payloads

    elif proto == 17:  # UDP protocol
        # Check if payload contains DHCP data
        if b'DHCP' in payload:
            # Decrypt DHCP payload
            decrypted_payload = decrypt_dhcp(payload)
            return decrypted_payload
        else:
            return payload.decode('utf-8', errors='replace')  # Default decoding for UDP payloads

    # Add more decryption logic for other protocols like FTP, Telnet, SNMP etc


def decrypt_http(payload):
    # Add decryption algorithm for HTTP payload

    decrypted_payload = payload.replace(b'HTTP', b'Decrypted HTTP')
    return decrypted_payload.decode('utf-8', errors='replace')


def decrypt_https(payload):
    # Add decryption algorithm for HTTPS payload

    decrypted_payload = payload.replace(b'HTTPS', b'Decrypted HTTPS')
    return decrypted_payload.decode('utf-8', errors='replace')


def decrypt_ftp(payload):
    # Add decryption algorithm for FTP payload

    decrypted_payload = payload.replace(b'FTP', b'Decrypted FTP')
    return decrypted_payload.decode('utf-8', errors='replace')


def decrypt_telnet(payload):
    # Add decryption algorithm for Telnet payload

    decrypted_payload = payload.replace(b'Telnet', b'Decrypted Telnet')
    return decrypted_payload.decode('utf-8', errors='replace')


def decrypt_snmp(payload):
    # Add decryption algorithm for SNMP payload

    decrypted_payload = payload.replace(b'SNMP', b'Decrypted SNMP')
    return decrypted_payload.decode('utf-8', errors='replace')


def decrypt_dhcp(payload):
    # Add decryption algorithm for DHCP payload

    decrypted_payload = payload.replace(b'DHCP', b'Decrypted DHCP')
    return decrypted_payload.decode('utf-8', errors='replace')


if __name__ == "__main__":
    main()
