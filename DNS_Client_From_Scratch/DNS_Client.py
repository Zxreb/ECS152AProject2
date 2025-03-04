import struct
import socket
import time
import requests

DEBUG = True  # Set to False to disable debug prints

def debug_print(msg):
    """ Helper function to print debug messages if enabled. """
    if DEBUG:
        print(msg)


#  DNS Query Construction

def build_dns_query(domain_name):
    """ Constructs a raw DNS query packet. """
    transaction_id = 1234  
    flags = 0x0100  
    qdcount = 1  
    ancount, nscount, arcount = 0, 0, 0  

    # Header section
    header = struct.pack("!HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount)

    # Convert domain name to DNS format
    def encode_domain(domain):
        parts = domain.split(".")
        encoded = b"".join([bytes([len(part)]) + part.encode() for part in parts]) + b"\x00"
        return encoded

    qname = encode_domain(domain_name)
    qtype = 1  # Type A (IPv4 address)
    qclass = 1  # Internet

    question = qname + struct.pack("!HH", qtype, qclass)

    return header + question


#  Sending DNS Requests

def send_dns_request(domain_name, dns_server, port=53, use_tcp=False):
    """ Sends a DNS request using either UDP or TCP and receives the response. """
    query = build_dns_query(domain_name)
    debug_print(f"Sending DNS request to {dns_server} for {domain_name} (TCP: {use_tcp})")

    if use_tcp:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((dns_server, port))
        sock.sendall(struct.pack("!H", len(query)) + query)  # Prefix length for TCP
        response = sock.recv(1024)  
        sock.close()
        return response[2:], None  # Skip the first 2 bytes (length prefix)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(10)
    start_time = time.time()
    sock.sendto(query, (dns_server, port))

    try:
        response, _ = sock.recvfrom(512)
        rtt = (time.time() - start_time) * 1000
        debug_print(f"Received response from {dns_server} in {rtt:.2f} ms")
        
        if response[2] & 0x02:  # Check TC (Truncated) bit
            debug_print("UDP response truncated, retrying with TCP...")
            return send_dns_request(domain_name, dns_server, port, use_tcp=True)
    except socket.timeout:
        debug_print(f"Request to {dns_server} timed out.")
        return None, None

    sock.close()
    return response, rtt


#  Parsing DNS Responses

def parse_compressed_name(response, offset):
    """ Parses a compressed or non-compressed domain name from a DNS response. """
    labels = []
    jumped = False
    initial_offset = offset

    while True:
        length = response[offset]

        if length == 0:  # End of domain name
            offset += 1
            break

        if length >= 192:  # Pointer detected
            pointer = struct.unpack("!H", response[offset:offset+2])[0] & 0x3FFF
            offset += 2
            if not jumped:
                initial_offset = offset
            offset = pointer
            jumped = True
            continue

        offset += 1
        labels.append(response[offset:offset+length].decode(errors='ignore'))
        offset += length

    return ".".join(labels), (initial_offset if jumped else offset)

def extract_ns_from_section(response, section_offset):
    """ Extracts NS records from a DNS response section. """
    offset = response.index(b"\x00") + section_offset  
    rdlength = struct.unpack("!H", response[offset:offset+2])[0]
    offset += 2
    return response[offset:offset+rdlength].decode(errors='ignore')

def extract_authoritative_ns(response):
    """ Extracts the Authoritative Name Server (NS) from the Authority section. """
    authority_count = struct.unpack("!H", response[8:10])[0]
    debug_print(f"Authority section count: {authority_count}")

    if authority_count == 0:
        return None

    offset = 12
    while response[offset] != 0:
        offset += 1
    offset += 5

    for _ in range(authority_count):
        ns_name, offset = parse_compressed_name(response, offset)
        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        if record_type == 2:
            authoritative_ns, _ = parse_compressed_name(response, offset)
            return authoritative_ns

        offset += rdlength

    return None

def extract_ns_ip(response):
    """ Extracts NS IP from the Additional section. """
    additional_count = struct.unpack("!H", response[10:12])[0]

    if additional_count == 0:
        return None

    offset = 12
    while response[offset] != 0:
        offset += 1
    offset += 5

    for _ in range(additional_count):
        domain_name, offset = parse_compressed_name(response, offset)
        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        if record_type == 1 and rdlength == 4:
            return ".".join(map(str, response[offset:offset+4]))

        offset += rdlength

    return None

def parse_dns_response(response):
    """ Extracts the first IPv4 address from a DNS response. """
    ancount = struct.unpack("!H", response[6:8])[0]

    if ancount == 0:
        return None

    offset = response.index(b"\x00") + 5  

    for _ in range(ancount):
        offset += 10  
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2
        if rdlength == 4:  
            return ".".join(map(str, response[offset:offset+rdlength]))
        offset += rdlength  

    return None


#  Recursive DNS Resolver

def recursive_dns_resolution(domain):
    root_servers = ["170.247.170.2", "192.33.4.12", "199.7.91.13"]

    for root_server in root_servers:
        response, _ = send_dns_request(domain, root_server)
        if response:
            tld_ip = extract_ns_ip(response)
            if tld_ip:
                break

    if not tld_ip:
        return None

    response, _ = send_dns_request(domain, tld_ip)
    if not response:
        return None

    authoritative_ns = extract_authoritative_ns(response)
    if not authoritative_ns:
        return None

    authoritative_ip = extract_ns_ip(response)

    if not authoritative_ip:
        authoritative_ip = socket.gethostbyname(authoritative_ns)

    if not authoritative_ip:
        return None

    response, _ = send_dns_request(domain, authoritative_ip)
    return parse_dns_response(response)

if __name__ == "__main__":
    domain = "wikipedia.org"
    print(f"Resolving {domain} using full recursive DNS resolution...")
    ip_address = recursive_dns_resolution(domain)
    if ip_address:
        print(f"Resolved IP: {ip_address}")
