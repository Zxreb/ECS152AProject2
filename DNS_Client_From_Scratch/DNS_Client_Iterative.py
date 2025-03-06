import struct
import socket
import time
import random

# Toggle debugging
DEBUG = False

def debug_print(msg):
    if DEBUG:
        print(msg)

# Function to build DNS query for given domain name and query type
def build_dns_query(domain_name, query_type=1):
    # Generate random transaction ID and set DNS flags
    transaction_id = random.randint(0, 65535)  
    flags = 0x0100  
    qdcount = 1  
    ancount, nscount, arcount = 0, 0, 0  

    # Pack DNS header into binary format
    hdr = struct.pack("!HHHHHH", transaction_id, flags, qdcount, ancount, nscount, arcount)

    # Function to encode domain name into DNS format
    def encode_domain(domain):
        parts = domain.split(".")
        return b"".join([bytes([len(part)]) + part.encode() for part in parts]) + b"\x00"

    # Encode domain name and pack query type and class
    qname = encode_domain(domain_name)
    question = qname + struct.pack("!HH", query_type, 1) 

    # Return complete DNS query
    return hdr + question

# Function to send DNS req to DNS server
def send_dns_req(domain_name, dns_server, port=53, use_tcp=False):
    query = build_dns_query(domain_name)
    debug_print(f"Sending DNS request to {dns_server} for {domain_name} (TCP: {use_tcp})")

    # Create socket (UDP or TCP based on use_tcp flag)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if not use_tcp else socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        start_time = time.time()
        
        # Handle TCP-based DNS queries
        if use_tcp:
            sock.connect((dns_server, port))
            query_with_length = struct.pack("!H", len(query)) + query
            sock.sendall(query_with_length)
            response = sock.recv(4096)
            response = response[2:] if len(response) > 2 else response
        # Handle UDP-based DNS queries
        else:
            sock.sendto(query, (dns_server, port))
            response, _ = sock.recvfrom(4096)
        
        # Calculate round-trip time (RTT)
        rtt = (time.time() - start_time) * 1000
        print(f"Received response from {dns_server} in {rtt:.2f} ms (RTT)")
        
        # Check if UDP response is truncated and retry with TCP if necessary
        if not use_tcp and response[2] & 0x02:
            debug_print("UDP response truncated, retrying with TCP...")
            sock.close()
            return send_dns_req(domain_name, dns_server, port, use_tcp=True)
        
        return response, rtt
    
    except Exception as e:
        debug_print(f"Error querying {dns_server}: {e}")
        return None, None
    finally:
        sock.close()

# Function to parse compressed domain name from DNS response
def parse_compressed_name(response, offset):
    labels = []
    jumped = False
    init_offset = offset

    while True:
        if offset >= len(response):
            return "", offset  

        length = response[offset]

        if length == 0:  
            offset += 1
            break

        # Handle compressed domain names (pointers)
        if length >= 192:  
            pointer = struct.unpack("!H", response[offset:offset+2])[0] & 0x3FFF
            offset += 2
            if not jumped:
                init_offset = offset
            offset = pointer
            jumped = True
            continue

        offset += 1
        if offset + length > len(response):
            return "", offset

        labels.append(response[offset:offset+length].decode(errors='ignore'))
        offset += length

    return ".".join(labels), (init_offset if jumped else offset)

# Function to extract referral information from DNS response
def extract_referral_info(response):
    referrals = []
    response_length = len(response)
    additional_count = struct.unpack("!H", response[10:12])[0]
    authority_count = struct.unpack("!H", response[8:10])[0]

    offset = 12  

    try:
        # Skip question section
        while offset < response_length and response[offset] != 0:
            offset += 1
        offset += 5  
    except IndexError:
        return []

    print("\n------ Processing Referral Information ------")

    # Dictionary to store possible NS entries
    possible_ns_entries = {}
    for _ in range(authority_count):
        domain_name, offset = parse_compressed_name(response, offset)
        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8  
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        # Check if record is an NS record
        if record_type == 2:  
            ns_name, _ = parse_compressed_name(response, offset)
            possible_ns_entries[ns_name] = domain_name
            print(f"Found NS record: {ns_name}")

        offset += rdlength  

    # Dictionary to map NS names to their IP addresses
    ns_ip_map = {}
    for _ in range(additional_count):
        name, offset = parse_compressed_name(response, offset)
        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8  
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        # Check if record is an A record (IPv4 address)
        if record_type == 1 and rdlength == 4:  
            nameserver_ip = ".".join(map(str, response[offset:offset+4]))
            ns_ip_map[name] = nameserver_ip
            print(f"Extracted IP for NS {name}: {nameserver_ip}")

        offset += rdlength  

    # Build list of referrals
    for ns_name, domain in possible_ns_entries.items():
        referrals.append((ns_name, ns_ip_map.get(ns_name)))

    return referrals

# Function to perform iterative DNS resolution
def iterative_dns_resolution(domain):
    # List of root DNS servers
    root_servers = [
        "198.41.0.4", "170.247.170.2", "192.33.4.12", "199.7.91.13", "192.203.230.10",
        "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30",
        "193.0.14.129", "199.7.83.42", "202.12.27.33"
    ]
    
    # Shuffle root servers
    random.shuffle(root_servers)

    print(f"Starting iterative DNS resolution for {domain}")

    current_servers = root_servers
    seen_servers = set()

    # Loop until domain is resolved or no more servers are available
    while current_servers:
        resolved = False
        
        for server in current_servers:
            if server in seen_servers:
                continue
            seen_servers.add(server)

            print(f"Querying {server} for {domain}")
            response, rtt = send_dns_req(domain, server)

            if not response:
                continue

            answer_count = struct.unpack("!H", response[6:8])[0]
            if answer_count > 0:
                ip = parse_compressed_name(response, 12)[0]  
                print(f"Resolved {domain} to IP {ip}")
                return ip

            # Extract referral information from response
            referrals = extract_referral_info(response)

            resolved_servers = [ns_ip for _, ns_ip in referrals if ns_ip]
            if resolved_servers:
                current_servers = resolved_servers
                resolved = True
                break

        if not resolved:
            print("Could not resolve domain through iterative resolution.")
            return None

# Function to resolve IP address of wikipedia.org
def get_wikipedia_ip():
    domain = "wikipedia.org"
    print(f"Starting DNS resolution for {domain}")
    # Measure RTT time between machine and wikipedia.org
    start_time = time.time()
    ip_addy = iterative_dns_resolution(domain)
    end_time = time.time()
    if ip_addy:
        # Convert rtt to ms
        rtt = (end_time - start_time) * 1000
        print(f"Successfully resolved {domain} to IP address: {ip_addy}")
        print(f"RTT to Wikipedia: {rtt:.2f} ms")  
    else:
        print(f"Failed to resolve {domain}")

if __name__ == "__main__":
    get_wikipedia_ip()