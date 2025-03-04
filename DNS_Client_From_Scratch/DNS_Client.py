import struct
import socket
import time
import requests

def build_dns_query(domain_name):
    # Constructs a raw DNS query packet
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
    # Type A (IPv4 address)
    qtype = 1  
    # Internet
    qclass = 1  

    question = qname + struct.pack("!HH", qtype, qclass)

    return header + question

def send_dns_req(domain_name, dns_server, port=53, use_tcp=False):
    # Sends a DNS request using either UDP or TCP and receives the response
    query = build_dns_query(domain_name)
    print(f"Sending DNS request to {dns_server} for {domain_name} (TCP: {use_tcp})")

    if use_tcp:
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sk.settimeout(10)
        sk.connect((dns_server, port))
        # Prefix length for TCP
        sk.sendall(struct.pack("!H", len(query)) + query)  
        response = sk.recv(1024)  
        sk.close()
        # Skip the first 2 bytes (length prefix)
        return response[2:], None  

    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.settimeout(10)
    start_time = time.time()
    sk.sendto(query, (dns_server, port))

    try:
        response, _ = sk.recvfrom(512)
        rtt = (time.time() - start_time) * 1000
        print(f"Received response from {dns_server} in {rtt:.2f} ms")
        
        # Check TC (Truncated) bit
        if response[2] & 0x02:  
            print("UDP response truncated, retrying with TCP...")
            return send_dns_req(domain_name, dns_server, port, use_tcp=True)
    except socket.timeout:
        print(f"Request to {dns_server} timed out.")
        return None, None

    sk.close()
    return response, rtt

def parse_compressed_name(response, offset):
    # Parses a compressed or non-compressed domain name from a DNS response
    labels = []
    jumped = False
    initial_offset = offset

    while True:
        length = response[offset]

        # End of domain name
        if length == 0:  
            offset += 1
            break

        # Pointer detected
        if length >= 192: 
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
    # Extracts NS records from the DNS response section
    offset = response.index(b"\x00") + section_offset  
    rdlength = struct.unpack("!H", response[offset:offset+2])[0]
    offset += 2
    return response[offset:offset+rdlength].decode(errors='ignore')

def extract_authoritative_ns(response):
    # Extracts the Authoritative Name Server (NS) from the Authority section
    authority_count = struct.unpack("!H", response[8:10])[0]
    print(f"Authority section count: {authority_count}")

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
    # Extracts NS IP from the Additional section
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
    # Extracts the first A (IPv4), AAAA (IPv6), or CNAME from a DNS response
    if not response:
        print("No response received.")
        return None
        
    ancount = struct.unpack("!H", response[6:8])[0]
    print(f"Answer count: {ancount}")

    if ancount == 0:
        print("No answer received.")
        return None

    # Skip over the question section and start after the header
    offset = 12  
    
    # Skip the QNAME
    while True:
        length = response[offset]
        if length == 0:
            # Skip the terminating zero
            offset += 1  
            break
        offset += length + 1
    
    # Skip QTYPE and QCLASS, we don't need it
    offset += 4  

    # Process the answers
    ipv4_address = None
    ipv6_address = None
    cname = None

    for _ in range(ancount):
        # Skip the name field (could be a pointer)
        # Check if it is a pointer
        if (response[offset] & 0xC0) == 0xC0:  
            offset += 2
        else:
            while response[offset] != 0:
                offset += 1
            offset += 1

        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2
        record_class = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2
        ttl = struct.unpack("!I", response[offset:offset+4])[0]
        offset += 4
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        print(f"Record type: {record_type}, Length: {rdlength}")

        # A record
        if record_type == 1 and rdlength == 4:  
            ipv4_address = ".".join(map(str, response[offset:offset+rdlength]))
            print(f"Found A record: {ipv4_address}")
            return ipv4_address

         # AAAA record
        elif record_type == 28 and rdlength == 16:
            ipv6_address = ":".join(
                f"{response[offset+i]:02x}{response[offset+i+1]:02x}" for i in range(0, rdlength, 2)
            )
            print(f"Found AAAA record: {ipv6_address}")

        # CNAME record
        elif record_type == 5: 
            cname, _ = parse_compressed_name(response, offset)
            print(f"Found CNAME: {cname}")

        offset += rdlength

    # Return the first found address
    if ipv4_address:
        return ipv4_address
    if ipv6_address:
        return ipv6_address
    if cname:
        print(f"Resolving CNAME: {cname}")
        return recursive_dns_resolution(cname)

    print("No valid A, AAAA, or CNAME record found in response.")
    return None

def recursive_dns_resolution(domain):
    # Performs full recursive DNS resolution by querying root, TLD, and authoritative DNS servers
    print(f"Resolving {domain} using full recursive DNS resolution...")
    root_servers = [
        "170.247.170.2",  # b.root-servers.net
        "192.33.4.12",    # c.root-servers.net
        "199.7.91.13",    # d.root-servers.net
    ]

    # Query a Root Server
    for root_server in root_servers:
        print(f"Querying Root DNS Server: {root_server}")
        response, _ = send_dns_req(domain, root_server)
        if response:
            tld_ns = extract_tld_ns(response)
            tld_ip = extract_ns_ip(response)

            if tld_ns:
                print(f"Extracted TLD NS: {tld_ns}")
            if tld_ip:
                print(f"Extracted TLD Name Server IP: {tld_ip}")
                # Found a valid TLD server, move to the next step
                break  

    if not tld_ip:
        print("Failed to retrieve TLD Name Server IP.")
        return None

    # Query the TLD Server
    print(f"Querying TLD DNS Server: {tld_ip}")
    response, _ = send_dns_req(domain, tld_ip)
    if not response:
        print("Failed to retrieve Authoritative server.")
        return None

    authoritative_ns = extract_authoritative_ns(response)
    authoritative_ip = extract_ns_ip(response)

    if authoritative_ns:
        print(f"Extracted Authoritative NS: {authoritative_ns}")
    if authoritative_ip:
        print(f"Extracted Authoritative NS IP: {authoritative_ip}")

    # Resolve Authoritative NS IP Manually if we need to
    if not authoritative_ip and authoritative_ns:
        print(f"Manually resolving authoritative NS: {authoritative_ns}")
        authoritative_ip = resolve_ns_ip_manually(authoritative_ns)

    if not authoritative_ip:
        print(f"Failed to resolve authoritative NS {authoritative_ns}")
        return None

    # Query the Authoritative Server for the final answer
    print(f"Querying Authoritative DNS Server: {authoritative_ip}")
    response, _ = send_dns_req(domain, authoritative_ip)

    return parse_dns_response(response)

def extract_tld_ns(response):
    # Extract the TLD Name Server (NS) from the authority section
    # Get the Authority section count
    authority_count = struct.unpack("!H", response[8:10])[0]  
    print(f"Authority section count: {authority_count}")

    if authority_count == 0:
        return None

    # DNS header is always 12 bytes long
    offset = 12  

    # Move past the Question section
    # Read domain name (could be compressed)
    while response[offset] != 0:  
        offset += 1
    # Skip null byte + QTYPE (2 bytes) + QCLASS (2 bytes)
    offset += 5  

    # Iterate through the Authority section
    for _ in range(authority_count):
        if response[offset] >= 192:  
            offset += 2
        else:
            while response[offset] != 0:
                offset += 1
             # Skip null byte
            offset += 1 

        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        # Skip type, class, TTL
        offset += 8  

        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2  

        if record_type == 2: 
            tld_ns, _ = parse_compressed_name(response, offset)
            return tld_ns

        # Move to the next record
        offset += rdlength  

    return None

def resolve_ns_ip_manually(ns_name):
    # Uses Python's socket API to resolve the IP address of a Name Server
    try:
        ns_ip = socket.gethostbyname(ns_name)
        print(f"Resolved {ns_name} manually to {ns_ip}")
        return ns_ip
    except socket.gaierror:
        print(f"Failed to manually resolve NS: {ns_name}")
        return None

def measure_http_rtt(ip_address):
    # Measures the RTT for an HTTP request to wikipedia.org using the resolved IP
    if not ip_address:
        print("Error: No valid IP address resolved. Cannot make HTTP request.")
        return None

    url = f"http://{ip_address}"  
    # Force the correct Host header
    headers = {"Host": "wikipedia.org"}

    print(f"Attempting HTTP request to {ip_address}")

    start_time = time.time()
    try:
        response = requests.get(
            url, 
            headers=headers, 
            timeout=5, 
            verify=False,
            # Don't follow any redirects
            allow_redirects=False  
        )
        # Calculate the RTT
        rtt = (time.time() - start_time) * 1000  
        print(f"HTTP Request RTT: {rtt:.2f} ms")
        print(f"HTTP Status Code: {response.status_code}")
        return rtt
    except requests.exceptions.RequestException as e:
        print(f"HTTP request failed: {e}")
        return None

if __name__ == "__main__":
    domain = "wikipedia.org"
    ip_address = recursive_dns_resolution(domain)
    if ip_address:
        print(f"Resolved IP: {ip_address}")
        print(f"DNS Resolution complete.")
        
        # Measure HTTP RTT
        http_rtt = measure_http_rtt(ip_address)
    else:
        print(f"Failed to resolve {domain}.")