import struct
import socket
import time
import random

DEBUG = True  # Set to False to disable debug prints

def debug_print(msg):
    """ Helper function to print debug messages if enabled. """
    if DEBUG:
        print(msg)

def build_dns_query(domain_name, query_type=1):
    """ Constructs a raw DNS query packet with randomized transaction ID. """
    transaction_id = random.randint(0, 65535)  # Randomize transaction ID
    flags = 0x0100  # Standard recursive query
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
    qtype = query_type  # Type A (IPv4 address) by default
    qclass = 1  # Internet

    question = qname + struct.pack("!HH", qtype, qclass)

    return header + question

def send_dns_request(domain_name, dns_server, port=53, use_tcp=False):
    """ Sends a DNS request using either UDP or TCP and receives the response. """
    query = build_dns_query(domain_name)
    debug_print(f"Sending DNS request to {dns_server} for {domain_name} (TCP: {use_tcp})")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if not use_tcp else socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        start_time = time.time()
        
        if use_tcp:
            sock.connect((dns_server, port))
            # Prefix length for TCP
            query_with_length = struct.pack("!H", len(query)) + query
            sock.sendall(query_with_length)
            response = sock.recv(4096)
            # Remove the 2-byte length prefix for TCP
            response = response[2:] if len(response) > 2 else response
        else:
            sock.sendto(query, (dns_server, port))
            response, _ = sock.recvfrom(4096)
        
        rtt = (time.time() - start_time) * 1000
        debug_print(f"Received response from {dns_server} in {rtt:.2f} ms")
        
        # Check for truncation and retry with TCP if needed
        if not use_tcp and response[2] & 0x02:
            debug_print("UDP response truncated, retrying with TCP...")
            sock.close()
            return send_dns_request(domain_name, dns_server, port, use_tcp=True)
        
        return response, rtt
    
    except Exception as e:
        debug_print(f"Error querying {dns_server}: {e}")
        return None, None
    finally:
        sock.close()

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

def extract_referral_info(response):
    """ 
    Extracts referral information from DNS response.
    Returns a list of (nameserver, nameserver_ip) tuples 
    """
    referrals = []
    additional_count = struct.unpack("!H", response[10:12])[0]
    authority_count = struct.unpack("!H", response[8:10])[0]

    offset = 12  # Start of the DNS header
    
    # Skip Question section
    while response[offset] != 0:
        offset += 1
    offset += 5  # Skip null byte, QTYPE, and QCLASS

    # Process Authority section to find NS
    possible_ns_entries = []
    for _ in range(authority_count):
        ns_name, offset = parse_compressed_name(response, offset)
        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8  # Skip type, class, and TTL
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        if record_type == 2:  # NS record
            possible_ns_entries.append(ns_name)

        offset += rdlength

    # Process Additional section to find NS IPs
    offset = 12  # Reset to header
    while response[offset] != 0:
        offset += 1
    offset += 5  # Skip question section

    for _ in range(additional_count):
        name, offset = parse_compressed_name(response, offset)
        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8  # Skip type, class, and TTL
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        if record_type == 1 and rdlength == 4:  # A record
            nameserver_ip = ".".join(map(str, response[offset:offset+4]))
            # Match IPs with nameservers
            for ns in possible_ns_entries:
                referrals.append((ns, nameserver_ip))

        offset += rdlength

    return referrals

def manual_ns_resolution(ns_name, max_depth=3):
    """ 
    Manually resolve nameserver IP using recursive DNS resolution 
    with a maximum depth to prevent infinite recursion
    """
    if max_depth <= 0:
        debug_print(f"Max depth reached while resolving {ns_name}")
        return None

    try:
        # Try system resolution first
        return socket.gethostbyname(ns_name)
    except socket.gaierror:
        # If system resolution fails, use our iterative resolution
        debug_print(f"Manually resolving {ns_name}")
        return iterative_dns_resolution(ns_name, manual_resolution=True, depth=max_depth-1)

def iterative_dns_resolution(domain, manual_resolution=False, depth=3):
    """ 
    Performs iterative DNS resolution by querying DNS servers step by step.
    Added manual resolution and depth tracking to prevent infinite loops.
    """
    # Expanded list of root servers with more comprehensive list
    root_servers = [
        "198.41.0.4",     # a.root-servers.net
        "199.9.14.201",   # b.root-servers.net
        "192.33.4.12",    # c.root-servers.net
        "199.7.91.13",    # d.root-servers.net
        "192.203.230.10", # e.root-servers.net
        "192.5.5.241",    # f.root-servers.net
        "192.112.36.4",   # g.root-servers.net
        "198.97.190.53",  # h.root-servers.net
        "192.36.148.17",  # i.root-servers.net
        "193.0.14.129",   # k.root-servers.net
        "202.12.27.33",   # l.root-servers.net
        "199.7.83.42",    # m.root-servers.net
    ]

    # Shuffle root servers to distribute load
    random.shuffle(root_servers)

    debug_print(f"Resolving {domain} using iterative DNS resolution")

    current_servers = root_servers
    seen_servers = set()

    while current_servers and depth > 0:
        for server in current_servers:
            # Prevent revisiting servers
            if server in seen_servers:
                continue
            seen_servers.add(server)

            debug_print(f"Querying DNS server: {server}")
            response, _ = send_dns_request(domain, server)

            if not response:
                debug_print(f"No response from {server}")
                continue

            # Check if we have a final answer
            answer_count = struct.unpack("!H", response[6:8])[0]
            if answer_count > 0:
                # We have our final IP
                ip = parse_dns_response(response)
                if ip:
                    return ip

            # Extract referral information
            referrals = extract_referral_info(response)

            if referrals:
                debug_print(f"Found {len(referrals)} referral(s)")
                
                # Deduplicate referral IPs
                unique_referrals = list(set([ip for _, ip in referrals if ip]))
                if unique_referrals:
                    current_servers = unique_referrals
                    debug_print(f"Using unique referral IPs: {current_servers}")
                    continue

                # If no IPs, try manual resolution for nameservers
                if not unique_referrals and not manual_resolution:
                    resolved_servers = []
                    for ns, _ in referrals:
                        ns_ip = manual_ns_resolution(ns)
                        if ns_ip:
                            resolved_servers.append(ns_ip)
                    
                    if resolved_servers:
                        current_servers = resolved_servers
                        debug_print(f"Manually resolved servers: {current_servers}")
                        continue

        depth -= 1  # Decrease depth to prevent infinite loops

    debug_print("Could not resolve domain.")
    return None

def parse_dns_response(response):
    """ Extracts the first A (IPv4), AAAA (IPv6), or CNAME from a DNS response. """
    ancount = struct.unpack("!H", response[6:8])[0]

    if ancount == 0:
        debug_print("No answer received.")
        return None

    offset = 12  # Start after header
    
    # Skip Question section
    while response[offset] != 0:
        offset += 1
    offset += 5  # Skip null byte, QTYPE, and QCLASS

    for _ in range(ancount):
        # Skip name (could be compressed)
        name, offset = parse_compressed_name(response, offset)

        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8  # Skip type, class, and TTL
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        if record_type == 1 and rdlength == 4:  # A record
            ipv4_address = ".".join(map(str, response[offset:offset+rdlength]))
            debug_print(f"Found A record: {ipv4_address}")
            return ipv4_address

        elif record_type == 28 and rdlength == 16:  # AAAA record
            ipv6_address = ":".join(
                f"{response[offset+i]:02x}{response[offset+i+1]:02x}" for i in range(0, rdlength, 2)
            )
            debug_print(f"Found AAAA record: {ipv6_address}")
            return ipv6_address

        elif record_type == 5:  # CNAME record
            cname, _ = parse_compressed_name(response, offset)
            debug_print(f"Found CNAME record: {cname}")
            return iterative_dns_resolution(cname)  # Resolve the canonical name

        offset += rdlength

    debug_print("No valid A, AAAA, or CNAME record found.")
    return None

# Main execution
if __name__ == "__main__":
    domain = "wikipedia.org"
    print(f"Resolving {domain} using iterative DNS resolution...")
    ip_address = iterative_dns_resolution(domain)
    if ip_address:
        print(f"Resolved IP: {ip_address}")
    else:
        print(f"Failed to resolve {domain}")


# ------------------------------------------------------------------------


'''

import struct
import socket
import time
import random

DEBUG = True  # Set to False to disable debug prints

def debug_print(msg):
    """ Helper function to print debug messages if enabled. """
    if DEBUG:
        print(msg)

def build_dns_query(domain_name, query_type=1):
    """ Constructs a raw DNS query packet with randomized transaction ID. """
    transaction_id = random.randint(0, 65535)  # Randomize transaction ID
    flags = 0x0100  # Standard recursive query
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
    qtype = query_type  # Type A (IPv4 address) by default
    qclass = 1  # Internet

    question = qname + struct.pack("!HH", qtype, qclass)

    return header + question

def send_dns_request(domain_name, dns_server, port=53, use_tcp=False):
    """ Sends a DNS request using either UDP or TCP and receives the response. """
    query = build_dns_query(domain_name)
    debug_print(f"Sending DNS request to {dns_server} for {domain_name} (TCP: {use_tcp})")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if not use_tcp else socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        start_time = time.time()
        
        if use_tcp:
            sock.connect((dns_server, port))
            # Prefix length for TCP
            query_with_length = struct.pack("!H", len(query)) + query
            sock.sendall(query_with_length)
            response = sock.recv(4096)
            # Remove the 2-byte length prefix for TCP
            response = response[2:] if len(response) > 2 else response
        else:
            sock.sendto(query, (dns_server, port))
            response, _ = sock.recvfrom(4096)
        
        rtt = (time.time() - start_time) * 1000
        debug_print(f"Received response from {dns_server} in {rtt:.2f} ms")
        
        # Check for truncation and retry with TCP if needed
        if not use_tcp and response[2] & 0x02:
            debug_print("UDP response truncated, retrying with TCP...")
            sock.close()
            return send_dns_request(domain_name, dns_server, port, use_tcp=True)
        
        return response, rtt
    
    except Exception as e:
        debug_print(f"Error querying {dns_server}: {e}")
        return None, None
    finally:
        sock.close()

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

def extract_referral_info(response):
    """ 
    Extracts referral information from DNS response.
    Returns a list of (nameserver, nameserver_ip) tuples 
    """
    referrals = []
    additional_count = struct.unpack("!H", response[10:12])[0]
    authority_count = struct.unpack("!H", response[8:10])[0]

    offset = 12  # Start of the DNS header
    
    # Skip Question section
    while response[offset] != 0:
        offset += 1
    offset += 5  # Skip null byte, QTYPE, and QCLASS

    # Process Authority section to find NS
    possible_ns_entries = []
    for _ in range(authority_count):
        ns_name, offset = parse_compressed_name(response, offset)
        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8  # Skip type, class, and TTL
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        if record_type == 2:  # NS record
            possible_ns_entries.append(ns_name)

        offset += rdlength

    # Process Additional section to find NS IPs
    offset = 12  # Reset to header
    while response[offset] != 0:
        offset += 1
    offset += 5  # Skip question section

    for _ in range(additional_count):
        name, offset = parse_compressed_name(response, offset)
        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8  # Skip type, class, and TTL
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        if record_type == 1 and rdlength == 4:  # A record
            nameserver_ip = ".".join(map(str, response[offset:offset+4]))
            # Match IPs with nameservers
            for ns in possible_ns_entries:
                referrals.append((ns, nameserver_ip))

        offset += rdlength

    return referrals

def manual_ns_resolution(ns_name, max_depth=3):
    """ 
    Manually resolve nameserver IP using recursive DNS resolution 
    with a maximum depth to prevent infinite recursion
    """
    if max_depth <= 0:
        debug_print(f"Max depth reached while resolving {ns_name}")
        return None

    try:
        # Try system resolution first
        return socket.gethostbyname(ns_name)
    except socket.gaierror:
        # If system resolution fails, use our iterative resolution
        debug_print(f"Manually resolving {ns_name}")
        return iterative_dns_resolution(ns_name, manual_resolution=True, depth=max_depth-1)

def iterative_dns_resolution(domain, manual_resolution=False, depth=3):
    """ 
    Performs iterative DNS resolution by querying DNS servers step by step.
    Added manual resolution and depth tracking to prevent infinite loops.
    """
    # Expanded list of root servers with more comprehensive list
    root_servers = [
        "198.41.0.4",     # a.root-servers.net
        "199.9.14.201",   # b.root-servers.net
        "192.33.4.12",    # c.root-servers.net
        "199.7.91.13",    # d.root-servers.net
        "192.203.230.10", # e.root-servers.net
        "192.5.5.241",    # f.root-servers.net
        "192.112.36.4",   # g.root-servers.net
        "198.97.190.53",  # h.root-servers.net
        "192.36.148.17",  # i.root-servers.net
        "193.0.14.129",   # k.root-servers.net
        "202.12.27.33",   # l.root-servers.net
        "199.7.83.42",    # m.root-servers.net
    ]

    # Shuffle root servers to distribute load
    random.shuffle(root_servers)

    debug_print(f"Resolving {domain} using iterative DNS resolution")

    current_servers = root_servers
    seen_servers = set()

    while current_servers and depth > 0:
        for server in current_servers:
            # Prevent revisiting servers
            if server in seen_servers:
                continue
            seen_servers.add(server)

            debug_print(f"Querying DNS server: {server}")
            response, _ = send_dns_request(domain, server)

            if not response:
                debug_print(f"No response from {server}")
                continue

            # Check if we have a final answer
            answer_count = struct.unpack("!H", response[6:8])[0]
            if answer_count > 0:
                # We have our final IP
                ip = parse_dns_response(response)
                if ip:
                    return ip

            # Extract referral information
            referrals = extract_referral_info(response)

            if referrals:
                debug_print(f"Found {len(referrals)} referral(s)")
                
                # Try referrals with known IPs first
                known_ip_referrals = [ref for ref in referrals if ref[1]]
                unknown_ip_referrals = [ref for ref in referrals if not ref[1]]

                # Try servers with known IPs
                if known_ip_referrals:
                    current_servers = [ip for _, ip in known_ip_referrals]
                    debug_print(f"Using referral IPs: {current_servers}")
                    continue

                # If no IPs, try manual resolution for nameservers
                if unknown_ip_referrals and not manual_resolution:
                    resolved_servers = []
                    for ns, _ in unknown_ip_referrals:
                        ns_ip = manual_ns_resolution(ns)
                        if ns_ip:
                            resolved_servers.append(ns_ip)
                    
                    if resolved_servers:
                        current_servers = resolved_servers
                        debug_print(f"Manually resolved servers: {current_servers}")
                        continue

        # If we can't resolve, break the loop
        break

    while current_servers and depth > 0:
       for server in current_servers:
           if server in seen_servers:
               continue
           seen_servers.add(server)

           debug_print(f"Querying DNS server: {server}")
           response, _ = send_dns_request(domain, server)

           if not response:
               debug_print(f"No response from {server}")
               continue

           answer_count = struct.unpack("!H", response[6:8])[0]
           if answer_count > 0:
               ip = parse_dns_response(response)
               if ip:
                   return ip

           referrals = extract_referral_info(response)
           if referrals:
               debug_print(f"Found {len(referrals)} referral(s)")
                
               # Deduplicate referral IPs
               unique_referrals = list(set([ip for _, ip in referrals if ip]))
               if unique_referrals:
                   current_servers = unique_referrals
                   debug_print(f"Using unique referral IPs: {current_servers}")
                   continue

               # If no IPs, try manual resolution for nameservers
               if not unique_referrals and not manual_resolution:
                   resolved_servers = []
                   for ns, _ in referrals:
                       ns_ip = manual_ns_resolution(ns)
                       if ns_ip:
                           resolved_servers.append(ns_ip)
                    
                   if resolved_servers:
                       current_servers = resolved_servers
                       debug_print(f"Manually resolved servers: {current_servers}")
                       continue

       depth -= 1  # Decrease depth to prevent infinite loops

    debug_print("Could not resolve domain.")
    return None

def parse_dns_response(response):
    """ Extracts the first A (IPv4), AAAA (IPv6), or CNAME from a DNS response. """
    ancount = struct.unpack("!H", response[6:8])[0]

    if ancount == 0:
        debug_print("No answer received.")
        return None

    offset = 12  # Start after header
    
    # Skip Question section
    while response[offset] != 0:
        offset += 1
    offset += 5  # Skip null byte, QTYPE, and QCLASS

    for _ in range(ancount):
        # Skip name (could be compressed)
        name, offset = parse_compressed_name(response, offset)

        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8  # Skip type, class, and TTL
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        if record_type == 1 and rdlength == 4:  # A record
            ipv4_address = ".".join(map(str, response[offset:offset+rdlength]))
            debug_print(f"Found A record: {ipv4_address}")
            return ipv4_address

        elif record_type == 28 and rdlength == 16:  # AAAA record
            ipv6_address = ":".join(
                f"{response[offset+i]:02x}{response[offset+i+1]:02x}" for i in range(0, rdlength, 2)
            )
            debug_print(f"Found AAAA record: {ipv6_address}")
            return ipv6_address

        offset += rdlength

    debug_print("No valid A or AAAA record found.")
    return None

# Main execution
if __name__ == "__main__":
    domain = "wikipedia.org"
    print(f"Resolving {domain} using iterative DNS resolution...")
    ip_address = iterative_dns_resolution(domain)
    if ip_address:
        print(f"Resolved IP: {ip_address}")
    else:
        print(f"Failed to resolve {domain}")
'''


# ---------------------------------------------------------------------------------------


'''

import struct
import socket
import time

DEBUG = True  # Set to False to disable debug prints

def debug_print(msg):
    """ Helper function to print debug messages if enabled. """
    if DEBUG:
        print(msg)

def build_dns_query(domain_name):
    """ Constructs a raw DNS query packet. """
    transaction_id = 1234  
    flags = 0x0100  # Standard recursive query
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

def extract_referral_info(response):
    """ 
    Extracts referral information from DNS response.
    Returns a tuple of (nameserver, nameserver_ip) 
    """
    additional_count = struct.unpack("!H", response[10:12])[0]
    authority_count = struct.unpack("!H", response[8:10])[0]

    offset = 12  # Start of the DNS header
    
    # Skip Question section
    while response[offset] != 0:
        offset += 1
    offset += 5  # Skip null byte, QTYPE, and QCLASS

    # Process Authority section to find NS
    possible_ns_names = []
    for _ in range(authority_count):
        # Skip name (could be compressed)
        if response[offset] >= 192:
            offset += 2  # Skip pointer
        else:
            while response[offset] != 0:
                offset += 1
            offset += 1  # Skip null byte

        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8  # Skip type, class, and TTL
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        if record_type == 2:  # NS record
            ns_name, _ = parse_compressed_name(response, offset)
            possible_ns_names.append(ns_name)

        offset += rdlength

    # Process Additional section to find NS IP
    offset = 12  # Reset to header
    while response[offset] != 0:
        offset += 1
    offset += 5  # Skip question section

    for _ in range(additional_count):
        # Skip name (could be compressed)
        if response[offset] >= 192:
            offset += 2
        else:
            while response[offset] != 0:
                offset += 1
            offset += 1

        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8  # Skip type, class, and TTL
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        if record_type == 1 and rdlength == 4:  # A record
            nameserver_ip = ".".join(map(str, response[offset:offset+4]))
            # If we have matching nameservers, return the first pair
            if possible_ns_names:
                return possible_ns_names[0], nameserver_ip

        offset += rdlength

    # If no IP found in Additional section, return first NS name
    return possible_ns_names[0] if possible_ns_names else None, None

def iterative_dns_resolution(domain):
    """ 
    Performs iterative DNS resolution by querying DNS servers step by step.
    """
    # Expanded list of root servers
    root_servers = [
        "170.247.170.2",   # b.root-servers.net
        "192.33.4.12",     # c.root-servers.net
        "199.7.91.13",     # d.root-servers.net
        "192.112.36.4",    # g.root-servers.net
        "193.0.14.129",    # k.root-servers.net
    ]

    debug_print(f"Resolving {domain} using iterative DNS resolution")

    # First, find TLD servers for the domain
    tld = domain.split('.')[-1]
    current_servers = root_servers

    for server in current_servers:
        debug_print(f"Querying root DNS server: {server}")
        response, _ = send_dns_request(domain, server)

        if not response:
            debug_print(f"No response from {server}")
            continue

        # Check if we have a final answer
        answer_count = struct.unpack("!H", response[6:8])[0]
        if answer_count > 0:
            ip = parse_dns_response(response)
            if ip:
                return ip

        # Extract referral information for TLD servers
        ns_name, ns_ip = extract_referral_info(response)

        if ns_name:
            debug_print(f"Referral to TLD Nameserver: {ns_name}")
            
            # If we have an IP for the nameserver, use it
            if ns_ip:
                debug_print(f"TLD Nameserver IP found: {ns_ip}")
                
                # Query TLD server
                tld_response, _ = send_dns_request(domain, ns_ip)
                
                if not tld_response:
                    debug_print(f"No response from TLD server {ns_ip}")
                    continue

                # Check for final answer in TLD response
                answer_count = struct.unpack("!H", tld_response[6:8])[0]
                if answer_count > 0:
                    ip = parse_dns_response(tld_response)
                    if ip:
                        return ip

                # Extract authoritative nameserver
                auth_ns_name, auth_ns_ip = extract_referral_info(tld_response)

                if auth_ns_name:
                    debug_print(f"Referral to Authoritative Nameserver: {auth_ns_name}")
                    
                    # Manually resolve authoritative nameserver if no IP
                    if not auth_ns_ip:
                        auth_ns_ip = manual_ns_resolution(auth_ns_name)

                    if auth_ns_ip:
                        debug_print(f"Authoritative Nameserver IP: {auth_ns_ip}")
                        
                        # Final query to authoritative nameserver
                        final_response, _ = send_dns_request(domain, auth_ns_ip)
                        
                        if final_response:
                            ip = parse_dns_response(final_response)
                            if ip:
                                return ip

        debug_print("Could not resolve domain through this server.")

    debug_print("Could not resolve domain.")
    return None

def manual_ns_resolution(ns_name):
    """ Manually resolve nameserver IP using system DNS resolution """
    try:
        return socket.gethostbyname(ns_name)
    except socket.gaierror:
        debug_print(f"Failed to resolve {ns_name}")
        return None

def iterative_dns_resolution(domain):
    """ 
    Performs iterative DNS resolution by querying DNS servers step by step.
    """
    # Start with root servers
    root_servers = [
        "170.247.170.2",  # b.root-servers.net
        "192.33.4.12",    # c.root-servers.net
        "199.7.91.13",    # d.root-servers.net
    ]

    current_servers = root_servers
    debug_print(f"Resolving {domain} using iterative DNS resolution")

    while current_servers:
        # Try each server in the current set
        for server in current_servers:
            debug_print(f"Querying DNS server: {server}")
            response, _ = send_dns_request(domain, server)

            if not response:
                debug_print(f"No response from {server}")
                continue

            # Check if we have a final answer
            answer_count = struct.unpack("!H", response[6:8])[0]
            if answer_count > 0:
                # We have our final IP
                ip = parse_dns_response(response)
                if ip:
                    return ip

            # Extract referral information
            ns_name, ns_ip = extract_referral_info(response)

            if ns_name:
                debug_print(f"Referral to Nameserver: {ns_name}")
                
                # If we have an IP for the nameserver, use it
                if ns_ip:
                    debug_print(f"Nameserver IP found: {ns_ip}")
                    current_servers = [ns_ip]
                    continue

                # If no IP, try to manually resolve
                ns_ip = manual_ns_resolution(ns_name)
                if ns_ip:
                    debug_print(f"Manually resolved {ns_name} to {ns_ip}")
                    current_servers = [ns_ip]
                    continue

        # If we can't resolve, break the loop
        break

    debug_print("Could not resolve domain.")
    return None

def parse_dns_response(response):
    """ Extracts the first A (IPv4), AAAA (IPv6), or CNAME from a DNS response. """
    ancount = struct.unpack("!H", response[6:8])[0]

    if ancount == 0:
        debug_print("No answer received.")
        return None

    offset = 12  # Start after header
    
    # Skip Question section
    while response[offset] != 0:
        offset += 1
    offset += 5  # Skip null byte, QTYPE, and QCLASS

    for _ in range(ancount):
        # Skip name (could be compressed)
        if response[offset] >= 192:
            offset += 2
        else:
            while response[offset] != 0:
                offset += 1
            offset += 1

        record_type = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 8  # Skip type, class, and TTL
        rdlength = struct.unpack("!H", response[offset:offset+2])[0]
        offset += 2

        if record_type == 1 and rdlength == 4:  # A record
            ipv4_address = ".".join(map(str, response[offset:offset+rdlength]))
            debug_print(f"Found A record: {ipv4_address}")
            return ipv4_address

        elif record_type == 28 and rdlength == 16:  # AAAA record
            ipv6_address = ":".join(
                f"{response[offset+i]:02x}{response[offset+i+1]:02x}" for i in range(0, rdlength, 2)
            )
            debug_print(f"Found AAAA record: {ipv6_address}")
            return ipv6_address

        offset += rdlength

    debug_print("No valid A or AAAA record found.")
    return None

# Main execution
if __name__ == "__main__":
    domain = "wikipedia.org"
    print(f"Resolving {domain} using iterative DNS resolution...")
    ip_address = iterative_dns_resolution(domain)
    if ip_address:
        print(f"Resolved IP: {ip_address}")
    else:
        print(f"Failed to resolve {domain}")

'''