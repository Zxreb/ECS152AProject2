import socket
import time

# Total packet size
PACKET_SIZE = 1024
# Bytes reserved for sequence ID
SEQUENCE_ID_SIZE = 4
# Bytes available
MESSAGE_SIZE = PACKET_SIZE - SEQUENCE_ID_SIZE
# Total packets to send
WINDOW_SIZE = 100
start_time = None

# Read data
with open('file.mp3', 'rb') as f:
    data = f.read()

# Creating UDP socket
bytes_sent = 0
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_socket:  # Renamed from "socket" to avoid conflicts
    # Start the throughput timer
    if start_time is None:
        start_time = time.time()

    udp_socket.bind(("0.0.0.0", 5000))
    udp_socket.settimeout(1)

    # Start sending data
    sequence_ID = 0
    # List to keep track of duplicate acks
    dup_acks = {}

    packet_time_list = {} 
    packet_delay_list = []
    acked_packets = 0
    packets_sent = 0

    while sequence_ID < len(data):
        # Create messages
        messages = []
        acks = {}
        tmp_sequence_ID = sequence_ID

        for i in range(WINDOW_SIZE):
            if tmp_sequence_ID >= len(data):
                break

            # Construct message with sequence ID
            message = int.to_bytes(tmp_sequence_ID, SEQUENCE_ID_SIZE, byteorder='big', signed=True) + \
                      data[tmp_sequence_ID: tmp_sequence_ID + MESSAGE_SIZE]

            messages.append((tmp_sequence_ID, message))
            acks[tmp_sequence_ID] = False
            dup_acks[tmp_sequence_ID] = 0
            tmp_sequence_ID += MESSAGE_SIZE

            if tmp_sequence_ID not in packet_time_list:
                packet_time_list[tmp_sequence_ID] = time.time()

        # Send messages
        for seq_id, message in messages:
            udp_socket.sendto(message, ('localhost', 5001))
            bytes_sent += len(message)
            packets_sent += 1

        # Wait for ACKs
        # Avoid infinite resends
        retry_limit = 3  
        retry_count = 0
        while retry_count < retry_limit:
            try:
                # Wait for ack
                ack, _ = udp_socket.recvfrom(PACKET_SIZE)

                # Check ACK size before processing
                if len(ack) >= SEQUENCE_ID_SIZE:
                    ack_ID = int.from_bytes(ack[:SEQUENCE_ID_SIZE], byteorder='big')
                else:
                    # Assign a default invalid value to prevent issues
                    ack_ID = -1  
                    # Skip processing this bad ACK
                    continue  

                # Validate ACK before processing
                if ack_ID in packet_time_list:
                    packet_delay = time.time() - packet_time_list[ack_ID]
                    packet_delay_list.append(packet_delay)
                    acked_packets += 1

                # Record ack ID into duplicate ack list
                if ack_ID not in dup_acks:
                    dup_acks[ack_ID] = 0
                else:
                    dup_acks[ack_ID] += 1

                # Mark previous and current sid as successful
                for sid in list(acks.keys()):
                    if sid <= ack_ID:
                        acks[sid] = True

                # If there are 3 duplicate ACKs, fast retransmit
                if dup_acks[ack_ID] == 3:
                    for sid, message in messages:
                        if sid == ack_ID:
                            udp_socket.sendto(message, ('localhost', 5001))
                            break

                # All ACKs received, move forward
                if all(acks.values()):
                    break

            except socket.timeout:
                retry_count += 1
                for sid, message in messages:
                    if not acks[sid]:
                        udp_socket.sendto(message, ('localhost', 5001))

        # Move sequence_ID forward even if ACK is unexpected
        if ack_ID in packet_time_list:
            sequence_ID = ack_ID + MESSAGE_SIZE
        else:
            sequence_ID += MESSAGE_SIZE  

    end_time = time.time()
    total_time = end_time - start_time
    throughput = bytes_sent / total_time if total_time > 0 else 0

    if acked_packets > 0:
        packet_delay_avg = sum(packet_delay_list) / acked_packets
    else:
        packet_delay_avg = float('inf')  

    # Metric Calculation
    metric = (0.3 * (throughput / 1000)) + (0.7 / packet_delay_avg if packet_delay_avg > 0 else 0)

    # Send final closing message
    final_ack_message = int.to_bytes(tmp_sequence_ID, SEQUENCE_ID_SIZE, byteorder='big', signed=True) + b'==FINALACK=='
    udp_socket.sendto(final_ack_message, ('localhost', 5001))  

    # Print the final information
    print(f"{throughput:.7f}")
    print(f"{packet_delay_avg:.7f}")
    print(f"{metric:.7f}")