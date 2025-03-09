import socket 
import time

# Total packet size
PACKET_SIZE = 1024
# Bytes reserved for sequence ID
SEQUENCE_ID_SIZE = 4
# Bytes available 
MESSAGE_SIZE = PACKET_SIZE - SEQUENCE_ID_SIZE
start_time = None

# Read data
with open('file.mp3', 'rb') as f:
    data = f.read()

# Creating UDP socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket:
    # Start the throughput timer
    if start_time is None:
        start_time = time.time()
    
    socket.bind(("0.0.0.0", 5000))
    socket.settimeout(1)

    # Start sending data
    sequence_ID = 0
    bytes_sent = 0

    # Packet delay
    pakcet_time_list = {}
    packet_delay_list = []
    acked_packets = 0
    packets_sent = 0

    while sequence_ID < len(data):
        tmp_sequence_ID = sequence_ID
        # Construct message
        message = int.to_bytes(tmp_sequence_ID, SEQUENCE_ID_SIZE, byteorder = 'big', signed = True) + data[tmp_sequence_ID : tmp_sequence_ID + MESSAGE_SIZE]
        tmp_sequence_ID += MESSAGE_SIZE
        # Send message
        socket.sendto(message, ('localhost', 5001))

        # Timer for packet delay (once packet is sent)
        if tmp_sequence_ID not in pakcet_time_list:
            pakcet_time_list[tmp_sequence_ID] = time.time()

        # For throughput
        bytes_sent += len(message)
        # Packet delay
        packets_sent +=1

        # Wait for ack
        while True:
            try:
                # Wait for ack
                ack, _ = socket.recvfrom(PACKET_SIZE)

                # Extract ack ID
                ack_ID = int.from_bytes(ack[:SEQUENCE_ID_SIZE], byteorder = 'big')
                print(ack_ID, ack[SEQUENCE_ID_SIZE])

                # Calculate packer delay
                if ack_ID in pakcet_time_list:
                    packet_delay = time.time() - pakcet_time_list[ack_ID]
                    packet_delay_list.append(packet_delay)
                    total_acked_packets += 1
                if ack_ID == sequence_ID + len(message) - SEQUENCE_ID_SIZE:
                    break
            except socket.timeout:
                # No ack received so resend unacked messages
                socket.sendto(message, ('localhost', 5001))
        
        # Move the sequence ID forward
        sequence_ID += MESSAGE_SIZE
    
    # Send clsoing message
    # Stop timer for throughput and calculate it
    end_time = time.time()
    total_time = end_time - start_time
    throughput = bytes_sent / total_time

    # Calculate packet delay
    packet_delay_avg = sum(packet_delay_list) / acked_packets
    
    # Metric
    metric = (0.3 * (throughput /1000) + ((0.7)/(packet_delay_avg)))
    
    # Send final closing message
    final_ack_message = int.to_bytes(tmp_sequence_ID, SEQUENCE_ID_SIZE, byteorder = 'big', signed = True) + b'==FINALACK=='
    socket.sendto(final_ack_message, ('lockalhost', 5001))

    # Print the final information
    print(f"Throughput: {throughput:.2f} B/S")
    print(f"Average Per-Packet Delay: {packet_delay_avg:.6f} seconds")
    print(f"Metric: {metric:.4f}")