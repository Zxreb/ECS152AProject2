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
bytes_sent = 0
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as socket:
    # Start the throughput timer
    if start_time is None:
        start_time = time.time()
    
    socket.bind(("0.0.0.0", 5000))
    socket.settimeout(1)

    # Start sending data
    sequence_ID = 0

    # Tahoe variables
    dup_acks = {}
    cwnd = 1
    ssthresh = 64
    last_ack = -1

    pakcet_time_list = {}
    packet_delay_list = []
    acked_packets = 0
    packets_sent = 0

    while sequence_ID < len(data):
        # Crate messages
        messages = []
        acks = {}
        tmp_sequence_ID = sequence_ID

        for i in range(int(cwnd)):
            
            if tmp_sequence_ID >= len(data):
                break
            # Construct messages
            # Sequence ID of length SEQ_ID_SIZE + message of remaining PACKET_SIZE - SEQ_ID_SIZE bytes
            message = int.to_bytes(tmp_sequence_ID, SEQUENCE_ID_SIZE, byteorder = 'big', signed = True) + data[tmp_sequence_ID : tmp_sequence_ID + MESSAGE_SIZE]
            messages.append((tmp_sequence_ID, message))
            acks[tmp_sequence_ID] = False
            dup_acks[tmp_sequence_ID] = 0
            tmp_sequence_ID += MESSAGE_SIZE

            if tmp_sequence_ID not in pakcet_time_list:
                pakcet_time_list[tmp_sequence_ID] = time.time()

        # Send messages
        for _, message in messages:
            socket.sendto(message, ('localhost', 5001))
            bytes_sent += len(message)
            packets_sent += 1

        # Wait for ack
        while True:
            try:
                # Wait for ack
                ack, _ = socket.recvfrom(PACKET_SIZE)

                # Extract ack ID
                ack_ID = int.from_bytes(ack[:SEQUENCE_ID_SIZE], byteorder = 'big')
                print(ack_ID, ack[SEQUENCE_ID_SIZE])

                if ack_ID in pakcet_time_list:
                    packet_delay = time.time() - pakcet_time_list[ack_ID]
                    packet_delay_list.append(packet_delay)
                    acked_packets += 1

                # Record ack ID into duplicate ack list 
                if ack_ID not in dup_acks:
                    dup_acks[ack_ID] = 0
                else:
                    dup_acks[ack_ID] += 1
                
                if ack_ID > last_ack:
                    last_ack = ack_ID
                    if cwnd < ssthresh:
                        cwnd += 1
                    else :
                        cwnd += 1 / cwnd

                # Mark previous and current sid as successful
                for sid in list(acks.keys()):
                    if sid <= ack_ID:
                        acks[sid] = True

                # If there are 3 acks do FRT
                if dup_acks[ack_ID] == 3:
                    # Go through message list to find sid
                    for sid, message in messages:
                        # If sid is == to ack ID then resend
                        if sid == ack_ID:
                            ssthresh = max(1, cwnd // 2)
                            cwnd = ssthresh + 3
                            socket.sendto(message, ('localhost', 5001))
                            break

                # All acks received so move on
                if all(acks.values()):
                    break

            except socket.timeout:
                ssthresh  =max(1, cwnd // 2)
                cwnd = 1
                # No ack received, resend unacked messages
                for sid, message in messages:
                    if not acks[sid]:
                        socket.sendto(message, ('localhost', 5001))

        # Move sequence ID forward
        sequence_ID = ack_ID

    end_time = time.time()
    total_time = end_time - start_time
    throughput = bytes_sent / total_time
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