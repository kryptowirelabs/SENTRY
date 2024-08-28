from scapy.all import *
from scapy.layers.inet import IP, TCP
import threading
import time
import datetime
import signal
import socket

# Global Variables
stop_sending = False
packet_dict = {}
# last_successful_cwin will by payload amount. Should be set to a reasonable payload, but not so high that packets are dropped immediately
last_successful_cwin = 500
next_cwin = 0
first = 0
count = 0
bytes_total = 0
count_rec = 0
dk_total = []

# Mutex to lock the packet dictionary
packet_dict_lock = threading.Lock()

# Signal handling for killing application and recording results
def signal_handler(sig, frame):
    global stop_sending
    print("Program killed, last cwin", last_successful_cwin)
    stop_sending = True
    with open(r'~/throughput_recorded.txt', 'w') as file:
        for dk in dk_total:
            file.write("%s\n" % dk)
    exit(0)

# Function for sending packets to destination
def send_packets(target_ip, target_port):
    global stop_sending, next_cwin, last_successful_cwin, packet_dict_lock, count
    seq_num = 0

    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    while not stop_sending:
        # Handler for cwin value. First tcp syn has no payload, then alternate between every other packet to send tcp syn with a payload
        if count == 0:
            next_cwin = 0
        elif count % 2 == 0:
            next_cwin = 0
        else:
            # increment bytes sent by 50
            next_cwin = last_successful_cwin + 50

        count += 1

        payload_cwin = Raw(b'A' * next_cwin)
        syn_packet = IP(dst=target_ip, flags=2) / TCP(dport=target_port, flags='S', seq=seq_num) / payload_cwin

        sender.sendto(bytes(syn_packet), (target_ip, 0))

        ack_key = 0
        # Lock the dictionary before modifying it
        with packet_dict_lock:
            if next_cwin != 0:
                ack_key = seq_num + next_cwin
            else:
                ack_key = seq_num + 1
            packet_dict[ack_key] = {'port': target_port, 'time_sent': datetime.datetime.now(), 'cwin': next_cwin}

        seq_num = ack_key

def receive_packets():
    sniff(filter="tcp and src host 192.168.99.3", prn=process_packet, store=0)


# Processing function for received packets. Determines if the packet can be added to the calculation
def process_packet(packet):
    global stop_sending, last_successful_cwin, packet_dict_lock, first, count_rec, bytes_total, dk_total
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        ack_num = tcp_layer.ack-1

        # Lock the dictionary before accessing it
        with packet_dict_lock:
            if tcp_layer.flags == 'RA':
                print(f"RST+ACK received, {packet.summary()}")
                if count_rec == 0:
                    first = time.time()
                if ack_num in packet_dict:
                    last_successful_cwin = packet_dict[ack_num]['cwin']
                    bytes_total += last_successful_cwin
                    del packet_dict[ack_num]
                else:
                    time_now = time.time()
                    if bytes_total != 0:
                        time_diff_s = (time_now-first)
                        dk = (bytes_total*8)/(time_diff_s)
                        dk_total.append(dk)

            elif tcp_layer.flags == 'SA':
                print(f"SYN+ACK received (WRONG), {packet.summary()}")
            elif tcp_layer.flags == 'A':
                if ack_num in packet_dict:
                    print(f"ACK received for seq {ack_num}, {packet.summary()}")
                    last_successful_cwin = packet_dict[ack_num]['cwin']
                    del packet_dict[ack_num]
            else:
                print(f"Unexpected response, {packet.summary()}")
        count_rec += 1
        print("dk total, ", dk_total)

def calc_throughput(target_ip, target_port):
    global stop_sending, packet_dict, dk_total

    # Start the sender thread
    sender_thread = threading.Thread(target=send_packets, args=(target_ip, target_port))
    sender_thread.start()

    # Start the receiver thread
    receiver_thread = threading.Thread(target=receive_packets)
    receiver_thread.start()


    # Wait for sender thread to finish
    sender_thread.join()
    receiver_thread.join()

    print("Stopped sending packets.")
    print("Remaining packets in dict:", packet_dict)


signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    target_ip = "192.168.99.3"
    target_port = 8001

    calc_throughput(target_ip, target_port)