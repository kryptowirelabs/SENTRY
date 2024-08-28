from scapy.all import *
from scapy.layers.inet import IP, TCP
import threading
import time
import signal
import socket

# Global variables
stop_sending = False
previous_time = 0
count = 0
count_process = 0
bk_total = []
cwin = 1000

# Signal handler for early termination
def signal_handler(sig, frame):
    global stop_sending
    print("Program killed")
    stop_sending = True
    print(bk_total)
    sum = 0
    for bk in bk_total:
        sum += bk
    bk_average = sum / len(bk_total)
    print("BK AVERAGE - ", bk_average)
    print(len(bk_total))
    print("Received cwin>0 count - ", count_process)
    exit(0)


# packet sending function, alternates between sending tcp syn with a payload of 0, and tcp rst with cwin payload
def send_packets(target_ip, target_port):
    global stop_sending, count, cwin
    seq_num = 1
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    while not stop_sending:
        # Send SYN packet with cwin=0
        syn_packet = IP(dst=target_ip) / TCP(dport=target_port, flags='S', seq=seq_num)
        #send(syn_packet, verbose=0)
        sender.sendto(bytes(syn_packet), (target_ip, 0))

        print(f"Sent SYN packet with seq: {seq_num}, cwin: 0")
        seq_num += 1

        # Send RST packet with cwin=1400
        rst_packet = IP(dst=target_ip) / TCP(dport=target_port, flags='R', seq=seq_num) / Raw(b'A' * cwin)
        #send(rst_packet, verbose=0)
        sender.sendto(bytes(rst_packet), (target_ip, 0))
        count += 1
        
        print(f"Sent RST packet with seq: {seq_num}, cwin: {cwin}")
        seq_num += 1
        # if statement can be modified, used for runtime of testing.
        if seq_num >= 50000:
            stop_sending = True


def receive_packets():
    sniff(filter="tcp and src host 192.168.70.11", prn=process_packet, store=0)


# Processes received packets, calculates capacity measurement if received packet is appropriate
def process_packet(packet):
    global stop_sending, previous_time, count_process, bk_total, cwin

    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        count_process += 1

        if tcp_layer.flags == 'RA':
            print(f"RST+ACK received, {packet.summary()}")

            if previous_time == 0:
                previous_time = time.time()
            else:
                time_received = time.time()
                time_difference_s = (time_received-previous_time)
                bk = (8*cwin)/time_difference_s
                bk_total.append(bk)
                previous_time = time_received

        elif tcp_layer.flags == 'SA':
            print(f"SYN+ACK received (WRONG), {packet.summary()}")

        elif tcp_layer.flags == 'A':
            print(f"Unexpected ACK received, {packet.summary()}")

        else:
            print(f"Unexpected response, {packet.summary()}")

def calc_throughput(target_ip, target_port):
    global stop_sending

    sender_thread = threading.Thread(target=send_packets, args=(target_ip, target_port))
    sender_thread.start()

    receiver_thread = threading.Thread(target=receive_packets)
    receiver_thread.start()

    sender_thread.join()
    receiver_thread.join()

    print("Stopped sending packets.")


signal.signal(signal.SIGINT, signal_handler)

if __name__ == "__main__":
    target_ip = "192.168.70.11"
    target_port = 8001

    calc_throughput(target_ip, target_port)

