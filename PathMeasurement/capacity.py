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
cwin = 4000
IP_ADDRESS = ""
packet_amount = 5000


# outdated, but can be useful for testing
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


# Function responsible for sending packets
def send_packets(target_ip, target_port):
    global stop_sending, count, cwin, packet_amount
    seq_num = 1
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)

    while packet_amount >= 0:
        # Send SYN packet with cwin=0
        syn_packet = IP(dst=target_ip) / TCP(dport=target_port, flags='S', seq=seq_num)
        #send(syn_packet, verbose=0)
        sender.sendto(bytes(syn_packet), (target_ip, 0))

        #print(f"Sent SYN packet with seq: {seq_num}, cwin: 0")
        seq_num += 1

        # Send RST packet with cwin=1400
        rst_packet = IP(dst=target_ip) / TCP(dport=target_port, flags='R', seq=seq_num) / Raw(b'A' * cwin)
        #send(rst_packet, verbose=0)
        sender.sendto(bytes(rst_packet), (target_ip, 0))
        count += 1
        
        #print(f"Sent RST packet with seq: {seq_num}, cwin: {cwin}")
        seq_num += 1
        packet_amount -= 1
    #sender.close()
    stop_sending = True


# sniffer for receiving packets
def receive_packets(ip):
    global stop_sending
    sniff(filter=f"tcp and src host {ip}", prn=process_packet, store=0, stop_filter=lambda p: stop_sending)


# Process packets that have been received for type, timing, etc. This function contains the LinkWidth protocol
def process_packet(packet):
    global previous_time, count_process, bk_total, cwin
    if packet.haslayer(TCP):
        tcp_layer = packet.getlayer(TCP)
        count_process += 1
        if tcp_layer.flags == 'RA':
            #confirmation message will block out other tests messages
            #print(f"RST+ACK received, {packet.summary()}")
            if previous_time == 0:
                previous_time = time.time()
            else:
                time_received = time.time()

                time_difference_s = (time_received-previous_time)
                #print("TIME dif - ", time_difference_s)
                bk = (8*cwin)/time_difference_s
                bk_total.append(bk)
                previous_time = time_received
        elif tcp_layer.flags == 'SA':
            print(f"SYN+ACK received (WRONG), {packet.summary()}")
        elif tcp_layer.flags == 'A':
            print(f"Unexpected ACK received, {packet.summary()}")
        else:
            print(f"Unexpected response, {packet.summary()}")


# Thread handler function
def calc_throughput(target_ip, target_port):
    sender_thread = threading.Thread(target=send_packets, args=(target_ip, target_port))
    sender_thread.start()
    receiver_thread = threading.Thread(target=receive_packets(target_ip))
    receiver_thread.start()
    sender_thread.join()
    receiver_thread.join()


# Signal handler, currently unused
signal.signal(signal.SIGINT, signal_handler)


# Main function, will run the thread handler then reset all global variables
def main(ip, port):
    global bk_total, count_process, packet_amount, stop_sending, previous_time, count
    #target_ip = "192.168.88.1"
    #target_port = 8001
    calc_throughput(ip, port)
    stop_sending = False
    total_bk_packets = bk_total
    count_processed = count_process
    packet_amount_total = packet_amount
    previous_time = 0
    count = 0
    count_process = 0
    bk_total = []
    packet_amount = 5000
    return total_bk_packets, count_processed, packet_amount_total

