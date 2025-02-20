from ping3 import ping
import time
import iperf3
import socket

# Global variable, controller for amount of pings to be sent
max_runs = 10


# Latency test, will ping the destination
def latency_test(ip):
    global max_runs
    latency_array = []
    while max_runs >= 0:
        latency = ping(ip)
        if latency is not None:
            # latency*1000 is latency in MS
            latency_array.append(latency*1000)
        else:
            print("Can not connect!")
        max_runs -= 1
        time.sleep(1)
    max_runs = 10
    return latency_array


# iperf wrapper for python, currently unused as GNS-3 does not interact well with iperf
def iperf_client_sentry(server_ip, port, speed):
    client = iperf3.Client()
    client.server_hostname = server_ip
    client.port = port
    # client.bitrate = speed * 1000000
    # Due to a current bug, this variable needs to be set lower than 99.
    client.duration = 98

    print(f"Starting iperf3 client to {server_ip}:{port}")
    result = client.run()
    if result.error:
        print(f"Error: {result.error}")
    else:
        print(f"iperf finished! Send Mbps: {result.sent_Mbps} Received_Mbps: {result.received_Mbps}")
        return result.sent_Mbps, result.received_Mbps


# Saturation function, can be customized by modifying packet size, duration, or sleep between packet sends
# At max packet size, about 70000 packets will be sent in 60 seconds. At cwin 1000, over 3,000,000 packets will be sent,
# making the modifications to the sleep between sends important
def throughput_saturation(server_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 65507
    payload = b'X' * 65507

    # run for 60 seconds
    duration = 60
    end_time = time.time() + duration
    packets_sent = 0
    print(f"Starting throughput saturation to {server_ip}:{port} for {duration}")

    while time.time() < end_time:
        sock.sendto(payload, (server_ip, port))
        packets_sent += 1
        # Sleep between packet sends
        time.sleep(.0045)

    print(f"Sent {packets_sent} packets. Throughput saturation ended!")
    #sock.close()
    # return packets_sent


# Current function for checking if a link is on the vpn path. requires at least 2 of the 3 tests to be positive
# Numbers are based on data collected, can be refined in the future by having a proper database
def check_if_link_is_on_path(latency, capacity, packets_returned):
    on_path_count = 0
    if latency > 10:
        print("LATENCY IS HIGH")
        on_path_count += 1
    if capacity < 50:
        print("Capacity is slow")
        on_path_count += 1
    if packets_returned < 4950:
        print("Packets being dropped!")
        on_path_count += 1
    if on_path_count >= 2:
        return True
    else:
        return False

