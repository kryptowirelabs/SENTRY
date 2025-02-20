import socket

import throughput
import capacity
import data_reliability
import threading
import signal
from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import psutil

# Global variables used for threaded functions
capacity_results = []
latency_results = []


# HTTP handler to receive curl commands
class SENTRYHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        global capacity_results, latency_results
        received_packet = urllib.parse.parse_qs(self.path[2:])
        print("Received packet: ", received_packet)
        response_message = ""
        ip = ""
        port = 8001
        function = ""
        speed_iperf = 0
        runner = False

        if "ip" in received_packet and "port" in received_packet and "function" in received_packet:
            ip = received_packet['ip'][0]
            port = received_packet['port'][0]
            function = received_packet['function'][0]
            response_message = f"Received IP: {ip}, Port:{port}, Function:{function}"
            runner = True
        elif "ip" in received_packet and "function" in received_packet:
            ip = received_packet['ip'][0]
            function = received_packet['function'][0]
            response_message = f"Received IP: {ip}, Port (USING DEFAULT): 8001, Function:{function}"
            runner = True
        else:
            response_message = "Missing Params. Default cannot be used for IP or Function."

        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        if runner:
            if int(function) == 3 and "speed" in received_packet:
                speed_iperf = int(received_packet['speed'][0])
            if int(function) == 3:
                mbps_sent, mbps_received = main(ip, port, function, speed_iperf)
                response_message = (f"Saturation sending finished! Mbps sent: {mbps_sent}, Mbps received: {mbps_received}")
            else:
                capacity, latency, packets, on_path = main(ip, port, function, speed_iperf)
                response_message = (f"Average Capacity (Bytes): {capacity}, Average Latency (MS): {latency}, "
                                f"Packets Received: {packets} Link is on VPN Path: {on_path}")

        self.wfile.write(bytes(response_message + "\n", "utf8"))
        capacity_results = []
        latency_results = []


# Get the IP address of this machine
def get_ip_for_httpserver(interface_name):
    addrs = psutil.net_if_addrs()
    if interface_name in addrs:
        for addr in addrs[interface_name]:
            if addr.family == 2:
                return addr.address
    return None


# RUNNER COMMAND curl "http://192.168.75.5:8080/?ip=192.168.88.1&port=8001&function=1"
# Start HTTP server
def start_server():
    host = get_ip_for_httpserver("ens33")
    port = 8080
    server = HTTPServer((host, port), SENTRYHandler)
    print(f"Server started. IP:{host}:{port}")
    server.serve_forever()


# Find the average of an input array
def find_average(populated_array):
    sum_num = 0
    for num in populated_array:
        sum_num += num
    average = sum_num / len(populated_array)
    return average


# Signal handler, currently unused
def signal_handler(sig, frame):
    print("Program killed")
    exit(0)


# Function used to store results of the capacity function thread
def capacity_thread(ip, port):
    global capacity_results
    capacity_results = capacity.main(ip, port)


# Function used to store results of the data reliability function thread
def data_reliability_thread(ip):
    global latency_results
    latency_results = data_reliability.latency_test(ip)


# Main function, contains the threads for the SENTRY application and controls the flow of data through associated files
def main(ip, port, function, speed_iperf):
    port = int(port)
    function = int(function)
    if function == 1:
        primary_thread = threading.Thread(target=capacity_thread, args=(ip, port))
    elif function == 2:
        primary_thread = threading.Thread(target=throughput.main, args=(ip, port))
    elif function == 3:
        # requires nc -u -l 8069 on destination
        packets_sent = data_reliability.throughput_saturation(ip, port)
        return packets_sent, packets_sent
    else:
        # Temp hard coded values for testing, remove all commands minus print
        print("Please enter appropriate function.")
        return -1

    latency_thread = threading.Thread(target=data_reliability_thread(ip))

    primary_thread.start()
    latency_thread.start()

    primary_thread.join()
    latency_thread.join()

    bk_total, packets_received, packets_sent = capacity_results
    average_latency = find_average(latency_results)
    average_capacity = find_average(bk_total)
    average_capacity = average_capacity * (packets_received/5000)
    on_path = data_reliability.check_if_link_is_on_path(average_latency, average_capacity, packets_received)
    print("Average capacity (Bytes): ", average_capacity)
    print("Average latency (MS): ", average_latency)
    print("Packets received: ", packets_received)
    print("Is link on VPN Path: ", on_path)
    return average_capacity, average_latency, packets_received, on_path


# Start HTTP server
start_server()
# Start signal handler, currently unused
signal.signal(signal.SIGINT, signal_handler)
