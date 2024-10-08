# Capacity and Through-put Applications
Measuring Paths & Link Characteristics
TCP Westwood, a variant of TCP, has a built-in mechanism to measure the available path bandwidth and use it to adjust the TCP slow-start threshold. In LinkWidth, we implemented a single-end TCP Westwood sender, thus requiring no support or active collaboration from a remote host or network device. We give more details about TCP Westwood Congestion Control later in this section.

To measure the available capacity to a destination, LinkWidth transmits TCP SYN packets to closed ports. The receiver, a router, or an end-host replies with a TCP packet with the RST and ACK flags set. Where TCP packets are filtered or rate-limited due to security considerations, we rely on ICMP ECHO REPLY messages from the receiver to signal correct reception of probe packets (by sending ICMP ECHO REQUEST packets instead of TCP SYNs). To measure end-to-end TCP capacity, the sender emulates the TCP Westwood sender by sending cwin packets. cwin − 2 TCP RST packets (called load packets) are “sandwiched” between two TCP SYN packets (called the head measurement packet and tail measurement packet, respectively). These TCP SYN packets sent to closed ports evoke TCP RST+ACK reply packets.

Figure 1 shows this arrangement of packets. Correct reception of the train of cwin + 1 (since we do not count the head measurement packet) packets is determined by two TCP packets with RST and ACK flags set that is sent from the receiver (due to the head and tail measurement packets). Each correct reception of the TCP RST+ACK pair causes cwin to be increased either exponentially (Slow Start phase) or linearly (Congestion Avoidance phase). Since we do not establish a TCP connection, the only way to signal a packet loss is by using a coarse timeout. After sending the train, the sender initializes a timer to wait for the two expected ACKs. The expiration of the timeout causes the re-adjustment of the cwin and ssthresh parameters inside a timeout event handler method.

The choice of TCP RST packets ensures that we will avoid unnecessary replies. These replies can be either in the form of TCP RST or ICMP Destination Host/Net Unreachable packets and can interfere with our forward probe traffic. The time dispersion between two consecutive TCP RST+ACK replies due to the head and tail measurement packets is stored as tn and tn−1. Thus, the capacity is measured as:

**bk = (cwin ∗ L) / (tn − tn1)**

Here bk is the measured “instantaneous” bandwidth, cwin ∗ L is the total data sent (in bits) for the entire train, and tn and tn−1 are the times of reception of the two TCP RST+ACK reply packets. Our method is a direct extension of the packet train method. The successful reception of a previous train determines how many packets we send in the current train.

Throughput measurement is a slight modification of the capacity measurement technique. The TCP RST load packets are replaced by TCP SYN packets (all destined to closed ports on the receiver). Figure 2 shows this arrangement of packets. The time of reception of the TCP RST+ACK due to the first TCP SYN packet is stored in the variable first. Thus, for any value of cwin, if any m replies are received correctly (such that 1 ≤ m ≤ cwin), this indicates that the throughput is:

**bk = (m ∗ L) / (tm − first )**

where tm is the time when the mth reply is correctly received. LinkWidth reports the measurement as Available Bandwidth Estimate (BWE). In some networks, we observed that TCP SYN packets might be filtered or rate-limited. To obtain measurements, we replaced the head and tail TCP SYN packets with ICMP ECHO packets. The load packets continue to be TCP RST packets. The correct reception of the packet train is indicated by the reception of ICMP ECHO REPLY packets at the sender. The arrangement of packets is shown in Figure 5. A similar modification is used for measuring throughput: the receiver waits to see how many ICMP ECHO REPLY response packets it receives before estimating the throughput. The corresponding packet arrangement is shown in Figure 2.


![image](https://github.com/user-attachments/assets/d6a6bcf6-ef8c-4ec8-ae60-7f26c2151ae5)
Figure 1: Arrangement of packets in LinkWidth for Measurement of Capacity. Figure 2: Arrangement of packet in LinkWidth for Measurement of Through- put.


**LinkWidth Implementation**: We implemented a prototype of LinkWidth for GNU/Linux. To avoid incurring packet delays due to kernel resource scheduling, we bypassed the regular protocol stack, and we crafted our own TCP and ICMP packets using the Raw Socket API. The coarse timeout is implemented using the standard POSIX API function setitimer(). The expiration of the timer is indicated by raising a SIGALRM signal.
