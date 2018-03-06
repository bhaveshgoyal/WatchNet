# WatchNet
WatchNet is a TCP, HTTP Packet Dissector which provides an analysis of TCP streams in a dump and binds request response
pairs for HTTP/1.0 traffic. The program also differentiates between HTTP v1.1 and HTTP v2.0 headers.

### To run:
```
Ensure you have libpcap library installed
sudo apt-get install libpcap-dev

git clone https://github.com/bhaveshgoyal/WatchNet.git
cd WatchNet/

To operate WatchNet for TCP analysis:
cd PART\ A_B/
make
chmod +x ./tcp_analysis
./tcp_analysis

To operate WatchNet for HTTP analysis:
cd PART\ C/
make
chmod +x ./http_analysis
./http_analysis [-r] <http_dump.pcap>
				optional parameter [Defaults: http_1080.pcap]
```

The Program when run in TCP mode, narrows down the number of TCP streams running in the dump and prints out header information for
first two transactions after handshake has been established. The throughput across the network is calculate as a function of effective
bytes sent over the network divides total time taken to send packets and an analysis on the loss rate on the wire is also provided. Since, the dump is assumed to be taken
on a single machine the program also calculates average RTT time for a TCP connection by analyzing entire stream with their individual RTTs.
Using the results, the program provides a performance analysis of the empirical throughput acquired with the theoretical throughput achievable across
the network.
Note: If any argument to HTTP analyzer is not provided, then the program defaults to using provided sample http\_1080.pcap file.

----------------------------------
**A Brief Note on TCP analyzer and implementation:**

Part A/B: (Combined Analysis)
The program makes use of libpcap library to acquire an offline pcap handle to loop over the dump packets. For each of the packets, the TCP offset
is calculated using the headers implemented in lib/defs.h. For each of the TCP packets, the set flags are analyzed to initialize a new stream whenever
a SYN flag is seen. Care has been provided to differentiate between all cases of 3-way handshake by analyzing current state of flow and the packet under
consideration. After establishing a 3 way handshake, the next packet from the sender is the first transaction packet and is recorded in a separate structure.
The packet is also examined to anticipate the ack number from the receiver based on current sequence number + payload sent by sender. Whenever a packet
corresponding to the anticipated ACK is seen, a transaction is said to be completed. The transaction information provides an analysis of Seq, ACK numbers as
well as the Advertised Window Sizes by either side. Since, TCP options specify the window scale option to determine the actual scaling factor for window size,
the factor was found to be 16384 (Shift Value of 14). Along with recording transactions, each of the requests were also stored to provide an average estimate
of RTTs. The stream was seen to have ended when a FIN to open stream was seen. At this point, an aggregate analysis is performed to estimate Average RTT and
throughput values. The Empirical Throughput was calculated as effective number of bytes transmitted (no. of bytes transmitted - no. of bytes retransmitted) / Time taken by bytes transmission.
This was compared to the Theoretical Throughput value achievable as a function of (MSS, LossRate, RTT). It was seen that in contrast to common belief, empirical throughput fell well above
theoretical limit. This could be attributed to the limit of Theoretical throughput w.r.t. the TCP Window size. Additionally, we might have been encountering a local maxima in the throughput values.
To provide a holistic view of empirical throughput we might need to consider longer data streams to improve the overall average and only include packets in one sliding window size
per its latency, as supposed to all bytes in the flow.
Moreover, more lossy networks were seen to have lower empirical throughput values, which is indeed understandable.

The TCP analyzer also estimates the first 10 Congestion Window sizes for TCP transactions. The Initial Congestion Window is estimated by calculating number of requests
sent over a flow before the first response is seen. Analyzing all the flows in the given dump, an initial window size of 10 is seen. Moreover, the window size increases
with every ACK received thereafter by 1, until any loss was observed. This effectively results in doubling the total number of packets that could be in transit in the flow.
Whenever a loss was seen the congestion window dropped by half if the loss was estimated w.r.t Fast Retransmits otherwise it was set to value 1 if the loss was due to a timeout.
Number of retransmissions due to Fast Retransmit was seen with the help of Triple Duplicate ACKs for any ACK number. This number was subtracted from the total number of 
retransmissions seen to get the number of timeout retransmissions(with an error limit of out or order TCP packet). 
This analysis was seen to be performed at the sender side of network since that side was seen to have varying sequence numbers with every requests implying the data sending side. 
Moreover, it was also seen that the same was the one to initiate a SYN connection, in contrast to a normal client - server browser fashion.

*Note:* Throughput Metrics are provided in Megabits / sec, RTT is provided in microseconds.

----------------------------
**Testing Environment**

```
g++ specifications: (Compiled with -lpcap)
Apple LLVM version 9.0.0 (clang-900.0.39.2)
Target: x86_64-apple-darwin17.4.0

Dependencies:
libpcap (stable)

OS specifications:
-Darwin 17.0.0 x86_64
(macOS High Sierra)

```