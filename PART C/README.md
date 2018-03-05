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
bytes sent over the network per RTT and an analysis on the loss rate on the wire is also provided. Since, the dump is assumed to be taken
on a single machine the program also calculates average RTT time for a TCP connection by analyzing entire stream with their individual RTTs.
Using the results, the program provides a performance analysis of the throughput aquired with the max theoretical throughput achievable across
the network.
Note: If any argument to HTTP analyzer is not provided, then the program defaults to using provided sample http\_1080.pcap file.

----------------------------------
**A Brief Note on HTTP analyzer and implementation:**

Part C:

Similar to the way the TCP analyzer parses the offline dump, it was seen that the HTTP header started after the offset of tcp\_section size. The code borrows a major from prior
implementation in Part A where TCP flow streams are analyzed for each of the HTTP dump packets. HTTP Request Response pairs were matched by calculating the offset of the 
expected acknowledgement number by adding the tcp payload size to the current sequence number. Whenever a HTTP Response was encountered (Differentiated by inspecting source
destination pairs), it was checked against if there was any existing request with the current acknowledgement number. This is because consecutive ack nums from the server to
client doesn't change for transmission segments. If so, the segments were put together in a different structure marked by the primary key of acknowledgement number. Later,
this key was analyzed to print the HTTP Request, Response and all the following TCP segments (if any).

To differentiate between different HTTP header versions, TCP flow streams patterns were taken into consideration. It was seen that the dump corresponding to http\_8091 was
HTTP/1.0 since there was a TCP flow for every HTTP transaction. Further, the dump file http\_8093 was seen to be HTTP/1.1 since there were 6 parallel connections that were seen
to be operating within a single flow. Finally, the dump http\_8092 was HTTP/2.0 since the entire page load was contained within a single TCP flow stream.
Analyzing, the bytes transferred and load times among all the versions, it was seen that HTTP/1.0 was fastest amongst both the versions due to the overhead of encryption and advanced header
options and maintenance of parallel connections. On the other hand other the same showed largest number of transferred bytes and two protocols were seen to have lesser number of bytes(HTTP/2.0)
being the least) in transit across network due to reduced overhead of TCP connection establishment and teardown communications.


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