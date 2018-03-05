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