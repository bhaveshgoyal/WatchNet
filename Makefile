all:
	g++ -lpcap -I./lib analysis_pcap_tcp.cpp -o tcp_analyze
	g++ -lpcap -I./lib analysis_pcap_http.cpp -o http_analyze
