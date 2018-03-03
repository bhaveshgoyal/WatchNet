#include <iostream>
#include <string>
#include "lib/defs.h"

using namespace std;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	cout << "HERE" << endl;

	return;
}
int main(int argc, char **argv){

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	string fname = "assignment2.pcap";

	handle = pcap_open_offline(fname.c_str(), errbuf);
	if (!handle){
		cout << "Error reading dump: " << fname << endl;
		exit(0);
	}

	pcap_loop(handle, -1, packet_handler, NULL);
	pcap_close(handle);

	return 0;


}
