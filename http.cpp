#include <iostream>
#include <string>
#include <time.h>
#include "lib/defs.h"
#include "lib/colors.h"
#include <netinet/ip.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <set>
#include <vector>
#include <unordered_map>
#include <sstream>
using namespace std;

typedef struct seg{
	int src_port;
	int dst_port;
	
	uint32_t seq_num;
	uint32_t ack_num;

}seg;

typedef struct seq{
	uint32_t count;
	
	string req;
	int req_len;
	string resp;
	int resp_len;

	uint32_t curr_seq;
	uint32_t next_ack;
	long ts_sec;
	long ts_usec;
	long rtt;
	int seg_len;
	vector<seg*>segs;

}seq;

typedef struct ack{
	uint32_t count;
}ack;

typedef struct flow{
	int src_port;
	int dst_port;
	u_short flags;
	int trans_seen;
	struct timeval syn_stamp;
	long bytes_sent;
	uint32_t packets_sent;
	uint32_t packets_rcvd;
	uint32_t re_trans;
	uint32_t fre_trans;
	uint32_t icwnd;
	long rtt;
	unordered_map<uint32_t, seq*> rtt_map;
	unordered_map<uint32_t, seq*> seq_map;
	unordered_map<uint32_t, ack*> ack_map;
	vector<int> wnd_sizes;

}flow;


unordered_map<string, flow*> flow_mon;
int flow_count = 0;

stringstream out_buff;

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip* ip;
	const struct sniff_tcp* tcp;
	int ip_size, tcp_size;
	int src_port, dst_port;
	string type;
	

	ethernet = (struct sniff_ethernet*)(packet);
	uint16_t p_type = ntohs(ethernet->ether_type);

	packet += ETHER_SIZE;

	if (p_type == ETHERTYPE_IP){
		ip = (struct sniff_ip*)(packet);
		ip_size = IP_HL(ip)*4;
		if (ip_size < 20){
			cout << "Error Processing IP packet";
			exit(0);
		}
		packet += ip_size;
		if (ip->ip_p == IPPROTO_TCP){
				type = "TCP";
				tcp = (struct sniff_tcp*)(packet);
				
				tcp_size = TH_OFF(tcp)*4;
				if (tcp_size < 20){
					cout << "Invalid TCP Packet";
					return;
				}
				
				packet += tcp_size;

				src_port = (ntohs(tcp->th_sport));
				dst_port = (ntohs(tcp->th_dport));
				
				string src2dst = to_string(src_port) + "_" + to_string(dst_port);
				string dst2src = to_string(dst_port) + "_" + to_string(src_port);
				
				
				int cap_len = header->len - ETHER_SIZE - ip_size - tcp_size;
				if ((tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK) && !flow_mon.count(src2dst)){ // Get First Seen SYNs
					flow_count++;			
					flow *flow_init = new flow;
					flow_init->src_port = src_port;
					flow_init->dst_port = dst_port;
					flow_init->flags = TH_SYN;
					flow_init->trans_seen = 0;
					flow_init->bytes_sent = 0;	
					flow_init->packets_sent = 1;
					flow_init->packets_rcvd = 0;
					flow_init->re_trans = 0;
					flow_init->fre_trans = 0;
					
					long curr_seq = ntohl(tcp->th_seq);
		//			cout << "CURR SEQ: " << curr_seq << endl;
					seq *seq_node = new seq;
					seq_node->curr_seq = curr_seq;
					seq_node->count = 1;
					seq_node->next_ack = curr_seq + header->caplen - ETHER_SIZE - tcp_size - ip_size;
					seq_node->ts_sec = header->ts.tv_sec;
					seq_node->ts_usec = header->ts.tv_usec;
					seq_node->rtt = 0;
					seq_node->seg_len = 0;
			//		if (seq_node->next_ack != seq_node->curr_seq){
					seq_node->req = (char*)packet;
					seq_node->req_len = 0;
			//		}
			//		else
			//		seq_node->req_len = 0;
					seq_node->resp_len = 0;
					flow_init->rtt_map[seq_node->next_ack] = seq_node;
					flow_init->seq_map[curr_seq] = seq_node;
					
					flow_init->syn_stamp = header->ts;	
					
					flow_mon[src2dst] = flow_init;
					//cout << "Flow Initiated :" << src_port << " " << dst_port << endl << endl;
				
				}
				else if ((tcp->th_flags & TH_ACK) && flow_mon.count(src2dst) && flow_mon[src2dst]->flags == (TH_SYN)){ // Ack to SYN-ACK. (First ACK from src2dst)
						flow_mon[src2dst]->flags |= TH_ACK;

						flow_mon[src2dst]->packets_sent += 1;
				}
				else if (flow_mon.count(dst2src) && flow_mon[dst2src]->flags == TH_SYN && tcp->th_flags == (TH_SYN | TH_ACK)){ // SYN-ACK RCVD

						uint32_t curr_ack = (uint32_t)ntohl(tcp->th_ack);

						if (flow_mon[dst2src]->rtt_map.count(curr_ack) > 0){
								
								struct timeval end_stamp = (header->ts);
								flow_mon[dst2src]->rtt_map[curr_ack]->rtt = (end_stamp.tv_sec - flow_mon[dst2src]->rtt_map[curr_ack]->ts_sec)*1000000L 
										+ (end_stamp.tv_usec - flow_mon[dst2src]->rtt_map[curr_ack]->ts_usec); 	

						}
						flow_mon[dst2src]->packets_rcvd += 1;
				}
				else { // Handshake done. Transaction Packet
						if (flow_mon.count(src2dst) && flow_mon[src2dst]->flags == (TH_SYN | TH_ACK)){ // Data Sender
								

								flow_mon[src2dst]->packets_sent += 1;
								
								uint32_t seq_n = (uint32_t)ntohl(tcp->th_seq);
								
								if (flow_mon[src2dst]->seq_map.count(seq_n) > 0){
										flow_mon[src2dst]->re_trans++;
										if (flow_mon[src2dst]->ack_map.count(seq_n) && flow_mon[src2dst]->ack_map[seq_n]->count > 3)
											flow_mon[src2dst]->fre_trans++;
								}
								else{
											if (cap_len > 0){
											int cap_len = header->len - ETHER_SIZE - ip_size - tcp_size;
											seq *seq_node = new seq;
											seq_node->count = 1;
											seq_node->next_ack = seq_n + header->len - ETHER_SIZE - ip_size - tcp_size;
											seq_node->rtt = 0;
											seq_node->ts_sec = header->ts.tv_sec;
											seq_node->ts_usec = header->ts.tv_usec;
											seq_node->seg_len = 0;
												seq_node->req = (char*)packet;
												seq_node->req_len = 10; // Non Zero;
											seq_node->resp_len = 0;
											flow_mon[src2dst]->rtt_map[seq_node->next_ack] = seq_node;
											flow_mon[src2dst]->seq_map[seq_n] = seq_node;
											}
							//				cout << "REQUEST: " << packet << endl;
								}
								//			cout << "REQUEST" << endl;

						}
						else if (flow_mon.count(dst2src) && flow_mon[dst2src]->flags == (TH_SYN | TH_ACK)){ // Data Receiver

								uint32_t res_ack = (uint32_t)ntohl(tcp->th_ack);
								
								if (cap_len > 0 && flow_mon[dst2src]->rtt_map.count(res_ack) > 0){ //Update RTT
//									cout << "RESPONSE: " << packet << endl;

									if (flow_mon[dst2src]->rtt_map[res_ack]->resp_len == 0){	
										flow_mon[dst2src]->rtt_map[res_ack]->resp = (char*)packet;
										flow_mon[dst2src]->rtt_map[res_ack]->resp_len = 10; // Non Zero
										flow_mon[dst2src]->rtt_map[res_ack]->seg_len = 0; // Non Zero

						//				cout << packet << endl;
									}
									else{
										seg *resp_n = new seg;
										resp_n->src_port = src_port;
										resp_n->dst_port = dst_port;
										resp_n->seq_num = ntohl(tcp->th_seq);
										resp_n->ack_num = res_ack;

										int seg_len = flow_mon[dst2src]->rtt_map[res_ack]->seg_len;
										flow_mon[dst2src]->rtt_map[res_ack]->segs.push_back(resp_n);
										flow_mon[dst2src]->rtt_map[res_ack]->seg_len = flow_mon[dst2src]->rtt_map[res_ack]->segs.size();
									}

				//					struct timeval end_stamp = (header->ts);
				//					flow_mon[dst2src]->rtt_map[res_ack]->rtt = (end_stamp.tv_sec - flow_mon[dst2src]->rtt_map[res_ack]->ts_sec)*1000000L 
				//																+ (end_stamp.tv_usec - flow_mon[dst2src]->rtt_map[res_ack]->ts_usec); 	
								}
								
								
								flow_mon[dst2src]->packets_rcvd += 1;
								
	//							if (flow_mon[dst2src]->ack_map.count(res_ack) > 0){ // Response Retransmission
	//									flow_mon[dst2src]->ack_map[res_ack]->count += 1;
	//							}
	//							else{
	//									ack *ack_num = new ack;
	//									ack_num->count = 1;
	//									flow_mon[dst2src]->ack_map[res_ack] = ack_num;	
	//							}
						}
				}


				if ((tcp->th_flags & TH_FIN) && flow_mon.count(src2dst)){ // FIN from Sender. Successful Flow seen
					

					unordered_map<uint32_t, seq*>::iterator it;
					for(it = flow_mon[src2dst]->rtt_map.begin(); it != flow_mon[src2dst]->rtt_map.end(); it++){
						string request = it->second->req;
						string response = it->second->resp;

						int idx = request.find("\r\n\r\n");
						if (idx > 0 && request.find("Date") == string::npos){
							out_buff << BOLD(FRED("REQUEST: ")) << request.substr(0, idx) << endl << endl;
						}
						idx = response.find("\r\n\r\n");
						if (idx > 0){
							out_buff << BOLD(FGRN("RESPONSE: ")) << response.substr(0, idx) << endl << endl;
						}
						if (it->second->seg_len > 0)
							out_buff << "Segments Found: " << it->second->seg_len << endl << endl;
						for(int i = 0; i < it->second->seg_len; i++){
							out_buff << endl;
							out_buff << "Source Port" << "\t" << "Destination Port\t";
							out_buff << "Sequence Number" << "\t" << "Acknowledgement Number" << endl;
							out_buff << it->second->segs[i]->src_port << "\t\t" << it->second->segs[i]->dst_port << "\t\t\t";
							out_buff << it->second->segs[i]->seq_num << "\t" << it->second->segs[i]->ack_num << endl;
						}
						out_buff << endl << endl;
					
					}

					flow_mon.erase(src2dst);
				}

		}
		else
			cout << "Non TCP Packet Seen" << endl;
	}
	return;
}
int main(int argc, char **argv){

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	string fname = "http_1080.pcap";
	if (argc == 3){
		if (strcmp("-r", argv[1]) == 0)
			fname = argv[2];	
		else{
			cout << "Invalid Option. usage: [-r] file-name" << endl;
			exit(0);
		}
	}
	else if (argc != 1){
		cout << "Error. usage: [-r] file-name" << endl;
		exit(0);
	
	}

	handle = pcap_open_offline(fname.c_str(), errbuf);
	if (!handle){
		cout << "Error reading dump: " << fname << endl;
		exit(0);
	}

	pcap_loop(handle, -1, packet_handler, NULL);
	pcap_close(handle);
	
	cout << endl;
	if (flow_count > 6){
		cout << UNDL(BOLD("HTTP Version: /1.0")) << endl << endl;
		cout << out_buff.str();	
	}
	else if (flow_count == 6){
		cout << BOLD("------------------") << endl << endl;
		cout << BOLD("HTTP Version: /1.1") << endl << endl;
		cout << BOLD("------------------") << endl << endl;
	}
	else if (flow_count < 3){
		cout << BOLD("------------------") << endl << endl;
		cout << BOLD("HTTP Version: /2.0") << endl << endl;
		cout << BOLD("------------------") << endl << endl;
	}
	return 0;


}
