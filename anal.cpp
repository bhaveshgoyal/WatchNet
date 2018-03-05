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
using namespace std;


typedef struct seq{
	uint32_t count;
	uint32_t curr_seq;
	uint32_t next_ack;
	long ts_sec;
	long ts_usec;
	long rtt;
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

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip* ip;
	const struct sniff_tcp* tcp;
	int ip_size, tcp_size;
	int src_port, dst_port;
	string type;

	ethernet = (struct sniff_ethernet*)(packet);
	uint16_t p_type = ntohs(ethernet->ether_type);
	
	if (p_type == ETHERTYPE_IP){
		ip = (struct sniff_ip*)(packet + ETHER_SIZE);
		ip_size = IP_HL(ip)*4;
		if (ip_size < 20){
			cout << "Error Processing IP packet";
			exit(0);
		}
		if (ip->ip_p == IPPROTO_TCP){
				type = "TCP";
				tcp = (struct sniff_tcp*)(packet + ETHER_SIZE + ip_size);
				
				tcp_size = TH_OFF(tcp)*4;
				if (tcp_size < 20){
					cout << "Invalid TCP Packet";
					return;
				}

				src_port = (ntohs(tcp->th_sport));
				dst_port = (ntohs(tcp->th_dport));
				
				string src2dst = to_string(src_port) + "_" + to_string(dst_port);
				string dst2src = to_string(dst_port) + "_" + to_string(src_port);
				
				if (flow_mon.count(src2dst)) //Throughput
					flow_mon[src2dst]->bytes_sent += header->len;
				else if (flow_mon.count(dst2src))
					flow_mon[dst2src]->bytes_sent += header->len;
				
				if ((tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK) && !flow_mon.count(src2dst)){ // Get First Seen SYNs
					
					flow *flow_init = new flow;
					flow_init->src_port = src_port;
					flow_init->dst_port = dst_port;
					flow_init->flags = TH_SYN;
					flow_init->trans_seen = 0;
					flow_init->bytes_sent = 0; //TODO Fix This	
					flow_init->packets_sent = 1;
					flow_init->packets_rcvd = 0;
					flow_init->re_trans = 0;
					flow_init->fre_trans = 0;
					
					long curr_seq = ntohl(tcp->th_seq);
					seq *seq_node = new seq;
					seq_node->curr_seq = curr_seq;
					seq_node->count = 1;
					seq_node->next_ack = curr_seq + header->len - ETHER_SIZE - tcp_size - ip_size + 1;
		//			seq_node->next_ack = curr_seq + 1;
					seq_node->ts_sec = header->ts.tv_sec;
					seq_node->ts_usec = header->ts.tv_usec;
					seq_node->rtt = 0;
					
					flow_init->rtt_map[seq_node->next_ack] = seq_node;
					flow_init->seq_map[curr_seq] = seq_node;
					
					const time_t *pkt_time = (time_t *)(&header->ts.tv_usec);
					flow_init->syn_stamp = header->ts;	
					
					flow_mon[src2dst] = flow_init;
					cout << "Flow Initiated :" << src_port << " " << dst_port << endl << endl;
//					cout << BOLD(FBLU("NEXT SYN ACK: ")) << seq_node->next_ack << endl;
				
				}
				else if ((tcp->th_flags & TH_ACK) && flow_mon.count(src2dst) && flow_mon[src2dst]->flags == (TH_SYN)){ // Ack to SYN-ACK. (First ACK from src2dst)
						flow_mon[src2dst]->flags |= TH_ACK;

						flow_mon[src2dst]->packets_sent += 1;
			//			cout << "DYUM !! " << ntohl(tcp->th_seq) + header->len - ETHER_SIZE - ip_size - tcp_size;
	//					struct timeval end_stamp = (header->ts);
	//					flow_mon[src2dst]->rtt = (end_stamp.tv_sec - flow_mon[src2dst]->syn_stamp.tv_sec)*1000000L 
	//												+ (end_stamp.tv_usec - flow_mon[src2dst]->syn_stamp.tv_usec); 	
						
						
	//					cout << BOLD(FBLU("Connection Established. RTT: ")) << to_string(flow_mon[src2dst]->rtt) << "usec" << endl << endl;
				}
				else if (flow_mon.count(dst2src) && flow_mon[dst2src]->flags == TH_SYN && tcp->th_flags == (TH_SYN | TH_ACK)){ // SYN-ACK RCVD

						uint32_t curr_ack = (uint32_t)ntohl(tcp->th_ack);

						if (flow_mon[dst2src]->rtt_map.count(curr_ack) > 0){
				//				cout << "SYN ACK MATCH !!" << endl;

								struct timeval end_stamp = (header->ts);
								flow_mon[dst2src]->rtt_map[curr_ack]->rtt = (end_stamp.tv_sec - flow_mon[dst2src]->rtt_map[curr_ack]->ts_sec)*1000000L 
										+ (end_stamp.tv_usec - flow_mon[dst2src]->rtt_map[curr_ack]->ts_usec); 	

				//				cout << "RTT: " << flow_mon[dst2src]->rtt_map[curr_ack]->rtt << endl;
						}

				//		cout << BOLD(FBLU("SYN-ACK: ")) << curr_ack << endl;

						flow_mon[dst2src]->packets_rcvd += 1;
				}
				else { // Handshake done. Transaction Packet
						if (flow_mon.count(src2dst) && flow_mon[src2dst]->flags == (TH_SYN | TH_ACK)){ // Data Sender
								flow* curr_flow = flow_mon[src2dst];

								flow_mon[src2dst]->packets_sent += 1;
								
								uint32_t seq_n = (uint32_t)ntohl(tcp->th_seq);
								
								if (!flow_mon[src2dst]->seq_map.count(seq_n) && (curr_flow->trans_seen < 2)){

										cout << FRED("Transaction ") << to_string(curr_flow->trans_seen) << ": @" << src2dst << endl;
										cout << "Sequence Number: " << to_string(ntohl(tcp->th_seq)) << endl;
										cout << "Acknowledgement Number: " << to_string(ntohl(tcp->th_ack)) << endl;

										tcp_opt *ops = (struct tcp_opt*)(packet + ETHER_SIZE + sizeof(tcp));
										int scale_fact = ntohs(ops->th_kind) - 6;

										cout << "Window Size: " << to_string(ntohs(tcp->th_win)*scale_fact) << endl << endl;


										flow_mon[src2dst]->trans_seen += 1;
								}
								
								if (flow_mon[src2dst]->seq_map.count(seq_n) > 0){	
										flow_mon[src2dst]->re_trans++;
										if (flow_mon[src2dst]->ack_map.count(seq_n) && flow_mon[src2dst]->ack_map[seq_n]->count > 3)
											flow_mon[src2dst]->fre_trans++;
								}
								else{
										seq *seq_node = new seq;
										seq_node->count = 1;
										seq_node->next_ack = seq_n + header->len - ETHER_SIZE - ip_size - tcp_size;
										seq_node->rtt = 0;
										seq_node->ts_sec = header->ts.tv_sec;
										seq_node->ts_usec = header->ts.tv_usec;
										flow_mon[src2dst]->rtt_map[seq_node->next_ack] = seq_node;
										flow_mon[src2dst]->seq_map[seq_n] = seq_node;
							//			cout << BOLD(FRED("NEXT NUM: ")) << seq_node->next_ack << endl;
								}

						}
						else if (flow_mon.count(dst2src) && flow_mon[dst2src]->flags == (TH_SYN | TH_ACK)){ // Data Receiver

								uint32_t res_ack = (uint32_t)ntohl(tcp->th_ack);
				//				cout << BOLD(FRED("ACK RCVD: ")) << res_ack << endl;

								if (flow_mon[dst2src]->rtt_map.count(res_ack)){ //Update RTT
									
									struct timeval end_stamp = (header->ts);
									flow_mon[dst2src]->rtt_map[res_ack]->rtt = (end_stamp.tv_sec - flow_mon[dst2src]->rtt_map[res_ack]->ts_sec)*1000000L 
																				+ (end_stamp.tv_usec - flow_mon[dst2src]->rtt_map[res_ack]->ts_usec); 	
								}
								
								
								if (flow_mon[dst2src]->packets_rcvd == 1){ // Only SNY-ACK RCVD
										flow_mon[dst2src]->icwnd = flow_mon[dst2src]->packets_sent - 2;
										cout << "CWND 0: " << flow_mon[dst2src]->icwnd << endl;
										flow_mon[dst2src]->wnd_sizes.push_back(flow_mon[dst2src]->icwnd);
								}
								else if (flow_mon[dst2src]->packets_rcvd > 1 && flow_mon[dst2src]->wnd_sizes.size() < 5){
									int curr_idx = flow_mon[dst2src]->wnd_sizes.size();
									flow_mon[dst2src]->wnd_sizes.push_back(flow_mon[dst2src]->wnd_sizes[curr_idx - 1] + 1);
									cout << "CWND " << curr_idx << ": " << flow_mon[dst2src]->wnd_sizes[curr_idx] << endl;	
								}

								flow_mon[dst2src]->packets_rcvd += 1;
								
								if (flow_mon[dst2src]->ack_map.count(res_ack) > 0){ // Response Retransmission
			//							flow_mon[dst2src]->re_trans += 1;
										flow_mon[dst2src]->ack_map[res_ack]->count += 1;
								}
								else{
										ack *ack_num = new ack;
										ack_num->count = 1;
										flow_mon[dst2src]->ack_map[res_ack] = ack_num;	
								}
						}
				}


				if ((tcp->th_flags & TH_FIN) && flow_mon.count(src2dst)){ // FIN from Sender. Successful Flow seen
					long rtt_net = 0;
					long rtt_cnt = 0;

					unordered_map<uint32_t, seq*>::iterator it;
					
					for(it = flow_mon[src2dst]->rtt_map.begin(); it != flow_mon[src2dst]->rtt_map.end(); it++){
						if (it->second->rtt != 0)
							rtt_cnt += 1;
					}
					
					for(it = flow_mon[src2dst]->rtt_map.begin(); it != flow_mon[src2dst]->rtt_map.end(); it++){
						rtt_net += ((it->second->rtt)/(double)rtt_cnt);
					}
					
					flow_mon[src2dst]->rtt = rtt_net;
					cout << "Flow Terminated :" << src_port << " " << dst_port << endl;
					double loss_rate = flow_mon[src2dst]->re_trans / (double)flow_mon[src2dst]->packets_sent;
					double emp_through = (1460*(sqrt(3/2.0)))/((flow_mon[src2dst]->rtt)*sqrt(loss_rate));
					cout << "Loss Rate: " << loss_rate << endl;
					cout << "Fast Retransmissions: " << flow_mon[src2dst]->fre_trans << endl;
					cout << "Timeouts: " << flow_mon[src2dst]->re_trans - flow_mon[src2dst]->fre_trans << endl;
					cout << "Empirical Throughput: " << emp_through << "Mbps" << endl;
					cout << "Theoretical Throughput: " << flow_mon[src2dst]->bytes_sent/(double)flow_mon[src2dst]->rtt << "Mbps" << endl << endl;
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
