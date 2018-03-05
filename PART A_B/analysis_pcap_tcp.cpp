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

typedef struct transaction{
	string sdr_seq_num;
	string sdr_ack_num;
	string sdr_wnd;
	string rcv_seq_num;
	string rcv_ack_num;
	string rcv_wnd;
}transaction;

typedef struct flow{
	int src_port;
	int dst_port;
	u_short flags;
	int send_trans_seen;
	int rcv_trans_seen;
	struct timeval syn_stamp;
	long bytes_sent;
	uint32_t packets_sent;
	uint32_t packets_rcvd;
	uint32_t re_trans;
	uint32_t re_trans_size;
	uint32_t fre_trans;
	uint32_t icwnd;
	long rtt;
	unordered_map<uint32_t, seq*> rtt_map;
	unordered_map<uint32_t, seq*> seq_map;
	unordered_map<uint32_t, ack*> ack_map;
	vector<int> wnd_sizes;
	vector<transaction*> transactions;
}flow;

typedef struct {
  uint8_t kind;
  uint8_t size;
} tcp_option_t;

int flow_count = 0;
unordered_map<string, flow*> flow_mon;
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
				
	//			if (flow_mon.count(src2dst)) //Throughput
	//				flow_mon[src2dst]->bytes_sent += header->len;
	//			else if (flow_mon.count(dst2src))
	//				flow_mon[dst2src]->bytes_sent += header->len;
				
				if ((tcp->th_flags & TH_SYN) && !(tcp->th_flags & TH_ACK) && !flow_mon.count(src2dst)){ // Get First Seen SYNs
					flow_count++;	
					flow *flow_init = new flow;
					flow_init->src_port = src_port;
					flow_init->dst_port = dst_port;
					flow_init->flags = TH_SYN;
					flow_init->send_trans_seen = 0;
					flow_init->rcv_trans_seen = 0;
					flow_init->bytes_sent = header->len;
					flow_init->packets_sent = 1;
					flow_init->packets_rcvd = 0;
					flow_init->re_trans = 0;
					flow_init->re_trans_size = 0;
					flow_init->fre_trans = 0;
					
					long curr_seq = ntohl(tcp->th_seq);
					seq *seq_node = new seq;
					seq_node->curr_seq = curr_seq;
					seq_node->count = 1;
					seq_node->next_ack = curr_seq + header->len - ETHER_SIZE - tcp_size - ip_size + 1;
					seq_node->ts_sec = header->ts.tv_sec;
					seq_node->ts_usec = header->ts.tv_usec;
					seq_node->rtt = 0;
					
					flow_init->rtt_map[seq_node->next_ack] = seq_node;
					flow_init->seq_map[curr_seq] = seq_node;
					
					const time_t *pkt_time = (time_t *)(&header->ts.tv_usec);
					flow_init->syn_stamp = header->ts;	
					
					flow_mon[src2dst] = flow_init;
					
					//					cout << "Flow Initiated :" << src_port << " " << dst_port << endl << endl;

				}
				else if ((tcp->th_flags & TH_ACK) && flow_mon.count(src2dst) && flow_mon[src2dst]->flags == (TH_SYN)){ // Ack to SYN-ACK. (First ACK from src2dst)
						flow_mon[src2dst]->flags |= TH_ACK;

						flow_mon[src2dst]->packets_sent += 1;
						
	//					cout << BOLD(FBLU("Connection Established. RTT: ")) << to_string(flow_mon[src2dst]->rtt) << "usec" << endl << endl;
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
								flow* curr_flow = flow_mon[src2dst];
								
								flow_mon[src2dst]->bytes_sent += header->len;
								flow_mon[src2dst]->packets_sent += 1;
								
								uint32_t seq_n = (uint32_t)ntohl(tcp->th_seq);
								
								if (!flow_mon[src2dst]->seq_map.count(seq_n) && (curr_flow->send_trans_seen < 2)){
										transaction *trx = new transaction;
										trx->sdr_seq_num = to_string(ntohl(tcp->th_seq));
										trx->sdr_ack_num = to_string(ntohl(tcp->th_ack));
										trx->sdr_wnd = to_string(ntohs(tcp->th_win)*16384);
										flow_mon[src2dst]->transactions.push_back(trx);
										//			tcp_opt *ops = (struct tcp_opt*)(packet + ETHER_SIZE + sizeof(tcp));
										//			int scale_fact = ntohs(ops->th_kind) - 6;

										flow_mon[src2dst]->send_trans_seen += 1;
								}
								
								if (flow_mon[src2dst]->seq_map.count(seq_n) > 0){	
										flow_mon[src2dst]->re_trans++;
										flow_mon[src2dst]->re_trans_size += header->len;
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
								}

						}
						else if (flow_mon.count(dst2src) && flow_mon[dst2src]->flags == (TH_SYN | TH_ACK)){ // Data Receiver

								uint32_t res_ack = (uint32_t)ntohl(tcp->th_ack);
								flow* curr_flow = flow_mon[dst2src];

								if (flow_mon[dst2src]->rtt_map.count(res_ack)){ //Update RTT
									
									struct timeval end_stamp = (header->ts);
									flow_mon[dst2src]->rtt_map[res_ack]->rtt = (end_stamp.tv_sec - flow_mon[dst2src]->rtt_map[res_ack]->ts_sec)*1000000L 
																				+ (end_stamp.tv_usec - flow_mon[dst2src]->rtt_map[res_ack]->ts_usec); 	
									if (curr_flow->rcv_trans_seen < 2){
										int rcv_trans_seen = flow_mon[dst2src]->rcv_trans_seen;		
										flow_mon[dst2src]->transactions[rcv_trans_seen]->rcv_seq_num = to_string(ntohl(tcp->th_seq));
										flow_mon[dst2src]->transactions[rcv_trans_seen]->rcv_ack_num = to_string(ntohl(tcp->th_ack));
										flow_mon[dst2src]->transactions[rcv_trans_seen]->rcv_wnd = to_string(ntohs(tcp->th_win)*16384);
										
							//			tcp_opt *ops = (struct tcp_opt*)(packet + ETHER_SIZE + sizeof(tcp));
							//			int scale_fact = ntohs(ops->th_kind) - 6;
										flow_mon[dst2src]->rcv_trans_seen += 1;		
									}
								}
								
								
								if (flow_mon[dst2src]->packets_rcvd == 1){ // Only SNY-ACK RCVD
										flow_mon[dst2src]->icwnd = flow_mon[dst2src]->packets_sent - 2;
										flow_mon[dst2src]->wnd_sizes.push_back(flow_mon[dst2src]->icwnd);
								}
								else if (flow_mon[dst2src]->packets_rcvd > 1 && flow_mon[dst2src]->wnd_sizes.size() < 10){
									int curr_idx = flow_mon[dst2src]->wnd_sizes.size();
									flow_mon[dst2src]->wnd_sizes.push_back(flow_mon[dst2src]->wnd_sizes[curr_idx - 1] + 1);
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
					
					out_buff << "--------------------------------------------------" << endl;
					out_buff << "\t\t\tFlow Summary: " << endl;

					for(int i = 0; i < 2; i++){
						transaction *tx = flow_mon[src2dst]->transactions[i];
						out_buff << BOLD("Transaction Number: ") << i << endl;
						out_buff << "\tSender Sequence        Number:\t" << tx->sdr_seq_num << endl;
						out_buff << "\tSender Ack             Number:\t" << tx->sdr_ack_num << endl;
						out_buff << "\tAdvertised Window to   Sender:\t" << tx->sdr_wnd << endl;
						out_buff << "\tReceiver Sequence      Number:\t" << tx->rcv_seq_num << endl;
						out_buff << "\tReceiver Ack           Number:\t" << tx->rcv_ack_num << endl;
						out_buff << "\tAdvertised Window to Receiver:\t" << tx->rcv_wnd << endl;	
					}
					out_buff << "Flow Terminated b/w (S/R): " << src_port << "/" << dst_port << endl;
					double loss_rate = flow_mon[src2dst]->re_trans / (double)flow_mon[src2dst]->packets_sent;
					double th_through = 0;
					out_buff << "RTT: " << flow_mon[src2dst]->rtt << " microsec" << endl;
					out_buff << "Loss Rate: " << loss_rate << endl;
					out_buff << "Fast Retransmissions: " << flow_mon[src2dst]->fre_trans << endl;
					out_buff << "Timeouts (Due to TDA): " << flow_mon[src2dst]->re_trans - flow_mon[src2dst]->fre_trans << endl;
					if (loss_rate != 0){
						th_through = (8*1460*(sqrt(3/2.0)))/((flow_mon[src2dst]->rtt)*sqrt(loss_rate));
						out_buff << "Theoretical Throughput: " << th_through << " Mbps" << endl;
					}
					else
						out_buff << "Theoretical Throughput: infinity" << " Mbps" << endl;
					out_buff << "Empirical Throughput: " << (((flow_mon[src2dst]->bytes_sent - flow_mon[src2dst]->re_trans_size)*8))/((double)flow_mon[src2dst]->rtt) << " Mbps" << endl;
					out_buff << FRED("Congestion Window Sizes:") << endl;
					for(int i = 0; i < flow_mon[src2dst]->wnd_sizes.size(); i++){
						if (!i)
							out_buff << "\t" << flow_mon[src2dst]->wnd_sizes[i] << "(icwnd)";
						else
							out_buff << " -> " << flow_mon[src2dst]->wnd_sizes[i];
					
					}
					out_buff << endl << endl;
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
	
	cout << BOLD(FBLU("\n\t\tNumber of Flows: ")) << flow_count << endl;
	cout << out_buff.str();

	return 0;


}
