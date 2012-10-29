/*
 * Basic Send
 *
 * The program creates a TCP packet with some arbitrary payload a send it to
 * a destination. Basic example to illustrate the use of the Send function and
 * how to construct a packet.
 */
#include <iostream>
#include <fstream>
#include <string>
#include <crafter.h>
#include <boost/shared_ptr.hpp>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main_read() {
	typedef boost::shared_ptr<Packet> packet_ptr;

	vector<packet_ptr> sack_pcks;
	ReadPcap(&sack_pcks,"sack.pcap");

	vector<packet_ptr>::iterator it_pck;

	for(it_pck = sack_pcks.begin() ; it_pck != sack_pcks.end() ; it_pck++)
		(*it_pck)->Print();

	return 0;
}

int main_write() {
	/* Create an IP header */
	IP ip_header;
	ip_header.SetSourceIP("1.2.3.4");
	ip_header.SetDestinationIP("3.4.5.6");

	TCP tcp_header;
	tcp_header.SetSrcPort(62345);
	tcp_header.SetDstPort(RNG16());
	tcp_header.SetFlags(TCP::SYN);

	/* SACK Permitted, on a SYN Packet */
	Packet packet = ip_header / tcp_header /
			        TCPOptionSACKPermitted() /
			        TCPOption::NOP /
			        TCPOption::EOL;

	packet.Send();

	tcp_header.SetFlags(TCP::ACK);

	TCPOptionSACK sack_opt;

	/* Create blocks */
	vector<TCPOptionSACK::Pair> blocks;
	blocks.push_back(TCPOptionSACK::Pair(10,20));
	blocks.push_back(TCPOptionSACK::Pair(300,400));
	blocks.push_back(TCPOptionSACK::Pair(5000,6000));

	sack_opt.SetBlocks(blocks);

	/* SACK Option */
	packet = ip_header / tcp_header /
			 sack_opt/
			 TCPOption::NOP /
			 TCPOption::EOL;

	packet.Send();

	return 0;
}

int main_access() {
	typedef boost::shared_ptr<Packet> packet_ptr;

	vector<packet_ptr> sack_pcks;
	ReadPcap(&sack_pcks,"sack.pcap");

	vector<packet_ptr>::iterator it_pck;

	for(it_pck = sack_pcks.begin() ; it_pck != sack_pcks.end() ; it_pck++) {

		TCPOptionSACK* sack_opt = (*it_pck)->GetLayer<TCPOptionSACK>();

		if(sack_opt) {
			vector<TCPOptionSACK::Pair> edges = sack_opt->GetBlocks();

			/* Print some data */
			vector<TCPOptionSACK::Pair>::iterator it_pair = edges.begin();

			for(; it_pair != edges.end() ; it_pair++)
				cout << "left = " << (*it_pair).left << " - right = " << (*it_pair).right << endl;
		}
	}

	return 0;
}

int main() {
	//main_read();
	//main_write();
	main_access();
	return 0;
}
