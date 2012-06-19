/*
 * Read and dump pcap files with libcrafter
 *
 * The program assembles a set of ARP requests and TCP packets on a
 * container and then dumps the data on a pcap file. Finally, we
 * read that file and prints the first 5 packets. Not very useful
 * but shows how to work with pcap files.
 */

#include <iostream>
#include <vector>
#include <list>
#include <deque>
#include <string>
#include <tr1/memory>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);
	/* Get the MAC Address associated to the interface */
	string MyMAC = GetMyMAC(iface);

	/* +++++++++++++++++++++ ARP PING +++++++++++++++++++++ */

	Ethernet ether_header;

	ether_header.SetSourceMAC(MyMAC);
	ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");

	ARP arp_header;

	arp_header.SetOperation(ARP::Request);
    arp_header.SetSenderIP(MyIP);
    arp_header.SetSenderMAC(MyMAC);

	/* Define the network to scan */
	vector<string> net = GetIPs("192.168.0.*");
	vector<string>::iterator it_IP;

	/* Create a PacketContainer to hold all the ARP requests */
	typedef tr1::shared_ptr<Packet> packet_ptr;
	vector<packet_ptr> request_packets;

	/* Iterate to access each string that defines an IP address */
	for(it_IP = net.begin() ; it_IP != net.end() ; it_IP++) {

		arp_header.SetTargetIP(*it_IP);

		/* Finally, push the packet into the container */
		request_packets.push_back(packet_ptr(new Packet(ether_header / arp_header)));
	}

	/* Dump the request to a pcap file */
	DumpPcap(request_packets.begin(), request_packets.end(), "arp.pcap");

	/* ++++++++++++++++++++ TCP TRACEROUTE +++++++++++++++++++++ */

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(GetMyIP(iface));
	ip_header.SetDestinationIP("1.2.3.4");

	/* Create a TCP header */
	TCP tcp_header;

	tcp_header.SetDstPort(1234);
	tcp_header.SetFlags(TCP::SYN);
	tcp_header.SetWindowsSize(5480);

	/* Create a PacketContainer to hold all the TCP packets */
	list<packet_ptr> tcp_packets;

	short_word port = 1;
	/* Create a packet for each TTL */
	for(int ttl = 1 ; ttl <= 30 ; ttl++) {
		/* Set a random ID for the IP header */
		ip_header.SetIdentification(RNG16());

		/* Set the TTL */
		ip_header.SetTTL(ttl);

		/* Set a Random sequence number for TCP syn packet*/
		tcp_header.SetSeqNumber(RNG32());
		tcp_header.SetSrcPort(port);

		/* Create a packet */
		packet_ptr packet = packet_ptr(new Packet);

		/* Push each layer... */
		packet->PushLayer(ip_header);
		packet->PushLayer(tcp_header);

		/* Push the packet into the container */
		tcp_packets.push_back(packet);

		port++;
	}

	/* Dump the tcp packets to a pcap file */
	DumpPcap(tcp_packets.begin(), tcp_packets.end(), "tcp.pcap");

	/* Now read the data we just put on those files */
	vector<packet_ptr> request_packets_read;
	ReadPcap(&request_packets_read,"arp.pcap");
	list<packet_ptr> tcp_packets_read;
	ReadPcap(&tcp_packets_read,"tcp.pcap");
	/* We can set a filter too :-) */
	deque<packet_ptr> tcp_filter_read;
	ReadPcap(&tcp_filter_read,"tcp.pcap","tcp and port 10");

	vector<packet_ptr>::iterator it_vec;
	list<packet_ptr>::iterator it_lst;
	deque<packet_ptr>::iterator it_deq;

	/* Print first 5 packets */
	cout << endl;
	cout << "[@] ++++++++++++++++ ARP requests : " << endl;
	cout << endl;
	for(it_vec = request_packets_read.begin() ; it_vec < request_packets_read.begin() + 5 ; it_vec++)
		(*it_vec)->Print();

	/* Print first 5 packets */
	cout << endl;
	cout << "[@] ++++++++++++++++ TCP packets : " << endl;
	cout << endl;

	list<packet_ptr>::iterator end_pck = tcp_packets_read.begin();
	advance(end_pck,5);
	for(it_lst = tcp_packets_read.begin() ; it_lst != end_pck ; it_lst++)
		(*it_lst)->Print();

	/* Print all packets filtered... */
	cout << endl;
	cout << "[@] ++++++++++++++++ TCP filter (only port 10) : " << endl;
	cout << endl;
	for(it_deq = tcp_filter_read.begin() ; it_deq != tcp_filter_read.end() ; it_deq++)
		(*it_deq)->Print();

	return 0;
}
