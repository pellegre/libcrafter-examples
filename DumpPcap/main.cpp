/*
 * Simple ARP Ping on local network
 *
 * The program assembles a set of ARP requests on a PacketContainer
 * and, using the SendRecv function, send them all. Finally, prints
 * on the standard output the IP and MAC address of the alive hosts.
 *
 */

#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Init the library */
	InitCrafter();

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
	vector<string>* net = ParseIP("192.168.0.*");
	vector<string>::iterator it_IP;

	/* Create a PacketContainer to hold all the ARP requests */
	PacketContainer request_packets;

	/* Iterate to access each string that defines an IP address */
	for(it_IP = net->begin() ; it_IP != net->end() ; it_IP++) {

		arp_header.SetTargetIP(*it_IP);

		/* Create a packet on the heap */
		Packet* packet = new Packet;

		/* Push the layers */
		packet->PushLayer(ether_header);
		packet->PushLayer(arp_header);

		/* Finally, push the packet into the container */
		request_packets.push_back(packet);
	}

	/* Dump the request to a pcap file */
	DumpPcap("arp.pcap",&request_packets);

	PacketContainer::iterator it_pck;
	/* Delete the container with the ARP requests */
	for(it_pck = request_packets.begin() ; it_pck < request_packets.end() ; it_pck++)
		delete (*it_pck);

	/* Delete the IP address container */
	delete net;

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
	PacketContainer tcp_packets;

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
		Packet* packet = new Packet;

		/* Push each layer... */
		packet->PushLayer(ip_header);
		packet->PushLayer(tcp_header);

		/* Push the packet into the container */
		tcp_packets.push_back(packet);

		port++;
	}

	/* Dump the tcp packets to a pcap file */
	tcp_packets.DumpPcap("tcp.pcap");

	/* Delete the container with the PINGS packets */
	for(it_pck = tcp_packets.begin() ; it_pck < tcp_packets.end() ; it_pck++)
		delete (*it_pck);

	/* Now read the data we just put on those files */
	PacketContainer* request_packets_read = ReadPcap("arp.pcap");
	PacketContainer* tcp_packets_read = ReadPcap("tcp.pcap");
	/* We can set a filter too :-) */
	PacketContainer* tcp_filter_read = ReadPcap("tcp.pcap","tcp and port 10");

	/* Print first 5 packets */
	cout << endl;
	cout << "[@] ++++++++++++++++ ARP requests : " << endl;
	cout << endl;
	for(it_pck = request_packets_read->begin() ; it_pck < request_packets_read->begin() + 5 ; it_pck++)
		(*it_pck)->Print();

	/* Print first 5 packets */
	cout << endl;
	cout << "[@] ++++++++++++++++ TCP packets : " << endl;
	cout << endl;
	for(it_pck = tcp_packets_read->begin() ; it_pck < tcp_packets_read->begin() + 5 ; it_pck++)
		(*it_pck)->Print();

	/* Print all packets filtered... */
	cout << endl;
	cout << "[@] ++++++++++++++++ TCP filter (only port 10) : " << endl;
	cout << endl;
	for(it_pck = tcp_filter_read->begin() ; it_pck < tcp_filter_read->end() ; it_pck++)
		(*it_pck)->Print();

	/* And here you should clean all this stuff... */
	request_packets_read.ClearPackets();
	tcp_packets_read.ClearPackets();
	tcp_filter_read.ClearPackets();

	/* Clean up library stuff */
	CleanCrafter();

	return 0;
}
