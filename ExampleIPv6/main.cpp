/*
 * Basic IPv6 Send *
 */
#include <iostream>
#include <fstream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIPv6 = GetMyIPv6(iface);
	cout << "[@] My IPv6 address is  : " << MyIPv6  << endl;

	string dst_ipv6 = "fe80::a00:27ff:fea4:73d6";

	Ethernet ether_header;

	ether_header.SetDestinationMAC(GetMAC(dst_ipv6));
	ether_header.SetSourceMAC(GetMyMAC(iface));

	/* Create an IP header */
	IPv6 ipv6_header;

	/* Set the Source and Destination IP address */
	ipv6_header.SetSourceIP(MyIPv6);
	ipv6_header.SetDestinationIP(dst_ipv6);

	/* Create a UDP header */
	TCP tcp_header;

	/* Set the source and destination ports */
	tcp_header.SetSrcPort(RNG16());
	tcp_header.SetDstPort(62345);
	tcp_header.SetSeqNumber(RNG32());
	tcp_header.SetFlags(TCP::SYN);

	/* Create a payload */
	RawLayer raw_header;
	raw_header.SetPayload("SomeTCPpayload\n");

	/* Create a packet... */
	Packet packet = ipv6_header / tcp_header / raw_header;

	/* Send the packet */
	Packet* rcv_packet = packet.SendRecv(iface,0.1,2);

	if(rcv_packet)
		rcv_packet->Print();
	else
		cout << "[@] No response... " << endl;

	return 0;
}
