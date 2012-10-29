/*
 * Ping
 *
 * Forge an ICMP echo-request packet and send it to some destination
 */
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string src_ipv6 = GetMyIPv6(iface);
	cout << "[@] My IPv6 address is  : " << src_ipv6  << endl;

	string dst_ipv6 = "fe80::a00:27ff:fe28:b8da";

	Ethernet ether_header;

	ether_header.SetDestinationMAC(GetMAC(dst_ipv6));
	ether_header.SetSourceMAC(GetMyMAC(iface));

	/* Create an IP header */
	IPv6 ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(src_ipv6);
	ip_header.SetDestinationIP(dst_ipv6);

	/* Create an ICMP header */
	ICMPv6 icmp_header;

	icmp_header.SetType(ICMPv6::EchoRequest);
	icmp_header.SetIdentifier(RNG16());

	/* Create a payload */
	RawLayer raw_header("HelloPing!\n");

	UDP udp_header;
	udp_header.SetSrcPort(RNG16());
	udp_header.SetDstPort(9999);
	/* Create a packet... */
	Packet packet = ether_header / ip_header / udp_header / raw_header;

	/* Send the packet, this would fill the missing fields (like checksum, lengths, etc) */
	Packet* rcv = packet.SendRecv(iface);

	if(rcv)
		rcv->Print();
	else
		cout << "[@] No response... " << endl;

	delete rcv;

	return 0;

}
