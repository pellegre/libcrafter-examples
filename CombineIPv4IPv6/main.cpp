/*
 * Create IP layer independent code (as long you need to access only to dst and src IP addresses)
 *
 * The program creates an TCP packet and a send it to a IPv4 or IPv6 host and check if
 * a port is open. As you can see, the function that checks the port is independent of the version
 * of the IP protocol. Very simple and silly example to show how to work with the IPLayer class.
 */
#include <iostream>
#include <fstream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

/* This functions send a TCP SYN and check if a port if open */
void SendAndRecvTCP(IPLayer* ip_layer, const string& iface, const string& src_ip, const string& dst_ip, short_word port) {
	/* Put the IP destination */
	ip_layer->SetSourceIP(src_ip);
	ip_layer->SetDestinationIP(dst_ip);

	/* Create the TCP packet */
	TCP tcp_header;
	tcp_header.SetSeqNumber(RNG32());
	tcp_header.SetSrcPort(RNG16());
	tcp_header.SetDstPort(port);
	tcp_header.SetFlags(TCP::SYN);

	/* Craft the packet */
	Packet pck = *ip_layer / tcp_header;

	Packet* pck_rcv = pck.SendRecv(iface,0.1,3);

	if(pck_rcv) {

		/* Get IP layer, no matter which version (4 or 6) */
		IPLayer* ip_rcv = GetIPLayer(*pck_rcv);
		/* Get TCP layer */
		TCP* tcp_rcv = GetTCP(*pck_rcv);

		if(tcp_rcv->GetACK() && tcp_rcv->GetSYN())
			cout << "[@] Port " << port << " is open on host " << ip_rcv->GetSourceIP() << endl;
		else
			cout << "[@] The port " << port << " is not open on host " << ip_rcv->GetSourceIP() << endl;

		delete pck_rcv;

	} else
		cout << "[@] NO response from " << dst_ip << endl;
}

int main() {

	/* Init the library */
	InitCrafter();

	/* Set the interface */
	string iface = "eth0";

	/* Create an IP header */
	IPv6* ipv6_header = new IPv6;
	IP* ipv4_header = new IP;

	/* Test a IPv6 address */
	string dst_ipv6 = "fe80::7aac:c0ff:febe:1f48";
	SendAndRecvTCP(ipv6_header, iface, GetMyIPv6(iface), dst_ipv6, 22);

	/* Test a IPv4 address */
	string dst_ipv4 = "10.73.36.211";
	SendAndRecvTCP(ipv4_header, iface, GetMyIP(iface), dst_ipv4, 22);

	/* Clean before exit */
	delete ipv4_header;
	delete ipv6_header;

	CleanCrafter();

	return 0;
}
