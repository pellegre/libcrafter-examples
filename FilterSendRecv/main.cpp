/*
 * Custom Filter on SendRecv function
 *
 * This program creates a weird packet and provides to the SendRecv function
 * a custom filter expression for the response matching.
 */
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	//Verbose(0);

	/* Set the interface */
	string iface="wlan0";

	/* Create an Ethernet layer */
	Ethernet ether_header;

	ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");
	ether_header.SetSourceMAC("aa:bb:cc:dd:ee:ff");

	/* Create an ARP layer */
	ARP arp_header;

	arp_header.SetSenderIP("3.3.3.3");
	arp_header.SetTargetIP("4.4.4.4");

	/* Create a IP layer */
	IP ip_header;

	ip_header.SetDestinationIP("1.1.1.1");
	ip_header.SetSourceIP("2.2.2.2");
	ip_header.SetTTL(6);
	ip_header.SetIdentification(RNG16());

	/* Create a ICMP layer */
	ICMP icmp_header;

	icmp_header.SetType(ICMP::DestinationUnreachable);

	/* Create an UDP layer */
	UDP udp_header;

	udp_header.SetDstPort(RNG16());
	udp_header.SetSrcPort(RNG16());

	/* Create a raw_layer with some random data */
	RawLayer raw_header("This is some random data");

	/* [+] Let craft one non-sense packet! :-) */

	Packet packet;

	/* Now, push the UDP layer... */
	packet.PushLayer(udp_header);
	/* ... then the ICMP layer. */
	packet.PushLayer(icmp_header);
	/* Now the payload... */
	packet.PushLayer(raw_header);
	/* Finally the IP and ARP layers... */
	packet.PushLayer(ip_header);
	packet.PushLayer(arp_header);
	/* ... and on the top of the packet, why not, an Ethernet layer :-) */
	packet.PushLayer(ether_header);

	/* This is one hell of a packet... */

	/*
	 * The packet is going to be written on the wire, but don't expect any answer...
	 * The library doesn't know how to match a response of this weird packet.
	 */
	Packet *rcv = packet.SendRecv(iface,2,2);   // <-- This call writes the packet on the wire
	                                            //     but doesn't wait for any answer

	/*
	 * If you want to "catch" a response, you should call SendRecv
	 * with a tcpdump filter expression as a third argument.
	 * So, the function will block until a packet that match that filter
	 * expression is captured.
	 */
	rcv = packet.SendRecv(iface,2,2,"tcp and src port 80");

	/* Check if the return value of SendRecv is not zero */
	if(rcv) {
		/* Print the packet */
		rcv -> Print();
		/* Delete the packet, is your responsibility */
		delete rcv;
	} else
		cout << "[@] No answer... " << endl;

	return 0;

}
