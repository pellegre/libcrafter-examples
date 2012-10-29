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

	/* Init the library */
	InitCrafter();

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);
	ip_header.SetDestinationIP("192.168.0.1");

	IPOptionTraceroute trace;
	trace.SetIDNumber(RNG16());
	trace.SetOrigIP(MyIP);

	/* Create an ICMP header */
	ICMP icmp_header;

	icmp_header.SetType(ICMP::EchoRequest);
	icmp_header.SetIdentifier(RNG16());

	/* Create a payload */
	RawLayer raw_header;
	raw_header.SetPayload("HelloPing!\n");

	/* Create a packet... */
	Packet packet = ip_header / trace / icmp_header / raw_header;

	/* Send the packet, this would fill the missing fields (like checksum, lengths, etc) */
	packet.Send(iface);

	/* Clean before exit */
	CleanCrafter();

	return 0;

}
