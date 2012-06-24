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
	string MyIP = GetMyIP(iface);

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);                      // <-- Set a source IP address.
	ip_header.SetDestinationIP("www.google.com.ar");  // <-- Set a destination IP address as a domain name

	/* Create an ICMP header */
	ICMP icmp_header;

	icmp_header.SetType(ICMP::EchoRequest);        // <-- Echo request (a ping)
	icmp_header.SetIdentifier(RNG16());            // <-- Set a random ID for the ICMP packet

	/* Create a payload */
	RawLayer raw_header("HelloPing!\n");

	/* Create a packet... */
	Packet packet;

	/* ... and push each layer */
	packet.PushLayer(ip_header);
	packet.PushLayer(icmp_header);
	packet.PushLayer(raw_header);


	/* Print before sending */
	cout << endl << "[@] Print before sending: " << endl;
	packet.Print();

	/* Send the packet, this would fill the missing fields (like checksum, lengths, etc) */
	packet.Send(iface);

	/* Print after sending, the packet is not the same. */
	cout << endl << "[@] Print after sending: " << endl;
	packet.Print();

	return 0;

}
