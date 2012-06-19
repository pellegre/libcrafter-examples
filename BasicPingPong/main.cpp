/*
 * Basic Ping Pong
 *
 * This program craft an ICMP echo-request packet and send it to a destination.
 * Using the SendRecv method, waits for a response. If a response is received,
 * prints the echo-reply packet received on standard output.
 *
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
	ip_header.SetSourceIP(MyIP);                   // <-- Set a source IP address.
	ip_header.SetDestinationIP("www.google.com");  // <-- Set a destination IP address as a domain name

	/* Create an ICMP header */
	ICMP icmp_header;

	icmp_header.SetType(ICMP::EchoRequest);        // <-- Echo request (a ping)
	icmp_header.SetIdentifier(RNG16());            // <-- Set a random ID for the ICMP packet

	/* Create a payload */
	RawLayer raw_header;
	raw_header.SetPayload("PingPongTest\n");

	/* Create a packet with the layers */
	Packet packet (ip_header / icmp_header / raw_header);

	/*
	 * If we send a PING (echo), we expect a PONG (reply).
	 * So, we use the SendRecv function.
	 */
	Packet *rcv = packet.SendRecv(iface,2);         // <-- If a reply is matched, the function
	                                                //     returns a pointer to that packet

	/* Check if the return value of SendRecv is not zero */
	if(rcv) {
		/* Print the packet */
		rcv -> Print();
		/* Delete the packet */
		delete rcv;
	} else
		cout << "[@] No answer... " << endl;

	return 0;

}
