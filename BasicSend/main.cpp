/*
 * Basic Send
 *
 * The program creates an UDP packet with some arbitrary payload a send it to
 * a destination. Basic example to illustrate the use of the Send function and
 * how to construct a packet.
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
	string iface = "ath0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);

	cout << "[@] My IP address is  : " << MyIP  << endl;

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);
	ip_header.SetDestinationIP("192.168.1.1");
	ip_header.SetFragmentOffset(4);

	/* Create a UDP header */
	UDP udp_header;

	/* Set the source and destination ports */
	udp_header.SetSrcPort(1089);
	udp_header.SetDstPort(5436);

	/* Create a payload */
	RawLayer raw_header;
	raw_header.SetPayload("Some_UDP_Payload\n");

	/* Create a packet... */
	Packet packet = ip_header / udp_header / raw_header;

	/* Print before sending */
	cout << endl << "[@] Print before sending: " << endl;
	packet.Print();

	/* Send the packet, this would fill the missing fields (like checksum, length, etc) */
	packet.Send(iface);

	cout << endl;
	cout << "[+] ***************************************************** [+]" << endl;
	cout << endl;

	/* Print after sending, the packet is not the same. */
	cout << "[@] Print after sending: " << endl;
	packet.Print();

	/* Clean before exit */
	CleanCrafter();

	return 0;
}
