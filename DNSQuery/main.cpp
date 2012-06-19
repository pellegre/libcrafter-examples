/*
 * DNS Query
 *
 * This program forges a DNS Query from the IP layer to the top and send it to
 * a DNS server. Using the SendRecv function, catch a response and print it to
 * the standard output. This program also shows how to construct a DNS layer from
 * a RawLayer.
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
	string dns_server = "192.168.0.1";

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);
	ip_header.SetDestinationIP(dns_server);

	/* Create a UDP header */
	UDP udp_header;

	/* Set the source and destination ports */
	udp_header.SetSrcPort(RNG16());
	udp_header.SetDstPort(53);

	/* Create a DNS layer */
	DNS dns_header;

	/* Set a random ID */
	dns_header.SetIdentification(RNG16());

	/* Create a DNSQuery class. This class IS NOT a <Layer> class */
	DNS::DNSQuery dns_query("www.google.com");
	/* Set the type */
	dns_query.SetType(DNS::TypeA);

	/* Push the query into a container inside the DNS header */
	dns_header.Queries.push_back(dns_query);

	/* Create a packet... */
	Packet packet = ip_header / udp_header / dns_header;

	/* Send and wait for an answer */
	Packet* rcv = packet.SendRecv(iface);

	if(rcv) {
		/*
		 * An application protocol is always get from the network as a raw layer. There is
		 * no way to know which protocol is on the top of a transport layer (unless we rely on
		 * standard ports numbers, which is not always the case).
		 */
		DNS dns_rcv;
		/* Fill the DNS layer information from a raw layer */
		dns_rcv.FromRaw(*(rcv->GetLayer<RawLayer>()));
		/* Finally print the response to STDOUT */
		dns_rcv.Print();
		/* Delete the received packet */
		delete rcv;
	} else
		cout << "[@] No response from DNS server" << endl;

	return 0;
}
