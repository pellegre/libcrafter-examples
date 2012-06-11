/*
 * Network Ping Scan
 *
 * This program performs a ping scan on a network specified by the user. The responses
 * are captured with a sniffer.
 */
#include <iostream>
#include <string>
#include <crafter.h>
#include <set>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

set<string> addr;

void PrintICMPInfo(Packet* sniff_packet, void* user) {

	/* Get the IP layer of the replied packet */
	IP* ip_layer = GetIP(*sniff_packet);

	/* Put the IP address into the set */
	addr.insert(ip_layer->GetSourceIP());

}

int main() {

	/* Init the library */
	InitCrafter();

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);
	cout << "[@] My IP address is  : " << MyIP  << endl;

	/* --------- Common data to all headers --------- */

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);                         // <-- Set a source IP address.

	/* Create an ICMP header */
	ICMP icmp_header;

	icmp_header.SetType(ICMP::EchoRequest);              // <-- Echo request (a ping)
	icmp_header.SetPayload("ThisIsThePayloadOfAPing\n"); // <-- Set an arbitrary payload

    /* ---------------------------------------------- */

	/* Define the network to scan */
	vector<string>* net = ParseIP("192.168.0.*");        // <-- Create a container of IP addresses from a "wildcard"
	vector<string>::iterator it_IP;                      // <-- Iterator

	/* Create a PacketContainer to hold all the ICMP packets (is just a typedef for vector<Packet*>) */
	PacketContainer pings_packets;

	/* Iterate to access each string that defines an IP address */
	for(it_IP = net->begin() ; it_IP != net->end() ; it_IP++) {

		ip_header.SetDestinationIP(*it_IP);              // <-- Set a destination IP address
		icmp_header.SetIdentifier(RNG16());              // <-- Set a random ID for the ICMP packet

		/* Create a packet on the heap */
		Packet* packet = new Packet;

		/* Push the layers */
		packet->PushLayer(ip_header);
		packet->PushLayer(icmp_header);

		/* Finally, push the packet into the container */
		pings_packets.push_back(packet);
	}

	/* Create a sniffer for listen to ICMP traffic (only the replies) */
	Sniffer sniff("icmp and icmp[0:1]==0",iface,PrintICMPInfo);

	/* Spawn the sniffer, the function returns immediately */
	sniff.Spawn(-1);

	/*
	 * At this point, we have all the packets into the
	 * pings_packets container. Now we can Send 'Em All.
	 */
	//for(int i = 0 ; i < 3 ; i++)
		pings_packets.Send(iface);

	/* Wait to sniff all the packets... */
	sleep(1);

	/* ... and close the sniffer */
	sniff.Cancel();


	/* Print the alive hosts */
	set<string>::iterator it_host;
	for(it_host = addr.begin() ; it_host != addr.end() ; it_host++)
		cout << "[@] Host " << (*it_host) << " up." << endl;

	/* Delete the container with the PINGS packets */
	pings_packets.ClearPackets();

	/* Delete the IP address container */
	delete net;

	/* Print the number of alive hosts */
	cout << "[@] " << addr.size() << " hosts up. " << endl;

	/* Clean up library stuff */
	CleanCrafter();

	return 0;
}
