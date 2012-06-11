/*
 * Ping Scan
 *
 * This program performs a ping scan on a network specified by the user.
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
	string MyMAC = GetMyMAC(iface);
	cout << "[@] My IP address is  : " << MyIP  << endl;
	cout << "[@] My MAC address is  : " << MyMAC  << endl;

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
	vector<string>* net = ParseIP("192.168.1.*");        // <-- Create a container of IP addresses from a "wildcard"
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

	/*
	 * At this point, we have all the packets into the
	 * pings_packets container. Now we can Send 'Em All.
	 *
	 * 48 (nthreads) -> Number of threads for distributing the packets
	 *                  (tunable, the best value depends on your
	 *                   network an processor). 32 is good :-)
	 * 0.1 (timeout) -> Timeout in seconds for waiting an answer
	 * 2  (retry)    -> Number of times we send a packet until a response is received
	 */
	cout << "[@] Sending the ICMP echoes. Wait..." << endl;
	PacketContainer* pongs_packets = pings_packets.SendRecv(iface,0.1,2,48);
	cout << "[@] SendRecv function returns :-) " << endl;

	/*
	 * pongs_packets is a pointer to a PacketContainer with the same size
	 * of pings_packets (first argument). So, at this point, (after
	 * the SendRecv functions returns) we can iterate over each
	 * reply packet, if any.
	 */
	PacketContainer::iterator it_pck;
	int counter = 0;
	for(it_pck = pongs_packets->begin() ; it_pck < pongs_packets->end() ; it_pck++) {
		/* Check if the pointer is not NULL */
		Packet* reply_packet = (*it_pck);
		if(reply_packet) {
            /* Get the ICMP layer */
            ICMP* icmp_layer = GetICMP(*reply_packet);
            if(icmp_layer->GetType() == ICMP::EchoReply) {
				/* Get the IP layer of the replied packet */
				IP* ip_layer = GetIP(*reply_packet);
				/* Print the Source IP */
				cout << "[@] Host " << ip_layer->GetSourceIP() << " up." << endl;
				counter++;
            }
		}
	}

	cout << "[@] " << counter << " hosts up. " << endl;

	/* Now, because we are good programmers, clean everything before exit */

	/* Delete the container with the PINGS packets */
	pings_packets.ClearPackets();

	/* Delete the container with the responses, if there is one (check the NULL pointer) */
	pongs_packets->ClearPackets();
	/* Delete the container itself */
	delete pongs_packets;

	/* Delete the IP address container */
	delete net;

	/* Clean up library stuff */
	CleanCrafter();

	return 0;
}
