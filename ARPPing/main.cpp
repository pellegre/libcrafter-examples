/*
 * Simple ARP Ping on local network
 *
 * The program assembles a set of ARP requests on a PacketContainer
 * and, using the SendRecv function, send them all. Finally, prints
 * on the standard output the IP and MAC address of the alive hosts.
 *
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
	/* Get the MAC Address associated to the interface */
	string MyMAC = GetMyMAC(iface);

	cout << "[@] My MAC address is : " << MyMAC << endl;
	cout << "[@] My IP address is  : " << MyIP  << endl;

	/* --------- Common data to all headers --------- */

	Ethernet ether_header;

	ether_header.SetSourceMAC(MyMAC);
	ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");   // <-- Set broadcast address

	ARP arp_header;

	arp_header.SetOperation(ARP::Request);                 // <-- Set Operation (ARP Request)
    arp_header.SetSenderIP(MyIP);                          // <-- Set our network data
    arp_header.SetSenderMAC(MyMAC);

    /* ---------------------------------------------- */

	/* Define the network to scan */
	vector<string>* net = ParseIP("192.168.0.*");             // <-- Create a container of IP addresses from a "wildcard"
	vector<string>::iterator it_IP;                        // <-- Iterator

	/* Create a PacketContainer to hold all the ARP requests */
	PacketContainer request_packets;

	/* Iterate to access each string that defines an IP address */
	for(it_IP = net->begin() ; it_IP != net->end() ; it_IP++) {

		arp_header.SetTargetIP(*it_IP);                    // <-- Set a destination IP address on ARP header

		/* Create a packet on the heap */
		Packet* packet = new Packet;

		/* Push the layers */
		packet->PushLayer(ether_header);
		packet->PushLayer(arp_header);

		/* Finally, push the packet into the container */
		request_packets.push_back(packet);
	}

	/*
	 * At this point, we have all the packets into the
	 * request_packets container. Now we can Send 'Em All.
	 *
	 * 48 (nthreads) -> Number of threads for distributing the packets
	 *                  (tunneable, the best value depends on your
	 *                   network an processor). 32 is good :-)
	 * 0.1  (timeout)-> Timeout in seconds for waiting an answer
	 * 2  (retry)    -> Number of times we send a packet until a response is received
	 */
	cout << "[@] Sending the ARP Requests. Wait..." << endl;
	PacketContainer* replies_packets = request_packets.SendRecv(iface,0.1,2,48);
	cout << "[@] SendRecv function returns :-) " << endl;

	/*
	 * replies_packets is a pointer to a PacketContainer with the same size
	 * of request_packets (first argument). So, at this point, (after
	 * the SendRecv functions returns) we can iterate over each
	 * reply packet, if any.
	 */
	PacketContainer::iterator it_pck;
	int counter = 0;
	for(it_pck = replies_packets->begin() ; it_pck < replies_packets->end() ; it_pck++) {
		/* Check if the pointer is not NULL */
		Packet* reply_packet = (*it_pck);
		if(reply_packet) {
			/* Get the ARP layer of the replied packet */
			ARP* arp_layer = GetARP(*reply_packet);
			/* Print the Source IP */
			cout << "[@] Host " << arp_layer->GetSenderIP() << " is up with "
					"MAC address " << arp_layer->GetSenderMAC() << endl;
			counter++;
		}
	}

	cout << "[@] " << counter << " hosts up. " << endl;

	/* Delete the container with the ARP requests */
	request_packets.Clear();

	/* Delete the container with the reponses, if there is one (check the NULL pointer) */
	replies_packets->Clear();
	/* Delete the container itself */
	delete replies_packets;

	/* Delete the IP address container */
	delete net;

	/* Clean up library stuff */
	CleanCrafter();

	return 0;
}
