/*
 * ARP Ping
 *
 * A more efficient way to do an ARP scan to a ethernet network. Instead of use
 * the SendRecv function, first we put a sniffer to catch ARP replies and then
 * we send a PacketContainer with the multi-threaded function Send(). This procedure
 * is much faster than the one which use the SendRecv() function.
 */

#include <iostream>
#include <string>
#include <map>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

map<string,string> pair_addr;

void PrintARPInfo(Packet* sniff_packet, void* user) {
	/* Get the ARP header from the sniffed packet */
	ARP* arp_layer = GetARP(*sniff_packet);

	/* Get the Source IP / MAC pair */
	pair_addr[arp_layer->GetSenderIP()] = arp_layer->GetSenderMAC();

}

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

	/* Create a sniffer for listen to ARP traffic of the network specified */
	Sniffer sniff("arp[7]=2",iface,PrintARPInfo);

	/* Spawn the sniffer, the function returns immediately */
	sniff.Spawn(-1);

	/*
	 * At this point, we have all the packets into the
	 * request_packets container. Now we can Send 'Em All (3 times).
	 */
	//for(int i = 0 ; i < 3 ; i++)
		request_packets.Send(iface,48);

	/* Wait a second to sniff all the responses... */
	sleep(1);

	/* ... and close the sniffer */
	sniff.Cancel();

	/* Print the alive hosts */
	map<string,string>::iterator it_host;
	for(it_host = pair_addr.begin() ; it_host != pair_addr.end() ; it_host++)
		cout << "[@] Host " << (*it_host).first << " is up "
				"with MAC address " << (*it_host).second << endl;

	/* Delete the container with the ARP requests */
	request_packets.ClearPackets();

	/* Delete the IP address container */
	delete net;

	/* Print number of host up */
	cout << "[@] " << pair_addr.size() << " hosts up. " << endl;

	/* Clean up library stuff */
	CleanCrafter();

	return 0;
}
