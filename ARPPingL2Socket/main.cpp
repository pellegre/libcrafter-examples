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
	ARP* arp_layer = sniff_packet->GetLayer<ARP>();

	/* Get the Source IP / MAC pair */
	pair_addr[arp_layer->GetSenderIP()] = arp_layer->GetSenderMAC();

}

int main() {

	/* Set the interface */
	string iface = "wlan0";

	int rawsock;

	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))== -1)
		exit(1);

	struct sockaddr_ll sll;
	struct ifreq ifr;

	memset(&sll,0,sizeof(sll));
	memset(&ifr,0,sizeof(ifr));

	/* First Get the Interface Index  */
	strncpy((char *)ifr.ifr_name, iface.c_str(), IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
	{
		perror("Getting Interface index");
		exit(1);
	}

	/* Bind our raw socket to this interface */
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);


	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
	{
		perror("Binding raw socket to interface");
		exit(1);
	}

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
	vector<string> net = GetIPs("192.168.0.*");            // <-- Create a container of IP addresses from a "wildcard"
	vector<string>::iterator it_IP;                        // <-- Iterator

	/* Create a container to hold all the ARP requests */
	vector<Packet*> request_packets;

	/* Iterate to access each string that defines an IP address */
	for(it_IP = net.begin() ; it_IP != net.end() ; it_IP++) {

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
	 * request_packets container. Now we can Send 'Em All (3 times)
	 * with 48 threads.
	 */
	for(int i = 0 ; i < 3 ; i++)
		SocketSend(rawsock,request_packets.begin(), request_packets.end(), 48);

	/* Give a second to the sniffer */
	sleep(1);

	/* ... and close the sniffer */
	sniff.Cancel();

	/* Print the alive hosts */
	map<string,string>::iterator it_host;
	for(it_host = pair_addr.begin() ; it_host != pair_addr.end() ; it_host++)
		cout << "[@] Host " << (*it_host).first << " is up "
				"with MAC address " << (*it_host).second << endl;

	/* Delete the container with the ARP requests */
	ClearContainer(request_packets);

	/* Print number of host up */
	cout << "[@] " << pair_addr.size() << " hosts up. " << endl;

	close(rawsock);

	return 0;
}
