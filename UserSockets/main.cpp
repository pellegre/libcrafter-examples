/*
 * Some examples to show how the user can write into his/her open sockets with libcrafter.
 *
 */
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

void ping_pong(int s) {

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
	Packet *rcv = packet.SocketSendRecv(s,iface,2);      // <-- If a reply is matched, the function
	                                                     //     returns a pointer to that packet

	/* Check if the return value of SendRecv is not zero */
	if(rcv) {
		/* Print the packet */
		rcv -> Print();
		/* Delete the packet */
		delete rcv;
	} else
		cout << "[@] No answer... " << endl;

}

void network_ping(int s) {

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
	vector<string> net = GetIPs("192.168.0.*");    // <-- Create a container of IP addresses from a "wildcard"
	vector<string>::iterator it_IP;                      // <-- Iterator

	/* Create a container of pointers to packets to hold all the ICMP packets */
	vector<Packet*> pings_packets;

	/* Iterate to access each string that defines an IP address */
	for(it_IP = net.begin() ; it_IP != net.end() ; it_IP++) {

		ip_header.SetDestinationIP(*it_IP);              // <-- Set a destination IP address
		icmp_header.SetIdentifier(RNG16());              // <-- Set a random ID for the ICMP packet

		/* Finally, push the packet into the container */
		pings_packets.push_back(new Packet(ip_header / icmp_header));
	}

	/*
	 * At this point, we have all the packets into the
	 * pings_packets container. Now we can Send 'Em All.
	 *
	 * 48 (nthreads) -> Number of threads for distributing the packets
	 *                  (tunable, the best value depends on your
	 *                   network an processor).
	 * 0.1 (timeout) -> Timeout in seconds for waiting an answer
	 * 2  (retry)    -> Number of times we send a packet until a response is received
	 */
	cout << "[@] Sending the ICMP echoes. Wait..." << endl;

	/* Create a packet container to hold all the answers */
	vector<Packet*> pongs_packets(pings_packets.size());
	SocketSendRecv(s,pings_packets.begin(),pings_packets.end(),pongs_packets.begin(),iface,0.1,2,48);

	cout << "[@] SendRecv function returns :-) " << endl;

	/*
	 * pongs_packets is a pointer to a PacketContainer with the same size
	 * of pings_packets (first argument). So, at this point, (after
	 * the SendRecv functions returns) we can iterate over each
	 * reply packet, if any.
	 */
	vector<Packet*>::iterator it_pck;
	int counter = 0;
	for(it_pck = pongs_packets.begin() ; it_pck < pongs_packets.end() ; it_pck++) {
		/* Check if the pointer is not NULL */
		Packet* reply_packet = (*it_pck);
		if(reply_packet) {
            /* Get the ICMP layer */
            ICMP* icmp_layer = reply_packet->GetLayer<ICMP>();
            if(icmp_layer->GetType() == ICMP::EchoReply) {
				/* Get the IP layer of the replied packet */
				IP* ip_layer = reply_packet->GetLayer<IP>();
				/* Print the Source IP */
				cout << "[@] Host " << ip_layer->GetSourceIP() << " up." << endl;
				counter++;
            }
		}
	}

	cout << "[@] " << counter << " hosts up. " << endl;

}

int main() {

    /* Create a socket descriptor */
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);

    if(s < 0)
		exit(1);

    /* Sock options */
    int one = 1;
    const int* val = &one;

    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0)
		exit(1);

	if(setsockopt(s, SOL_SOCKET, SO_BROADCAST, val, sizeof(one)) < 0)
		exit(1);

	cout << "[@] SIMPLE PING: " << endl;
	ping_pong(s);

	cout << "[@] NETWORK PING: " <<  endl;
	network_ping(800);

	close(s);

	return 0;
}
