/*
 * TCP Traceroute
 *
 * This program perform a TCP traceroute to some host.
 */
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Set the interface */
	string iface = "tun0";

	/* ----------- Host and traceroute data --------- */

	/* This is the IP we want to scan */
	string scan_ip = "www.google.com.ar";

	/*  Set the destination port for the TCP packets */
	int port_number = 33434;

	/* Max hops, i.e. the max number of TTL on the packets */
	int max_hops = 30;

	/* --------- Common data to all packets ---------- */

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(GetMyIP(iface));
	ip_header.SetDestinationIP(scan_ip);

	/* Create a TCP header */
	UDP udp_header;

    /* ---------------------------------------------- */

	/* Create a container to hold all the TCP packets */
	vector<Packet*> udp_packets;

	/* Create a packet for each TTL */
	for(int ttl = 1 ; ttl <= max_hops ; ttl++) {

		/* Set a random ID for the IP header */
		ip_header.SetIdentification(RNG16());
		/* Set the TTL */
		ip_header.SetTTL(ttl);

		/* Set a Random sequence number for TCP syn packet*/
		udp_header.SetDstPort(port_number++);
		udp_header.SetSrcPort(RNG16());

		/* Create a packet */
		Packet* packet = new Packet(ip_header/udp_header);

		/* Push the packet into the container */
		udp_packets.push_back(packet);
	}

	cout << "[@] Sending the UDP packets. Wait..." << endl;

	/* Create a TCP packet container to hold the responses */
	PacketContainer ret_packets(udp_packets.size());

	SendRecv(udp_packets.begin(),udp_packets.end(),ret_packets.begin(),iface,1.0,3,48);

	cout << "[@] SendRecv function returns :-) " << endl;

	/* Now, check each answer */
	vector<Packet*>::iterator it_pck;

	int counter = 1;
	for(it_pck = ret_packets.begin() ; it_pck < ret_packets.end() ; it_pck++) {
		/* Check if the pointer is not NULL */
		Packet* reply_packet = (*it_pck);
		if(reply_packet) {

			/* Get the IP layer of the replied packet */
			IP* ip_layer = reply_packet->GetLayer<IP>();
			/* Check if the received packet was an ICMP message */
			ICMP* icmp_layer = reply_packet->GetLayer<ICMP>();

			/* If isn't an ICMP packet, break the loop. You can do additional checks. (TCP flags, ICMP type, etc...)*/
			if(!icmp_layer) break;

			/* ICMP packet should be of type "11" (destination unreachable) */
			if(icmp_layer->GetType() != 11) break;

			/* Get source IP of the packet */
			string src_ip = ip_layer->GetSourceIP();
			/* Print the Source IP */
			cout << "[" << counter << "] " << src_ip << endl;


		} else
			cout << "[" << counter << "] *.*.*.* " << endl;

		/* Increment counter (= TTL) */
		counter++;
	}

	/* Delete the container with the PINGS packets */
	for(it_pck = udp_packets.begin() ; it_pck < udp_packets.end() ; it_pck++)
		delete (*it_pck);

	/* Delete the container with the responses, if there is one (check the NULL pointer) */
	for(it_pck = ret_packets.begin() ; it_pck < ret_packets.end() ; it_pck++)
		delete (*it_pck);

	return 0;
}
