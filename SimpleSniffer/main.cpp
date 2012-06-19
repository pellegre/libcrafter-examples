/*
 * Simple Sniffer
 *
 * Simple program to illustrate how to use the Sniffer class
 */
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

/* Function for handling a packet */
void PacketHandler(Packet* sniff_packet, void* user) {
	/* sniff_packet -> pointer to the packet captured */
	/* user -> void pointer to the data supplied by the user */

	/* Check if there is a payload */
	RawLayer* raw_payload = sniff_packet->GetLayer<RawLayer>();
	if(raw_payload) {

		cout << "[+] ------- [+]" << endl;
		/* Summarize some data */
		TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
		cout << "[#] TCP packet from source port: " << tcp_layer->GetSrcPort() << endl;

		cout << "[#] With Payload: " << endl;
		/* You can get the payload as a string */
		string payload = raw_payload->GetStringPayload();
		cout << payload << endl;

	}
}


int main() {

	/* Set the interface */
	string iface = "wlan0";

	/*
	 * First, you should create a sniffer
	 * - 1st argument: Filter expression (tcpdump syntax)
	 * - 2nd argument: Interface
	 * - 3rd argument: A function that will be executed when a packet
	 * captured satisfies the filter expression (the default behavior is to
	 * print the packets to STDOUT).
	 */
	Sniffer sniff("tcp and port 22",iface,PacketHandler);

	/* Now, start the capture (five packets) */
	sniff.Capture(5);

	return 0;
}
