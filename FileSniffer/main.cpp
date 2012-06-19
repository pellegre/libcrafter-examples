/*
 * File Sniffer
 *
 * This program spawn a sniffer for capturing TCP traffic that goes to
 * the http port (80). The HTTP requests (packet payload) are saved on
 * a file.
 */
#include <iostream>
#include <fstream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

/* File stream */
ofstream file;

/* Function for handling a packet */
void PacketHandler(Packet* sniff_packet, void* user) {
	/* sniff_packet -> pointer to the packet captured */
	/* user -> void pointer to the data supplied by the user */

	/* Check if there is a payload */
	RawLayer* raw_payload = sniff_packet->GetLayer<RawLayer>();
	if(raw_payload) {

		file << "[+] ------- [+]" << endl;
		/* Summarize some data */
		TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
		file << "[#] TCP packet from source port: " << tcp_layer->GetSrcPort() << endl;

		file << "[#] With Payload: " << endl;
		/* You can get the payload as a string */
		string payload = raw_payload->GetStringPayload();
		file << payload << endl;

	}
}


int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Open the file */
	file.open("http.dat");

	/*
	 * First, you should create a sniffer
	 * - 1st argument: Filter expression (tcpdump syntax)
	 * - 2nd argument: Interface
	 * - 3rd argument: A function that will be executed when a packet
	 * captured satisfies the filter expression (the default behavior is to
	 * print the packets to STDOUT).
	 */
	Sniffer sniff("tcp and dst port 80",iface,PacketHandler);

	/* Spawn the sniffer (ad-infinitum) */
	sniff.Spawn(-1);

	/* Estimated number of seconds */
	int nseconds = 20;
	for(int i = 0 ; i < nseconds ; i++) {
		cout << "[#] " << i << " seconds... " << endl;
		sleep(1);
	}

	/* Shut down cleanly the sniffer */
	sniff.Cancel();

	/* Close the file */
	file.close();

	return 0;
}
