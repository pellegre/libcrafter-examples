/*
 * Basic Send
 *
 * The program creates a TCP packet with some arbitrary payload a send it to
 * a destination. Basic example to illustrate the use of the Send function and
 * how to construct a packet.
 */
#include <iostream>
#include <fstream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

void PrintPacket(Packet *p){p->Print();}
int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);
	string DstIP = "192.168.0.1";

	cout << "[@] My IP address is  : " << MyIP  << endl;

	Ethernet ether_header;

	ether_header.SetDestinationMAC(GetMAC(DstIP,iface)); /* GetMAC() will do an ARP request and get that IP address */
	ether_header.SetSourceMAC(GetMyMAC(iface));

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);
	ip_header.SetDestinationIP(DstIP);

	/* Create a TCP header */
	TCP tcp_header;

	/* Set the source and destination ports */
	tcp_header.SetSrcPort(62345);
	tcp_header.SetDstPort(RNG16());
	/* Set some TCP flags */
	tcp_header.SetFlags(TCP::SYN | TCP::CWR | TCP::ECE);

	/* Create a payload */
	RawLayer raw_header;
	raw_header.SetPayload("SomeTCPPayload\n");

	/* Create a packet... */
	Packet packet = ether_header / ip_header / tcp_header / raw_header;

	/* Print before sending */
	cout << endl << "[@] Print before sending: " << endl;
	packet.Print(); /* This goes to cout by default */

	/* Send the packet, this would fill the missing fields (like checksum, length, etc) */
	packet.Send();

	cout << endl;
	cout << "[+] ***************************************************** [+]" << endl;
	cout << endl;

	/* Print after sending, the fields on the layers of the packet were filled with the correct values. */
	cout << "[@] Print after sending: " << endl;
	packet.Print();

	/* You can print the data to a file */
	ofstream out("test.dat");
	packet.HexDump(out);
	packet.RawString(out);
	out.close();

	return 0;
}
