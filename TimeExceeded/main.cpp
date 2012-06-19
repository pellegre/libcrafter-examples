/*
 * Ping
 *
 * Forge an ICMP time exceeded message with ICMP extensions
 */
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Create an IP header */
	IP ip_header;
	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(GetMyIP(iface));
	ip_header.SetDestinationIP("1.2.3.4");
	/* Create an ICMP header */
	ICMP icmp_header;
	icmp_header.SetType(ICMP::TimeExceeded);
	icmp_header.SetCode(0);

	/* ----- Original payload ----- */
	IP orig_ip;
	orig_ip.SetSourceIP("5.6.7.8");
	orig_ip.SetDestinationIP("10.11.12.13");
	UDP orig_udp;
	orig_udp.SetSrcPort(53);
	orig_udp.SetDstPort(1111);
	Packet orig_payload = orig_ip / orig_udp / RawLayer("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			                                            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
			                                            "AAAAAAAAAAAAAAAAAAAAAAAA");

	/* ----- ICMP extension ----- */

	ICMPExtensionMPLS mpls_1; mpls_1.SetLabel(1234); mpls_1.SetTTL(100);
	ICMPExtensionMPLS mpls_2; mpls_2.SetLabel(2345); mpls_2.SetTTL(150);
	ICMPExtensionMPLS mpls_3; mpls_3.SetLabel(1048575); mpls_3.SetExperimental(6) ; mpls_3.SetTTL(200);

	/* Create a packet... */
	Packet packet = ip_header / icmp_header / orig_payload /
			        ICMPExtension() / ICMPExtensionObject() / mpls_1 / mpls_2 / mpls_3;

	packet.Send();

	return 0;

}
