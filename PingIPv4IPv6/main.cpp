#include <iostream>
#include <fstream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main(int argc, char* argv[]) {

	if(argc < 3) {
		cout << "[@] Usage <ip> <interface>" << endl;
		return 1;
	}
	/* Get IP address (4 or 6) */
	string dst_ip = string(argv[1]);
	/* Set the interface */
	string iface = string(argv[2]);

	/*
	 * Build a IP layer from the destination address (this should create a pointer to a IPv4/6 layer)
	 * The source IP address is obtained from the interface
	 */
	IPLayer* ip_header = IPLayer::BuildDst(dst_ip,iface);

	/*
	 * Build an ICMP layer. This types are common to both versions :
	 *
	 * DestinationUnreachable;
	 * TimeExceeded;
	 * ParameterProblem;
	 * EchoRequest;
	 * EchoReply;
	 *
	 * The Build method will select the correct type value according to the ICMP version (which
	 * is obtained with the IP address provided).
	*/
	ICMPLayer* icmp_layer = ICMPLayer::Build(dst_ip,ICMPLayer::EchoRequest);
	/* Build packet */
	Packet raw_pck = (*ip_header) / (*icmp_layer);

	/* ---- Test the packet decoding (from IPLayer) */
	cout << "[#] ICMP request : " << endl;
	Packet pck(raw_pck.GetRawPtr(),raw_pck.GetSize(),IPLayer::PROTO);
	pck.Print();

	cout << "[#] Pinging... " << endl;
	/* Send packet */
	Packet* rcv_pck = pck.SendRecv(iface);
	if(rcv_pck) {
		cout << "[#] ICMP reply : " << endl;
		rcv_pck->Print();
		/* Get type of ICMP layer */
		ICMPLayer* icmp = rcv_pck->GetLayer<ICMPLayer>();
		cout << "[#] ICMP type : " << dec << (int)icmp->GetType() << endl;
	} else
		cout << "[#] No response... " << endl;

	delete ip_header;
	delete icmp_layer;
	delete rcv_pck;

	return 0;
}
