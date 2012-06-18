/*
 * Ping
 *
 * Forge an ICMP echo-request packet and send it to some destination
 */
#include <iostream>
#include <string>
#include <vector>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Init the library */
	InitCrafter();

	/* Set the interface */
	string iface = "wlan0";

	/* Get the IP address associated to the interface */
	string MyIP = GetMyIP(iface);

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);                   
	ip_header.SetDestinationIP("www.google.com.ar");

	/* ++++++++++++ Example how-to use LSRR options (same for SSRR) */
	vector<string> ips;
	ips.push_back("1.2.3.4");
	ips.push_back("2.3.4.5");
	ips.push_back("3.4.5.6");
	vector<byte> raw_ips = IPtoRawData(ips);

	IPOptionLSRR lsrr;
	lsrr.SetPointer(8);
	lsrr.SetPayload(raw_ips);
	/* +++++++++++++ */

	/* ++++++++++++ RR options (is the same as SSRR and LLRR) */
	vector<string> ipsrr(8,"0.0.0.0"); // <-- Area to hold all the IP address expected
	/* Convert IP addresses on string container into raw data in network byte order */
	vector<byte> raw_ipsrr = IPtoRawData(ipsrr);

	IPOptionRR rr;
	rr.SetPointer(4);
	/* Put the raw IPs data in the optoin payload */
	rr.SetPayload(raw_ipsrr);
	/* +++++++++++++ */

	/* Create an ICMP header */
	ICMP icmp_header;

	icmp_header.SetType(ICMP::EchoRequest);
	icmp_header.SetIdentifier(RNG16());

	/* Create a payload */
	RawLayer raw_header;
	raw_header.SetPayload("HelloPing!\n");

	/* Create a packet... */
	Packet packet = ip_header / rr /
	                /* Padding IP options to a multiple of 32 bits (1 EOL byte) */
	                IPOption::EOL /
	                /* Put the rest of the data */
	                icmp_header / raw_header;


	Packet p;
        p.PacketFromIP(packet.GetRawPtr(), packet.GetSize());
        p.Print();
/* Send and receive an echoreply packet */
	Packet *rcv = 0;//packet.SendRecv(iface,2);


	/* Check if the return value of SendRecv is not zero */
	if(rcv) {
		/* Print the packet */
		rcv -> Print();
		
		LayerStack::iterator it_layer;

		cout << "[@] Parsing RR IP options " << endl;

		/* Print RR data of the IP option on the received packet */
		for(it_layer = rcv->begin() ; it_layer != rcv->end() ; ++it_layer) {

			if( (*it_layer)->GetID() == IPOptionRR::PROTO ) {

				IPOptionRR* rr_rcv = dynamic_cast<IPOptionRR*>((*it_layer));
				/* Get pointer position */
				cout << "[@] Pointer = " << dec << (int)rr_rcv->GetPointer() << endl;
				/* Get the list of ip addresses as a string container */
				vector<string> ips = RawDatatoIP(rr_rcv->GetPayload().GetContainer());
				/* Iterate and print each IP address */
				cout << "[@] IP addresses : " << endl;
				vector<string>::iterator it_ip;
				for(it_ip = ips.begin() ; it_ip != ips.end() ; ++it_ip)
					cout << "  + " << (*it_ip) << endl;

			}
			
		}
	
		delete rcv;
	} else
		cout << "[@] No answer... " << endl;

	/* Clean before exit */
	CleanCrafter();

	return 0;

}
