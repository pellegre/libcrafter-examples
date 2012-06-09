/*
 * Basic TCP Options Send
 *
 * The program creates an TCP packet with some options on the top of it.
 */
#include <iostream>
#include <fstream>
#include <string>
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
	string DstIP = "192.168.0.108";

	Ethernet ether_header;

	ether_header.SetDestinationMAC(GetMAC(DstIP,iface)); /* GetMAC will do an ARP request and get that IP address */
	ether_header.SetSourceMAC(GetMyMAC());

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP(MyIP);
	ip_header.SetDestinationIP(DstIP);

	/* Create a UDP header */
	TCP tcp_header;

	/* Set the source and destination ports */
	tcp_header.SetSrcPort(RNG16());
	tcp_header.SetDstPort(22);
	tcp_header.SetFlags(TCP::SYN);

	/* Max segment size option */
	TCPOptionMaxSegSize maxseg;
	maxseg.SetMaxSegSize(1460);

	/* Set some generic option (and if the option holds more data, should be added on the payload) */
	TCPOption wind;
	wind.SetKind(3);
	wind.SetPayload("\x7");

	/* Time stamp option */
	TCPOptionTimestamp tstamp;
	tstamp.SetValue(398303815);

	/*
	 * Padding using NOPs and the EOL of option are also a layer class
	 * TCPOptionPad is a class with only one field (Kind field).
	 * TCPOption padding ALWAYS should be done with object of the TCPOptionPad class.
	 */
	TCPOptionPad nop; nop.SetKind(1);
	TCPOptionPad eol; eol.SetKind(0);

	/* Create a payload */
	RawLayer raw_header;
	raw_header.SetPayload("SomeTCPPayload\n");

	/* Create a packet... */
	Packet packet = ether_header / ip_header / tcp_header /
			        /* START Option (padding should be controlled by the user) */
					maxseg /            // 4  bytes
					wind /              // 3  bytes
					tstamp /            // 10 bytes
					nop / nop / eol /   // 3  bytes <-- Padded to a multiple of 32 bits
					/* END Option  TOTAL = 20 bytes */
					raw_header;

	/* Send the packet, and wait for an answer.... */
	Packet* pck_rcv = packet.SendRecv(iface,0.1,3);

	if(pck_rcv) {

		/* Print all the received packet */
		pck_rcv->Print();

		TCP* rcv_tcp = GetTCP(*pck_rcv);

		/* We want to check some option of the SYN/ACK received */
		if(rcv_tcp->GetACK() && rcv_tcp->GetSYN()) {
			cout << "[@] Port open, parsing options... " << endl;
			LayerStack::iterator it;

			for(it  = pck_rcv->begin() ;it != pck_rcv->end() ; it++) {

				/* Look for the Timestamp option on the received packet */
				if((*it)->GetID() == TCPOptionTimestamp::PROTO) {
					TCPOptionTimestamp* tstamp = dynamic_cast<TCPOptionTimestamp*>((*it));

					cout << "[++++] Timestamp OPTION " << endl;
					/* Print some info */
					cout << "[@] Timestamp value      = " << dec << tstamp->GetValue() << endl;
					cout << "[@] Timestamp echo-reply = " << dec << tstamp->GetEchoReply() << endl;
				}

				/* Look for some option that is not implemented in libcrafter (for example the Windows Scale Option - Kind = 3) */
				if((*it)->GetID() == TCPOption::PROTO) {
					TCPOption* generic_opt = dynamic_cast<TCPOption*>((*it));
					if(generic_opt->GetKind() == 0x03) {
						/* This is a Windows Scale Opt, and get the raw data from the payload */
						vector<byte> opt_data =  generic_opt->GetPayload().GetContainer();
						cout << "[++++] Window Scale OPTION " << endl;
						/* We know that there is one byte indicating the window scale : */
						cout << "[@] Windows Scale = " << dec << (int)opt_data[0] << endl;
					}

				}

			}

		} else
			cout << "Port not open." << endl;


	} else
		cout << "[@] NO response." << endl;

	/* Clean before exit */
	CleanCrafter();

	return 0;
}
