/*
 * Create a DHCP request
 *
 * Simple examples to show how to use DHCP layer and DHCP options.
 */
#include <iostream>
#include <string>
#include <cstdio>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

const word SPERW = 7 * 24 * 3600;
const word SPERD = 24 * 3600;
const word SPERH = 3600;
const word SPERM = 60;

void PrintTime(word t) {
	t = htonl(t);
	cout << "( ";
	if (t > SPERW) { cout <<  t / (SPERW) << " week(s) "; t %= SPERW; }
	if (t > SPERD) { cout <<  t / (SPERD) << " day(s) "; t %= SPERD; }
	if (t > SPERH) { cout <<  t / (SPERH) << " hour(s) "; t %= SPERH; }
	if (t > SPERM) { cout <<  t / (SPERM) << " minute(s) "; t %= SPERM; }
	if (t > 0) cout << t << " second(s)";
	cout << ")";
}

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Data of the DHCP client */
	string mac_address = GetMyMAC(iface);
	string hostname = "HelloDCHP:-)";
	string request_ip = "192.168.0.105";

	/* Create Ethernet header */
	Ethernet ether_header;

	/* Set the source and destination MAC address */
	ether_header.SetSourceMAC(mac_address);
	ether_header.SetDestinationMAC("ff:ff:ff:ff:ff:ff");

	/* Create an IP header */
	IP ip_header;

	/* Set the Source and Destination IP address */
	ip_header.SetSourceIP("0.0.0.0");
	ip_header.SetDestinationIP("255.255.255.255");

	/* Create a UDP header */
	UDP udp_header;

	/* Set the source and destination ports */
	udp_header.SetSrcPort(68);
	udp_header.SetDstPort(67);

	/* Create a payload */
	DHCP dhcp_header;
	dhcp_header.SetOperationCode(DHCP::Request);
	dhcp_header.SetTransactionID(RNG32());
	dhcp_header.SetClientMAC(mac_address);

	/* Options[0] */
	/* ----------------------- Add options (type of message) --------------------- */
	dhcp_header.Options.push_back(CreateDHCPOption(DHCPOptions::DHCPMsgType,
			                                       DHCPOptions::DHCPDISCOVER,
			                                       DHCPOptions::BYTE));
	/* --------------------------------------------------------------------------- */

	/* Options[1] */
	/* ------------------------ Request an IP address ---------------------------- */
	vector<string> ip_addr;
	ip_addr.push_back(request_ip);
	dhcp_header.Options.push_back(CreateDHCPOption(DHCPOptions::AddressRequest,
			                                       ip_addr));
	/* --------------------------------------------------------------------------- */

	/* Options[2] */
	/* ---------------------- Parameter list request ----------------------------- */
	byte parameters[] = { DHCPOptions::SubnetMask,
	                      DHCPOptions::BroadcastAddress,
	                      DHCPOptions::TimeOffset,
	                      DHCPOptions::Router,
	                      DHCPOptions::Hostname,
	                      DHCPOptions::AddressTime,
	                      DHCPOptions::DomainName,
	                      DHCPOptions::DomainServer,
	                      DHCPOptions::TimeServer
	                     };
	dhcp_header.Options.push_back(CreateDHCPOption(DHCPOptions::ParameterList,
			                                       parameters,
			                                       sizeof(parameters)));
	/* --------------------------------------------------------------------------- */

	/* Create a packet... */
	Packet packet = ether_header / ip_header / udp_header / dhcp_header;
	packet.Print();
	/* Send the packet */
	Packet* rcv = packet.SendRecv(iface,2,3,"udp and src port 67 and dst port 68");

	/* Received DHCP layer */
	DHCP* dhcp_rcv = new DHCP();

	if(rcv) {
		/*
		 * An application protocol is always get from the network as a raw layer.
		 */
		dhcp_rcv->FromRaw(*GetRawLayer(*rcv));
		/* Print the response to STDOUT to see how it looks like */
		cout << "[@] ---------- DHCP response from server after a DISCOVERY message : " << endl;
		dhcp_rcv->Print();
		cout << "[@] ---------- " << endl;
	} else {
		cout << "[@] No response from any DHCP server" << endl;
		CleanCrafter();
		exit(1);
	}

	/* Now, lets parse the response from the server */
	string ip_offered = dhcp_rcv->GetYourIP();
	cout << "[@] IP address offered : " << ip_offered << endl;

	/* Now, lets go through the DHCP options */
	vector<DHCPOptions*>::const_iterator it_opt;

	for(it_opt = dhcp_rcv->Options.begin() ; it_opt != dhcp_rcv->Options.end() ; it_opt++) {

		/* Get the server ID */
		if((*it_opt)->GetCode() == DHCPOptions::DHCPServerId) {
			ip_addr = (*it_opt)->GetIPAddresses();
			if(ip_addr.size() > 0)
				cout << "[@] DHCP sever Identification : " << ip_addr[0] << endl;
		}

		/* Get the host name of teh DHCP server */
		if((*it_opt)->GetCode() == DHCPOptions::Hostname) {
			cout << "[@] DHCP hostname : " << (*it_opt)->GetString() << endl;
		}

		/* Get the router IP address */
		if((*it_opt)->GetCode() == DHCPOptions::Router) {
			ip_addr = (*it_opt)->GetIPAddresses();
			if(ip_addr.size() > 0)
				cout << "[@] Router IP address : " << ip_addr[0] << endl;
		}

		/* Get the subnet mask */
		if((*it_opt)->GetCode() == DHCPOptions::SubnetMask) {
			ip_addr = (*it_opt)->GetIPAddresses();
			if(ip_addr.size() > 0)
				cout << "[@] Network subnet mask : " << ip_addr[0] << endl;
		}

		/* Get the domain name server */
		if((*it_opt)->GetCode() == DHCPOptions::DomainServer) {
			ip_addr = (*it_opt)->GetIPAddresses();
			if(ip_addr.size() > 0)
				cout << "[@] Domain name server IP address : " << ip_addr[0] << endl;
		}

		/* Get the IP address lease time */
		if((*it_opt)->GetCode() == DHCPOptions::AddressTime) {
			word time_seconds = (*it_opt)->GetNumber();
			cout << "[@] IP address lease time : ";
			PrintTime(time_seconds);
			cout <<  endl;
		}

	}
	cout << "[@] ---------- " << endl;
	/* Done with this packet */
	delete rcv;

	/* Now, we should the request the IP address provided by the server */
	DHCP dhcp_request;
	dhcp_request.SetOperationCode(DHCP::Request);
	dhcp_request.SetTransactionID(dhcp_header.GetTransactionID());
	dhcp_request.SetClientMAC(dhcp_header.GetClientMAC());

	/* Options[0] */
	/* ----------------------- Add options (type of message) --------------------- */
	dhcp_request.Options.push_back(CreateDHCPOption(DHCPOptions::DHCPMsgType,
			                                       DHCPOptions::DHCPREQUEST,
			                                       DHCPOptions::BYTE));
	/* --------------------------------------------------------------------------- */

	/* Options[1] */
	/* ------------------------ Request an IP address ---------------------------- */
    ip_addr.clear();
	ip_addr.push_back(ip_offered);
	dhcp_request.Options.push_back(CreateDHCPOption(DHCPOptions::AddressRequest,
			                                       ip_addr));
	/* --------------------------------------------------------------------------- */

	/* Options[2] */
	/* ---------------------- Parameter list request ----------------------------- */
	dhcp_header.Options.push_back(CreateDHCPOption(DHCPOptions::ParameterList,
			                                       parameters,
			                                       sizeof(parameters)));
	/* --------------------------------------------------------------------------- */

	/* Options[3] */
	/* -------------------------- Put our hostname ------------------------------- */
	dhcp_request.Options.push_back(CreateDHCPOption(DHCPOptions::Hostname,
			                                        hostname));
	/* --------------------------------------------------------------------------- */

	/* Rehuse the packet we alerady have */
	packet.PopLayer();
	packet /= dhcp_request;

	/* Send the request... */
	rcv = packet.SendRecv(iface,2,3,"udp and src port 67 and dst port 68");

	if(rcv) {
		/*
		 * An application protocol is always get from the network as a raw layer.
		 */
		dhcp_rcv->FromRaw(*GetRawLayer(*rcv));
		/* Print the response to STDOUT to see how it looks like */
		cout << "[@] ---------- DHCP response from server after a REQUEST message : " << endl;
		dhcp_rcv->Print();
		cout << "[@] ---------- " << endl;
	} else
		cout << "[@] No response to the request message " << endl;

	delete rcv;

	return 0;
}
