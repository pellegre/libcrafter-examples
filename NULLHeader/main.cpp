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
#include <boost/shared_ptr.hpp>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main_read() {
	typedef boost::shared_ptr<Packet> packet_ptr;

	vector<packet_ptr> sack_pcks;
	ReadPcap(&sack_pcks,"NullLayerIPv4.pcap");

	vector<packet_ptr>::iterator it_pck;

	for(it_pck = sack_pcks.begin() ; it_pck != sack_pcks.end() ; it_pck++)
		(*it_pck)->Print();

	return 0;
}


int main() {
	main_read();
	return 0;
}
