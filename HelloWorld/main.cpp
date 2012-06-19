/*
 * Hello World
 *
 * Simple program that writes into the wire the "Hello World!" string
 */
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

int main() {

	/* Create a Raw layer with some data on it... */
	RawLayer hello("Hello ");
	/* ...or a pointer */
	RawLayer* world = new RawLayer("World!");

	/* Create a packet to hold both layers */
	Packet packet;

	/* Push the first layer... */
	packet.PushLayer(hello);
	/* ... and finally the second one */
	packet.PushLayer(*world);

	/* You may print the packet to STDOUT... */
	cout << "[@] --- Print packet to STDOUT: " << endl;
	packet.Print();
	/* ...or hexdump it... */
	cout << "[@] --- HexDump the packet: " << endl;
	packet.HexDump();
	/* ...or print a hex string (so it's easy to include it on a C code, or whatever). */
	cout << "[@] --- Print RawString: " << endl;
	packet.RawString();

	/* And last but not least, you can write the packet on the wire :-) */
	packet.Send("wlan0");

	delete world;

	return 0;
}
