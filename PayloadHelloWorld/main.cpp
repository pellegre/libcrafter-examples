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

	/* Create the layer */
	RawLayer raw_layer;

	/* Set a payload... */
	raw_layer.SetPayload("Hello ");
	/* Concatenate a string to the payload */
	raw_layer.AddPayload("World!");

	/* You can create a packet from a layer */
	Packet packet = raw_layer;

	/* Send it throught the network  */
	packet.Send();

	/* You can manipulate the raw layer once is "inside" the packet */
	RawLayer* raw_packet_layer = GetRawLayer(packet);

	/* Put another payload */
	raw_packet_layer->SetPayload("This is a new Payload");

	/* And send it again...*/
	packet.Send();

	/* Create another raw layer */
	RawLayer new_raw_layer("This is another payload on another layer");

	/* You can rehuse the packet and push layers with the "/" operator: */
	packet = raw_layer / new_raw_layer;

	/* And send it again...*/
	packet.Send();


	return 0;
}
