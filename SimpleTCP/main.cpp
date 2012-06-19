/*
 * Simple TCP
 *
 * Program that shows how to perform a TCP connection at user level. We should
 * use IPTABLES to avoid RST packets from the kernel.
 */
#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

/*
 * Use IPTABLES for dropping packets received from the destination IP address. The
 * kernel shouldn't be aware of the connection we are trying to establish
 */
void iptables_reset(const string& dst_ip, int dst_port, int src_port);

/* Delete the rules */
void iptables_clear_reset(const string& dst_ip, int dst_port, int src_port);

int main() {

	/* Set the interface */
	string iface = "wlan0";

	/* Set connection data */
	string dst_ip = "192.168.0.108";  // <-- Destination IP
	string src_ip = GetMyIP(iface);   // <-- Our IP
	short_word srcport = RNG16();     // <-- Some Random source port
	short_word dstport = 80;          // <-- Destination Port

	/* Initialize connection */
	TCPConnection tcp_connection(src_ip,dst_ip,srcport,dstport,iface);

	/*
	 * We can't establish a connection on kernel's back. In this function
	 * we use IPTABLES to politely say to the kernel: Stay out of out way.
	 */
	iptables_reset(dst_ip, dstport, srcport);

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

	tcp_connection.Reset();

	/* Delete IPTABLES rules */
	iptables_clear_reset(dst_ip, dstport, srcport);

	return 0;
}

void iptables_reset(const string& dst_ip, int dst_port, int src_port) {
	string rule = "/sbin/iptables  -A INPUT -s " + dst_ip +
			      " -p tcp --sport " + StrPort(dst_port) + " --dport " + StrPort(src_port) +
			      " -j DROP";

	cout << rule << endl;
	/* Drop packets received from the destination IP address */
	system(rule.c_str());

	/* Remember that libcrafter doesn't mind about local firewalls rules... */
}

void iptables_clear_reset(const string& dst_ip, int dst_port, int src_port) {
	const char* rule = string("/sbin/iptables  -D INPUT -s " + dst_ip +
			      " -p tcp --sport " + StrPort(dst_port) + " --dport " + StrPort(src_port) +
			      " -j DROP").c_str();

	cout << rule << endl;
	/* Drop packets received from the destination IP address */
	system(rule);

}
