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
void iptables_reset(const string& dst_ip, int dst_port);

/* Delete the rules */
void iptables_clear_reset(const string& dst_ip, int dst_port);

/* Global TCP connection pointer, so the signal handler can close the connection */
TCPConnection* tcp_ptr;

void ctrl_c(int dummy) {
	/* Close the connection when we press CTRL-C */
	tcp_ptr->Close();
}

int main() {

	/* Init the library */
	InitCrafter();

	/* Set the interface */
	string iface = "vboxnet0";

	/* Set connection data */
	string dst_ip = "192.168.56.101"; // <-- Destination IP
	string src_ip = GetMyIP(iface);   // <-- Our IP
	short_word srcport = RNG16();     // <-- Some Random source port
	short_word dstport = 10000;       // <-- Destination Port

	/* Initialize connection */
	TCPConnection tcp_connection(src_ip,dst_ip,srcport,dstport,iface);

	/*
	 * We can't establish a connection on kernel's back. In this function
	 * we use IPTABLES to politely say to the kernel: Stay out of out way.
	 */
	iptables_reset(dst_ip, dstport);

	/* Establish a connection */
	tcp_connection.Sync();

	/* Set a signal handler for a CTRL-C */
	signal(SIGINT,ctrl_c);
	/* Set the global connection pointer */
	tcp_ptr = &tcp_connection;

	/* Send lines from standard input */
	string line;
	while(tcp_connection.GetStatus() != TCPConnection::CLOSED) {
		/* Get a line from standard input */
		getline(cin,line);
		line += "\n";
		/* Send to the destination */
		tcp_connection.Send(line.c_str());
	}

	/* Delete IPTABLES rules */
	iptables_clear_reset(dst_ip, dstport);

	/* Clean before exit */
	CleanCrafter();

	return 0;
}

void iptables_reset(const string& dst_ip, int dst_port) {

	/* Drop packets received from the destination IP address */
	system(string("/sbin/iptables  -A INPUT -s " + dst_ip +
			      " -p tcp --sport " + StrPort(dst_port) + " -j DROP").c_str());

	/* Remember that libcrafter doesn't mind about local firewalls rules... */
}

void iptables_clear_reset(const string& dst_ip, int dst_port) {

	system(string("/sbin/iptables  -D INPUT -s " + dst_ip +
			      " -p tcp --sport " + StrPort(dst_port) + " -j DROP").c_str());

}
