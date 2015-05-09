/*
* ExtendedDataOffset
*
* Create/Parse packets with an EDO Request TCP option flagged to SYN
* @author : Julien Colmonts
* */
#include <iostream>
#include <string>
#include <crafter.h>

using namespace std;
using namespace Crafter;

int main() {
    /* Create an IP header */
    IP ip_header;
    /* Set the Source and Destination IP address */
    ip_header.SetSourceIP("192.168.0.1");
    ip_header.SetDestinationIP("192.168.0.4");
    
    /* Dummy TCP header */
    TCP tcp_header;

    /* Set the source and destination ports */
    tcp_header.SetSrcPort(RNG16());
    tcp_header.SetDstPort(22);
    tcp_header.SetSeqNumber(RNG32());
    tcp_header.SetFlags(TCP::SYN);

    /* EDO size option */
    TCPEDORequest edo;


    /* Dummy Payload */
    RawLayer payload("Hello World!");
    
    /* Create a packet... */
    Packet packet = ip_header / tcp_header /  edo /  TCPOption::NOP /TCPOption::NOP /payload;
    packet.PreCraft();
    cout << "Original packet:" << endl;
    packet.Print();
    
    /* Decode it */
    Packet decoded;
    decoded.Decode(packet.GetRawPtr(), packet.GetSize(), IP::PROTO);
    cout << "Decoded packet:" << endl;
    decoded.Print();
    
    return 0;
}
