/*
* ExtendedDataOffset
*
* Create/Parse packets with an EDO TCP option
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

    TCPOptionPad nop = TCPOption::NOP;

    /* EDO size option */
    TCPEDO edo;

    /* MSS */
    TCPOptionMaxSegSize mss;

    /* Dummy Payload */
    RawLayer payload("Hello World!");
    
    /* Create a packet... */
    Packet packet = ip_header / tcp_header / edo / nop / nop / nop / nop / nop / nop / nop / nop / nop / nop / nop / nop / nop / nop / mss / payload;
    packet.PreCraft();
    cout << "Original packet:" << endl;
    packet.Print();
    packet.HexDump();
    
    /* Decode it */
    Packet decoded;
    decoded.Decode(packet.GetRawPtr(), packet.GetSize(), IP::PROTO);
    cout << "Decoded packet:" << endl;
    decoded.Print();
    
    return 0;
}
