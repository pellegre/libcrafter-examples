/*
* IPv6RoutingHeader
*
* Create/Parse packets with an IPv6 Routing Extension Header
* */
#include <iostream>
#include <string>
#include <crafter.h>

using namespace std;
using namespace Crafter;

int main() {
    /* Create an IP header */
    IPv6 ip_header;
    /* Set the Source and Destination IP address */
    ip_header.SetSourceIP("2001:db8:dead:beef:cafe::0");
    ip_header.SetDestinationIP("2001:db8:1234::1");
    /* Create a segment routing header */
    IPv6SegmentRoutingHeader sr_header;
    sr_header.PushIPv6Segment("2001:db8:1234::2");
    sr_header.PushIPv6Segment("2001:db8:1234::3");
    sr_header.PushIPv6Segment("2001:db8:1234::4");
    sr_header.PushIPv6Segment("2001:db8:1234::5");
    sr_header.PolicyList[2].type = IPv6SegmentRoutingHeader::SRPolicy::SRPOLICY_EGRESS;
    sr_header.PolicyList[2].policy[6] = 0xff;
    sr_header.SetCFlag(1);
    sr_header.SetHMACKeyID(5);
    sr_header.HMAC[15] = 0xff;
    
    /* Dummy TCP header */
    TCP tcp_header;
    /* Dummy Payload */
    RawLayer payload("Hello World!");
    
    /* Create a packet... */
    Packet packet = ip_header / sr_header / tcp_header / payload;
    packet.PreCraft();
    cout << "Original packet:" << endl;
    packet.Print();
    
    /* Decode it */
    Packet decoded;
    decoded.Decode(packet.GetRawPtr(), packet.GetSize(), IPv6::PROTO);
    cout << "Decoded packet:" << endl;
    decoded.Print();
    
    return 0;
}
