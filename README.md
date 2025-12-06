# libcrafter Examples

A collection of example programs demonstrating the usage of [libcrafter](https://github.com/pellegre/libcrafter), a high-level C++ library for crafting and decoding network packets.

libcrafter is designed to make packet manipulation easy, allowing developers to forge and decode packets from the application layer down to the link layer. It supports IPv4, IPv6, TCP, UDP, ICMP, ARP, DNS, DHCP, and many other protocols.

## Building

### Using CMake (recommended)

```bash
cmake .
make
```

Executables will be placed in the `bin/` directory.

### Manual compilation (single example)

```bash
g++ main.cpp -o example -lcrafter -lpcap -lpthread -lresolv
```

## Running

Most examples require root privileges to send/receive raw packets:

```bash
sudo ./bin/ExampleName
```

**Note:** Before running, check the interface name (commonly `wlan0`, `eth0`, or `enp0s3`) and IP address ranges in the source code. Modify them according to your network configuration.

---

## Examples Overview

### Basic Examples

| Example | Description |
|---------|-------------|
| **HelloWorld** | Simplest example. Creates a raw layer with "Hello World!" and writes it to the network interface. |
| **PayloadHelloWorld** | Demonstrates RawLayer manipulation, payload concatenation, and the `/` operator for combining layers. |
| **BasicSend** | Constructs a TCP packet with Ethernet, IP, and TCP headers, sends it, and shows field auto-completion. |

### ICMP / Ping

| Example | Description |
|---------|-------------|
| **Ping** | Forges an ICMP echo-request (ping) and sends it to a destination. |
| **BasicPingPong** | Sends a ping and waits for a reply using `SendRecv()`. |
| **NetworkPing** | Performs a ping scan on a /24 network using multi-threaded `SendRecv()`. |
| **Ping6** | IPv6 ping example using ICMPv6. |
| **PingIPv4IPv6** | IP-version-independent ping using `IPLayer` and `ICMPLayer` abstractions. |
| **SnifferNetworkPing** | Network ping scan using a sniffer to capture replies instead of `SendRecv()`. |
| **TimeExceeded** | Creates an ICMP Time Exceeded message with MPLS extensions. |

### ARP

| Example | Description |
|---------|-------------|
| **ARPPing** | ARP scan on a local network using `SendRecv()` to discover live hosts. |
| **ARPPingL2Socket** | Efficient ARP scan using raw L2 sockets and a sniffer. |
| **SnifferARPPing** | ARP scan using `Send()` with a spawned sniffer for replies. |
| **SimpleARPPoison** | Basic ARP spoofing between two hosts (man-in-the-middle). |
| **SnifferARPPoison** | ARP poisoning combined with HTTP traffic sniffing. |
| **SpawnARPPoison** | Uses `ARPSpoofingReply()` helper function for background ARP poisoning. |

### DNS

| Example | Description |
|---------|-------------|
| **DNSQuery** | Forges a DNS query and sends it to a DNS server, prints the response. |
| **DNSSpoof** | DNS spoofing attack combined with ARP poisoning. |

### TCP

| Example | Description |
|---------|-------------|
| **SimpleTCP** | User-level TCP connection establishment using `TCPConnection` class. |
| **TCPOptions** | Demonstrates TCP options: MSS, Window Scale, Timestamp. |
| **TCPTraceroute** | TCP-based traceroute using SYN packets with varying TTL. |
| **SimpleHijackConnection** | TCP session hijacking demonstration. |
| **SimpleSpoofConnection** | Spoofed TCP connection from a victim's IP address. |

### UDP

| Example | Description |
|---------|-------------|
| **UDPTraceroute** | UDP-based traceroute using varying TTL values. |

### DHCP

| Example | Description |
|---------|-------------|
| **DHCPRequest** | Sends DHCP Discovery and Request messages, parses server responses. |

### IPv6

| Example | Description |
|---------|-------------|
| **ExampleIPv6** | Basic IPv6 packet construction and transmission. |
| **CombineIPv4IPv6** | IP-version-independent code using `IPLayer` abstraction. |
| **IPv6RoutingHeader** | Creates IPv6 packets with Segment Routing and Mobile Routing headers. |

### IP Options

| Example | Description |
|---------|-------------|
| **IPOptions** | ICMP ping with IP Traceroute option. |
| **IPOptionRecordRoute** | Uses LSRR (Loose Source Record Route) and RR (Record Route) IP options. |

### Packet Capture / PCAP

| Example | Description |
|---------|-------------|
| **SimpleSniffer** | Basic packet sniffer capturing TCP port 22 traffic. |
| **FileSniffer** | Captures HTTP traffic and saves payloads to a file. |
| **ReadPcap** | Reads packets from a pcap file and prints them. |
| **DumpPcap** | Creates packets and dumps them to pcap files, then reads them back. |

### Advanced / Miscellaneous

| Example | Description |
|---------|-------------|
| **FilterSendRecv** | Uses custom tcpdump filter expressions with `SendRecv()`. |
| **UserSockets** | Demonstrates using user-created raw sockets with libcrafter. |
| **NULLHeader** | Reads pcap files with NULL/Loopback link layer (requires Boost). |
| **SACKOption** | TCP SACK (Selective Acknowledgment) option parsing and creation (requires Boost). |
| **ExtendedDataOffset** | TCP Extended Data Offset (EDO) option examples. |

---

## Code Patterns

### Creating and Sending a Packet

```cpp
#include <crafter.h>
using namespace Crafter;

// Create layers
IP ip; 
ip.SetSourceIP("192.168.1.100");
ip.SetDestinationIP("192.168.1.1");

ICMP icmp;
icmp.SetType(ICMP::EchoRequest);

// Combine layers using / operator
Packet packet = ip / icmp;

// Send the packet
packet.Send("eth0");
```

### Send and Receive

```cpp
Packet* reply = packet.SendRecv("eth0", 2.0);  // 2 second timeout
if (reply) {
    reply->Print();
    delete reply;
}
```

### Sniffing Packets

```cpp
void handler(Packet* pkt, void* user) {
    pkt->Print();
}

Sniffer sniff("tcp port 80", "eth0", handler);
sniff.Capture(10);  // Capture 10 packets
```

---

## Important Notes

1. **Interface Names**: Default examples use `wlan0`. Change to your interface (e.g., `eth0`, `enp0s3`).

2. **IP Addresses**: Network ranges like `192.168.0.*` are hardcoded. Adjust for your network.

3. **Root Privileges**: Raw socket operations require root access.

4. **Security Warning**: Some examples (ARP poisoning, DNS spoofing, connection hijacking) are for educational purposes only. Use responsibly and only on networks you own or have permission to test.

5. **iptables**: Some examples modify iptables rules. They attempt cleanup on exit, but verify your firewall rules after running.

## License

These examples are provided for educational purposes to demonstrate libcrafter usage.

