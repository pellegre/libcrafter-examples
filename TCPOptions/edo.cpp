/*
* EDO
*
* Create/Parse packets with and without the TCP EDO option
* */
#include <iostream>
#include <string>
#include <crafter.h>
#include <crafter/Protocols/TCPOption.h>

using namespace std;
using namespace Crafter;

static int test_run = 0;
static int test_success = 0;

void test_packet(const char *test_title, Packet &packet) {
    ++test_run;
    cout << "Testing: " << test_title << endl;
	packet.HexDump(cout);
    packet.PreCraft();
    cout << "Original packet:" << endl;
    packet.HexDump(cout);
    packet.Print();
    cout << endl;

    /* Decode it */
    Packet decoded;
    decoded.Decode(packet.GetRawPtr(), packet.GetSize(), IP::PROTO);
    cout << "Decoded packet:" << endl;
    decoded.HexDump(cout);
    decoded.Print();
    cout << endl;

    bool same = true;
    if (packet.GetSize() != decoded.GetSize()) {
        PrintMessage(PrintCodes::PrintError,
                "test_packet::same_size",
                "The two packet do not have the same size");
        return;
    }
    const byte *orig = packet.GetRawPtr();
    const byte *d = decoded.GetRawPtr();
    for (size_t i = 0; i < packet.GetSize(); ++i)
        if (orig[i] != d[i]) {
            same = false;
            cout << "Bytes at " << i << " differs: "
                <<  (int)orig[i] << " vs " << (int)d[i] << endl;
        }
    if (!same) {
        PrintMessage(PrintCodes::PrintError,
                "test_packet()::same_bytes",
                "The two packets have different bytes !");
        return;
    } else {
        PrintMessage(PrintCodes::PrintMessage,
                "test_packet()", "The two packets are the same!");
    }
	if (packet.GetLayerCount() != decoded.GetLayerCount()) {
		PrintMessage(PrintCodes::PrintError,
				"test_packet()", "The two packets are not parsed in the same"
				"way: the number of layers differ!");
		return;
	}

    cout << endl;
    ++test_success;
}

int main() {
	Packet pkt = IP() / TCP() / RawLayer("Hello world!");
	test_packet("Without EDO", pkt);

	pkt = IP() / TCP() / TCPOptionEDO(TCPOptionEDO::EDOREQUEST) / TCPOption::NOP / TCPOption::NOP / RawLayer("Hello world!");
	test_packet("With EDOREQUEST", pkt);

	pkt = IP() / TCP() / TCPOptionEDO(TCPOptionEDO::EDO) / RawLayer("Hello world!");
	test_packet("With EDO", pkt);
	++test_run;
	if (pkt.GetLayer<TCPOptionEDO>()->GetHeaderLength() == pkt.GetLayer<TCP>()->GetDataOffset())
		++test_success;
	else
		std::cerr << "The header length / data offset are unconsistent!" << std::endl;

	pkt = IP() / TCP() / TCPOption::NOP / TCPOption::NOP / TCPOptionEDO(TCPOptionEDO::EDOEXT) / RawLayer("Hello world!");
	test_packet("With EDOEXT", pkt);
	++test_run;
	if (pkt.GetLayer<TCPOptionEDO>()->GetSegmentLength() == pkt.GetLayer<RawLayer>()->GetSize())
		++test_success;
	else
		std::cerr << "The segment length / raw layer length are unconsistent!" << std::endl;

	pkt = IP() / TCP() / TCPOptionEDO(TCPOptionEDO::EDO) / TCPOptionSACKPermitted() / TCPOption::NOP / TCPOption::NOP / RawLayer("Hello world!");
	test_packet("With EDO and sackp/nop/nop", pkt);
	++test_run;
	if (pkt.GetLayer<TCPOptionEDO>()->GetHeaderLength() != pkt.GetLayer<TCP>()->GetDataOffset())
		if (pkt.GetLayer<TCPOptionEDO>()->GetHeaderLength() == 5 + 1 + 1) /* TCP + EDO + SAKP/NOP/NOP */
			++test_success;
		else
			std::cerr << "The header length has the wrong value!" << std::endl;
	else
		std::cerr << "The header length / data offset are the same but should not!" << std::endl;

	cout << "Test success rate: " << test_success << "/" << test_run << endl;
    return 0;
}
