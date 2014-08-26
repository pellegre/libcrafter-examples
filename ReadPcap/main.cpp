#include <iostream>
#include <crafter.h>

using namespace Crafter;

int main() {
    std::vector<Packet*> pck_cont;

    /* Put you pcap file */
    ReadPcap(&pck_cont, "example.pcap");

    std::vector<Packet*>::iterator it_pck;
    for(it_pck = pck_cont.begin() ; it_pck != pck_cont.end() ; it_pck++) {
        /* Print time stamp */
        timeval ts = (*it_pck)->GetTimestamp();
        std::cout << "ts_sec = " << ts.tv_sec << " ts_usec = " << ts.tv_usec << std::endl;
        /* Modfiy time stamp */
        ts.tv_sec = 11;
        ts.tv_usec = 110;
        (*it_pck)->SetTimestamp(ts);
    }
    
    DumpPcap(pck_cont.begin(),pck_cont.end(),"modified.pcap");

    return 0;
}
