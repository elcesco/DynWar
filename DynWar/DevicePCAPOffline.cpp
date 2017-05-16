#include <cstdio>

#include <pcap.h>

#include "ConfigurationManager.h"
#include "DynWarden.h"

#include "DevicePCAPOffline.h"

void DevicePCAPOffline::dlt_EN10MB(const u_char * packet) {
    
    const struct ether_header* ethernetHeader = (struct ether_header*) (packet);

    /* Ethernet protocol ID's */
    int ret = ntohs(ethernetHeader->ether_type);
    switch (ret) {
        case ETHERTYPE_IP: /* IP */
        {
            // Pick the correct offset in an Ethernet frame and pass 
            // the IP packet to the dynamic warden for further processing
            DynWarden* dw = DynWarden::getInstance();
            dw->receivedPacket(packet + sizeof (struct ether_header));
        }
            break;
        default:
            cout << "Unknown ETHERTYPE=" << ret << endl;
            break;
    }
}

void DevicePCAPOffline::dlt_RAW(const u_char * packet) {

    //pass the IP packet to the dynamic warden for further processing
    DynWarden* dw = DynWarden::getInstance();
    dw->receivedPacket(packet);

}

// *****************************************************************************
// Static PACKETHANDLER which is called back by pcap library for each packet 
// chunk.
// *****************************************************************************

void DevicePCAPOffline::packetHandler(u_char *userData, 
        const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    //We have store a pointer to class in the structure 
    //so we can get the pcap_descr of the open input
    //stream from the dynamic object (while being in the
    //static callback function.)
    pcap_data_t *pd = (pcap_data_t*) userData;

    // Received a packet from the input, so let's check
    // which link-layer header type we have received.
    // We can not assume its always an Ethernet type.
    switch (pcap_datalink(pd->deviceInstance->p)) {

        case DLT_EN10MB: //We got an standard Ethernet frame
            pd->deviceInstance->dlt_EN10MB(packet);
            break;

        case DLT_RAW: //this is a raw IP frame
            pd->deviceInstance->dlt_RAW(packet);
            break;

        default:
            cout << "DevicePCAPOffline: Error: Unknown datalink header."
                    << pcap_datalink(pd->deviceInstance->p) << endl;
            break;
    }

}

// ***************************************************************************
// CONSTRUCTOR
// ***************************************************************************

DevicePCAPOffline::DevicePCAPOffline() {

}

// ***************************************************************************
// DECONSTRUCTOR
// ***************************************************************************

DevicePCAPOffline::~DevicePCAPOffline() {

}

// ***************************************************************************
// OPEN
// ***************************************************************************

int DevicePCAPOffline::open(bool dir) {

    this->dir = dir; /* save file storage type for later when closing */
    
    char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer for pcap library */

    if (dir) { // File open for input direction

        printf("DevicePCAPOffline: Opening PCAP file in read mode\n");

        string ifile = (ConfigurationManager::getInstance())->getInput();

        // open capture file for offline processing
        p = pcap_open_offline(ifile.c_str(), errbuf);
        if (p == NULL) {
            printf("DevicePCAPOffline: pcap_open_offline() failed: %s", errbuf);
            return -1;
        }

        return 0;
    } else { // File open for output direction
        printf("DevicePCAPOffline: Opening PCAP file in write mode\n");

        string ofile = (ConfigurationManager::getInstance())->getOutput();

        p = pcap_open_dead(DLT_RAW, 1 << 16);
        dumper = pcap_dump_open(p, ofile.c_str());

        if (dumper == NULL) {
            printf("Error opening savefile %s with error: %s\n", ofile.c_str(),
                    pcap_geterr(p));
            return -1;
        }
        return 0;
    }

}

// ***************************************************************************
// CLOSE
// ***************************************************************************

int DevicePCAPOffline::close() {

    if (this->dir) { /* closing input file */
        printf("PCAP: Closing PCAP input file\n");

        // pcap_close() closes the files associated with pcap_descr and deallocates
        // resources.  
        pcap_close(p);

    } else { /* closing output file */
        printf("PCAP: Closing PCAP output file\n");
        if (pcap_dump_flush(dumper) == -1)
            printf("Error when flushing pcap savefile");

        pcap_dump_close(dumper);
    }

    return 0;
}

// ***************************************************************************
// RECEIVE data from pcap file
// ***************************************************************************

int DevicePCAPOffline::receive() {

    // start packet processing loop, just like live capture
    pd.deviceInstance = this;

    return pcap_dispatch(p, 1, this->packetHandler, (u_char*) & pd);
}

// ***************************************************************************
// WRITE data to pcap file.
// ***************************************************************************

int DevicePCAPOffline::send(const ip* packet) {

    //pcap_dump( (u_char*) dumper, NULL, (u_char*) packet);
    
    return 0;
}