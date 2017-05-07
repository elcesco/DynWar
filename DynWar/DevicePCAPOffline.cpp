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

// ****************************************************************************
// Static PACKETHANDLER which is called back by pcap library for each packet 
// chunk.
// ***************************************************************************

void DevicePCAPOffline::packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {

    //We have store a pointer to class in the structure 
    //so we can get the pcap_descr of the open input
    //stream from the dynamic object (while being in the
    //static callback function.)
    pcap_data_t *pd = (pcap_data_t*) userData;

    // Received a packet from the input, so let's check
    // which link-layer header type we have received.
    // We can not assume its always an Ethernet type.
    switch (pcap_datalink(pd->deviceInstance->pcap_descr)) {

        case DLT_EN10MB: //We got an standard Ethernet frame
            pd->deviceInstance->dlt_EN10MB(packet);
            break;

        case DLT_RAW: //this is a pure IP frame
            pd->deviceInstance->dlt_RAW(packet);
            break;

        default:
            cout << "DevicePCAPOffline: Error: Unknown datalink header." << pcap_datalink(pd->deviceInstance->pcap_descr) << endl;
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

int DevicePCAPOffline::open() {
    cout << "DevicePCAPOffline: Opening PCAP in offline mode" << endl;

    char errbuf[PCAP_ERRBUF_SIZE];

    string inputfile = (ConfigurationManager::getInstance())->getInput();

    // open capture file for offline processing
    pcap_descr = pcap_open_offline(inputfile.c_str(), errbuf);
    if (pcap_descr == NULL) {
        cout << "DevicePCAPOffline: pcap_open_offline() failed: " << errbuf << endl;
        return 1;
    }
    _online = true;

    return 0;
}

// ***************************************************************************
// CLOSE
// ***************************************************************************

int DevicePCAPOffline::close() {
    cout << "DevicePCAPOffline: Closing PCAP in offline mode" << endl;

    // pcap_close() closes the files associated with pcap_descr and deallocates resources.  
    if (pcap_descr != NULL) {
        pcap_close(pcap_descr);
        _online = false;
        return 0;
    }

    return 1;
}

// ***************************************************************************
// HASDATA
// ***************************************************************************

bool DevicePCAPOffline::hasData() {
    return _online; //FIXME
}

// ***************************************************************************
// ISONLINE
// ***************************************************************************

bool DevicePCAPOffline::isOnline() {
    // For offline mode devices this functions returns the same as hasData(). However
    // in online mode there might be situations where the stream is still online and 
    // further packets are simply not received yet. In this case we just have to wait
    // for the next packet to arrive.
    return _online;
}

// ***************************************************************************
// RECEIVE
// ***************************************************************************

int DevicePCAPOffline::receivedPacket() {

    pd.deviceInstance = this;

    // start packet processing loop, just like live capture
    int ret = pcap_dispatch(pcap_descr, 1, this->packetHandler, (u_char*) & pd);
    if (ret < 0) {
        cout << "DevicePCAPOffline: pcap_dispatch() failed: " << pcap_geterr(pcap_descr);
        return 1;
    } else if (ret == 0) {
        _online = false;
        return -1;
    }

    return -1;
}

