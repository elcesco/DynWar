#include <cstdio>
#include <pcap.h>

#include "ConfigurationManager.h"
#include "DevicePCAPOffline.h"
#include "DynWarden.h"

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
            printf("DevicePCAPOffline: pcap_open_offline() failed: %s", 
                    errbuf);
            return -1;
        }

        return 0;
    } else { // File open for output direction
        printf("DevicePCAPOffline: Opening PCAP file in write mode\n");

        string ofile = (ConfigurationManager::getInstance())->getOutput();

        p = pcap_open_dead(DLT_RAW, 1 << 16);
        
        dumper = pcap_dump_open(p, ofile.c_str());
        if (dumper == NULL) {
            printf("Error opening savefile %s with error: %s\n", 
                    ofile.c_str(),
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
int DevicePCAPOffline::start_rx() {
    
    // We using this structure to pass the pointer to object instance
    // to each callback.
    pcap_umbrella_t* pu = (pcap_umbrella_t*) malloc(sizeof(pcap_umbrella_t));
    if (pu == NULL)
        printf("Error while allocating memory for pcap_umbrella\n");
    pu->deviceInstance = this;
    
    return pcap_dispatch(p, // ptr to the opened pcap descriptor
            1, // only 1 packet to read at a  time
            this->rx_packet_handler, // ptr to the handler function
            (u_char*) pu );  // ptr to user defined data
}

// *****************************************************************************
// Static PACKETHANDLER which is called back by pcap library for each packet 
// chunk.
// *****************************************************************************
void DevicePCAPOffline::rx_packet_handler(
        u_char *userData, 
        const struct pcap_pkthdr* pkthdr, 
        const u_char* packet) 
{
    // Allocate space in memory for each received packet to store meta data on 
    // the packet till we transmitted it again to the output.
    pcap_umbrella_t* pu_new = (pcap_umbrella_t*) malloc(sizeof(pcap_umbrella_t));
    if (pu_new == NULL)
        printf("Error while allocating memory for pcap_umbrella\n");
  
    pu_new->pcap_desc = ((pcap_umbrella_t*) userData)->deviceInstance->p;
    pu_new->deviceInstance = ((pcap_umbrella_t*) userData)->deviceInstance;
    pu_new->pcap_header = pkthdr;
    pu_new->pcap_packet = packet;
    
    int ret = clock_gettime(CLOCK_MONOTONIC, &pu_new->rx_time);
    if (ret != 0)
        printf("Error setting timestamp for received packet\n");
    
    DynWarden::getInstance()->receivedPacket(pu_new);    
}

// ***************************************************************************
// WRITE data to pcap file.
// ***************************************************************************
int DevicePCAPOffline::send(pcap_umbrella_t* pu, timespec* tm) {
    
    pcap_dump( (u_char*) dumper, // Ptr to the opened pcap descriptor
            pu->pcap_header,                  // Ptr to the pcap packet header
            pu->pcap_packet);

    int ret = clock_gettime(CLOCK_MONOTONIC, &pu->tx_time);
    if (ret == -1)
        printf("Error setting timestamp for transmitted packet - erro: %d\n", 
                errno);

    *tm = diff( pu->rx_time, pu->tx_time);
    
    // Clean up the memory we allocated with malloc for the 
    // umbrella structure.
    free(pu);
    
    return 0;
}

timespec DevicePCAPOffline::diff(timespec start, timespec end)
{
	timespec temp;
	if ((end.tv_nsec-start.tv_nsec)<0) {
		temp.tv_sec = end.tv_sec-start.tv_sec-1;
		temp.tv_nsec = 1000000000+end.tv_nsec-start.tv_nsec;
	} else {
		temp.tv_sec = end.tv_sec-start.tv_sec;
		temp.tv_nsec = end.tv_nsec-start.tv_nsec;
	}
	return temp;
}