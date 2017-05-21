#pragma once

#include <time.h>
#include <pcap.h>

#include "main.h"

class DevicePCAPOffline;

////! Used to transfer data from static callback to procPacket method
//
//typedef struct {
//    DevicePCAPOffline *deviceInstance;
//    //    DynWarden *dynWarden;
//} pcap_data_t;

typedef struct {
    pcap_t            *pcap_desc;      /* Ptr to the valid pcap_t structure */
    DevicePCAPOffline *deviceInstance; /* Ptr to the pcap device instance  */
    const pcap_pkthdr *pcap_header;    /* the pcap internal header */
    const u_char      *pcap_packet;    /* the proper network datagram */
    const u_char      *pcap_user_data; /*  */
    timespec          last_rx_time;    /* when did we rx the last packet of */
    timespec          rx_time;         /* timestamp when this packet was received */
    timespec          tx_time;         /* timestemp when packet was passed on again */
    //fi_struct* flowinfo 
} pcap_umbrella_t;

class DevicePCAPOffline {
private:
    pcap_t *p;
    pcap_dumper_t *dumper;
    bool dir; /* determines if this is a input- or output file */
    char* pWarden = nullptr;
 
    static void rx_packet_handler(u_char * userData, const pcap_pkthdr * pkthdr, const u_char * packet);
    timespec diff(timespec start, timespec end);
    
public:

    DevicePCAPOffline();
    ~DevicePCAPOffline();

    int open(bool dir);
    int close();
    int start_rx();
    int send(pcap_umbrella_t* packet, timespec* tm);
};


