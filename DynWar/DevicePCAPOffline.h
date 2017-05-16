#pragma once

#include <pcap.h>

#include "IODevice.h"

#include "main.h"

class DevicePCAPOffline;

//! Used to transfer data from static callback to procPacket method

typedef struct {
    DevicePCAPOffline *deviceInstance;
    //    DynWarden *dynWarden;
} pcap_data_t;

class DevicePCAPOffline :
public IODevice {
private:
    pcap_t *p;
    pcap_dumper_t *dumper;
    bool dir; /* determines if this is a input- or output file */
    
    char* pWarden = nullptr;
    pcap_data_t pd;

    void dlt_EN10MB(const u_char *packet);
    void dlt_RAW(const u_char *packet);

    static void packetHandler(u_char * userData, const pcap_pkthdr * pkthdr, const u_char * packet);

public:

    DevicePCAPOffline();
    ~DevicePCAPOffline();

    int open(bool dir);
    int close();

    int receive();
    int send(const ip* packet);
};


