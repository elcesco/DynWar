#pragma once

#include "cuckoofilter.h"

#include "SamplingManager.h"

#include "DynWarden.h"


//#include "main.h"

using namespace std;
using namespace cuckoofilter;

class DynWarden {
private:
    //cuckoohash_map<uint32_t, uint32_t> innocent_table;
    //cuckoohash_map<uint32_t, uint32_t> suspicious_table;
    static DynWarden *s_instance; //link to the globally available instance	
    CuckooFilter<unsigned __int128, 32, cuckoofilter::SingleTable>* innocentFlows;
    CuckooFilter<unsigned __int128, 32, cuckoofilter::SingleTable>* suspiciousFlows;
    uint32_t PacketCounter = 0; // to count incomming packets
    uint32_t FlowCounter = 0; // to count unique incomming ip flows

    SamplingManager SamplingMgr;

    unsigned __int128* getFlowIDv4(const ip* ipHeader);

public:
    DynWarden();
    ~DynWarden();
    int start();

    static DynWarden *getInstance(); //get access to the one and only dynamic warden instance	

    void sendPacket(const u_char* IPPacket);
    void receivedPacket(const u_char * IPPacket);

};

