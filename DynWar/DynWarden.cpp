#include "IODevice.h"
#include "DevicePCAPOffline.h"

#include "DynWarden.h"


DynWarden *DynWarden::s_instance = NULL;

DynWarden::DynWarden() {

    // *************************************************************************
    // Reset counters
    // *************************************************************************
    this->PacketCounter = 0;
    this->FlowCounter = 0;
    
    // *********************************************************************
    // Instantiate the sampling manager
    // *********************************************************************
    std::unique_ptr<SamplingManager> _sampler(SamplingManager::getInstance());


}

DynWarden::~DynWarden() {

    // *************************************************************************
    // Output performance data
    // *************************************************************************
    setlocale(LC_ALL,"");
    printf("\n");
    printf("Performance data:\n");
    printf("=================\n");
    printf("Packet Counter: %'d\n", this->PacketCounter);
    printf("Flow Counter:   %'d\n", this->FlowCounter);

}

DynWarden * DynWarden::getInstance() {
    if (s_instance == NULL) {
        s_instance = new DynWarden();
    }
    return s_instance;
}

int DynWarden::start() {
    std::cout << "starting dynamic warden..." << std::endl;
    
    // *************************************************************************
    // Initialize cukoo filters for the list of innocent flows
    // when we find an innocent flow we will store its flow ID
    // in this table so we can skip any further processing
    // *************************************************************************
    //TODO: Verify how to proper instanciate the filters. Currently I seems still
    // to be a strange workaround by utilizing another variable
    // *************************************************************************

    CuckooFilter<unsigned __int128, 32, cuckoofilter::SingleTable > a_flows(1000000);
    this->innocentFlows = &a_flows;

    CuckooFilter<unsigned __int128, 32, cuckoofilter::SingleTable > b_flows(1000000);
    this->suspiciousFlows = &b_flows;

    // Initialize cuckoo based map to store any suspicious flow ID
    // and a pointer to the flow informations.
    //FIXME: Still needs to be implemented

    // *************************************************************************
    // initialize input device
    // *************************************************************************
    IODevice* inputdevice = (IODevice*) (new DevicePCAPOffline());
    inputdevice->open();

    // *************************************************************************
    // initialize output
    // *************************************************************************
    //IODevice* outputdevice = (IODevice*)(new DevicePCAPOffline());
    //outputdevice->open();
    //FIXME

    // start processing incomming packets
    do {
        // is packet available ?
        if (inputdevice->hasData()) {

            // enable packet receiver
            inputdevice->receivedPacket();
        }

    } while (inputdevice->isOnline());

    // *************************************************************************
    // Close input and outout devices
    // *************************************************************************
    inputdevice->close();
    //outputdevice->close();

    return 0;
}

unsigned __int128* DynWarden::getFlowID(const ip* ipHeader) {

    // *************************************************************************
    // Calculate Flow ID
    // *************************************************************************
    // the 128 bit value is a combination of specific packets field to generate
    // an unique flow identifier.
    // 
    // Used mask:
    //  0 -  31 Source IP
    // 32 -  63 Destination IP
    // 64 - 159 Source Port
    // 80 - 191 Destination Port
    // 96 - 127 reserved

    unsigned __int128 *flowID = new unsigned __int128(0);

    *flowID += (uint32_t) ipHeader->ip_src.s_addr;
    *flowID = *flowID << 32;

    *flowID += (uint32_t) ipHeader->ip_dst.s_addr;
    *flowID = *flowID << 32;

    //TODO Get used port from sub protocols and add it to the flow id.
    
    return flowID;
}

void DynWarden::sendPacket(const u_char* IPPacket) {

    // TODO: Add the code to send the packet to the network again.

    return;
}

void DynWarden::receivedPacket(const u_char* IPPacket) {

    this->PacketCounter++;
    
    const struct ip* ipHeader = (struct ip*) IPPacket;

    // *************************************************************************
    // Get unique Flow ID
    // *************************************************************************
    // the 128 bit value is a combination of specific packets field to generate
    // an unique flow identifier.    
    //unsigned __int128 *flowID = new unsigned __int128;
    unsigned __int128 flowID = *getFlowID(ipHeader);

    // *************************************************************************
    // Received an known innocent flow ?
    // *************************************************************************
    // If we can identify an innocent flow by its characteristics we will store
    // its flowID so we can skip any further processing of the packet.
    // *************************************************************************
    if (innocentFlows->Contain(flowID) == cuckoofilter::Ok) {
        sendPacket(IPPacket);
        return;
    }

    // *************************************************************************
    // Is this a known flow which is already under surveillance ? If so we will
    // process the defined normalization rules on this packet before we proceed.
    // *************************************************************************
    if (suspiciousFlows->Contain(flowID) == cuckoofilter::Ok) {
      
        //TODO: Do the normalization job
        
    } else {
        
        // *********************************************************************
        // We have received an packet of an unknown flow. Let's check with 
        // the sampling manager if this flow will get sampled.
        // *********************************************************************
        if (SamplingMgr.consider(IPPacket)) {
            // Add flow to suspicious flow filter.
            if (suspiciousFlows->Contain(flowID) != cuckoofilter::Ok) {
                printf("Error adding new flow to suspicious flow filter\n");
            } else {
                this->FlowCounter++;
            }
 
            //TODO: Do the normalization job

        }
    }  

    // *************************************************************************
    // When all processing is completed we will send this packet to the output
    // *************************************************************************
    sendPacket(IPPacket);
    
}
