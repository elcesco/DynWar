#include "DynWarden.h"

DynWarden *DynWarden::s_instance = NULL;

DynWarden::DynWarden() {

}

DynWarden::~DynWarden() {

}

DynWarden * DynWarden::getInstance() {
    if (s_instance == NULL) {
        s_instance = new DynWarden();
    }
    return s_instance;
}

int DynWarden::start() {
    std::cout << "starting dynamic warden..." << std::endl;

    // Initialize cukoo filters for the list of innocent flows
    // when we find an innocent flow we will store its flow ID
    // in this table so we can skip any further processing

    // Create a cuckoo filter where each item is of type size_t and 
    // use 128 bits for each item:
    CuckooFilter<uint64_t, 32> a_flows(100000);
    this->ptrInnocent_flows = &a_flows;
    cout << ptrInnocent_flows->Info() << endl;

    // Initialize cuckoo based map to store any suspicious flow ID
    // and a pointer to the flow informations.
    //FIXME: Still needs to be implemented

    // initialize input
    IODevice* inputdevice = (IODevice*) (new DevicePCAPOffline());
    inputdevice->open();

    // initialize output
    //IODevice* outputdevice = (IODevice*)(new DevicePCAPOffline());
    //outputdevice->open();
    //FIXME

    // start processing incomming packets
    int counter = 0;
    do {
        // is packet available ?
        if (inputdevice->hasData()) {

            // enable packet receiver
            inputdevice->receivedPacket();

            // Is there another packet comming ? or are we done ?
            //std::cout << counter << ": Looping thru the packets." << std::endl;
            //FIXME
            counter++;

        }

    } while (inputdevice->isOnline());

    // Close input and outout devices
    inputdevice->close();
    //outputdevice->close();

    // Start analysis of the experiment
    //FIXME

    return 0;
}

void DynWarden::receivedPacket(const u_char * IPPacket) {
    const struct ip* ipHeader = (struct ip*) IPPacket;

    char sourceIp[INET_ADDRSTRLEN];
    char destIp[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

    //cout << printf("RAW IPv4 : Source: %-20s  --> Destination: %-20s ", sourceIp, destIp) << endl;

    //FIXME: Calculate Flow ID
    uint64_t flowID = 32;

    // Is this an innocent flow ID ?
    if (ptrInnocent_flows->Add(flowID) != cuckoofilter::Ok) {
        cerr << "Error adding flowID to cuckoo filter" << endl;
    }

    // Is this a known suspicious flow id ?
    //FIXME

    // Which sampling strategy to use ?
    //FIXME
    bool sampling = true;

    // Do we sample this packet ?
    if (sampling) {

        // Add to the cuckooMap
    }


}
