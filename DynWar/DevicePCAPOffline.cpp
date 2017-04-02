#include "DevicePCAPOffline.h"

using namespace std;

//! transfer data from static callback to procPacket method
typedef struct
{
	DevicePCAPOffline *nt;
} pcap_data_t;

void DevicePCAPOffline::dlt_EN10MB(const u_char * packet)
{
	const struct ether_header* ethernetHeader = (struct ether_header*) (packet);

	/* Ethernet protocol ID's */
	int ret = ntohs(ethernetHeader->ether_type);
	switch (ret)
	{
	case ETHERTYPE_IP: /* IP */
	{
		const struct ip* ipHeader = (struct ip*)(packet + sizeof(struct ether_header));

		char sourceIp[INET_ADDRSTRLEN];
		char destIp[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

		cout << "Ethertype: IPv4" << " : ";
		cout << "Source: " << sourceIp << " --> ";
		cout << "Destination: " << destIp << endl;
	}
	break;
	default:
		cout << "Unknown ETHERTYPE=" << ret << endl;
		break;
	}
}

void DevicePCAPOffline::dlt_RAW(const u_char * packet)
{
	const struct ip* ipHeader = (struct ip*)packet;

	char sourceIp[INET_ADDRSTRLEN];
	char destIp[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

	cout << "RAW IPv4 : Source: " << sourceIp << " --> Destination: " << destIp << endl;
}

// ****************************************************************************
// Static PACKETHANDLER which is called back by pcap library for each packet 
// chunk.
// ***************************************************************************
void DevicePCAPOffline::packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	//cout << "DevicePCAPOffline: called back packetHandler..." << endl;

	// Let's check which link-layer header type we have received. We can not 
	// assume its always an Ethernet type.
	pcap_data_t *pd = (pcap_data_t*) userData;
	switch (pcap_datalink(pd->nt->pcap_descr))
	{
	case DLT_EN10MB:
		pd->nt->dlt_EN10MB(packet);
		break;

	case DLT_RAW:
		pd->nt->dlt_RAW(packet);
		break;

	default:
		cout << "DevicePCAPOffline: Error: Unknown datalink header." << pcap_datalink(pd->nt->pcap_descr) << endl;
		break;
	}
	
	//((DynWarden) pd->nt->pWarden)->receivedPacket(packet);


}

// ***************************************************************************
// CONSTRUCTOR
// ***************************************************************************
DevicePCAPOffline::DevicePCAPOffline(char* dynwarden)
{
	// cout << "DevicePCAPOffline: Constructing DevicePCAPOffline()" << endl;
}

// ***************************************************************************
// DECONSTRUCTOR
// ***************************************************************************
DevicePCAPOffline::~DevicePCAPOffline()
{
	// cout << "DevicePCAPOffline: Destructing DevicePCAPOffline()" << endl;
}

// ***************************************************************************
// OPEN
// ***************************************************************************
int DevicePCAPOffline::open()
{
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

	//cout << "DevicePCAPOffline: pcap_open_offline() succeeded: " << endl;
	return 0;
}

// ***************************************************************************
// CLOSE
// ***************************************************************************
int DevicePCAPOffline::close()
{
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
bool DevicePCAPOffline::hasData()
{
	return _online; //FIXME
}

// ***************************************************************************
// ISONLINE
// ***************************************************************************
bool DevicePCAPOffline::isOnline()
{
	// For offline mode devices this functions returns the same as hasData(). However
	// in online mode there might be situations where the stream is still online and 
	// further packets are simply not received yet. In this case we just have to wait
	// for the next packet to arrive.
	return _online;
}

// ***************************************************************************
// RECEIVE
// ***************************************************************************
int DevicePCAPOffline::receivedPacket()
{
	pcap_data_t pd;
	pd.nt = this;

	// start packet processing loop, just like live capture
	int ret = pcap_dispatch(pcap_descr, 1, this->packetHandler, (u_char*) &pd );
	if (ret < 0) {
		cout << "DevicePCAPOffline: pcap_dispatch() failed: " << pcap_geterr(pcap_descr);
		return 1;
	}
	else if (ret == 0) {
		_online = false;
		return -1;
	}

	return -1;
}

