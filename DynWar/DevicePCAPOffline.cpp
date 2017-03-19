#include "DevicePCAPOffline.h"

using namespace std;

// ***************************************************************************
// PACKETHANDLER
// ***************************************************************************
void DevicePCAPOffline::packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	//cout << "DevicePCAPOffline: called back packetHandler..." << endl;

	//FIXME: the switch block needs to move to the DynWarden class !!!

	/* Ethernet protocol ID's */
	const struct ether_header* ethernetHeader;
	ethernetHeader = (struct ether_header*)packet;
	int ret = ntohs(ethernetHeader->ether_type);
	switch (ret)
	{
	case ETHERTYPE_PUP: /* Xerox PUP */
		cout << "Ethertype: PUP" << endl;
		break;
	case ETHERTYPE_SPRITE: /* Sprite */
		cout << "Ethertype: SPRITE" << endl;
		break;
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
	case ETHERTYPE_ARP: /* Address resolution */
		cout << "Ethertype: ARP" << endl;
		break;
	case ETHERTYPE_REVARP: /* Reverse ARP */
		cout << "Ethertype: Reverse ARP" << endl;
		break;
	case ETHERTYPE_AT: /* AppleTalk protocol */
		cout << "Ethertype: AppleTalk" << endl;
		break;
	case ETHERTYPE_AARP: /* AppleTalk ARP */
		cout << "Ethertype: AppleTalk ARP" << endl;
		break;
	case ETHERTYPE_VLAN: /* IEEE 802.1Q VLAN tagging */
		cout << "Ethertype: VLAN" << endl;
		break;
	case ETHERTYPE_IPX: /* IPX */
		cout << "Ethertype: IPX" << endl;
		break;
	case ETHERTYPE_IPV6: /* IP protocol version 6 */
		cout << "Ethertype: IPv6" << endl;
		break;
	case ETHERTYPE_LOOPBACK: /* used to test interfaces */
		cout << "Ethertype: LOOPBACK" << endl;
		break;
	default:
		cout << "Unknown ETHERTYPE=" << ret << endl;
		break;
	}
}

// ***************************************************************************
// CONSTRUCTOR
// ***************************************************************************
DevicePCAPOffline::DevicePCAPOffline()
{
	cout << "DevicePCAPOffline: Constructing DevicePCAPOffline()" << endl;
}

// ***************************************************************************
// DECONSTRUCTOR
// ***************************************************************************
DevicePCAPOffline::~DevicePCAPOffline()
{
	cout << "DevicePCAPOffline: Destructing DevicePCAPOffline()" << endl;
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

	cout << "DevicePCAPOffline: pcap_open_offline() succeeded: " << endl;
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
	//cout << "DevicePCAPOffline: Checking of further data is available in pcap trace file" << endl;

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

	//cout << "DevicePCAPOffline: Checking if we are still online" << endl;

	return _online;
}

// ***************************************************************************
// RECEIVE
// ***************************************************************************
int DevicePCAPOffline::receive()
{
	// start packet processing loop, just like live capture
	int ret = pcap_dispatch(pcap_descr, 1, this->packetHandler, NULL);
	if (ret < 0) {
		cout << "DevicePCAPOffline: pcap_dispatch() failed: " << pcap_geterr(pcap_descr);
		return 1;
	}
	else if (ret == 0) {
		_online = false;
		return -1;
	}
}

// ***************************************************************************
// GETINFO
// ***************************************************************************
int DevicePCAPOffline::getInfo()
{

	char *dev; /* name of the device to use */
	char *net; /* dot notation of the network address */
	char *mask;/* dot notation of the network mask    */
	pcap_t* descr;
	int ret;   /* return code */

	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp; /* ip          */
	bpf_u_int32 maskp;/* subnet mask */
	struct in_addr addr;

	/* ask pcap to find a valid device for use to sniff on */
	dev = pcap_lookupdev(errbuf);

	/* error checking */
	if (dev == NULL)
	{
		printf("%s\n", errbuf);
		return 1;
	}

	/* ask pcap for the network address and mask of the device */
	pcap_lookupnet(dev, &netp, &maskp, errbuf);

	return 0;
}
