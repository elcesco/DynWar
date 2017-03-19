#include "DevicePCAPOffline.h"

using namespace std;

void DevicePCAPOffline::packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	cout << "DevicePCAPOffline: called back packetHandler..." << endl;

	const struct ether_header* ethernetHeader;
	const struct ip* ipHeader;
	const struct tcphdr* tcpHeader;
	//char sourceIp[INET_ADDRSTRLEN];
	//char destIp[INET_ADDRSTRLEN];
	u_int sourcePort, destPort;
	u_char *data;
	int dataLength = 0;
	string dataStr = "";

	ethernetHeader = (struct ether_header*)packet;
	//if (ntohs(ethernetHeader->ether_type) == ETHERTYPE_IP) {
	//	ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
	//	inet_ntop(AF_INET, &(ipHeader->ip_src), sourceIp, INET_ADDRSTRLEN);
	//	inet_ntop(AF_INET, &(ipHeader->ip_dst), destIp, INET_ADDRSTRLEN);

	//	if (ipHeader->ip_p == IPPROTO_TCP) {
	//		tcpHeader = (tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
	//		sourcePort = ntohs(tcpHeader->source);
	//		destPort = ntohs(tcpHeader->dest);
	//		data = (u_char*)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
	//		dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));

	//		// convert non-printable characters, other than carriage return, line feed,
	//		// or tab into periods when displayed.
	//		for (int i = 0; i < dataLength; i++) {
	//			if ((data[i] >= 32 && data[i] <= 126) || data[i] == 10 || data[i] == 11 || data[i] == 13) {
	//				dataStr += (char)data[i];
	//			}
	//			else {
	//				dataStr += ".";
	//			}
	//		}

	//		// print the results
	//		cout << sourceIp << ":" << sourcePort << " -> " << destIp << ":" << destPort << endl;
	//		if (dataLength > 0) {
	//			cout << dataStr << endl;
	//		}
	//	}
	//}

}

DevicePCAPOffline::DevicePCAPOffline()
{
	cout << "DevicePCAPOffline: Constructing DevicePCAPOffline()" << endl;
}

DevicePCAPOffline::~DevicePCAPOffline()
{
	cout << "DevicePCAPOffline: Destructing DevicePCAPOffline()" << endl;
}

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

	cout << "DevicePCAPOffline: pcap_open_offline() succeeded: " << endl;
	return 0;
}

int DevicePCAPOffline::close()
{
	cout << "DevicePCAPOffline: Closing PCAP in offline mode" << endl;

	// pcap_close() closes the files associated with pcap_descr and deallocates resources.  
	if (pcap_descr != NULL) {
		pcap_close(pcap_descr);
		return 0;
	}

	return 1;
}

bool DevicePCAPOffline::hasData()
{
	cout << "DevicePCAPOffline: Checking of further data is available in pcap trace file" << endl;

	return true; //FIXME
}

bool DevicePCAPOffline::isOnline()
{
	// For offline mode devices this functions returns the same as hasData(). However
	// in online mode there might be situations where the stream is still online and 
	// further packets are simply not received yet. In this case we just have to wait
	// for the next packet to arrive.

	cout << "DevicePCAPOffline: Checking if we are still online" << endl;

	return true; //FIXME
}

int DevicePCAPOffline::getData()
{
	// start packet processing loop, just like live capture
	if (pcap_loop(pcap_descr, 1, this->packetHandler, NULL) < 0) {
		cout << "DevicePCAPOffline: pcap_loop() failed: " << pcap_geterr(pcap_descr);
		return 1;
	}
}

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
	//struct in_addr addr;

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
