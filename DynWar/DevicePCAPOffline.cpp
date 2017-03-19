#include "DevicePCAPOffline.h"

DevicePCAPOffline::DevicePCAPOffline()
{
}

DevicePCAPOffline::~DevicePCAPOffline()
{
}

void DevicePCAPOffline::getInfo()
{

	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t *descr;
	
	descr = pcap_open_offline("http.cap", errbuf);

	//if (dev == NULL) {
	//	fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
	//	return;
	//}
	//printf("Device: %s\n", dev);

	return;
}
