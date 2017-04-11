#pragma once

#include <pcap.h>

#include "IODevice.h"
#include "main.h"

class DevicePCAPOffline :
	public IODevice
{
private:
	pcap_t *pcap_descr;
	bool _online = false;
	char* pWarden = nullptr;

	void dlt_EN10MB(const u_char *packet);
	void dlt_RAW(const u_char *packet);

public:
	static void packetHandler(u_char * userData, const pcap_pkthdr * pkthdr, const u_char * packet);

	DevicePCAPOffline(char* dynwarden);
	~DevicePCAPOffline();

	int open();
	int close();
	bool hasData();
	bool isOnline();
	
	int receivedPacket();
};

