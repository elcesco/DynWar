#pragma once
#include "IODevice.h"
#include "main.h"

class DevicePCAPOffline :
	public IODevice
{
private:
	pcap_t *pcap_descr;

public:
	static void packetHandler(u_char * userData, const pcap_pkthdr * pkthdr, const u_char * packet);

	DevicePCAPOffline();
	~DevicePCAPOffline();

	int open();
	int close();
	bool hasData();
	bool isOnline();
	
	int getData();
	int getInfo();
};

