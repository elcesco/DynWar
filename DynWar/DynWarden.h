#pragma once
#include "main.h"


class DynWarden
{
private:
	cuckoohash_map<uint32_t, uint32_t> innocent_table;
	cuckoohash_map<uint32_t, uint32_t> suspicious_table;
	
public:
	DynWarden();
	~DynWarden();
	int start();

	static void receivedPacket(ether_header * ethernetHeader);
	
};

